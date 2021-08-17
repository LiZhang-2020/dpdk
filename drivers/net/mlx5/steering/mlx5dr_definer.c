/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5dr_internal.h"

#define DW_SIZE		4
#define BITS_IN_BYTE	8
#define STE_IPV4	0x1
#define STE_IPV6	0x2

/* Selectors based on match TAG */
#define DW_SELECTORS	6
#define BYTE_SELECTORS	8

/* The maximum number of supported fields in HWS */
#define MLX5DR_DEFINER_FIELD_MAX	3

/* Tag setter function based on bit offset and mask */
#define DR_TAG_SET(p, v, byte_off, bit_off, mask) \
	do { \
		u32 _v = v; \
		*((rte_be32_t *)(p) + (byte_off / 4)) = \
		rte_cpu_to_be_32((rte_be_to_cpu_32(*((u32 *)(p) + \
				  (byte_off / 4))) & \
				  (~(mask << bit_off))) | \
				 (((_v) & mask) << \
				  bit_off)); \
	} while (0)

#define DR_HL_SET(fc, p, fld) \
	do { \
		fc->bit_mask = __mlx5_mask(definer_hl, fld); \
		fc->bit_off = __mlx5_dw_bit_off(definer_hl, fld); \
		fc->byte_off = MLX5_BYTE_OFF(definer_hl, fld); \
		MLX5_SET(definer_hl, p, fld, -1); \
	} while (0)

struct mlx5dr_definer {
	uint8_t dw_selector[DW_SELECTORS];
	uint8_t byte_selector[BYTE_SELECTORS];
};

struct mlx5dr_definer_fc {
	uint8_t item_idx;
	uint32_t byte_off;
	uint32_t bit_off;
	uint32_t bit_mask;
	void (*tag_set)(struct mlx5dr_definer_fc *fc,
			const void *item_spec,
			uint8_t *tag);
};

static void
mlx5dr_definer_set_ipv4_dst_addr(struct mlx5dr_definer_fc *fc,
				 const void *item_spec,
				 uint8_t *tag)
{
	const struct rte_ipv4_hdr *v = item_spec;

	DR_TAG_SET(tag, v->dst_addr, fc->byte_off, fc->bit_off, fc->bit_mask);
}

static void
mlx5dr_definer_set_ipv4_src_addr(struct mlx5dr_definer_fc *fc,
				 const void *item_spec,
				 uint8_t *tag)
{
	const struct rte_ipv4_hdr *v = item_spec;

	DR_TAG_SET(tag, v->src_addr, fc->byte_off, fc->bit_off, fc->bit_mask);
}

static void
mlx5dr_definer_set_ipv4_version(struct mlx5dr_definer_fc *fc,
				const void *item_spec,
				uint8_t *tag)
{
	const struct rte_ipv4_hdr *v = item_spec;

	if (v->version == IPVERSION)
		DR_TAG_SET(tag, STE_IPV4, fc->byte_off, fc->bit_off, fc->bit_mask);
	else
		DR_TAG_SET(tag, -1, fc->byte_off, fc->bit_off, fc->bit_mask);
}

static int
mlx5dr_definer_conv_item_ipv4(struct mlx5dr_definer_fc *fc,
			      struct rte_flow_item *item,
			      int item_idx,
			      uint8_t *hl)
{
	const struct rte_ipv4_hdr *m = item->mask;
	int total_fcs = 0;

	if (m->dst_addr && ++total_fcs) {
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_set_ipv4_dst_addr;
		DR_HL_SET(fc, hl, ipv4_src_dest_outer.destination_address);
		fc++;
	}

	if (m->src_addr && ++total_fcs) {
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_set_ipv4_src_addr;
		DR_HL_SET(fc, hl, ipv4_src_dest_outer.source_address);
		fc++;
	}

	if (m->version && ++total_fcs) {
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_set_ipv4_version;
		DR_HL_SET(fc, hl, eth_l2_outer.l3_type);
		fc++;
	}

	return total_fcs;
}

static int
mlx5dr_definer_conv_items_to_hl(struct mlx5dr_matcher *matcher,
				struct rte_flow_item *items,
				uint8_t *hl)
{
	struct mlx5dr_definer_fc fc[MLX5DR_DEFINER_FIELD_MAX] = {{0}};
	uint32_t total = 0;
	int i;

	/* Collect all RTE fields to the field array and set header layout */
	for (i = 0; items->type != RTE_FLOW_ITEM_TYPE_END; i++, items++) {
		switch (items->type) {
		case RTE_FLOW_ITEM_TYPE_IPV4:
			total += mlx5dr_definer_conv_item_ipv4(&fc[total],
							       items, i, hl);
			break;
		default:
			rte_errno = ENOTSUP;
			return rte_errno;
		}
	}

	matcher->fc = simple_calloc(total, sizeof(*matcher->fc));
	if (!matcher->fc) {
		DRV_LOG(ERR, "Failed to allocate field copy array");
                rte_errno = ENOMEM;
                return rte_errno;
	}

	memcpy(matcher->fc, fc, total * sizeof(*matcher->fc));
	matcher->fc_sz = total;

	return 0;
}

static int
mlx5dr_definer_find_byte_in_tag(struct mlx5dr_definer *definer,
				uint32_t hl_byte_off,
				uint32_t *tag_byte_off)
{
	uint8_t byte_offset;;
	int i;

	/* Add offset to skip DWs in definer */
	byte_offset = DW_SIZE * DW_SELECTORS;
	for (i = 0; i < BYTE_SELECTORS; i++) {
		if (definer->byte_selector[i] == hl_byte_off) {
			*tag_byte_off = byte_offset + (BYTE_SELECTORS - i - 1);
			return 0;
		}
	}

	/* Add offset since each DW covers multiple BYTEs */
	byte_offset = hl_byte_off % DW_SIZE;
	for (i = 0; i < DW_SELECTORS; i++) {
		if (definer->dw_selector[i] == hl_byte_off / DW_SIZE) {
			*tag_byte_off = byte_offset + DW_SIZE * (DW_SELECTORS - i - 1);
			return 0;
		}
	}

	/* The hl byte offset must be part of the definer */
	DRV_LOG(ERR, "Programming error failed to map header layout to definer");
	rte_errno = EINVAL;
	return rte_errno;
}

static int
mlx5dr_definer_fc_bind(struct mlx5dr_definer *definer,
		       struct mlx5dr_definer_fc *fc,
		       uint32_t fc_sz)
{
	uint32_t tag_offset;
	int ret, byte_diff;
	uint32_t i;

	for (i = 0; i < fc_sz; i++) {
		/* Map header layout byte offset to byte offset in tag */
		ret = mlx5dr_definer_find_byte_in_tag(definer, fc->byte_off, &tag_offset);
		if (ret)
			return ret;

		/* Move setter based on the location in the definer */
		byte_diff = tag_offset % DW_SIZE - fc->byte_off % DW_SIZE;
		fc->bit_off = fc->bit_off + byte_diff * BITS_IN_BYTE;

		/* Update offset in headers layout to offset in tag */
		fc->byte_off = tag_offset;
		fc++;
	}

	return 0;
}

static int
mlx5dr_definer_find_best_hl_fit(struct mlx5dr_definer *definer,
				uint16_t *format_id)
{
	definer->dw_selector[5] = 64;
	definer->dw_selector[4] = 65;
	definer->dw_selector[3] = 24;
	definer->dw_selector[2] = 2;
	definer->dw_selector[1] = 138;
	definer->dw_selector[0] = 0;
	definer->byte_selector[7] = 32;
	definer->byte_selector[6] = 33;
	definer->byte_selector[5] = 34;
	definer->byte_selector[4] = 35;
	definer->byte_selector[3] = 36;
	definer->byte_selector[2] = 37;
	definer->byte_selector[1] = 4;
	definer->byte_selector[0] = 5;

	*format_id = 22;
	return 0;
}

static void
mlx5dr_definer_create_tag_mask(struct rte_flow_item *items,
			       struct mlx5dr_definer_fc *fc,
			       uint32_t fc_sz,
			       uint8_t *tag)
{
	uint32_t i;

	for (i = 0; i < fc_sz; i++) {
		fc->tag_set(fc, items[fc->item_idx].mask, tag);
		fc++;
	}
}

void mlx5dr_definer_create_tag(struct rte_flow_item *items,
			       struct mlx5dr_definer_fc *fc,
			       uint32_t fc_sz,
			       uint8_t *tag)
{
	uint32_t i;

	for (i = 0; i < fc_sz; i++) {
		fc->tag_set(fc, items[fc->item_idx].spec, tag);
		fc++;
	}
}

int mlx5dr_definer_create(struct mlx5dr_matcher *matcher,
			  struct rte_flow_item *items)
{
	struct ibv_context *ibv_ctx = matcher->tbl->ctx->ibv_ctx;
	struct mlx5dr_cmd_definer_create_attr def_attr = {0};
	uint8_t tag[MLX5DR_MATCH_TAG_SZ] = {0};
	struct mlx5dr_definer definer;
	uint16_t format_id;
	uint8_t *hl;
	int ret;

	/* Header layout (hl) holds full bit mask per field */
	hl = simple_calloc(1, MLX5_ST_SZ_BYTES(definer_hl));
	if (!hl) {
		DRV_LOG(ERR, "Failed to allocate memory for header layout");
                rte_errno = ENOMEM;
                return rte_errno;
	}

	/* Convert items to hl and allocate the field copy array (fc) */
	ret = mlx5dr_definer_conv_items_to_hl(matcher, items, hl);
	if (ret) {
		DRV_LOG(ERR, "Failed to convert items to hl");
		goto free_hl;
	}

	/* Find the definer for given header layout */
	ret = mlx5dr_definer_find_best_hl_fit(&definer, &format_id);
	if (ret) {
		DRV_LOG(ERR, "Failed to create definer from header layout");
		goto free_field_copy;
	}

	/* Align field copy array based on the new definer */
	ret = mlx5dr_definer_fc_bind(&definer, matcher->fc, matcher->fc_sz);
	if (ret) {
		DRV_LOG(ERR, "Failed to bind field copy to definer");
		goto free_field_copy;
	}

	mlx5dr_definer_create_tag_mask(items, matcher->fc, matcher->fc_sz, tag);

	/* Create definer based on the bitmask tag */
	def_attr.match_mask = tag;
	def_attr.format_id = format_id;
	matcher->definer = mlx5dr_cmd_definer_create(ibv_ctx, &def_attr);
	if (!matcher->definer)
		goto free_field_copy;

	return 0;

free_field_copy:
	simple_free(matcher->fc);
free_hl:
	simple_free(hl);
	return rte_errno;
}

void mlx5dr_definer_destroy(struct mlx5dr_matcher *matcher)
{
	simple_free(matcher->fc);
	mlx5dr_cmd_destroy_obj(matcher->definer);
}
