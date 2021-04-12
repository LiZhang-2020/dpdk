/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2015 6WIND S.A.
 * Copyright 2015-2019 Mellanox Technologies, Ltd
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_prefetch.h>
#include <rte_common.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_cycles.h>
#include <rte_flow.h>

#include <mlx5_prm.h>
#include <mlx5_common.h>

#include "mlx5_autoconf.h"
#include "mlx5_defs.h"
#include "mlx5.h"
#include "mlx5_utils.h"
#include "mlx5_rxtx.h"
#include "mlx5_rx.h"
#include "mlx5_tx.h"

uint32_t mlx5_ptype_table[] __rte_cache_aligned = {
	[0xff] = RTE_PTYPE_ALL_MASK, /* Last entry for errored packet. */
};

uint8_t mlx5_cksum_table[1 << 10] __rte_cache_aligned;
uint8_t mlx5_swp_types_table[1 << 10] __rte_cache_aligned;

uint64_t rte_net_mlx5_dynf_inline_mask;

/**
 * Build a table to translate Rx completion flags to packet type.
 *
 * @note: fix mlx5_dev_supported_ptypes_get() if any change here.
 */
void
mlx5_set_ptype_table(void)
{
	unsigned int i;
	uint32_t (*p)[RTE_DIM(mlx5_ptype_table)] = &mlx5_ptype_table;

	/* Last entry must not be overwritten, reserved for errored packet. */
	for (i = 0; i < RTE_DIM(mlx5_ptype_table) - 1; ++i)
		(*p)[i] = RTE_PTYPE_UNKNOWN;
	/*
	 * The index to the array should have:
	 * bit[1:0] = l3_hdr_type
	 * bit[4:2] = l4_hdr_type
	 * bit[5] = ip_frag
	 * bit[6] = tunneled
	 * bit[7] = outer_l3_type
	 */
	/* L2 */
	(*p)[0x00] = RTE_PTYPE_L2_ETHER;
	/* L3 */
	(*p)[0x01] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_L4_NONFRAG;
	(*p)[0x02] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_L4_NONFRAG;
	/* Fragmented */
	(*p)[0x21] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_L4_FRAG;
	(*p)[0x22] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_L4_FRAG;
	/* TCP */
	(*p)[0x05] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_L4_TCP;
	(*p)[0x06] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_L4_TCP;
	(*p)[0x0d] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_L4_TCP;
	(*p)[0x0e] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_L4_TCP;
	(*p)[0x11] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_L4_TCP;
	(*p)[0x12] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_L4_TCP;
	/* UDP */
	(*p)[0x09] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_L4_UDP;
	(*p)[0x0a] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_L4_UDP;
	/* Repeat with outer_l3_type being set. Just in case. */
	(*p)[0x81] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_L4_NONFRAG;
	(*p)[0x82] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_L4_NONFRAG;
	(*p)[0xa1] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_L4_FRAG;
	(*p)[0xa2] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_L4_FRAG;
	(*p)[0x85] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_L4_TCP;
	(*p)[0x86] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_L4_TCP;
	(*p)[0x8d] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_L4_TCP;
	(*p)[0x8e] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_L4_TCP;
	(*p)[0x91] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_L4_TCP;
	(*p)[0x92] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_L4_TCP;
	(*p)[0x89] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_L4_UDP;
	(*p)[0x8a] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_L4_UDP;
	/* Tunneled - L3 */
	(*p)[0x40] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN;
	(*p)[0x41] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_NONFRAG;
	(*p)[0x42] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_NONFRAG;
	(*p)[0xc0] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN;
	(*p)[0xc1] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_NONFRAG;
	(*p)[0xc2] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_NONFRAG;
	/* Tunneled - Fragmented */
	(*p)[0x61] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_FRAG;
	(*p)[0x62] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_FRAG;
	(*p)[0xe1] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_FRAG;
	(*p)[0xe2] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_FRAG;
	/* Tunneled - TCP */
	(*p)[0x45] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_TCP;
	(*p)[0x46] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_TCP;
	(*p)[0x4d] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_TCP;
	(*p)[0x4e] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_TCP;
	(*p)[0x51] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_TCP;
	(*p)[0x52] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_TCP;
	(*p)[0xc5] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_TCP;
	(*p)[0xc6] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_TCP;
	(*p)[0xcd] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_TCP;
	(*p)[0xce] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_TCP;
	(*p)[0xd1] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_TCP;
	(*p)[0xd2] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_TCP;
	/* Tunneled - UDP */
	(*p)[0x49] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_UDP;
	(*p)[0x4a] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_UDP;
	(*p)[0xc9] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_UDP;
	(*p)[0xca] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		     RTE_PTYPE_INNER_L4_UDP;
}

/**
 * Build a table to translate packet to checksum type of Verbs.
 */
void
mlx5_set_cksum_table(void)
{
	unsigned int i;
	uint8_t v;

	/*
	 * The index should have:
	 * bit[0] = PKT_TX_TCP_SEG
	 * bit[2:3] = PKT_TX_UDP_CKSUM, PKT_TX_TCP_CKSUM
	 * bit[4] = PKT_TX_IP_CKSUM
	 * bit[8] = PKT_TX_OUTER_IP_CKSUM
	 * bit[9] = tunnel
	 */
	for (i = 0; i < RTE_DIM(mlx5_cksum_table); ++i) {
		v = 0;
		if (i & (1 << 9)) {
			/* Tunneled packet. */
			if (i & (1 << 8)) /* Outer IP. */
				v |= MLX5_ETH_WQE_L3_CSUM;
			if (i & (1 << 4)) /* Inner IP. */
				v |= MLX5_ETH_WQE_L3_INNER_CSUM;
			if (i & (3 << 2 | 1 << 0)) /* L4 or TSO. */
				v |= MLX5_ETH_WQE_L4_INNER_CSUM;
		} else {
			/* No tunnel. */
			if (i & (1 << 4)) /* IP. */
				v |= MLX5_ETH_WQE_L3_CSUM;
			if (i & (3 << 2 | 1 << 0)) /* L4 or TSO. */
				v |= MLX5_ETH_WQE_L4_CSUM;
		}
		mlx5_cksum_table[i] = v;
	}
}

/**
 * Build a table to translate packet type of mbuf to SWP type of Verbs.
 */
void
mlx5_set_swp_types_table(void)
{
	unsigned int i;
	uint8_t v;

	/*
	 * The index should have:
	 * bit[0:1] = PKT_TX_L4_MASK
	 * bit[4] = PKT_TX_IPV6
	 * bit[8] = PKT_TX_OUTER_IPV6
	 * bit[9] = PKT_TX_OUTER_UDP
	 */
	for (i = 0; i < RTE_DIM(mlx5_swp_types_table); ++i) {
		v = 0;
		if (i & (1 << 8))
			v |= MLX5_ETH_WQE_L3_OUTER_IPV6;
		if (i & (1 << 9))
			v |= MLX5_ETH_WQE_L4_OUTER_UDP;
		if (i & (1 << 4))
			v |= MLX5_ETH_WQE_L3_INNER_IPV6;
		if ((i & 3) == (PKT_TX_UDP_CKSUM >> 52))
			v |= MLX5_ETH_WQE_L4_INNER_UDP;
		mlx5_swp_types_table[i] = v;
	}
}

#define MLX5_SYSTEM_LOG_DIR "/var/log"
/**
 * Dump debug information to log file.
 *
 * @param fname
 *   The file name.
 * @param hex_title
 *   If not NULL this string is printed as a header to the output
 *   and the output will be in hexadecimal view.
 * @param buf
 *   This is the buffer address to print out.
 * @param len
 *   The number of bytes to dump out.
 */
void
mlx5_dump_debug_information(const char *fname, const char *hex_title,
			    const void *buf, unsigned int hex_len)
{
	FILE *fd;

	MKSTR(path, "%s/%s", MLX5_SYSTEM_LOG_DIR, fname);
	fd = fopen(path, "a+");
	if (!fd) {
		DRV_LOG(WARNING, "cannot open %s for debug dump", path);
		MKSTR(path2, "./%s", fname);
		fd = fopen(path2, "a+");
		if (!fd) {
			DRV_LOG(ERR, "cannot open %s for debug dump", path2);
			return;
		}
		DRV_LOG(INFO, "New debug dump in file %s", path2);
	} else {
		DRV_LOG(INFO, "New debug dump in file %s", path);
	}
	if (hex_title)
		rte_hexdump(fd, hex_title, buf, hex_len);
	else
		fprintf(fd, "%s", (const char *)buf);
	fprintf(fd, "\n\n\n");
	fclose(fd);
}

/**
 * Modify a Verbs/DevX queue state.
 * This must be called from the primary process.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param sm
 *   State modify request parameters.
 *
 * @return
 *   0 in case of success else non-zero value and rte_errno is set.
 */
int
mlx5_queue_state_modify_primary(struct rte_eth_dev *dev,
			const struct mlx5_mp_arg_queue_state_modify *sm)
{
	int ret;
	struct mlx5_priv *priv = dev->data->dev_private;

	if (sm->is_wq) {
		struct mlx5_rxq_priv *rxq = mlx5_rxq_get(dev, sm->queue_id);

		ret = priv->obj_ops.rxq_res_modify(rxq, sm->state);
		if (ret) {
			DRV_LOG(ERR, "Cannot change Rx WQ state to %u  - %s",
					sm->state, strerror(errno));
			rte_errno = errno;
			return ret;
		}
	} else {
		struct mlx5_txq_data *txq = (*priv->txqs)[sm->queue_id];
		struct mlx5_txq_ctrl *txq_ctrl =
			container_of(txq, struct mlx5_txq_ctrl, txq);

		ret = priv->obj_ops.txq_obj_modify(txq_ctrl->obj,
						   MLX5_TXQ_MOD_ERR2RDY,
						   (uint8_t)priv->dev_port);
		if (ret)
			return ret;
	}
	return 0;
}

/**
 * Modify a Verbs queue state.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param sm
 *   State modify request parameters.
 *
 * @return
 *   0 in case of success else non-zero value.
 */
int
mlx5_queue_state_modify(struct rte_eth_dev *dev,
			struct mlx5_mp_arg_queue_state_modify *sm)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	int ret = 0;

	switch (rte_eal_process_type()) {
	case RTE_PROC_PRIMARY:
		ret = mlx5_queue_state_modify_primary(dev, sm);
		break;
	case RTE_PROC_SECONDARY:
		ret = mlx5_mp_req_queue_state_modify(&priv->mp_id, sm);
		break;
	default:
		break;
	}
	return ret;
}

/* Generate routines with Enhanced Multi-Packet Write support. */
MLX5_TXOFF_DECL(full_empw,
		MLX5_TXOFF_CONFIG_FULL | MLX5_TXOFF_CONFIG_EMPW)

MLX5_TXOFF_DECL(none_empw,
		MLX5_TXOFF_CONFIG_NONE | MLX5_TXOFF_CONFIG_EMPW)

MLX5_TXOFF_DECL(md_empw,
		MLX5_TXOFF_CONFIG_METADATA | MLX5_TXOFF_CONFIG_EMPW)

MLX5_TXOFF_DECL(mt_empw,
		MLX5_TXOFF_CONFIG_MULTI | MLX5_TXOFF_CONFIG_TSO |
		MLX5_TXOFF_CONFIG_METADATA | MLX5_TXOFF_CONFIG_EMPW)

MLX5_TXOFF_DECL(mtsc_empw,
		MLX5_TXOFF_CONFIG_MULTI | MLX5_TXOFF_CONFIG_TSO |
		MLX5_TXOFF_CONFIG_SWP |	MLX5_TXOFF_CONFIG_CSUM |
		MLX5_TXOFF_CONFIG_METADATA | MLX5_TXOFF_CONFIG_EMPW)

MLX5_TXOFF_DECL(mti_empw,
		MLX5_TXOFF_CONFIG_MULTI | MLX5_TXOFF_CONFIG_TSO |
		MLX5_TXOFF_CONFIG_INLINE |
		MLX5_TXOFF_CONFIG_METADATA | MLX5_TXOFF_CONFIG_EMPW)

MLX5_TXOFF_DECL(mtv_empw,
		MLX5_TXOFF_CONFIG_MULTI | MLX5_TXOFF_CONFIG_TSO |
		MLX5_TXOFF_CONFIG_VLAN |
		MLX5_TXOFF_CONFIG_METADATA | MLX5_TXOFF_CONFIG_EMPW)

MLX5_TXOFF_DECL(mtiv_empw,
		MLX5_TXOFF_CONFIG_MULTI | MLX5_TXOFF_CONFIG_TSO |
		MLX5_TXOFF_CONFIG_INLINE | MLX5_TXOFF_CONFIG_VLAN |
		MLX5_TXOFF_CONFIG_METADATA | MLX5_TXOFF_CONFIG_EMPW)

MLX5_TXOFF_DECL(sc_empw,
		MLX5_TXOFF_CONFIG_SWP |	MLX5_TXOFF_CONFIG_CSUM |
		MLX5_TXOFF_CONFIG_METADATA | MLX5_TXOFF_CONFIG_EMPW)

MLX5_TXOFF_DECL(sci_empw,
		MLX5_TXOFF_CONFIG_SWP |	MLX5_TXOFF_CONFIG_CSUM |
		MLX5_TXOFF_CONFIG_INLINE |
		MLX5_TXOFF_CONFIG_METADATA | MLX5_TXOFF_CONFIG_EMPW)

MLX5_TXOFF_DECL(scv_empw,
		MLX5_TXOFF_CONFIG_SWP |	MLX5_TXOFF_CONFIG_CSUM |
		MLX5_TXOFF_CONFIG_VLAN |
		MLX5_TXOFF_CONFIG_METADATA | MLX5_TXOFF_CONFIG_EMPW)

MLX5_TXOFF_DECL(sciv_empw,
		MLX5_TXOFF_CONFIG_SWP |	MLX5_TXOFF_CONFIG_CSUM |
		MLX5_TXOFF_CONFIG_INLINE | MLX5_TXOFF_CONFIG_VLAN |
		MLX5_TXOFF_CONFIG_METADATA | MLX5_TXOFF_CONFIG_EMPW)

MLX5_TXOFF_DECL(i_empw,
		MLX5_TXOFF_CONFIG_INLINE |
		MLX5_TXOFF_CONFIG_METADATA | MLX5_TXOFF_CONFIG_EMPW)

MLX5_TXOFF_DECL(v_empw,
		MLX5_TXOFF_CONFIG_VLAN |
		MLX5_TXOFF_CONFIG_METADATA | MLX5_TXOFF_CONFIG_EMPW)

MLX5_TXOFF_DECL(iv_empw,
		MLX5_TXOFF_CONFIG_INLINE | MLX5_TXOFF_CONFIG_VLAN |
		MLX5_TXOFF_CONFIG_METADATA | MLX5_TXOFF_CONFIG_EMPW)

/* Generate routines without Enhanced Multi-Packet Write support. */
MLX5_TXOFF_DECL(full,
		MLX5_TXOFF_CONFIG_FULL)

MLX5_TXOFF_DECL(none,
		MLX5_TXOFF_CONFIG_NONE)

MLX5_TXOFF_DECL(md,
		MLX5_TXOFF_CONFIG_METADATA)

MLX5_TXOFF_DECL(mt,
		MLX5_TXOFF_CONFIG_MULTI | MLX5_TXOFF_CONFIG_TSO |
		MLX5_TXOFF_CONFIG_METADATA)

MLX5_TXOFF_DECL(mtsc,
		MLX5_TXOFF_CONFIG_MULTI | MLX5_TXOFF_CONFIG_TSO |
		MLX5_TXOFF_CONFIG_SWP |	MLX5_TXOFF_CONFIG_CSUM |
		MLX5_TXOFF_CONFIG_METADATA)

MLX5_TXOFF_DECL(mti,
		MLX5_TXOFF_CONFIG_MULTI | MLX5_TXOFF_CONFIG_TSO |
		MLX5_TXOFF_CONFIG_INLINE |
		MLX5_TXOFF_CONFIG_METADATA)


MLX5_TXOFF_DECL(mtv,
		MLX5_TXOFF_CONFIG_MULTI | MLX5_TXOFF_CONFIG_TSO |
		MLX5_TXOFF_CONFIG_VLAN |
		MLX5_TXOFF_CONFIG_METADATA)


MLX5_TXOFF_DECL(mtiv,
		MLX5_TXOFF_CONFIG_MULTI | MLX5_TXOFF_CONFIG_TSO |
		MLX5_TXOFF_CONFIG_INLINE | MLX5_TXOFF_CONFIG_VLAN |
		MLX5_TXOFF_CONFIG_METADATA)

MLX5_TXOFF_DECL(sc,
		MLX5_TXOFF_CONFIG_SWP |	MLX5_TXOFF_CONFIG_CSUM |
		MLX5_TXOFF_CONFIG_METADATA)

MLX5_TXOFF_DECL(sci,
		MLX5_TXOFF_CONFIG_SWP |	MLX5_TXOFF_CONFIG_CSUM |
		MLX5_TXOFF_CONFIG_INLINE |
		MLX5_TXOFF_CONFIG_METADATA)


MLX5_TXOFF_DECL(scv,
		MLX5_TXOFF_CONFIG_SWP |	MLX5_TXOFF_CONFIG_CSUM |
		MLX5_TXOFF_CONFIG_VLAN |
		MLX5_TXOFF_CONFIG_METADATA)


MLX5_TXOFF_DECL(sciv,
		MLX5_TXOFF_CONFIG_SWP |	MLX5_TXOFF_CONFIG_CSUM |
		MLX5_TXOFF_CONFIG_INLINE | MLX5_TXOFF_CONFIG_VLAN |
		MLX5_TXOFF_CONFIG_METADATA)

MLX5_TXOFF_DECL(i,
		MLX5_TXOFF_CONFIG_INLINE |
		MLX5_TXOFF_CONFIG_METADATA)

MLX5_TXOFF_DECL(v,
		MLX5_TXOFF_CONFIG_VLAN |
		MLX5_TXOFF_CONFIG_METADATA)

MLX5_TXOFF_DECL(iv,
		MLX5_TXOFF_CONFIG_INLINE | MLX5_TXOFF_CONFIG_VLAN |
		MLX5_TXOFF_CONFIG_METADATA)

/* Generate routines with timestamp scheduling. */
MLX5_TXOFF_DECL(full_ts_nompw,
		MLX5_TXOFF_CONFIG_FULL | MLX5_TXOFF_CONFIG_TXPP)

MLX5_TXOFF_DECL(full_ts_nompwi,
		MLX5_TXOFF_CONFIG_MULTI | MLX5_TXOFF_CONFIG_TSO |
		MLX5_TXOFF_CONFIG_SWP | MLX5_TXOFF_CONFIG_CSUM |
		MLX5_TXOFF_CONFIG_VLAN | MLX5_TXOFF_CONFIG_METADATA |
		MLX5_TXOFF_CONFIG_TXPP)

MLX5_TXOFF_DECL(full_ts,
		MLX5_TXOFF_CONFIG_FULL | MLX5_TXOFF_CONFIG_TXPP |
		MLX5_TXOFF_CONFIG_EMPW)

MLX5_TXOFF_DECL(full_ts_noi,
		MLX5_TXOFF_CONFIG_MULTI | MLX5_TXOFF_CONFIG_TSO |
		MLX5_TXOFF_CONFIG_SWP | MLX5_TXOFF_CONFIG_CSUM |
		MLX5_TXOFF_CONFIG_VLAN | MLX5_TXOFF_CONFIG_METADATA |
		MLX5_TXOFF_CONFIG_TXPP | MLX5_TXOFF_CONFIG_EMPW)

MLX5_TXOFF_DECL(none_ts,
		MLX5_TXOFF_CONFIG_NONE | MLX5_TXOFF_CONFIG_TXPP |
		MLX5_TXOFF_CONFIG_EMPW)

MLX5_TXOFF_DECL(mdi_ts,
		MLX5_TXOFF_CONFIG_INLINE | MLX5_TXOFF_CONFIG_METADATA |
		MLX5_TXOFF_CONFIG_TXPP | MLX5_TXOFF_CONFIG_EMPW)

MLX5_TXOFF_DECL(mti_ts,
		MLX5_TXOFF_CONFIG_MULTI | MLX5_TXOFF_CONFIG_TSO |
		MLX5_TXOFF_CONFIG_INLINE | MLX5_TXOFF_CONFIG_METADATA |
		MLX5_TXOFF_CONFIG_TXPP | MLX5_TXOFF_CONFIG_EMPW)

MLX5_TXOFF_DECL(mtiv_ts,
		MLX5_TXOFF_CONFIG_MULTI | MLX5_TXOFF_CONFIG_TSO |
		MLX5_TXOFF_CONFIG_INLINE | MLX5_TXOFF_CONFIG_VLAN |
		MLX5_TXOFF_CONFIG_METADATA | MLX5_TXOFF_CONFIG_TXPP |
		MLX5_TXOFF_CONFIG_EMPW)

/*
 * Generate routines with Legacy Multi-Packet Write support.
 * This mode is supported by ConnectX-4 Lx only and imposes
 * offload limitations, not supported:
 *   - ACL/Flows (metadata are becoming meaningless)
 *   - WQE Inline headers
 *   - SRIOV (E-Switch offloads)
 *   - VLAN insertion
 *   - tunnel encapsulation/decapsulation
 *   - TSO
 */
MLX5_TXOFF_DECL(none_mpw,
		MLX5_TXOFF_CONFIG_NONE | MLX5_TXOFF_CONFIG_EMPW |
		MLX5_TXOFF_CONFIG_MPW)

MLX5_TXOFF_DECL(mci_mpw,
		MLX5_TXOFF_CONFIG_MULTI | MLX5_TXOFF_CONFIG_CSUM |
		MLX5_TXOFF_CONFIG_INLINE | MLX5_TXOFF_CONFIG_EMPW |
		MLX5_TXOFF_CONFIG_MPW)

MLX5_TXOFF_DECL(mc_mpw,
		MLX5_TXOFF_CONFIG_MULTI | MLX5_TXOFF_CONFIG_CSUM |
		MLX5_TXOFF_CONFIG_EMPW | MLX5_TXOFF_CONFIG_MPW)

MLX5_TXOFF_DECL(i_mpw,
		MLX5_TXOFF_CONFIG_INLINE | MLX5_TXOFF_CONFIG_EMPW |
		MLX5_TXOFF_CONFIG_MPW)
