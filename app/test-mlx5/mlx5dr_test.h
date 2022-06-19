/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_TEST_H_
#define MLX5DR_TEST_H_

#include <infiniband/verbs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <rte_flow.h>
#include "../../drivers/net/mlx5/steering/mlx5dr.h"
#include "/usr/include/infiniband/mlx5dv.h"

/* W/A Below enum needed for cmd.h*/
enum mlx5_ifc_stc_action_type {
	MLX5_IFC_STC_ACTION_TYPE_NOP = 0x00,
	MLX5_IFC_STC_ACTION_TYPE_COPY = 0x05,
	MLX5_IFC_STC_ACTION_TYPE_SET = 0x06,
	MLX5_IFC_STC_ACTION_TYPE_ADD = 0x07,
	MLX5_IFC_STC_ACTION_TYPE_HEADER_REMOVE = 0x09,
	MLX5_IFC_STC_ACTION_TYPE_HEADER_INSERT = 0x0b,
	MLX5_IFC_STC_ACTION_TYPE_TAG = 0x0c,
	MLX5_IFC_STC_ACTION_TYPE_ACC_MODIFY_LIST = 0x0e,
	MLX5_IFC_STC_ACTION_TYPE_ASO = 0x12,
	MLX5_IFC_STC_ACTION_TYPE_COUNTER = 0x14,
	MLX5_IFC_STC_ACTION_TYPE_JUMP_TO_STE_TABLE = 0x80,
	MLX5_IFC_STC_ACTION_TYPE_JUMP_TO_TIR = 0x81,
	MLX5_IFC_STC_ACTION_TYPE_JUMP_TO_FT = 0x82,
	MLX5_IFC_STC_ACTION_TYPE_DROP = 0x83,
	MLX5_IFC_STC_ACTION_TYPE_ALLOW = 0x84,
	MLX5_IFC_STC_ACTION_TYPE_JUMP_TO_VPORT = 0x85,
	MLX5_IFC_STC_ACTION_TYPE_JUMP_TO_UPLINK = 0x86,
};

#include "../../drivers/net/mlx5/steering/mlx5dr_pool.h"
#include "../../drivers/net/mlx5/steering/mlx5dr_context.h"
#include "../../drivers/net/mlx5/steering/mlx5dr_send.h"
#include "../../drivers/net/mlx5/steering/mlx5dr_rule.h"
#include "../../drivers/net/mlx5/steering/mlx5dr_cmd.h"
#include "../../drivers/net/mlx5/steering/mlx5dr_action.h"

#define MAX_ITEMS 10

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

#define __mlx5_nullp(typ) ((struct mlx5_ifc_##typ##_bits *)0)
#define __mlx5_bit_sz(typ, fld) sizeof(__mlx5_nullp(typ)->fld)
#define __mlx5_bit_off(typ, fld) ((unsigned int)(unsigned long) \
				  (&(__mlx5_nullp(typ)->fld)))
#define __mlx5_dw_bit_off(typ, fld) (32 - __mlx5_bit_sz(typ, fld) - \
				    (__mlx5_bit_off(typ, fld) & 0x1f))
#define __mlx5_dw_off(typ, fld) (__mlx5_bit_off(typ, fld) / 32)
#define __mlx5_64_off(typ, fld) (__mlx5_bit_off(typ, fld) / 64)
#define __mlx5_dw_mask(typ, fld) (__mlx5_mask(typ, fld) << \
				  __mlx5_dw_bit_off(typ, fld))
#define __mlx5_mask(typ, fld) ((u32)((1ull << __mlx5_bit_sz(typ, fld)) - 1))
#define __mlx5_16_off(typ, fld) (__mlx5_bit_off(typ, fld) / 16)
#define __mlx5_16_bit_off(typ, fld) (16 - __mlx5_bit_sz(typ, fld) - \
				    (__mlx5_bit_off(typ, fld) & 0xf))
#define __mlx5_mask16(typ, fld) ((u16)((1ull << __mlx5_bit_sz(typ, fld)) - 1))
#define __mlx5_16_mask(typ, fld) (__mlx5_mask16(typ, fld) << \
				  __mlx5_16_bit_off(typ, fld))
#define MLX5_ST_SZ_BYTES(typ) (sizeof(struct mlx5_ifc_##typ##_bits) / 8)
#define MLX5_ST_SZ_DW(typ) (sizeof(struct mlx5_ifc_##typ##_bits) / 32)
#define MLX5_BYTE_OFF(typ, fld) (__mlx5_bit_off(typ, fld) / 8)
#define MLX5_ADDR_OF(typ, p, fld) ((char *)(p) + MLX5_BYTE_OFF(typ, fld))

/* insert a value to a struct */
#define MLX5_SET(typ, p, fld, v) \
	do { \
		u32 _v = v; \
		*((rte_be32_t *)(p) + __mlx5_dw_off(typ, fld)) = \
		rte_cpu_to_be_32((rte_be_to_cpu_32(*((u32 *)(p) + \
				  __mlx5_dw_off(typ, fld))) & \
				  (~__mlx5_dw_mask(typ, fld))) | \
				 (((_v) & __mlx5_mask(typ, fld)) << \
				   __mlx5_dw_bit_off(typ, fld))); \
	} while (0)

#define MLX5_SET64(typ, p, fld, v) \
	do { \
		MLX5_ASSERT(__mlx5_bit_sz(typ, fld) == 64); \
		*((rte_be64_t *)(p) + __mlx5_64_off(typ, fld)) = \
			rte_cpu_to_be_64(v); \
	} while (0)

#define MLX5_SET16(typ, p, fld, v) \
	do { \
		u16 _v = v; \
		*((rte_be16_t *)(p) + __mlx5_16_off(typ, fld)) = \
		rte_cpu_to_be_16((rte_be_to_cpu_16(*((rte_be16_t *)(p) + \
				  __mlx5_16_off(typ, fld))) & \
				  (~__mlx5_16_mask(typ, fld))) | \
				 (((_v) & __mlx5_mask16(typ, fld)) << \
				  __mlx5_16_bit_off(typ, fld))); \
	} while (0)

#define MLX5_GET_VOLATILE(typ, p, fld) \
	((rte_be_to_cpu_32(*((volatile __be32 *)(p) +\
	__mlx5_dw_off(typ, fld))) >> __mlx5_dw_bit_off(typ, fld)) & \
	__mlx5_mask(typ, fld))
#define MLX5_GET(typ, p, fld) \
	((rte_be_to_cpu_32(*((rte_be32_t *)(p) +\
	__mlx5_dw_off(typ, fld))) >> __mlx5_dw_bit_off(typ, fld)) & \
	__mlx5_mask(typ, fld))
#define MLX5_GET16(typ, p, fld) \
	((rte_be_to_cpu_16(*((rte_be16_t *)(p) + \
	  __mlx5_16_off(typ, fld))) >> __mlx5_16_bit_off(typ, fld)) & \
	 __mlx5_mask16(typ, fld))
#define MLX5_GET64(typ, p, fld) rte_be_to_cpu_64(*((rte_be64_t *)(p) + \
						   __mlx5_64_off(typ, fld)))
#define MLX5_FLD_SZ_BYTES(typ, fld) (__mlx5_bit_sz(typ, fld) / 8)



struct mlx5_ifc_set_action_in_bits {
	u8 action_type[0x4];
	u8 field[0xc];
	u8 reserved_at_10[0x3];
	u8 offset[0x5];
	u8 reserved_at_18[0x3];
	u8 length[0x5];
	u8 data[0x20];
};

struct mlx5_ifc_add_action_in_bits {
	u8 action_type[0x4];
	u8 field[0xc];
	u8 reserved_at_10[0x10];

	u8 data[0x20];
};

enum {
	MLX5_MODIFICATION_TYPE_SET = 0x1,
	MLX5_MODIFICATION_TYPE_ADD = 0x2,
	MLX5_MODIFICATION_TYPE_COPY = 0x3,
};


/* Tests */

int run_test_post_send(struct ibv_context *ibv_ctx);
int run_test_rule_insert(struct ibv_context *ibv_ctx);
int run_test_rule_insert_mult(struct ibv_context *ibv_ctx);
int run_test_modify_header_action(struct ibv_context *ibv_ctx);
int run_test_pool(struct ibv_context *ibv_ctx);
int run_test_vlan_action(struct ibv_context *ibv_ctx);
int run_test_rte_insert(struct ibv_context *ibv_ctx);

#endif

