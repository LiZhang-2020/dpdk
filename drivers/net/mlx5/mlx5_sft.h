/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#ifndef RTE_PMD_MLX5_MLX5_H
#define RTE_PMD_MLX5_MLX5_H

struct rte_sft_entry {
	ILIST_ENTRY(uint32_t)next;
	struct rte_flow *flow;
	struct rte_flow *itmd_flow;
	struct rte_flow *miss_flow;
	uint32_t idx;
	uint32_t state;
	uint32_t fid_zone;
};

#define MLX5_SFT_QUEUE_MAX			(64)
#define MLX5_SFT_FID_ZONE_MASK			(0x00FFFFFF)
#define MLX5_SFT_RSVD_SHIFT			(24)
#define MLX5_SFT_FID_ZONE_STAT_SHIFT		(0)
#define MLX5_SFT_FID_ZONE_STAT_MASK		(0xF)
#define MLX5_SFT_USER_STAT_SHIFT		(16)
#define MLX5_SFT_USER_STAT_MASK			(0xFF)

#define MLX5_SFT_ENCODE_MARK(valid, usr) \
	((((valid) & MLX5_SFT_FID_ZONE_STAT_MASK) << \
	   MLX5_SFT_FID_ZONE_STAT_SHIFT) | \
	 (((usr) & MLX5_SFT_USER_STAT_MASK) << \
	  MLX5_SFT_USER_STAT_SHIFT))

#endif