/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <rte_sft_driver.h>

#include <mlx5.h>

static int mlx5_sft_start(struct rte_eth_dev *dev, uint16_t nb_queue,
			  uint16_t data_len, struct rte_sft_error *error)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(nb_queue);
	RTE_SET_USED(data_len);
	RTE_SET_USED(error);

	return 0;
}

static int mlx5_sft_stop(struct rte_eth_dev *dev, struct rte_sft_error *error)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(error);

	return 0;
}

static struct rte_sft_entry *
mlx5_sft_entry_create(struct rte_eth_dev *dev, uint32_t fid, uint16_t queue,
		      const struct rte_flow_item *pattern,
		      uint64_t miss_conditions,
		      const struct rte_flow_action *actions,
		      const struct rte_flow_action *miss_actions,
		      const uint32_t *data, uint16_t data_len,
		      uint8_t state, struct rte_sft_error *error)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(fid);
	RTE_SET_USED(queue);
	RTE_SET_USED(pattern);
	RTE_SET_USED(miss_conditions);
	RTE_SET_USED(actions);
	RTE_SET_USED(miss_actions);
	RTE_SET_USED(data);
	RTE_SET_USED(data_len);
	RTE_SET_USED(state);
	RTE_SET_USED(error);

	return NULL;
}

static int mlx5_sft_entry_destroy(struct rte_eth_dev *dev,
				  struct rte_sft_entry *entry, uint16_t queue,
				  struct rte_sft_error *error)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(entry);
	RTE_SET_USED(queue);
	RTE_SET_USED(error);

	return 0;
}

static int mlx5_sft_entry_decode(struct rte_eth_dev *dev, uint16_t queue,
				 struct rte_mbuf *mbuf,
				 struct rte_sft_decode_info *info,
				 struct rte_sft_error *error)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(queue);
	RTE_SET_USED(mbuf);
	RTE_SET_USED(info);
	RTE_SET_USED(error);

	return 0;
}

static int mlx5_sft_entry_modify(struct rte_eth_dev *dev, uint16_t queue,
				 struct rte_sft_entry *entry,
				 const uint32_t *data, uint16_t data_len,
				 uint8_t state, struct rte_sft_error *error)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(queue);
	RTE_SET_USED(entry);
	RTE_SET_USED(data);
	RTE_SET_USED(data_len);
	RTE_SET_USED(state);
	RTE_SET_USED(error);

	return 0;
}

static const struct rte_sft_ops mlx5_sft_ops = {
	.sft_start = mlx5_sft_start,
	.sft_stop = mlx5_sft_stop,
	.sft_create_entry = mlx5_sft_entry_create,
	.sft_entry_modify = mlx5_sft_entry_modify,
	.sft_entry_destroy = mlx5_sft_entry_destroy,
	.sft_entry_decode = mlx5_sft_entry_decode,
};

/**
 * Get SFT operations.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param arg
 *   Pointer to set the sft operations.
 *
 * @return
 *   Always 0.
 */
int
mlx5_sft_ops_get(struct rte_eth_dev *dev __rte_unused, void *arg)
{
	*(const struct rte_sft_ops **)arg = &mlx5_sft_ops;
	return 0;
}
