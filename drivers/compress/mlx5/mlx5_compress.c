/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Mellanox Technologies, Ltd
 */

#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_errno.h>
#include <rte_bus_pci.h>
#include <rte_comp.h>
#include <rte_compressdev.h>
#include <rte_compressdev_pmd.h>

#include <mlx5_glue.h>
#include <mlx5_common.h>
#include <mlx5_common.h>
#include <mlx5_devx_cmds.h>
#include <mlx5_common_os.h>
#include <mlx5_prm.h>

#include "mlx5_compress_utils.h"

#define MLX5_COMPRESS_DRIVER_NAME mlx5_compress
#define MLX5_COMPRESS_LOG_NAME    pmd.compress.mlx5
#define MLX5_COMPRESS_MAX_QPS 1024

struct mlx5_compress_priv {
	TAILQ_ENTRY(mlx5_compress_priv) next;
	struct ibv_context *ctx; /* Device context. */
	struct rte_compressdev *cdev;
	void *uar;
	uint32_t pdn; /* Protection Domain number. */
	uint8_t min_block_size;
	/* Minimum huffman block size supported by the device. */
	struct ibv_pd *pd;
	struct rte_compressdev_config dev_config;
};

TAILQ_HEAD(mlx5_compress_privs, mlx5_compress_priv) mlx5_compress_priv_list =
				TAILQ_HEAD_INITIALIZER(mlx5_compress_priv_list);
static pthread_mutex_t priv_list_lock = PTHREAD_MUTEX_INITIALIZER;

int mlx5_compress_logtype;

const struct rte_compressdev_capabilities mlx5_caps[RTE_COMP_ALGO_LIST_END];


static void
mlx5_compress_dev_info_get(struct rte_compressdev *dev,
			   struct rte_compressdev_info *info)
{
	RTE_SET_USED(dev);
	if (info != NULL) {
		info->max_nb_queue_pairs = MLX5_COMPRESS_MAX_QPS;
		info->feature_flags = RTE_COMPDEV_FF_HW_ACCELERATED;
		info->capabilities = mlx5_caps;
	}
}

static int
mlx5_compress_dev_configure(struct rte_compressdev *dev,
			    struct rte_compressdev_config *config)
{
	struct mlx5_compress_priv *priv;

	if (dev == NULL || config == NULL)
		return -EINVAL;
	priv = dev->data->dev_private;
	priv->dev_config = *config;
	return 0;
}

static int
mlx5_compress_dev_close(struct rte_compressdev *dev)
{
	RTE_SET_USED(dev);
	return 0;
}

static struct rte_compressdev_ops mlx5_compress_ops = {
	.dev_configure		= mlx5_compress_dev_configure,
	.dev_start		= NULL,
	.dev_stop		= NULL,
	.dev_close		= mlx5_compress_dev_close,
	.dev_infos_get		= mlx5_compress_dev_info_get,
	.stats_get		= NULL,
	.stats_reset		= NULL,
	.queue_pair_setup	= NULL,
	.queue_pair_release	= NULL,
	.private_xform_create	= NULL,
	.private_xform_free	= NULL,
	.stream_create		= NULL,
	.stream_free		= NULL,
};

static void
mlx5_compress_hw_global_release(struct mlx5_compress_priv *priv)
{
	if (priv->pd != NULL) {
		claim_zero(mlx5_glue->dealloc_pd(priv->pd));
		priv->pd = NULL;
	}
	if (priv->uar != NULL) {
		mlx5_glue->devx_free_uar(priv->uar);
		priv->uar = NULL;
	}
}

static int
mlx5_compress_pd_create(struct mlx5_compress_priv *priv)
{
#ifdef HAVE_IBV_FLOW_DV_SUPPORT
	struct mlx5dv_obj obj;
	struct mlx5dv_pd pd_info;
	int ret;

	priv->pd = mlx5_glue->alloc_pd(priv->ctx);
	if (priv->pd == NULL) {
		DRV_LOG(ERR, "Failed to allocate PD.");
		return errno ? -errno : -ENOMEM;
	}
	obj.pd.in = priv->pd;
	obj.pd.out = &pd_info;
	ret = mlx5_glue->dv_init_obj(&obj, MLX5DV_OBJ_PD);
	if (ret != 0) {
		DRV_LOG(ERR, "Fail to get PD object info.");
		mlx5_glue->dealloc_pd(priv->pd);
		priv->pd = NULL;
		return -errno;
	}
	priv->pdn = pd_info.pdn;
	return 0;
#else
	(void)priv;
	DRV_LOG(ERR, "Cannot get pdn - no DV support.");
	return -ENOTSUP;
#endif /* HAVE_IBV_FLOW_DV_SUPPORT */
}

static int
mlx5_compress_hw_global_prepare(struct mlx5_compress_priv *priv)
{
	if (mlx5_compress_pd_create(priv) != 0)
		return -1;
	priv->uar = mlx5_devx_alloc_uar(priv->ctx, -1);
	if (priv->uar == NULL || mlx5_os_get_devx_uar_reg_addr(priv->uar) ==
	    NULL) {
		rte_errno = errno;
		claim_zero(mlx5_glue->dealloc_pd(priv->pd));
		DRV_LOG(ERR, "Failed to allocate UAR.");
		return -1;
	}
	return 0;
}

static int
mlx5_compress_dev_probe(struct rte_device *dev)
{
	struct ibv_device *ibv;
	struct rte_compressdev *cdev;
	struct ibv_context *ctx;
	struct mlx5_compress_priv *priv;
	struct mlx5_hca_attr att = { 0 };
	struct rte_compressdev_pmd_init_params init_params = {
		.name = "",
		.socket_id = dev->numa_node,
	};

	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		DRV_LOG(ERR, "Non-primary process type is not supported.");
		rte_errno = ENOTSUP;
		return -rte_errno;
	}
	ibv = mlx5_os_get_ibv_dev(dev);
	if (ibv == NULL)
		return -rte_errno;
	ctx = mlx5_glue->dv_open_device(ibv);
	if (ctx == NULL) {
		DRV_LOG(ERR, "Failed to open IB device \"%s\".", ibv->name);
		rte_errno = ENODEV;
		return -rte_errno;
	}
	if (mlx5_devx_cmd_query_hca_attr(ctx, &att) != 0 ||
	    att.mmo_compress_en == 0 || att.mmo_decompress_en == 0 ||
	    att.mmo_dma_en == 0) {
		DRV_LOG(ERR, "Not enough capabilities to support compress "
			"operations, maybe old FW/OFED version?");
		claim_zero(mlx5_glue->close_device(ctx));
		rte_errno = ENOTSUP;
		return -ENOTSUP;
	}
	cdev = rte_compressdev_pmd_create(ibv->name, dev,
					  sizeof(*priv), &init_params);
	if (cdev == NULL) {
		DRV_LOG(ERR, "Failed to create device \"%s\".", ibv->name);
		claim_zero(mlx5_glue->close_device(ctx));
		return -ENODEV;
	}
	DRV_LOG(INFO,
		"Compress device %s was created successfully.", ibv->name);
	cdev->dev_ops = &mlx5_compress_ops;
	cdev->dequeue_burst = NULL;
	cdev->enqueue_burst = NULL;
	cdev->feature_flags = RTE_COMPDEV_FF_HW_ACCELERATED;
	priv = cdev->data->dev_private;
	priv->ctx = ctx;
	priv->cdev = cdev;
	priv->min_block_size = att.compress_min_block_size;
	if (mlx5_compress_hw_global_prepare(priv) != 0) {
		rte_compressdev_pmd_destroy(priv->cdev);
		claim_zero(mlx5_glue->close_device(priv->ctx));
		return -1;
	}
	pthread_mutex_lock(&priv_list_lock);
	TAILQ_INSERT_TAIL(&mlx5_compress_priv_list, priv, next);
	pthread_mutex_unlock(&priv_list_lock);
	return 0;
}

static int
mlx5_compress_dev_remove(struct rte_device *dev)
{
	struct mlx5_compress_priv *priv = NULL;

	pthread_mutex_lock(&priv_list_lock);
	TAILQ_FOREACH(priv, &mlx5_compress_priv_list, next)
		if (priv->cdev->device == dev)
			break;
	if (priv)
		TAILQ_REMOVE(&mlx5_compress_priv_list, priv, next);
	pthread_mutex_unlock(&priv_list_lock);
	if (priv) {
		mlx5_compress_hw_global_release(priv);
		rte_compressdev_pmd_destroy(priv->cdev);
		claim_zero(mlx5_glue->close_device(priv->ctx));
	}
	return 0;
}

static const struct rte_pci_id mlx5_compress_pci_id_map[] = {
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
				PCI_DEVICE_ID_MELLANOX_CONNECTX6DXBF)
	},
	{
		.vendor_id = 0
	}
};

static struct mlx5_class_driver mlx5_compress_driver = {
	.drv_class = MLX5_CLASS_COMPRESS,
	.name = RTE_STR(MLX5_COMPRESS_DRIVER_NAME),
	.id_table = mlx5_compress_pci_id_map,
	.probe = mlx5_compress_dev_probe,
	.remove = mlx5_compress_dev_remove,
};

RTE_INIT(rte_mlx5_compress_init)
{
	mlx5_common_init();
	if (mlx5_glue != NULL)
		mlx5_class_driver_register(&mlx5_compress_driver);
}

RTE_LOG_REGISTER(mlx5_compress_logtype, MLX5_COMPRESS_LOG_NAME, NOTICE)
RTE_PMD_EXPORT_NAME(MLX5_COMPRESS_DRIVER_NAME, __COUNTER__);
RTE_PMD_REGISTER_PCI_TABLE(MLX5_COMPRESS_DRIVER_NAME, mlx5_compress_pci_id_map);
RTE_PMD_REGISTER_KMOD_DEP(MLX5_COMPRESS_DRIVER_NAME, "* ib_uverbs & mlx5_core & mlx5_ib");
