/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA Corporation & Affiliates
 */

#include <rte_malloc.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_bus_pci.h>

#include <mlx5_glue.h>
#include <mlx5_common.h>
#include <mlx5_devx_cmds.h>
#include <mlx5_common_os.h>

#include "mlx5_crypto_utils.h"
#include "mlx5_crypto.h"

#define MLX5_CRYPTO_DRIVER_NAME crypto_mlx5
#define MLX5_CRYPTO_LOG_NAME pmd.crypto.mlx5

#define MLX5_CRYPTO_FEATURE_FLAGS \
	RTE_CRYPTODEV_FF_HW_ACCELERATED

TAILQ_HEAD(mlx5_crypto_privs, mlx5_crypto_priv) mlx5_crypto_priv_list =
				TAILQ_HEAD_INITIALIZER(mlx5_crypto_priv_list);
static pthread_mutex_t priv_list_lock = PTHREAD_MUTEX_INITIALIZER;

int mlx5_crypto_logtype;

uint8_t mlx5_crypto_driver_id;

const struct rte_cryptodev_capabilities mlx5_crypto_caps[] = {
	{		/* AES XTS */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			{.cipher = {
				.algo = RTE_CRYPTO_CIPHER_AES_XTS,
				.block_size = 16,
				.key_size = {
					.min = 32,
					.max = 64,
					.increment = 32
				},
				.iv_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				},
				.dataunit_set =
				RTE_CRYPTO_CIPHER_DATA_UNIT_LEN_512_BYTES |
				RTE_CRYPTO_CIPHER_DATA_UNIT_LEN_4096_BYTES,
			}, }
		}, }
	},
};

static const char mlx5_crypto_drv_name[] = RTE_STR(MLX5_CRYPTO_DRIVER_NAME);

static const struct rte_driver mlx5_drv = {
	.name = mlx5_crypto_drv_name,
	.alias = mlx5_crypto_drv_name
};

static struct cryptodev_driver mlx5_cryptodev_driver;

static void
mlx5_crypto_dev_infos_get(struct rte_cryptodev *dev,
			  struct rte_cryptodev_info *dev_info)
{
	RTE_SET_USED(dev);
	if (dev_info != NULL) {
		dev_info->driver_id = mlx5_crypto_driver_id;
		dev_info->feature_flags = MLX5_CRYPTO_FEATURE_FLAGS;
		dev_info->capabilities = mlx5_crypto_caps;
		dev_info->max_nb_queue_pairs = 0;
		dev_info->min_mbuf_headroom_req = 0;
		dev_info->min_mbuf_tailroom_req = 0;
		dev_info->sym.max_nb_sessions = 0;
		/*
		 * If 0, the device does not have any limitation in number of
		 * sessions that can be used.
		 */
	}
}

static int
mlx5_crypto_dev_configure(struct rte_cryptodev *dev,
			  struct rte_cryptodev_config *config)
{
	struct mlx5_crypto_priv *priv = dev->data->dev_private;

	if (config == NULL) {
		DRV_LOG(ERR, "Invalid crypto dev configure parameters.");
		return -EINVAL;
	}
	if ((config->ff_disable & RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO) != 0) {
		DRV_LOG(ERR,
			"Disabled symmetric crypto feature is not supported.");
		return -ENOTSUP;
	}
	if (mlx5_crypto_dek_setup(priv) != 0) {
		DRV_LOG(ERR, "Dek hash list creation has failed.");
		return -ENOMEM;
	}
	priv->dev_config = *config;
	DRV_LOG(DEBUG, "Device %u was configured.", dev->driver_id);
	return 0;
}

static void
mlx5_crypto_dev_stop(struct rte_cryptodev *dev)
{
	RTE_SET_USED(dev);
}

static int
mlx5_crypto_dev_start(struct rte_cryptodev *dev)
{
	RTE_SET_USED(dev);
	return 0;
}

static int
mlx5_crypto_dev_close(struct rte_cryptodev *dev)
{
	struct mlx5_crypto_priv *priv = dev->data->dev_private;

	mlx5_crypto_dek_unset(priv);
	DRV_LOG(DEBUG, "Device %u was closed.", dev->driver_id);
	return 0;
}

static struct rte_cryptodev_ops mlx5_crypto_ops = {
	.dev_configure			= mlx5_crypto_dev_configure,
	.dev_start			= mlx5_crypto_dev_start,
	.dev_stop			= mlx5_crypto_dev_stop,
	.dev_close			= mlx5_crypto_dev_close,
	.dev_infos_get			= mlx5_crypto_dev_infos_get,
	.stats_get			= NULL,
	.stats_reset			= NULL,
	.queue_pair_setup		= NULL,
	.queue_pair_release		= NULL,
	.sym_session_get_size		= NULL,
	.sym_session_configure		= NULL,
	.sym_session_clear		= NULL,
	.sym_get_raw_dp_ctx_size	= NULL,
	.sym_configure_raw_dp_ctx	= NULL,
};

static void
mlx5_crypto_hw_global_release(struct mlx5_crypto_priv *priv)
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
mlx5_crypto_pd_create(struct mlx5_crypto_priv *priv)
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
mlx5_crypto_hw_global_prepare(struct mlx5_crypto_priv *priv)
{
	if (mlx5_crypto_pd_create(priv) != 0)
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
mlx5_crypto_dev_probe(struct rte_device *dev)
{
	struct ibv_device *ibv;
	struct rte_cryptodev *crypto_dev;
	struct ibv_context *ctx;
	struct mlx5_crypto_priv *priv;
	struct mlx5_hca_attr attr = { 0 };
	struct rte_cryptodev_pmd_init_params init_params = {
		.name = "",
		.private_data_size = sizeof(struct mlx5_crypto_priv),
		.socket_id = dev->numa_node,
		.max_nb_queue_pairs =
				RTE_CRYPTODEV_PMD_DEFAULT_MAX_NB_QUEUE_PAIRS,
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
	if (mlx5_devx_cmd_query_hca_attr(ctx, &attr) != 0 ||
	    attr.crypto == 0 || attr.aes_xts == 0) {
		DRV_LOG(ERR, "Not enough capabilities to support crypto "
			"operations, maybe old FW/OFED version?");
		claim_zero(mlx5_glue->close_device(ctx));
		rte_errno = ENOTSUP;
		return -ENOTSUP;
	}
	crypto_dev = rte_cryptodev_pmd_create(ibv->name, dev,
					&init_params);
	if (crypto_dev == NULL) {
		DRV_LOG(ERR, "Failed to create device \"%s\".", ibv->name);
		claim_zero(mlx5_glue->close_device(ctx));
		return -ENODEV;
	}
	DRV_LOG(INFO,
		"Crypto device %s was created successfully.", ibv->name);
	crypto_dev->dev_ops = &mlx5_crypto_ops;
	crypto_dev->dequeue_burst = NULL;
	crypto_dev->enqueue_burst = NULL;
	crypto_dev->feature_flags = MLX5_CRYPTO_FEATURE_FLAGS;
	crypto_dev->driver_id = mlx5_crypto_driver_id;
	priv = crypto_dev->data->dev_private;
	priv->ctx = ctx;
	priv->crypto_dev = crypto_dev;
	if (mlx5_crypto_hw_global_prepare(priv) != 0) {
		rte_cryptodev_pmd_destroy(priv->crypto_dev);
		claim_zero(mlx5_glue->close_device(priv->ctx));
		return -1;
	}
	pthread_mutex_lock(&priv_list_lock);
	TAILQ_INSERT_TAIL(&mlx5_crypto_priv_list, priv, next);
	pthread_mutex_unlock(&priv_list_lock);
	return 0;
}

static int
mlx5_crypto_dev_remove(struct  rte_device *dev)
{
	struct mlx5_crypto_priv *priv = NULL;

	pthread_mutex_lock(&priv_list_lock);
	TAILQ_FOREACH(priv, &mlx5_crypto_priv_list, next)
		if (priv->crypto_dev->device == dev)
			break;
	if (priv)
		TAILQ_REMOVE(&mlx5_crypto_priv_list, priv, next);
	pthread_mutex_unlock(&priv_list_lock);
	if (priv) {
		mlx5_crypto_hw_global_release(priv);
		rte_cryptodev_pmd_destroy(priv->crypto_dev);
		claim_zero(mlx5_glue->close_device(priv->ctx));
	}
	return 0;
}

static const struct rte_pci_id mlx5_crypto_pci_id_map[] = {
		{
			RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
					PCI_DEVICE_ID_MELLANOX_CONNECTX6)
		},
		{
			.vendor_id = 0
		}
};

static struct mlx5_class_driver mlx5_crypto_driver = {
	.drv_class = MLX5_CLASS_CRYPTO,
	.name = RTE_STR(MLX5_CRYPTO_DRIVER_NAME),
	.id_table = mlx5_crypto_pci_id_map,
	.probe = mlx5_crypto_dev_probe,
	.remove = mlx5_crypto_dev_remove,
};

RTE_INIT(rte_mlx5_crypto_init)
{
	mlx5_common_init();
	if (mlx5_glue != NULL)
		mlx5_class_driver_register(&mlx5_crypto_driver);
}

RTE_PMD_REGISTER_CRYPTO_DRIVER(mlx5_cryptodev_driver, mlx5_drv,
			       mlx5_crypto_driver_id);

RTE_LOG_REGISTER(mlx5_crypto_logtype, pmd.crypto.mlx5, NOTICE)
RTE_PMD_EXPORT_NAME(MLX5_CRYPTO_DRIVER_NAME, __COUNTER__);
RTE_PMD_REGISTER_PCI_TABLE(MLX5_CRYPTO_DRIVER_NAME, mlx5_crypto_pci_id_map);
RTE_PMD_REGISTER_KMOD_DEP(MLX5_CRYPTO_DRIVER_NAME, "* ib_uverbs & mlx5_core & mlx5_ib");
