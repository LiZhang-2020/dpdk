/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#ifndef MLX5_REGEX_H
#define MLX5_REGEX_H

#include <rte_regexdev.h>

#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>

#include <mlx5_common.h>
#include <mlx5_common_mr.h>

#include "mlx5_rxp.h"
#include "mlx5_regex_utils.h"

#define RTE_REGEXDEV_BF2_VERSION "BF2"
#define RTE_REGEXDEV_BF3_VERSION "BF3"

struct mlx5_regex_sq {
	uint16_t log_nb_desc; /* Log 2 number of desc for this object. */
	struct mlx5_devx_obj *obj; /* The SQ DevX object. */
	int64_t dbr_offset; /* Door bell record offset. */
	uint32_t dbr_umem; /* Door bell record umem id. */
	uint8_t *wqe; /* The SQ ring buffer. */
	struct mlx5dv_devx_umem *wqe_umem; /* SQ buffer umem. */
	size_t pi, db_pi;
	size_t ci;
	uint32_t sqn;
	uint32_t *dbr;
};

struct mlx5_regex_cq {
	uint32_t log_nb_desc; /* Log 2 number of desc for this object. */
	struct mlx5_devx_obj *obj; /* The CQ DevX object. */
	int64_t dbr_offset; /* Door bell record offset. */
	uint32_t dbr_umem; /* Door bell record umem id. */
	volatile struct mlx5_cqe *cqe; /* The CQ ring buffer. */
	struct mlx5dv_devx_umem *cqe_umem; /* CQ buffer umem. */
	size_t ci;
	uint32_t *dbr;
};

struct mlx5_regex_qp {
	uint32_t flags; /* QP user flags. */
	uint32_t nb_desc; /* Total number of desc for this qp. */
	struct mlx5_regex_sq *sqs; /* Pointer to sq array. */
	uint16_t nb_obj; /* Number of sq objects. */
	struct mlx5_regex_cq cq; /* CQ struct. */
	uint32_t free_sqs;
	struct mlx5_regex_job *jobs;
	struct ibv_mr *metadata;
	struct ibv_mr *outputs;
	struct ibv_mr *imkey_addr; /* Indirect mkey array region. */
	size_t ci, pi;
	struct mlx5_mr_ctrl mr_ctrl;
};

struct mlx5_regex_priv {
	TAILQ_ENTRY(mlx5_regex_priv) next;
	struct ibv_context *ctx; /* Device context. */
	struct rte_regexdev *regexdev; /* Pointer to the RegEx dev. */
	uint16_t nb_queues; /* Number of queues. */
	struct mlx5_regex_qp *qps; /* Pointer to the QP array. */
	uint16_t nb_max_matches; /* Max number of matches. */
	enum mlx5_rxp_program_mode prog_mode;
	uint32_t nb_engines; /* Number of RegEx engines. */
	uint32_t eqn; /* EQ number. */
	struct mlx5dv_devx_uar *uar; /* UAR object. */
	struct ibv_pd *pd;
	struct mlx5_dbr_page_list dbrpgs; /* Door-bell pages. */
	TAILQ_ENTRY(mlx5_regex_priv) mem_event_cb;
	/* Called by memory event callback. */
	struct mlx5_mr_share_cache mr_scache; /* Global shared MR cache. */
	uint8_t is_bf2; /* The device is BF2 device. */
	uint8_t regexp_sq_en; /* RegEx SQ supported */
	uint8_t has_umr; /* The device supports UMR. */
	uint8_t sq_ts_format; /* Whether SQ supports timestamp formats. */
};

#ifdef HAVE_IBV_FLOW_DV_SUPPORT
static inline int
regex_get_pdn(void *pd, uint32_t *pdn)
{
	struct mlx5dv_obj obj;
	struct mlx5dv_pd pd_info;
	int ret = 0;

	obj.pd.in = pd;
	obj.pd.out = &pd_info;
	ret = mlx5_glue->dv_init_obj(&obj, MLX5DV_OBJ_PD);
	if (ret) {
		DRV_LOG(DEBUG, "Fail to get PD object info");
		return ret;
	}
	*pdn = pd_info.pdn;
	return 0;
}
#endif

/* mlx5_regex.c */
int mlx5_regex_start(struct rte_regexdev *dev);
int mlx5_regex_stop(struct rte_regexdev *dev);
int mlx5_regex_close(struct rte_regexdev *dev);
void mlx5_regex_mr_mem_event_cb(enum rte_mem_event event_type,
				const void *addr, size_t len, void *arg);

/* mlx5_rxp.c */
int mlx5_regex_info_get(struct rte_regexdev *dev,
			struct rte_regexdev_info *info);
int mlx5_regex_configure(struct rte_regexdev *dev,
			 const struct rte_regexdev_config *cfg);
int mlx5_regex_rules_db_import(struct rte_regexdev *dev,
			       const char *rule_db, uint32_t rule_db_len);

/* mlx5_regex_devx.c */
int mlx5_devx_regex_rules_program(void *ctx, uint8_t engine, uint32_t rof_mkey,
				uint32_t rof_size, uint64_t db_mkey_offset);

/* mlx5_regex_control.c */
int mlx5_regex_qp_setup(struct rte_regexdev *dev, uint16_t qp_ind,
			const struct rte_regexdev_qp_conf *cfg);
void mlx5_regex_clean_ctrl(struct rte_regexdev *dev);

/* mlx5_regex_fastpath.c */
int mlx5_regexdev_setup_fastpath(struct mlx5_regex_priv *priv, uint32_t qp_id);
void mlx5_regexdev_teardown_fastpath(struct mlx5_regex_priv *priv,
				     uint32_t qp_id);
uint16_t mlx5_regexdev_enqueue(struct rte_regexdev *dev, uint16_t qp_id,
		       struct rte_regex_ops **ops, uint16_t nb_ops);
uint16_t mlx5_regexdev_dequeue(struct rte_regexdev *dev, uint16_t qp_id,
		       struct rte_regex_ops **ops, uint16_t nb_ops);
uint16_t mlx5_regexdev_enqueue_gga(struct rte_regexdev *dev, uint16_t qp_id,
		       struct rte_regex_ops **ops, uint16_t nb_ops);
#endif /* MLX5_REGEX_H */
