#include <rte_flow.h>

#include <mlx5_malloc.h>

#include "mlx5_defs.h"
#include "mlx5_flow.h"
#include "mlx5_flow_os.h"

const struct mlx5_flow_driver_ops mlx5_flow_hw_drv_ops;

static int
flow_hw_configure(struct rte_eth_dev *dev,
		  const struct rte_flow_port_attr *port_attr,
		  const struct rte_flow_queue_attr *queue_attr[],
		  struct rte_flow_error *err)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5dr_context *dr_ctx = NULL;
	struct mlx5dr_context_attr dr_ctx_attr = {0};
	struct mlx5_hw_q_job *job = NULL;
	uint32_t mem_size, i, j;

	if (!port_attr || !port_attr->nb_queues || !queue_attr) {
		rte_errno = EINVAL;
		goto err;
	}
	dr_ctx_attr.pd = priv->sh->cdev->pd;
	dr_ctx_attr.queues = port_attr->nb_queues;
	/* TODO: Should configure the queue size individually.*/
	dr_ctx_attr.queue_size = queue_attr[0]->size;
	dr_ctx = mlx5dr_context_open(priv->sh->cdev->ctx, &dr_ctx_attr);
	if (!dr_ctx)
		goto err;
	priv->dr_ctx = dr_ctx;
	/* Allocate the queue job descriptor LIFO. */
	mem_size = sizeof(priv->hw_q[0]) * port_attr->nb_queues;
	for (i = 0; i < port_attr->nb_queues; i++)
		mem_size += (sizeof(struct mlx5_hw_q_job *) +
			    sizeof(struct mlx5_hw_q_job)) *
			    queue_attr[0]->size;
	priv->hw_q = mlx5_malloc(MLX5_MEM_ZERO, mem_size,
				 64, SOCKET_ID_ANY);
	if (!priv->hw_q) {
		rte_errno = ENOMEM;
		goto err;
	}
	for (i = 0; i < port_attr->nb_queues; i++) {
		priv->hw_q[i].job_idx = queue_attr[i]->size;
		priv->hw_q[i].size = queue_attr[i]->size;
		if (i == 0)
			priv->hw_q[i].job = (struct mlx5_hw_q_job **)
					    &priv->hw_q[port_attr->nb_queues];
		else
			priv->hw_q[i].job = (struct mlx5_hw_q_job **)
					    &job[queue_attr[i - 1]->size];
		job = (struct mlx5_hw_q_job *)
		      &priv->hw_q[i].job[queue_attr[i]->size];
		for (j = 0; j < queue_attr[i]->size; j++)
			priv->hw_q[i].job[j] = &job[j];
	}
	return 0;
err:
	if (dr_ctx)
		claim_zero(mlx5dr_context_close(dr_ctx));
	return rte_flow_error_set(err, rte_errno,
				  RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				  "fail to configure port");
}

void
flow_hw_resource_release(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;

	if (!priv->dr_ctx)
		return;
	mlx5_free(priv->hw_q);
	claim_zero(mlx5dr_context_close(priv->dr_ctx));
}

const struct mlx5_flow_driver_ops mlx5_flow_hw_drv_ops = {
	.configure = flow_hw_configure,
};
