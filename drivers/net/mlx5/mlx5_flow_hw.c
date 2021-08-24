#include <rte_flow.h>

#include <mlx5_malloc.h>

#include "mlx5_defs.h"
#include "mlx5_flow.h"
#include "mlx5_flow_os.h"

const struct mlx5_flow_driver_ops mlx5_flow_hw_drv_ops;

static struct rte_flow_action_template *
flow_hw_action_template_create(struct rte_eth_dev *dev,
			       const struct rte_flow_action_template_attr *attr,
			       const struct rte_flow_action actions[],
			       const struct rte_flow_action masks[],
			       struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	int len, act_len, mask_len, i;
	struct rte_flow_action_template *at;

	act_len = rte_flow_conv(RTE_FLOW_CONV_OP_ACTIONS,
				NULL, 0, actions, error);
	if (act_len <= 0)
		return NULL;
	len = RTE_ALIGN(act_len, 16);
	mask_len = rte_flow_conv(RTE_FLOW_CONV_OP_ACTIONS,
				 NULL, 0, masks, error);
	if (mask_len <= 0)
		return NULL;

	len += RTE_ALIGN(mask_len, 16);
	at = mlx5_malloc(MLX5_MEM_ZERO | MLX5_MEM_SYS, len + sizeof(*at),
			 64, SOCKET_ID_ANY);
	if (!at) {
		rte_flow_error_set(error, ENOMEM,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL,
				   "cannot allocate action template");
		return NULL;
	}
	at->attr = *attr;
	at->actions = (struct rte_flow_action *)(at + 1);
	act_len = rte_flow_conv(RTE_FLOW_CONV_OP_ACTIONS, at->actions, len,
				actions, error);
	if (act_len <= 0)
		goto error;
	at->masks = (struct rte_flow_action *)
		    (((uint8_t *)at->actions) + act_len);
	mask_len = rte_flow_conv(RTE_FLOW_CONV_OP_ACTIONS, at->masks,
				 len - act_len, masks, error);
	if (mask_len <= 0)
		goto error;
	for (i = 0; actions->type != RTE_FLOW_ACTION_TYPE_END;
	     actions++, masks++, i++) {
		if (actions->type == RTE_FLOW_ACTION_TYPE_INDIRECT) {
			at->actions[i].conf = actions->conf;
			at->masks[i].conf = masks->conf;
		}
	}
	__atomic_fetch_add(&at->refcnt, 1, __ATOMIC_RELAXED);
	LIST_INSERT_HEAD(&priv->flow_hw_at, at, next);
	return at;
error:
	mlx5_free(at);
	return NULL;
}

static int
flow_hw_action_template_destroy(struct rte_eth_dev *dev __rte_unused,
				struct rte_flow_action_template *template,
				struct rte_flow_error *error __rte_unused)
{
	if (__atomic_load_n(&template->refcnt, __ATOMIC_RELAXED) > 1)
		DRV_LOG(WARNING, "Acts template %p is still in use.",
			(void *)template);
	LIST_REMOVE(template, next);
	mlx5_free(template);
	return 0;
}

static struct rte_flow_item_template *
flow_hw_item_template_create(struct rte_eth_dev *dev,
			     const struct rte_flow_item_template_attr *attr,
			     const struct rte_flow_item items[],
			     struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct rte_flow_item_template *it;

	it = mlx5_malloc(MLX5_MEM_ZERO, sizeof(*it), 0, SOCKET_ID_ANY);
	if (!it) {
		rte_flow_error_set(error, ENOMEM,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL,
				   "cannot allocate item template");
		return NULL;
	}
	it->attr = *attr;
	it->mt = mlx5dr_match_template_create(items, attr->relaxed_matching);
	if (!it->mt) {
		mlx5_free(it);
		return NULL;
	}
	__atomic_fetch_add(&it->refcnt, 1, __ATOMIC_RELAXED);
	LIST_INSERT_HEAD(&priv->flow_hw_itt, it, next);
	return it;
}

static int
flow_hw_item_template_destroy(struct rte_eth_dev *dev __rte_unused,
			      struct rte_flow_item_template *template,
			      struct rte_flow_error *error __rte_unused)
{
	if (__atomic_load_n(&template->refcnt, __ATOMIC_RELAXED) > 1)
		DRV_LOG(WARNING, "Item template %p is still in use.",
			(void *)template);
	LIST_REMOVE(template, next);
	mlx5dr_match_template_destroy(template->mt);
	mlx5_free(template);
	return 0;
}

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
	struct rte_flow_item_template *it;
	struct rte_flow_action_template *at;

	if (!priv->dr_ctx)
		return;
	while (!LIST_EMPTY(&priv->flow_hw_itt)) {
		it = LIST_FIRST(&priv->flow_hw_itt);
		flow_hw_item_template_destroy(dev, it, NULL);
	}
	while (!LIST_EMPTY(&priv->flow_hw_at)) {
		at = LIST_FIRST(&priv->flow_hw_at);
		flow_hw_action_template_destroy(dev, at, NULL);
	}
	mlx5_free(priv->hw_q);
	claim_zero(mlx5dr_context_close(priv->dr_ctx));
}

const struct mlx5_flow_driver_ops mlx5_flow_hw_drv_ops = {
	.configure = flow_hw_configure,
	.item_template_create = flow_hw_item_template_create,
	.item_template_destroy = flow_hw_item_template_destroy,
	.action_template_create = flow_hw_action_template_create,
	.action_template_destroy = flow_hw_action_template_destroy,
};
