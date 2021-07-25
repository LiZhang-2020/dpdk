/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5dr_internal.h"

struct mlx5dr_send_engine_post_ctrl
mlx5dr_send_engine_post_start(struct mlx5dr_send_engine *queue)
{
	struct mlx5dr_send_engine_post_ctrl ctrl;

	ctrl.queue = queue;
	ctrl.send_ring = &queue->send_ring[0]; // TODO: Change when send rings > 1
	ctrl.num_wqebbs = 0;

	return ctrl;
}

void mlx5dr_send_engine_post_req_wqe(struct mlx5dr_send_engine_post_ctrl *ctrl,
				     char **buf, size_t *len)
{
	struct mlx5dr_send_ring_sq *send_sq = &ctrl->send_ring->send_sq;

	*buf = send_sq->buf + ((send_sq->cur_post + (ctrl->num_wqebbs << MLX5_SEND_WQE_SHIFT)) & send_sq->buf_mask);
	*len = MLX5_SEND_WQE_BB;

	if (!ctrl->num_wqebbs) {
		*buf += sizeof(struct mlx5dr_wqe_ctrl_seg);
		*len -= sizeof(struct mlx5dr_wqe_ctrl_seg);
	}

	ctrl->num_wqebbs++;
}

static void mlx5dr_send_engine_post_ring(struct mlx5dr_send_ring_sq *sq,
					 struct mlx5dv_devx_uar *uar,
					 struct mlx5dr_wqe_ctrl_seg *wqe_ctrl)
{
	rte_compiler_barrier();
	sq->db[MLX5_SND_DBR] = rte_cpu_to_be_32(sq->cur_post);

	rte_wmb();
	mlx5dr_uar_write64_relaxed(*((uint64_t *)wqe_ctrl), uar->reg_addr);
	rte_wmb();
}

void mlx5dr_send_engine_post_end(struct mlx5dr_send_engine_post_ctrl *ctrl,
				 struct mlx5dr_send_engine_post_attr *attr)
{
	struct mlx5dr_wqe_ctrl_seg *wqe_ctrl;
	struct mlx5dr_send_ring_sq *sq;
	unsigned idx;

	sq = &ctrl->send_ring->send_sq;
	idx = sq->cur_post & sq->buf_mask;

	wqe_ctrl = (void *)(sq->buf + (idx << MLX5_SEND_WQE_SHIFT));

	wqe_ctrl->opmod_idx_opcode =
		rte_cpu_to_be_32(((sq->cur_post & 0xffff) << 8) | attr->opcode);
	wqe_ctrl->qpn_ds = rte_cpu_to_be_32((attr->len + sizeof(struct mlx5dr_wqe_ctrl_seg)) / 16 |
			       sq->sqn << 8);
	wqe_ctrl->imm = rte_cpu_to_be_32(attr->id);

	wqe_ctrl->flags = rte_cpu_to_be_32(attr->notify_hw ? MLX5_WQE_CTRL_CQ_UPDATE : 0);

	sq->wr_priv[idx].rule = attr->rule;
	sq->wr_priv[idx].user_comp = attr->user_comp;
	sq->wr_priv[idx].num_wqebbs = ctrl->num_wqebbs;

	sq->cur_post += ctrl->num_wqebbs;

	if (attr->notify_hw)
		mlx5dr_send_engine_post_ring(sq, ctrl->queue->uar, wqe_ctrl);
}

static void mlx5dr_send_engine_update_rule(struct mlx5dr_send_ring_priv *priv,
					   struct mlx5dr_rule *rule[],
					   size_t *i)
{
	// TODO: Add check for cqe status i,j values for error
	priv->rule->rule_status = MLX5DR_RULE_COMPLETED_SUCC;
	if (priv->user_comp) {
		rule[*i] = priv->rule;
		(*i)++;
	}
}

static int __mlx5dr_send_engine_poll(struct mlx5dr_send_ring *send_ring,
				     struct mlx5dr_rule *rule[],
				     size_t *i,
				     size_t rule_sz)
{
	struct mlx5dr_send_ring_cq *cq = &send_ring->send_cq;
	struct mlx5dr_send_ring_sq *sq = &send_ring->send_sq;
	uint32_t cq_idx = cq->cons_index & ( cq->buf_mask);
	struct mlx5dr_send_ring_priv *priv;
	struct mlx5_cqe64 *cqe;
	uint8_t cqe_opcode;
	uint8_t cqe_owner;
	uint16_t wqe_cnt;
	uint8_t sw_own;

	cqe = (void *)(cq->buf + (cq_idx << cq->cqe_log_sz));

	sw_own = (cq->cons_index & cq->buf_sz) ? 1 : 0;
	cqe_opcode = mlx5dv_get_cqe_opcode(cqe);
	cqe_owner = mlx5dv_get_cqe_owner(cqe);

	if (cqe_opcode == MLX5_CQE_INVALID ||
	    cqe_owner != sw_own)
		return -1;

	if (cqe_opcode != MLX5_CQE_REQ) //TODO debug
                printf("CQE Error op=0x%x\n", cqe_opcode);

	rte_io_rmb();

	wqe_cnt = be16toh(cqe->wqe_counter) & sq->buf_mask;

	while (cq->poll_wqe != wqe_cnt && *i < rule_sz) {
		priv = &sq->wr_priv[cq->poll_wqe];
		mlx5dr_send_engine_update_rule(priv, rule ,i);
		cq->poll_wqe = (cq->poll_wqe + priv->num_wqebbs) & sq->buf_mask;
	}

	priv = &sq->wr_priv[wqe_cnt];
	cq->poll_wqe = (wqe_cnt + priv->num_wqebbs) & sq->buf_mask;
	if (*i >= rule_sz)
		return 0;
	mlx5dr_send_engine_update_rule(priv, rule ,i);

	return 0;
}

int mlx5dr_send_engine_poll(struct mlx5dr_send_ring *send_ring,
			    struct mlx5dr_rule *rule[], //TODO: Maybe should be rte flow res?
			    size_t rule_sz)
{
	size_t i = 0;
	int ret = 0;

	//TODO: Check completed list first

	for (; i < rule_sz && !ret;) {
		ret = __mlx5dr_send_engine_poll(send_ring, &rule[i], &i, rule_sz);
		if (ret)
			goto out;
		send_ring->send_cq.cons_index++;
	}

out:
	*send_ring->send_cq.db = htobe32(send_ring->send_cq.cons_index & 0xffffffff);

	return ret;
}

static inline uint64_t roundup_pow_of_two(uint64_t n)
{
	return n == 1 ? 1 : 1ULL << log2above(n);
}

static int mlx5dr_send_ring_create_sq_obj(struct mlx5dr_context *ctx,
					  struct mlx5dr_send_engine *queue,
					  struct mlx5dr_send_ring_sq *sq,
					  struct mlx5dr_send_ring_cq *cq,
					  size_t log_wq_sz)
{
	struct mlx5dr_cmd_sq_create_attr attr = {0};
	int err;

	attr.cqn = cq->cqn;
	attr.pdn = ctx->pd_num;
	attr.page_id = queue->uar->page_id;
	attr.dbr_id = sq->db_umem->umem_id;
	attr.wq_id = sq->buf_umem->umem_id;
	attr.log_wq_sz = log_wq_sz;

	sq->obj = mlx5dr_cmd_sq_create(ctx->ibv_ctx, &attr);
	if (!sq->obj)
		return rte_errno;

	sq->sqn = sq->obj->id;

	err = mlx5dr_cmd_sq_modify_rdy(sq->obj);
	if (err)
		goto free_sq;

	return 0;

free_sq:
	mlx5dr_cmd_destroy_obj(sq->obj);

	return err;
}

static inline unsigned long align(unsigned long val, unsigned long align)
{
        return (val + align - 1) & ~(align - 1);
}

/* As a single operation requires at least two WQEBBS this means a maximum of 16
 * such operations per rule
 */
#define MAX_WQES_PER_RULE 32

static int mlx5dr_send_ring_open_sq(struct mlx5dr_context *ctx,
				    struct mlx5dr_send_engine *queue,
				    struct mlx5dr_send_ring_sq *sq,
				    struct mlx5dr_send_ring_cq *cq)
{
	size_t sq_log_buf_sz;
	size_t buf_aligned;
	size_t sq_buf_sz;
	size_t buf_sz;
	int err;

	buf_sz = queue->queue_num_entries * MAX_WQES_PER_RULE;
	sq_log_buf_sz = log2above(buf_sz);
	sq_buf_sz = 1 << (sq_log_buf_sz + log2above(MLX5_SEND_WQE_BB));
	sq->reg_addr = queue->uar->reg_addr;

	buf_aligned = align(sq_buf_sz, sysconf(_SC_PAGESIZE));
	err = posix_memalign((void **)&sq->buf, sysconf(_SC_PAGESIZE), buf_aligned);
	if (err) {
		rte_errno = ENOMEM;
		return err;
	}

	err = posix_memalign((void **)&sq->db, 8, 8);
	if (err)
		goto free_buf;

	sq->buf_umem = mlx5_glue->devx_umem_reg(ctx->ibv_ctx, sq->buf, sq_buf_sz, 0);

	if (!sq->buf_umem) {
		err = errno;
		goto free_db;
	}

	sq->db_umem = mlx5_glue->devx_umem_reg(ctx->ibv_ctx, sq->db, 8, 0);
	if (!sq->db_umem) {
		err = errno;
		goto free_buf_umem;
	}

	err = mlx5dr_send_ring_create_sq_obj(ctx, queue, sq, cq, sq_log_buf_sz);

	if (err)
		goto free_db_umem;

	sq->wr_priv = simple_malloc(sizeof(*sq->wr_priv) * buf_sz);
	if (!sq->wr_priv) {
		err = ENOMEM;
		goto destroy_sq_obj;
	}

	sq->buf_mask = buf_sz - 1;

	return 0;

destroy_sq_obj:
	mlx5dr_cmd_destroy_obj(sq->obj);
free_db_umem:
	mlx5_glue->devx_umem_dereg(sq->db_umem);
free_buf_umem:
	mlx5_glue->devx_umem_dereg(sq->buf_umem);
free_db:
	free(sq->db);
free_buf:
	free(sq->buf);
	rte_errno = err;
	return err;
}

static void mlx5dr_send_ring_close_sq(struct mlx5dr_send_ring_sq *sq)
{
	mlx5dr_cmd_destroy_obj(sq->obj);
	mlx5_glue->devx_umem_dereg(sq->db_umem);
	mlx5_glue->devx_umem_dereg(sq->buf_umem);
	simple_free(sq->wr_priv);
	free(sq->db);
	free(sq->buf);
}

static int mlx5dr_send_ring_open_cq(struct mlx5dr_context *ctx,
				    struct mlx5dr_send_engine *queue,
				    struct mlx5dr_send_ring_cq *cq)
{
	struct mlx5dv_cq mlx5_cq = {0};
	struct mlx5dv_obj obj;
	struct ibv_cq *ibv_cq;
	size_t cq_size;
	int err;

	cq_size = queue->queue_num_entries;
	ibv_cq = mlx5_glue->create_cq(ctx->ibv_ctx, cq_size, NULL, NULL, 0);
	if (!ibv_cq) {
		DRV_LOG(ERR, "Failed to create CQ");
		rte_errno = errno;
		return rte_errno;
	}

	obj.cq.in = ibv_cq;
	obj.cq.out = &mlx5_cq;
	err = mlx5_glue->dv_init_obj(&obj, MLX5DV_OBJ_CQ);
	if (err) {
		err = errno;
		goto close_cq;
	}

	cq->buf = mlx5_cq.buf;
	cq->db = mlx5_cq.dbrec;
	cq->ncqe = mlx5_cq.cqe_cnt;
	if (cq->ncqe < queue->queue_num_entries)
		DRV_LOG(ERR, "%s - (ncqe: %u quque_num_entries: %u) Bug?!\n",
			__func__,
			cq->ncqe,
			queue->queue_num_entries); /* TODO - Debug test */
	cq->cqe_sz = mlx5_cq.cqe_size;
	cq->cqe_log_sz = log2above(cq->cqe_sz);
	cq->buf_mask = cq->ncqe - 1;
	cq->buf_sz = cq->cqe_sz * cq->ncqe;
        cq->cqn = mlx5_cq.cqn;
	cq->ibv_cq = ibv_cq;

        return 0;

close_cq:
	mlx5_glue->destroy_cq(ibv_cq);
	rte_errno = err;
	return err;
}

static void mlx5dr_send_ring_close_cq(struct mlx5dr_send_ring_cq *cq)
{
	mlx5_glue->destroy_cq(cq->ibv_cq);
}

static void mlx5dr_send_ring_close(struct mlx5dr_send_ring *ring)
{
	mlx5dr_send_ring_close_sq(&ring->send_sq);
	mlx5dr_send_ring_close_cq(&ring->send_cq);
}

static int mlx5dr_send_ring_open(struct mlx5dr_context *ctx,
				 struct mlx5dr_send_engine *queue,
				 struct mlx5dr_send_ring *ring)
{
	int err;

	err = mlx5dr_send_ring_open_cq(ctx, queue, &ring->send_cq);
	if (err)
		return err;

	err = mlx5dr_send_ring_open_sq(ctx, queue, &ring->send_sq, &ring->send_cq);
	if (err)
		goto close_cq;

	return err;

close_cq:
	mlx5dr_send_ring_close_cq(&ring->send_cq);

	return err;
}

static void __mlx5dr_send_rings_close(struct mlx5dr_send_engine *queue,
				      uint16_t i)
{
	while (i--)
		mlx5dr_send_ring_close(&queue->send_ring[i]);
}

static void mlx5dr_send_rings_close(struct mlx5dr_send_engine *queue)
{
	__mlx5dr_send_rings_close(queue, queue->rings);
}

static int mlx5dr_send_rings_open(struct mlx5dr_context *ctx,
				  struct mlx5dr_send_engine *queue)
{
	uint16_t i;
	int err;

	for (i = 0; i < queue->rings; i++) {
		err = mlx5dr_send_ring_open(ctx, queue, &queue->send_ring[i]);
		if (err)
			goto free_rings;
	}

	return 0;

free_rings:
	__mlx5dr_send_rings_close(queue, i);

	return err;
}

static void mlx5dr_send_queue_close(struct mlx5dr_send_engine *queue)
{
	mlx5dr_send_rings_close(queue);
	mlx5_glue->devx_free_uar(queue->uar);
}

static int mlx5dr_send_queue_open(struct mlx5dr_context *ctx,
				  struct mlx5dr_send_engine *queue,
				  uint16_t queue_size)
{
	struct mlx5dv_devx_uar *uar;
	int err;

	uar = mlx5_glue->devx_alloc_uar(ctx->ibv_ctx, MLX5_IB_UAPI_UAR_ALLOC_TYPE_NC);
	if (!uar)
		return errno;

	queue->uar = uar;

	queue->rings = MLX5DR_NUM_SEND_RINGS;
	queue->queue_num_entries = roundup_pow_of_two(queue_size); /* TODO */

	err = mlx5dr_send_rings_open(ctx, queue);
	if (err)
		goto free_uar;

	return 0;

free_uar:
	mlx5_glue->devx_free_uar(uar);

	return err;
}

static void __mlx5dr_send_queues_close(struct mlx5dr_context *ctx, uint16_t queues)
{
	struct mlx5dr_send_engine *queue;

	while (queues--) {
		queue = &ctx->send_queue[queues];

		mlx5dr_send_queue_close(queue);
	}
}

void mlx5dr_send_queues_close(struct mlx5dr_context *ctx)
{
	__mlx5dr_send_queues_close(ctx, ctx->queues);
	simple_free(ctx->send_queue);
}

int mlx5dr_send_queues_open(struct mlx5dr_context *ctx,
			    uint16_t queues,
			    uint16_t queue_size)
{
	uint32_t i;
	int err;

	/* TODO: For now there is a 1:1 queue:ring mapping
	 * add middle logic layer if it ever changes.
	 */
	ctx->queues = queues;

	ctx->send_queue = simple_calloc(queues, sizeof(*ctx->send_queue));
	if (!ctx->send_queue) {
		rte_errno = ENOMEM;
		return rte_errno;
	}

	for (i = 0; i < queues; i++) {
		err = mlx5dr_send_queue_open(ctx, &ctx->send_queue[i], queue_size);
		if (err)
			goto close_send_queues;
	}

	return err;

close_send_queues:
	 __mlx5dr_send_queues_close(ctx, i);

	simple_free(ctx->send_queue);

	return err;
}
