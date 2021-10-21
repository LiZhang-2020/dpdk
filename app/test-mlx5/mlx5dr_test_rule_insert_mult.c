/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include <time.h>
#include "mlx5dr_test.h"

#define MAX_ITEMS 10
#define BIG_LOOP 100
#define MAX_ITEMS 10
#define NUM_OF_QUEUES 16
#define QUEUE_SIZE 1024
#define NUM_OF_RULES (QUEUE_SIZE * 3906) // Almost 1M
#define BURST_TH (64)
#define NUM_CORES 8
#define COL_LOG 0
#define ROW_LOG 22

struct thread_info {
	struct mlx5dr_context *ctx;
	int queue_id;
	const char *thread_name;
	struct mlx5dr_matcher *matcher;
	struct mlx5dr_action *drop;
};

struct thread_info th_info[8];

static int poll_for_comp(struct mlx5dr_context *ctx,
			 uint16_t queue_id,
			 uint32_t *pending_rules,
			 uint32_t expected_comp,
			 uint32_t *miss_count,
			 uint32_t *hw_bp,
			 bool drain)
{
	bool queue_full = *pending_rules == QUEUE_SIZE;
	bool got_comp = *pending_rules >= expected_comp;
	struct rte_flow_q_op_res comp[BURST_TH];
	bool first_comp = true;
	int ret;
	int j;

	/* Check if there are any completions at all */
	if (!got_comp)
		return 0;

	while (queue_full || ((got_comp || drain) && *pending_rules)) {
		ret = mlx5dr_send_queue_poll(ctx, queue_id, comp, expected_comp);
		if (ret < 0) {
			printf("Failed during poll queue\n");
			return -1;
		}

		if (ret) {
			(*pending_rules) -= ret;
			for (j = 0; j < ret; j++) {
				if (comp[j].status == RTE_FLOW_Q_OP_RES_ERROR)
					(*miss_count)++;
			}

			queue_full = false;
		} else if (queue_full && first_comp) {
			first_comp = false;
			(*hw_bp)++;
		}

		got_comp = !!ret;
	}

	return 0;
}

static void set_match_mavneir(struct rte_flow_item_eth *eth_m,
			      struct rte_flow_item_eth *eth_v,
			      struct rte_ipv4_hdr *ip_m,
			      struct rte_ipv4_hdr *ip_v,
			      struct rte_flow_item_udp *udp_m,
			      struct rte_flow_item_udp *udp_v,
			      struct rte_flow_item_gtp *gtp_m,
			      struct rte_flow_item_gtp *gtp_v,
			      struct rte_ipv4_hdr *ip_m_in,
			      struct rte_ipv4_hdr *ip_v_in,
			      struct rte_flow_item_tcp *tcp_m_in,
			      struct rte_flow_item_tcp *tcp_v_in,
			      struct rte_flow_item *items)

{
	if (eth_m) {
		memset(eth_m, 0, sizeof(*eth_m));
		memset(eth_v, 0, sizeof(*eth_v));
		items->type = RTE_FLOW_ITEM_TYPE_ETH;
		items->mask = eth_m;
		items->spec = eth_v;
		items++;
	}

	if (ip_m) {
		memset(ip_m, 0, sizeof(*ip_m));
		memset(ip_v, 0, sizeof(*ip_v));
		ip_m->dst_addr = 0xffffffff;
		ip_m->src_addr = 0xffffffff;
		ip_v->dst_addr = 0x02020202;
		ip_v->src_addr = 0x01010101;
		ip_m->version = 0xf;
		ip_v->version = 0x4;
		items->type = RTE_FLOW_ITEM_TYPE_IPV4;
		items->mask = ip_m;
		items->spec = ip_v;
		items++;
	}

	if (udp_m) {
		memset(udp_m, 0, sizeof(*udp_m));
		memset(udp_v, 0, sizeof(*udp_v));
		items->type = RTE_FLOW_ITEM_TYPE_UDP;
		items->mask = udp_m;
		items->spec = udp_m;
		items++;
	}

	if (gtp_m) {
		memset(gtp_m, 0, sizeof(*gtp_m));
		memset(gtp_v, 0, sizeof(*gtp_v));
		gtp_m->teid = -1;
		gtp_v->teid = 0xabcd;
		items->type = RTE_FLOW_ITEM_TYPE_GTP;
		items->mask = gtp_m;
		items->spec = gtp_v;
		items++;
	}

	if (ip_m_in) {
		memset(ip_m_in, 0, sizeof(*ip_m_in));
		memset(ip_v_in, 0, sizeof(*ip_v_in));
		ip_m_in->dst_addr = 0xffffffff;
		ip_m_in->src_addr = 0xffffffff;
		ip_v_in->dst_addr = 0x04040404;
		ip_v_in->src_addr = 0x03030303;
		ip_v_in->version = 0xf;
		ip_v_in->version = 0x4;
		items->type = RTE_FLOW_ITEM_TYPE_IPV4;
		items->mask = ip_m_in;
		items->spec = ip_v_in;
		items++;
	}

	if (tcp_m_in) {
		memset(tcp_m_in, 0, sizeof(*tcp_m_in));
		memset(tcp_v_in, 0, sizeof(*tcp_v_in));
		tcp_m_in->hdr.dst_port = -1;
		tcp_m_in->hdr.src_port = -1;
		tcp_v_in->hdr.dst_port = 0xbbbb;
		tcp_v_in->hdr.src_port = 0xaaaa;
		items->type = RTE_FLOW_ITEM_TYPE_TCP;
		items->mask = tcp_m_in;
		items->spec = tcp_v_in;
		items++;
	}

	items->type = RTE_FLOW_ITEM_TYPE_END;
}

static int run_loop(__rte_unused void *nothing)
{
	struct rte_flow_item items[MAX_ITEMS] = {{0}};
	struct mlx5dr_rule_action rule_actions[10];
	struct rte_flow_item_eth eth_value, eth_mask;
	struct rte_ipv4_hdr ipv_mask, ipv_value;
	struct mlx5dr_rule_attr rule_attr = {0};
	struct mlx5dr_matcher *hws_matcher;
	int lcore_id = rte_lcore_id();
	struct mlx5dr_rule *hws_rule;
	struct mlx5dr_action *drop;
	struct mlx5dr_context *ctx;
	uint32_t miss_count, hw_bp;
	uint32_t pending_rules = 0;
	uint64_t start, end;
	int j, i, ret;
	int queue_id;

	printf("Starting lcore_id %d\n", lcore_id);

	ctx = th_info[lcore_id % NUM_CORES].ctx;
	queue_id = lcore_id % NUM_CORES;
	hws_matcher = th_info[lcore_id % NUM_CORES].matcher;
	drop = th_info[lcore_id % NUM_CORES].drop;

	set_match_mavneir(&eth_mask, &eth_value,
			  &ipv_mask, &ipv_value,
			  NULL, NULL,
			  NULL, NULL,
			  NULL, NULL,
			  NULL, NULL,
			  items);

	/* Allocate HWS rules */
	hws_rule = calloc(NUM_OF_RULES, mlx5dr_rule_get_handle_size());
	if (!hws_rule) {
		printf("Failed to allocate memory for hws_rule\n");
		return -1;
	}

	for (j = 0; j < BIG_LOOP; j++) {
		miss_count = 0;
		hw_bp = 0;
		start = rte_rdtsc();

		/* Create HWS rules */
		for (i = 0; i < NUM_OF_RULES; i++) {
			rule_attr.queue_id = queue_id;
			rule_attr.user_data = &hws_rule[i];
			rule_attr.burst = !((i + 1) % BURST_TH == 0); /* Ring doorbell */

			ipv_value.src_addr = i;
			//ipv_value.dst_addr = i;

			rule_actions[0].action = drop;

			ret = mlx5dr_rule_create(hws_matcher, 0, items, rule_actions, 1, &rule_attr, &hws_rule[i]);
			if (ret) {
				printf("Failed to create hws rule\n");
				return -1;
			}

			pending_rules++;

			poll_for_comp(ctx, rule_attr.queue_id, &pending_rules, BURST_TH, &miss_count, &hw_bp, false);
		}

		end = rte_rdtsc();
		/* Drain the queue */
		poll_for_comp(ctx, rule_attr.queue_id, &pending_rules, BURST_TH, &miss_count, &hw_bp, true);
		printf("%d K-Rules/Sec: %lf Insertion. Total misses: %u (out of: %u) HW bp %u\n", lcore_id, (double) ((double) NUM_OF_RULES / 1000) / ((double) (end - start) / rte_get_tsc_hz()),
		       miss_count, NUM_OF_RULES, hw_bp);

		miss_count = 0;
		hw_bp = 0;
		start = rte_rdtsc();

		/* Delete HWS rules */
		for (i = 0; i < NUM_OF_RULES; i++) {
			rule_attr.queue_id = queue_id;
			rule_attr.user_data = &hws_rule[i];

			/* Ring doorbell */
			rule_attr.burst = !((i + 1) % (BURST_TH) == 0);

			ret = mlx5dr_rule_destroy(&hws_rule[i], &rule_attr);
			if (ret) {
				printf("Failed to destroy hws rule\n");
				return -1;
			}

			pending_rules++;

			poll_for_comp(ctx, rule_attr.queue_id, &pending_rules, BURST_TH, &miss_count, &hw_bp, false);
		}

		end = rte_rdtsc();
		/* Drain the queue */
		poll_for_comp(ctx, rule_attr.queue_id, &pending_rules, BURST_TH, &miss_count, &hw_bp, true);
		printf("%d K-Rules/Sec: %lf Deletion. Total misses: %u (out of: %u) HW bp %u\n", lcore_id, (double) ((double) NUM_OF_RULES / 1000) / ((double) (end - start) / rte_get_tsc_hz()),
		       miss_count, NUM_OF_RULES, hw_bp);
	}
	return 0;
}

int run_test_rule_insert_mult(struct ibv_context *ibv_ctx)
{
	struct mlx5dr_context *ctx;
	struct mlx5dr_table *hws_tbl;
	struct mlx5dr_matcher *hws_matcher1, *hws_matcher2, *hws_matcher3, *hws_matcher4;
	struct mlx5dr_matcher *hws_matcher5, *hws_matcher6, *hws_matcher7, *hws_matcher8;
	struct mlx5dr_context_attr dr_ctx_attr = {0};
	struct mlx5dr_table_attr dr_tbl_attr = {0};
	struct mlx5dr_matcher_attr matcher_attr = {0};
	struct rte_flow_item items[MAX_ITEMS] = {{0}};
	struct rte_flow_item_eth eth_mask;
	struct rte_flow_item_eth eth_value;
	struct rte_ipv4_hdr ipv_mask;
	struct rte_ipv4_hdr ipv_value;
	struct mlx5dr_match_template *mt;
	struct mlx5dr_action *drop;

	dr_ctx_attr.initial_log_ste_memory = 0;
	dr_ctx_attr.pd = NULL;
	dr_ctx_attr.queues = NUM_OF_QUEUES;
	dr_ctx_attr.queue_size = QUEUE_SIZE;

	ctx = mlx5dr_context_open(ibv_ctx, &dr_ctx_attr);
	if (!ctx) {
		printf("Failed to create context\n");
		goto out_err;
	}

	/* Create HWS table */
	dr_tbl_attr.level = 1;
	dr_tbl_attr.type = MLX5DR_TABLE_TYPE_NIC_RX;
	hws_tbl = mlx5dr_table_create(ctx, &dr_tbl_attr);
	if (!hws_tbl) {
		printf("Failed to create HWS table\n");
		goto close_ctx;
	}

	set_match_mavneir(&eth_mask, &eth_value,
			  &ipv_mask, &ipv_value,
			  NULL, NULL,
			  NULL, NULL,
			  NULL, NULL,
			  NULL, NULL,
			  items);

	mt = mlx5dr_match_template_create(items);
	if (!mt) {
		printf("Failed HWS template\n");
		goto destroy_hws_tbl;
	}

	/* Create HWS matcher1 */
	matcher_attr.priority = 0;
	matcher_attr.insertion_mode = MLX5DR_MATCHER_INSERTION_MODE_BEST_EFFORT;
	matcher_attr.sz_hint_col_log = COL_LOG;
	matcher_attr.sz_hint_row_log = ROW_LOG;
	hws_matcher1 = mlx5dr_matcher_create(hws_tbl, &mt, 1, &matcher_attr);
	if (!hws_matcher1) {
		printf("Failed to create HWS matcher 1\n");
		goto destroy_template;
	}

	/* Create HWS matcher2 */
	matcher_attr.priority = 2;
	matcher_attr.insertion_mode = MLX5DR_MATCHER_INSERTION_MODE_BEST_EFFORT;
	matcher_attr.sz_hint_col_log = COL_LOG;
	matcher_attr.sz_hint_row_log = ROW_LOG;
	hws_matcher2 = mlx5dr_matcher_create(hws_tbl, &mt, 1, &matcher_attr);
	if (!hws_matcher2) {
		printf("Failed to create HWS matcher 2\n");
		goto destroy_hws_matcher1;
	}

	/* Create HWS matcher3 */
	matcher_attr.priority = 3;
	matcher_attr.insertion_mode = MLX5DR_MATCHER_INSERTION_MODE_BEST_EFFORT;
	matcher_attr.sz_hint_col_log = COL_LOG;
	matcher_attr.sz_hint_row_log = ROW_LOG;
	hws_matcher3 = mlx5dr_matcher_create(hws_tbl, &mt, 1, &matcher_attr);
	if (!hws_matcher3) {
		printf("Failed to create HWS matcher 3\n");
		goto destroy_hws_matcher2;
	}

	/* Create HWS matcher4 */
	matcher_attr.priority = 4;
	matcher_attr.insertion_mode = MLX5DR_MATCHER_INSERTION_MODE_BEST_EFFORT;
	matcher_attr.sz_hint_col_log = COL_LOG;
	matcher_attr.sz_hint_row_log = ROW_LOG;
	hws_matcher4 = mlx5dr_matcher_create(hws_tbl, &mt, 1, &matcher_attr);
	if (!hws_matcher4) {
		printf("Failed to create HWS matcher 4\n");
		goto destroy_hws_matcher3;
	}

	/* Create HWS matcher5 */
	matcher_attr.priority = 5;
	matcher_attr.insertion_mode = MLX5DR_MATCHER_INSERTION_MODE_BEST_EFFORT;
	matcher_attr.sz_hint_col_log = COL_LOG;
	matcher_attr.sz_hint_row_log = ROW_LOG;
	hws_matcher5 = mlx5dr_matcher_create(hws_tbl, &mt, 1, &matcher_attr);
	if (!hws_matcher5) {
		printf("Failed to create HWS matcher 5\n");
		goto destroy_hws_matcher4;
	}

	/* Create HWS matcher6 */
	matcher_attr.priority = 6;
	matcher_attr.insertion_mode = MLX5DR_MATCHER_INSERTION_MODE_BEST_EFFORT;
	matcher_attr.sz_hint_col_log = COL_LOG;
	matcher_attr.sz_hint_row_log = ROW_LOG;
	hws_matcher6 = mlx5dr_matcher_create(hws_tbl, &mt, 1, &matcher_attr);
	if (!hws_matcher6) {
		printf("Failed to create HWS matcher 6\n");
		goto destroy_hws_matcher5;
	}

	/* Create HWS matcher7 */
	matcher_attr.priority = 7;
	matcher_attr.insertion_mode = MLX5DR_MATCHER_INSERTION_MODE_BEST_EFFORT;
	matcher_attr.sz_hint_col_log = COL_LOG;
	matcher_attr.sz_hint_row_log = ROW_LOG;
	hws_matcher7 = mlx5dr_matcher_create(hws_tbl, &mt, 1, &matcher_attr);
	if (!hws_matcher7) {
		printf("Failed to create HWS matcher 7\n");
		goto destroy_hws_matcher6;
	}

	/* Create HWS matcher8 */
	matcher_attr.priority = 8;
	matcher_attr.insertion_mode = MLX5DR_MATCHER_INSERTION_MODE_BEST_EFFORT;
	matcher_attr.sz_hint_col_log = COL_LOG;
	matcher_attr.sz_hint_row_log = ROW_LOG;
	hws_matcher8 = mlx5dr_matcher_create(hws_tbl, &mt, 1, &matcher_attr);
	if (!hws_matcher8) {
		printf("Failed to create HWS matcher 8\n");
		goto destroy_hws_matcher7;
	}

	drop = mlx5dr_action_create_dest_drop(ctx, MLX5DR_ACTION_FLAG_HWS_RX);
	if (!drop) {
		printf("Failed to create action drop\n");
		goto destroy_hws_matcher8;
	}

	th_info[0].ctx = ctx;
	th_info[0].queue_id = 0;
	th_info[0].thread_name = "Thread 1!";
	th_info[0].matcher = hws_matcher1;
	th_info[0].drop = drop;

	th_info[1].ctx = ctx;
	th_info[1].queue_id = 1;
	th_info[1].thread_name = "Thread 2!";
	th_info[1].matcher = hws_matcher2;
	th_info[1].drop = drop;

	th_info[2].ctx = ctx;
	th_info[2].queue_id = 1;
	th_info[2].thread_name = "Thread 3!";
	th_info[2].matcher = hws_matcher3;
	th_info[2].drop = drop;

	th_info[3].ctx = ctx;
	th_info[3].queue_id = 1;
	th_info[3].thread_name = "Thread 4!";
	th_info[3].matcher = hws_matcher4;
	th_info[3].drop = drop;

	th_info[4].ctx = ctx;
	th_info[4].queue_id = 1;
	th_info[4].thread_name = "Thread 5!";
	th_info[4].matcher = hws_matcher5;
	th_info[4].drop = drop;

	th_info[5].ctx = ctx;
	th_info[5].queue_id = 1;
	th_info[5].thread_name = "Thread 6!";
	th_info[5].matcher = hws_matcher6;
	th_info[5].drop = drop;

	th_info[6].ctx = ctx;
	th_info[6].queue_id = 1;
	th_info[6].thread_name = "Thread 7!";
	th_info[6].matcher = hws_matcher7;
	th_info[6].drop = drop;

	th_info[7].ctx = ctx;
	th_info[7].queue_id = 1;
	th_info[7].thread_name = "Thread 8!";
	th_info[7].matcher = hws_matcher8;
	th_info[7].drop = drop;

	rte_eal_mp_remote_launch(run_loop, NULL, CALL_MAIN);

	rte_eal_mp_wait_lcore();

        mlx5dr_action_destroy(drop);
	mlx5dr_matcher_destroy(hws_matcher8);
	mlx5dr_matcher_destroy(hws_matcher7);
	mlx5dr_matcher_destroy(hws_matcher6);
	mlx5dr_matcher_destroy(hws_matcher5);
	mlx5dr_matcher_destroy(hws_matcher4);
	mlx5dr_matcher_destroy(hws_matcher3);
	mlx5dr_matcher_destroy(hws_matcher2);
	mlx5dr_matcher_destroy(hws_matcher1);
	mlx5dr_match_template_destroy(mt);
	mlx5dr_table_destroy(hws_tbl);
	mlx5dr_context_close(ctx);

	return 0;

destroy_hws_matcher8:
	mlx5dr_matcher_destroy(hws_matcher8);
destroy_hws_matcher7:
	mlx5dr_matcher_destroy(hws_matcher7);
destroy_hws_matcher6:
	mlx5dr_matcher_destroy(hws_matcher6);
destroy_hws_matcher5:
	mlx5dr_matcher_destroy(hws_matcher5);
destroy_hws_matcher4:
	mlx5dr_matcher_destroy(hws_matcher4);
destroy_hws_matcher3:
	mlx5dr_matcher_destroy(hws_matcher3);
destroy_hws_matcher2:
	mlx5dr_matcher_destroy(hws_matcher2);
destroy_hws_matcher1:
	mlx5dr_matcher_destroy(hws_matcher1);
destroy_template:
	mlx5dr_match_template_destroy(mt);
destroy_hws_tbl:
	mlx5dr_table_destroy(hws_tbl);
close_ctx:
	mlx5dr_context_close(ctx);
out_err:
	return -1;
}
