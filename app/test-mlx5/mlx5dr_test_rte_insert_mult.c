/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include <time.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_mtr.h>
#include <rte_gtp.h>
#include "mlx5dr_test.h"

#define RTE_IP_TYPE_UDP	17
#define RTE_IP_TYPE_GRE	47
#define RTE_VXLAN_GPE_UDP_PORT 250
#define RTE_GENEVE_UDP_PORT 6081
#define QNUM 4
#define MAX_ITEMS 10
#define BIG_LOOP 10
#define MAX_ITEMS 10
#define QUEUE_SIZE 256
#define NUM_OF_RULES (QUEUE_SIZE * 3906 * 4) /* Almost 1M */
#define BURST_TH (QUEUE_SIZE / 8)

#define INVAL_QUEUE UINT32_MAX

struct multi_cores_pool {
	uint32_t cores_count;
	uint32_t rules_count;
	uint32_t rules_per_core;
} __rte_cache_aligned;

static struct multi_cores_pool mc_pool = {
	.cores_count = 1,
	.rules_count = NUM_OF_RULES,
};
static struct rte_mempool *mbuf_mp;
static struct rte_flow_template_table *tbl, *htbl;

static int poll_for_comp(uint32_t port,
			 uint16_t queue_id,
			 uint32_t *pending_rules,
			 uint32_t expected_comp,
			 uint32_t *miss_count,
			 bool drain)
{
	bool queue_full = *pending_rules == QUEUE_SIZE;
	bool got_comp = *pending_rules >= expected_comp;
	struct rte_flow_op_result comp[BURST_TH];
	int ret;
	int j;

	/* Check if there are any completions at all */
	if (!got_comp)
		return 0;

	while (queue_full || ((got_comp || drain) && *pending_rules)) {
		ret = rte_flow_pull(port, queue_id, comp,
					 expected_comp, NULL);
		if (ret < 0) {
			printf("Failed during poll queue\n");
			return -1;
		}

		if (ret) {
			(*pending_rules) -= ret;
			for (j = 0; j < ret; j++) {
				if (comp[j].status == RTE_FLOW_OP_ERROR && miss_count)
					(*miss_count)++;
			}
			queue_full = false;
		}

		got_comp = !!ret;
	}

	return 0;
}

static void
init_port(void)
{
	int ret;
	uint16_t std_queue;
	uint16_t port_id;
	uint16_t nr_ports;
	uint16_t nr_queues;
	struct rte_eth_conf port_conf = {
		.rx_adv_conf = {
			.rss_conf.rss_hf =
				ETH_RSS_IP,
		}
	};
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_dev_info dev_info;

	nr_queues = QNUM;

	nr_ports = rte_eth_dev_count_avail();
	if (nr_ports == 0)
		rte_exit(EXIT_FAILURE, "Error: no port detected\n");

	mbuf_mp = rte_pktmbuf_pool_create("mbuf_pool",
					32000, 512,
					0, 2048,
					rte_socket_id());
	if (mbuf_mp == NULL)
		rte_exit(EXIT_FAILURE, "Error: can't init mbuf pool\n");

	for (port_id = 0; port_id < nr_ports; port_id++) {
		ret = rte_eth_dev_info_get(port_id, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device"
				" (port %u) info: %s\n",
				port_id, strerror(-ret));

		port_conf.txmode.offloads &= dev_info.tx_offload_capa;
		port_conf.rxmode.offloads &= dev_info.rx_offload_capa;

		printf(":: initializing port: %d\n", port_id);

		ret = rte_eth_dev_configure(port_id, nr_queues,
				nr_queues, &port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				":: cannot configure device: err=%d, port=%u\n",
				ret, port_id);

		rxq_conf = dev_info.default_rxconf;
		for (std_queue = 0; std_queue < nr_queues; std_queue++) {
			ret = rte_eth_rx_queue_setup(port_id, std_queue, 512,
					rte_eth_dev_socket_id(port_id),
					&rxq_conf,
					mbuf_mp);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
				":: Rx queue setup failed: err=%d, port=%u\n",
				ret, port_id);
		}

		txq_conf = dev_info.default_txconf;
		for (std_queue = 0; std_queue < nr_queues; std_queue++) {
			ret = rte_eth_tx_queue_setup(port_id, std_queue, 512,
					rte_eth_dev_socket_id(port_id),
					&txq_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
				":: Tx queue setup failed: err=%d, port=%u\n",
				ret, port_id);
		}
		ret = rte_eth_dev_start(port_id);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"rte_eth_dev_start:err=%d, port=%u\n",
				ret, port_id);
	}
}

static void
update_ct_conf(struct rte_flow_action_conntrack *ct_conf, uint32_t seq)
{
	uint32_t ack = UINT32_MAX - seq;

	*ct_conf = (struct rte_flow_action_conntrack) {
		.peer_port = 0,
		.is_original_dir = 1,
		.enable = 1,
		.selective_ack = 1,
		.state = RTE_FLOW_CONNTRACK_STATE_SYN_RECV,
		.retransmission_limit = 5,
		.original_dir = (struct rte_flow_tcp_dir_param) {
			.scale = 7,
			.data_unacked = 1,
			.sent_end = seq + 1,
			.max_win = 0xfaf0,
		},
		.last_window = 0xfaf0,
		.last_index = RTE_FLOW_CONNTRACK_FLAG_SYNACK,
		.last_seq = seq,
		.last_end = seq + 1,
	};
	ct_conf->original_dir.data_unacked = 0;
	ct_conf->original_dir.reply_end =
		ct_conf->original_dir.sent_end + 0xfaf0;

	/* data_len = 0 */
	ct_conf->reply_dir.scale = 7;
	ct_conf->reply_dir.last_ack_seen = 1;
	ct_conf->reply_dir.data_unacked = 1;
	ct_conf->reply_dir.sent_end = ack + 1;
	ct_conf->reply_dir.reply_end = ct_conf->reply_dir.sent_end +
		ct_conf->original_dir.max_win;
	ct_conf->reply_dir.max_win = 0x7120;
	ct_conf->reply_dir.max_ack = seq + 1;

	ct_conf->last_window = 0x7120;
	ct_conf->last_seq = ack;
	ct_conf->last_ack = seq + 1;
	ct_conf->last_end = ct_conf->reply_dir.sent_end;
}

static struct rte_flow_action_handle *
create_ct_action(uint16_t port_id,
		uint32_t queue_id,
		const struct rte_flow_op_attr *op_attr,
		const struct rte_flow_indir_action_conf *indir_action_conf,
		const struct rte_flow_action *action,
		void *user_data,
		struct rte_flow_error *error)
{
	uint32_t pending_rules = 1;
	struct rte_flow_action_handle *handle;

	if (queue_id == INVAL_QUEUE)
		return rte_flow_action_handle_create(port_id, indir_action_conf,
						     action, error);
	handle = rte_flow_async_action_handle_create(port_id, queue_id,
		op_attr, indir_action_conf, action, user_data, error);
	if (!handle)
		return NULL;
	poll_for_comp(port_id, queue_id, &pending_rules, 1, NULL, true);
	return handle;
}

static int
destroy_ct_action(uint16_t port_id,
		uint32_t queue_id,
		const struct rte_flow_op_attr *op_attr,
		struct rte_flow_action_handle *action_handle,
		void *user_data,
		struct rte_flow_error *error)
{
	uint32_t pending_rules = 1;
	int ret;

	if (queue_id == INVAL_QUEUE)
		return rte_flow_action_handle_destroy(port_id, action_handle, error);
	ret = rte_flow_async_action_handle_destroy(port_id, queue_id,
		op_attr, action_handle, user_data, error);
	if (ret)
		return ret;
	return poll_for_comp(port_id, queue_id, &pending_rules, 1, NULL, true);
}

static int
update_ct_action(uint16_t port_id,
		uint32_t queue_id,
		const struct rte_flow_op_attr *op_attr,
		struct rte_flow_action_handle *action_handle,
		const void *update,
		void *user_data,
		struct rte_flow_error *error)
{
	uint32_t pending_rules = 1;
	int ret;

	if (queue_id == INVAL_QUEUE)
		return rte_flow_action_handle_update(port_id, action_handle,
						     update, error);
	ret = rte_flow_async_action_handle_update(port_id, queue_id,
		op_attr, action_handle, update, user_data, error);
	if (ret)
		return ret;
	return poll_for_comp(port_id, queue_id, &pending_rules, 1, NULL, true);
}

static int
run_rte_flow_handler_cores(void *data __rte_unused)
{
	uint32_t lcore_counter = 0;
	uint32_t lcore_id = rte_lcore_id();
	uint32_t ct_queue = lcore_id;
	uint64_t start, end;
	uint32_t i, j;
	uint32_t pending_rules = 0, miss_count = 0;
	int ret;
	uint32_t dst;
	struct rte_flow_error error = {0};
	struct rte_flow **bflow;
	struct rte_flow_action_handle **bct;
	struct rte_flow_op_attr hqatr = {
		.postpone = 0,
	};
	struct rte_flow_op_attr ct_attr = {
		.postpone = 0,
	};
	struct rte_flow_item_ipv4 ipv4_value;
	struct rte_flow_item_tcp tcp_value;
	struct rte_flow_item items[4] = {
		[0] = (struct rte_flow_item){
			.type = RTE_FLOW_ITEM_TYPE_ETH,
		},
		[1] = (struct rte_flow_item){
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.spec = &ipv4_value,
		},
		[2] = (struct rte_flow_item){
			.type = RTE_FLOW_ITEM_TYPE_TCP,
			.spec = &tcp_value,
		},
		[3] = (struct rte_flow_item){
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};
	struct rte_flow_action_modify_field mdf_conf = {
		.operation = RTE_FLOW_MODIFY_SET,
		.dst = {
			.field = RTE_FLOW_FIELD_TAG,
		},
		.src = {
			.field = RTE_FLOW_FIELD_VALUE,
		},
	};
	struct rte_flow_action hws_actions[] = {
		[0] = (struct rte_flow_action){
			.type = RTE_FLOW_ACTION_TYPE_MODIFY_FIELD,
			.conf = &mdf_conf,
		},
		[1] = (struct rte_flow_action){
			.type = RTE_FLOW_ACTION_TYPE_INDIRECT,
		},
		[2] = (struct rte_flow_action){
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &(struct rte_flow_action_jump){
				.group = 2,
			},
		},
		[3] = (struct rte_flow_action){
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	struct rte_flow_action_conntrack ct_conf = { 0 };
	struct rte_flow_indir_action_conf ct_ctx_conf = { .ingress = 1, };
	struct rte_flow_action ct_action = {
		.type = RTE_FLOW_ACTION_TYPE_CONNTRACK,
		.conf = &ct_conf,
	};
	struct rte_flow_modify_conntrack modify_ct = {
		.new_ct = {
			.is_original_dir = 0,
		},
		.direction = 1,
	};

	RTE_LCORE_FOREACH(i) {
		/*  If core not needed return. */
		if (lcore_id == i) {
			printf(":: lcore %d mapped with index %d\n",
			       lcore_id, lcore_counter);
			if (lcore_counter >= mc_pool.cores_count)
				return 0;
			break;
		}
		lcore_counter++;
	}
	lcore_id = lcore_counter;
	if (lcore_id >= mc_pool.cores_count)
		return 0;
	memset(mdf_conf.src.value, 0xa5, sizeof(mdf_conf.src.value));
	update_ct_conf(&ct_conf, 0);
	memset(&tcp_value, 0, sizeof(tcp_value));
	memset(&ipv4_value, 0, sizeof(ipv4_value));
	tcp_value.hdr.src_port = 0x5555;
	ipv4_value.hdr.src_addr = 0x5555555;
	dst = mc_pool.rules_per_core * (lcore_id + 1) * 2;
	tcp_value.hdr.dst_port = dst + 0x123;

	/* Allocate HWS rules */
	bflow = calloc(mc_pool.rules_per_core * 2, sizeof(struct rte_flow *));
	if (!bflow) {
		printf("Failed to allocate memory for hws_rule\n");
		return -1;
	}
	/* Allocate CT action */
	bct = calloc(mc_pool.rules_per_core, sizeof(struct rte_flow_action_handle *));
	if (!bflow) {
		printf("Failed to allocate memory for hws_rule\n");
		return -1;
	}
	printf("Core index:%d, dst:0x%x, rule_per_core:%d\n",
	       lcore_id, dst, mc_pool.rules_per_core);
	/* ct_queue = INVAL_QUEUE; */
	for (j = 0; j < BIG_LOOP; j++) {
		start = rte_rdtsc();

		pending_rules = 0;
		miss_count = 0;
		/* Create HWS rules */
		for (i = 0; i < mc_pool.rules_per_core * 2; i++) {
			if (!(i & 1)) {
				update_ct_conf(&ct_conf, dst + i);
				bct[i >> 1] = create_ct_action(0, ct_queue, &ct_attr,
						&ct_ctx_conf, &ct_action, NULL, NULL);
				if (!bct[i >> 1]) {
					printf("Core:%d, fail to allocate ct:%d\n",
					       lcore_id, i >> 1);
					return -1;
				}
			}
		}
		for (i = 0; i < mc_pool.rules_per_core * 2; i++) {
			if (i & 1) {
				ret = update_ct_action(0, ct_queue, &ct_attr, bct[i >> 1],
					 &modify_ct, NULL, NULL);
				if (ret) {
					printf("Core:%d, fail to modify ct:%d\n",
					       lcore_id, i >> 1);
					return -1;
				}
			}
			/* Ring doorbell */
			hqatr.postpone = !((i + 1) % BURST_TH == 0);
			hws_actions[1].conf = bct[i >> 1];
			ipv4_value.hdr.dst_addr = dst + i;
			bflow[i] = rte_flow_async_create(0, lcore_id, &hqatr, htbl,
							  items, 0, hws_actions,
							  0, NULL, &error);
			if (!bflow[i]) {
				printf("Core:%d, Fail create rule: %d, misscount:%u\n",
				       lcore_id, i, miss_count);
				return -1;
			}

			pending_rules++;
			poll_for_comp(0, lcore_id, &pending_rules, BURST_TH,
				      &miss_count, false);
		}

		end = rte_rdtsc();
		printf("Core:%d K-Rules/Sec: %lf Insertion, miss_count:%d\n",
			lcore_id,
			(double) ((double) mc_pool.rules_per_core * 2 / 1000) /
			((double) (end - start) / rte_get_tsc_hz()),
			miss_count);

		/* Drain the queue */
		poll_for_comp(0, lcore_id, &pending_rules, BURST_TH,
			      &miss_count, true);
		miss_count = 0;
		start = rte_rdtsc();

		/* Delete HWS rules */
		for (i = 0; i < mc_pool.rules_per_core * 2; i++) {
			hqatr.postpone = !((i + 1) % BURST_TH == 0);
			ret = rte_flow_async_destroy(0, lcore_id, &hqatr,
						      bflow[i], NULL, &error);
			if (ret) {
				printf("Core:%d, Fail destroy rule:%d, misscount:%u\n",
				       lcore_id, i, miss_count);
				return -1;
			}

			pending_rules++;
			poll_for_comp(0, lcore_id, &pending_rules, BURST_TH,
				      &miss_count, false);
		}

		end = rte_rdtsc();
		printf("Core:%d K-Rules/Sec: %lf Deletion, miss_count:%d\n",
			lcore_id,
			(double) ((double) mc_pool.rules_per_core * 2 / 1000) /
			((double) (end - start) / rte_get_tsc_hz()),
			miss_count);
		/* Drain the queue */
		poll_for_comp(0, lcore_id, &pending_rules, BURST_TH,
			      &miss_count, true);
		for (i = 0; i < mc_pool.rules_per_core; i++) {
			ret = destroy_ct_action(0, ct_queue, &ct_attr, bct[i], NULL, NULL);
			if (ret) {
				printf("Fail to destroy ct:%d\n", i);
				return -1;
			}
		}
	}
	free(bflow);
	return 0;
}

int run_test_rte_insert_mult(struct ibv_context *ibv_ctx __rte_unused)
{
	uint32_t pending_rules = 0, miss_count = 0;
	int ret;
	const struct rte_flow_port_attr port_attr = {
		.nb_counters = 0,
		.nb_cts = 1 << 23,
	};
	struct rte_flow_queue_attr queue_attr = {
		.size = QUEUE_SIZE,
	};
	const struct rte_flow_queue_attr *pqa[16] = {
		&queue_attr, &queue_attr,
		&queue_attr, &queue_attr,
		&queue_attr, &queue_attr,
		&queue_attr, &queue_attr,
		&queue_attr, &queue_attr,
		&queue_attr, &queue_attr,
		&queue_attr, &queue_attr,
		&queue_attr, &queue_attr,
	};
	struct rte_flow_error error = {0};
	struct rte_flow_pattern_template *it, *hit;
	struct rte_flow_actions_template *at, *hat;
#define MAX_AT 16
#define MAX_IT 16
	struct rte_flow_pattern_template *it_array[MAX_IT], *hit_array[MAX_IT];
	struct rte_flow_actions_template *at_array[MAX_AT], *hat_array[MAX_AT];
	struct rte_flow_pattern_template_attr itr = { .ingress = 1, };
	struct rte_flow_actions_template_attr atr = { .ingress = 1, };
	const struct rte_flow_action root_actions[] = {
		[0] = {
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &(struct rte_flow_action_jump){
				.group = 1,
			},
		},
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	struct rte_flow_item items_conn[] = {
		[0] = (struct rte_flow_item){
			.type = RTE_FLOW_ITEM_TYPE_ETH,
		},
		[1] = (struct rte_flow_item){
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};

	struct rte_flow_item items[] = {
		[0] = (struct rte_flow_item){
			.type = RTE_FLOW_ITEM_TYPE_ETH,
		},
		[1] = (struct rte_flow_item){
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.mask = &rte_flow_item_ipv4_mask,
		},
		[2] = (struct rte_flow_item){
			.type = RTE_FLOW_ITEM_TYPE_TCP,
			.mask = &rte_flow_item_tcp_mask,
		},
		[3] = (struct rte_flow_item){
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};
	struct rte_flow_action_modify_field mdf_conf = {
		.operation = RTE_FLOW_MODIFY_SET,
		.dst = {
			.field = RTE_FLOW_FIELD_TAG,
		},
		.src = {
			.field = RTE_FLOW_FIELD_VALUE,
		},
	};
	struct rte_flow_action hws_actions[] = {
		[0] = (struct rte_flow_action){
			.type = RTE_FLOW_ACTION_TYPE_MODIFY_FIELD,
			.conf = &mdf_conf,
		},
		[1] = (struct rte_flow_action){
			.type = RTE_FLOW_ACTION_TYPE_INDIRECT,
		},
		[2] = (struct rte_flow_action){
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &(struct rte_flow_action_jump){
				.group = 2,
			},
		},
		[3] = (struct rte_flow_action){
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	struct rte_flow_action_modify_field mdf_conf_mask = mdf_conf;
	struct rte_flow_action hws_action_masks[] = {
		[0] = (struct rte_flow_action){
			.type = RTE_FLOW_ACTION_TYPE_MODIFY_FIELD,
			.conf = &mdf_conf_mask,
		},
		[1] = (struct rte_flow_action){
			.type = RTE_FLOW_ACTION_TYPE_CONNTRACK,
		},
		[2] = (struct rte_flow_action){
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &(struct rte_flow_action_jump){
				.group = 2,
			},
		},
		[3] = (struct rte_flow_action){
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	struct rte_flow_template_table_attr tatr = {
		.flow_attr = {
			.group = 0,
			.ingress = 1,
		},
		.nb_flows = 64,
	};
	struct rte_flow *flow;
	struct rte_flow_op_attr qatr = {
		.postpone = 0,
	};

	memset(mdf_conf.src.value, 0xa5, sizeof(mdf_conf.src.value));
	mdf_conf_mask.dst.level = UINT32_MAX;
	mdf_conf_mask.dst.offset = UINT32_MAX;
	mdf_conf_mask.src.level = UINT32_MAX;
	mdf_conf_mask.src.offset = UINT32_MAX;
	mdf_conf_mask.width = UINT32_MAX;
	mc_pool.cores_count = rte_lcore_count();
	mc_pool.rules_per_core = mc_pool.rules_count / mc_pool.cores_count;
	init_port();
	if (rte_eth_dev_stop(0))
		return -1;
	ret = rte_flow_configure(0, &port_attr, mc_pool.cores_count, pqa, &error);
	if (ret)
		return -1;
	if (rte_eth_dev_start(0))
		return -1;
	it = rte_flow_pattern_template_create(0, &itr, items_conn, &error);
	if (!it) {
		printf("Create item template failed.\n");
		return 0;
	}
	hit = rte_flow_pattern_template_create(0, &itr, items, &error);
	if (!hit) {
		printf("Create hws item template failed.\n");
		return 0;
	}
	at = rte_flow_actions_template_create(0, &atr, root_actions,
					     root_actions, &error);
	if (!at) {
		printf("Create action template failed.\n");
		return 0;
	}
	hat = rte_flow_actions_template_create(0, &atr, hws_actions,
					       hws_action_masks, &error);
	if (!hat) {
		printf("Create hws action template failed.\n");
		return 0;
	}
	it_array[0] = it;
	at_array[0] = at;
	tbl = rte_flow_template_table_create(0, &tatr, it_array, 1,
				    at_array, 1, &error);
	if (!tbl) {
		printf("Create root table failed.\n");
		return 0;
	}
	tatr.flow_attr.group = 1;
	tatr.nb_flows = mc_pool.rules_count * 2;
	hit_array[0] = hit;
	hat_array[0] = hat;
	htbl = rte_flow_template_table_create(0, &tatr, hit_array, 1,
				     hat_array, 1, &error);
	if (!htbl) {
		printf("Create hws table failed.\n");
		return 0;
	}
	flow = rte_flow_async_create(0, 0, &qatr, tbl, items_conn, 0,
				      root_actions, 0, NULL, &error);
	if (!flow) {
		printf("Create root jump flow failed.\n");
		return 0;
	}
	pending_rules = 1;
	poll_for_comp(0, 0, &pending_rules, 1, &miss_count, true);
	printf("RTE flow testing:\n");

	rte_eal_mp_remote_launch(run_rte_flow_handler_cores, NULL, CALL_MAIN);
	qatr.postpone = 0;
	rte_flow_async_destroy(0, 0, &qatr, flow, NULL, NULL);
	pending_rules = 1;
	poll_for_comp(0, 0, &pending_rules, 1, &miss_count, true);
	rte_flow_template_table_destroy(0, tbl, NULL);
	rte_flow_template_table_destroy(0, htbl, NULL);
	rte_flow_actions_template_destroy(0, at, NULL);
	rte_flow_actions_template_destroy(0, hat, NULL);
	rte_flow_pattern_template_destroy(0, it, NULL);
	rte_flow_pattern_template_destroy(0, hit, NULL);
	if (miss_count) {
		printf("Test has miss_count:%d\n", miss_count);
		return -1;
	}
	return 0;
}
