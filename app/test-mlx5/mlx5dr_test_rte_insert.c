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
#define NUM_OF_RULES (QUEUE_SIZE * 3906) /* Almost 1M */
#define BURST_TH (QUEUE_SIZE / 8)

static struct rte_mempool *mbuf_mp;

static int poll_for_comp(uint32_t port,
			 uint16_t queue_id,
			 uint32_t *pending_rules,
			 uint32_t expected_comp,
			 uint32_t *miss_count,
			 bool drain)
{
	bool queue_full = *pending_rules == QUEUE_SIZE;
	bool got_comp = *pending_rules >= expected_comp;
	struct rte_flow_q_op_res comp[BURST_TH];
	int ret;
	int j;

	/* Check if there are any completions at all */
	if (!got_comp)
		return 0;

	while (queue_full || ((got_comp || drain) && *pending_rules)) {
		ret = rte_flow_q_dequeue(port, queue_id, comp,
					 expected_comp, NULL);
		if (ret < 0) {
			printf("Failed during poll queue\n");
			return -1;
		}

		if (ret) {
			(*pending_rules) -= ret;
			for (j = 0; j < ret; j++) {
				if (comp[j].status == RTE_FLOW_Q_OP_ERROR)
					(*miss_count)++;
			}
			queue_full = false;
		}

		got_comp = !!ret;
	}

	return 0;
}

static void set_match_simple(struct rte_ipv4_hdr *ip_m,
			     struct rte_ipv4_hdr *ip_v,
			     struct rte_flow_item *items)
{
	memset(ip_m, 0, sizeof(*ip_m));
	memset(ip_v, 0, sizeof(*ip_v));

	ip_m->dst_addr = 0xffffffff;
	ip_m->version = 0xf;
	ip_v->version = 0x4;

	items[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
	items[0].mask = ip_m;
	items[0].spec = ip_v;

	items[1].type = RTE_FLOW_ITEM_TYPE_END;
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
add_ether_header(uint8_t **header)
{
	struct rte_ether_hdr eth_hdr;

	memset(&eth_hdr, 0, sizeof(struct rte_ether_hdr));
	eth_hdr.ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
	memcpy(*header, &eth_hdr, sizeof(eth_hdr));
	*header += sizeof(eth_hdr);
}

static void
add_ipv4_header(uint8_t **header)
{
	struct rte_ipv4_hdr ipv4_hdr;
	uint32_t ip_dst = 0x12345;

	memset(&ipv4_hdr, 0, sizeof(struct rte_ipv4_hdr));
	ipv4_hdr.src_addr = RTE_IPV4(127, 0, 0, 1);
	ipv4_hdr.dst_addr = RTE_BE32(ip_dst);
	ipv4_hdr.version_ihl = RTE_IPV4_VHL_DEF;
	ipv4_hdr.next_proto_id = RTE_IP_TYPE_UDP;
	memcpy(*header, &ipv4_hdr, sizeof(ipv4_hdr));
	*header += sizeof(ipv4_hdr);
}

static void
add_udp_header(uint8_t **header)
{
	struct rte_udp_hdr udp_hdr;

	memset(&udp_hdr, 0, sizeof(struct rte_flow_item_udp));
	udp_hdr.dst_port = RTE_BE16(RTE_GTPU_UDP_PORT);
	 memcpy(*header, &udp_hdr, sizeof(udp_hdr));
	 *header += sizeof(udp_hdr);
}

static void
add_gtp_header(uint8_t **header)
{
	struct rte_gtp_hdr gtp_hdr;
	uint32_t teid_value = 0x12;
	memset(&gtp_hdr, 0, sizeof(struct rte_flow_item_gtp));

	gtp_hdr.teid = RTE_BE32(teid_value);
	gtp_hdr.msg_type = 255;

	memcpy(*header, &gtp_hdr, sizeof(gtp_hdr));
	*header += sizeof(gtp_hdr);
}

int run_test_rte_insert(struct ibv_context *ibv_ctx __rte_unused)
{
	uint32_t pending_rules = 0, miss_count = 0;
	uint64_t start, end;
	int ret, i, j;

	const struct rte_flow_port_attr port_attr = {
		.nb_queues = 2,
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
	struct rte_flow_item items_conn[MAX_ITEMS] = {{0}};
	struct rte_ipv4_hdr ipv_mask_conn;
	struct rte_ipv4_hdr ipv_value_conn;
	struct rte_flow_item items[MAX_ITEMS] = {{0}};
	struct rte_flow_item_eth eth_mask;
	struct rte_flow_item_eth eth_value;
	struct rte_ipv4_hdr ipv_mask;
	struct rte_ipv4_hdr ipv_value;
	struct rte_flow_item_udp udp_mask;
	struct rte_flow_item_udp udp_value;
	struct rte_flow_item_template *it, *hit;
	struct rte_flow_action_template *at, *hat;
#define MAX_AT 16
#define MAX_IT 16
	struct rte_flow_item_template *it_array[MAX_IT], *hit_array[MAX_IT];
	struct rte_flow_action_template *at_array[MAX_AT], *hat_array[MAX_AT];
	struct rte_flow_item_template_attr itr = {0};
	struct rte_flow_action_template_attr atr = {0};
	struct action_rss_data {
			struct rte_flow_action_rss conf;
			uint8_t key[40];
			uint16_t queue[128];
	} rss_data = {
		.conf = (struct rte_flow_action_rss){
			.func = RTE_ETH_HASH_FUNCTION_DEFAULT,
			.level = 0,
			.types = ETH_RSS_IP,
			.key_len = sizeof(rss_data.key),
			.queue_num = QNUM,
			.key = rss_data.key,
			.queue = rss_data.queue,
		},
		.key = { 1 },
		.queue = { 0 },
	};
	struct rte_flow_action_mark mark = {
		.id = 0xa5a5a5a5,
	};
	struct rte_flow_action_queue queue_action = {
		.index = 2,
	};
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
	struct action_raw_encap_data {
		struct rte_flow_action_raw_encap conf;
		uint8_t data[1024];
		uint8_t preserve[128];
	} raw_encap;

	const struct rte_flow_action hws_actions[] = {
		[0] = {
			.type = RTE_FLOW_ACTION_TYPE_MARK,
			.conf = &mark,
		},
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &queue_action,
		},
		[2] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	struct rte_flow_table_attr tatr = {
		.flow_attr = {
			.group = 0,
			.ingress = 1,
		},
		.nb_flows = 1 << 21,
	};
	struct rte_flow_table *tbl, *htbl;
	struct rte_flow *flow;
	struct rte_flow **bflow;
	struct rte_flow_q_ops_attr qatr = {
		.user_data = (void *)0x5a5a,
		.drain = 0,
	};
	struct rte_flow_q_ops_attr hqatr = {
		.user_data = (void *)0x5a5a,
		.drain = 0,
	};
	uint8_t *header = raw_encap.data;

	add_ether_header(&header);
	add_ipv4_header(&header);
	add_udp_header(&header);
	add_gtp_header(&header);
	raw_encap.conf.data = raw_encap.data;
	raw_encap.conf.size = header - raw_encap.data;

	for (i = 0; i < QNUM; i++)
		rss_data.queue[i] = i;
	init_port();
	/* Allocate HWS rules */
	bflow = calloc(NUM_OF_RULES + 2, sizeof(struct rte_flow *));
	if (!bflow) {
		printf("Failed to allocate memory for hws_rule\n");
		return -1;
	}
	ret = rte_flow_configure(0, &port_attr, pqa, &error);
	if (ret)
		return -1;
	set_match_mavneir(&eth_mask, &eth_value,
			  &ipv_mask, &ipv_value,
			  &udp_mask, &udp_value,
			  NULL, NULL,
			  NULL, NULL,
			  NULL, NULL,
			  items);
	set_match_simple(&ipv_mask_conn, &ipv_value_conn, items_conn);
	it = rte_flow_item_template_create(0, &itr, items_conn, &error);
	if (!it) {
		printf("Create item template failed.\n");
		return 0;
	}
	hit = rte_flow_item_template_create(0, &itr, items, &error);
	if (!hit) {
		printf("Create hws item template failed.\n");
		return 0;
	}
	at = rte_flow_action_template_create(0, &atr, root_actions,
					     root_actions, &error);
	if (!at) {
		printf("Create action template failed.\n");
		return 0;
	}
	hat = rte_flow_action_template_create(0, &atr,
					      hws_actions, hws_actions, &error);
	if (!hat) {
		printf("Create hws action template failed.\n");
		return 0;
	}
	it_array[0] = it;
	at_array[0] = at;
	tbl = rte_flow_table_create(0, &tatr, it_array, 1,
				    at_array, 1, &error);
	if (!tbl) {
		printf("Create root table failed.\n");
		return 0;
	}
	tatr.flow_attr.group = 1;
	hit_array[0] = hit;
	hat_array[0] = hat;
	htbl = rte_flow_table_create(0, &tatr, hit_array, 1,
				     hat_array, 1, &error);
	if (!htbl) {
		printf("Create hws table failed.\n");
		return 0;
	}
	flow = rte_flow_q_flow_create(0, 0, &qatr, tbl, items_conn, 0,
				      root_actions, 0, &error);
	if (!flow) {
		printf("Create root jump flow failed.\n");
		return 0;
	}
	pending_rules = 1;
	poll_for_comp(0, 0, &pending_rules, 1, &miss_count, true);
	printf("RTE flow testing:\n");
	for (j = 0; j < BIG_LOOP; j++) {
		start = rte_rdtsc();

		pending_rules = 0;
		miss_count = 0;
		/* Create HWS rules */
		for (i = 0; i < NUM_OF_RULES; i++) {
			/* Ring doorbell */
			hqatr.drain = ((i + 1) % BURST_TH == 0);

			ipv_value.dst_addr = i;
			mark.id = i;
			bflow[i] = rte_flow_q_flow_create(0, 0, &hqatr, htbl,
							  items, 0, hws_actions,
							  0, &error);
			if (!bflow[i]) {
				printf("Fail create rule: %d, misscount:%u\n",
				       i, miss_count);
				return -1;
			}

			pending_rules++;
			poll_for_comp(0, 0, &pending_rules, BURST_TH,
				      &miss_count, false);
		}

		end = rte_rdtsc();
		printf("K-Rules/Sec: %lf Insertion, miss_count:%d\n",
			(double) ((double) NUM_OF_RULES / 1000) /
			((double) (end - start) / rte_get_tsc_hz()),
			miss_count);

		/* Drain the queue */
		poll_for_comp(0, 0, &pending_rules, BURST_TH,
			      &miss_count, true);
		miss_count = 0;
		start = rte_rdtsc();

		/* Delete HWS rules */
		for (i = 0; i < NUM_OF_RULES; i++) {
			hqatr.drain = ((i + 1) % BURST_TH == 0);
			ret = rte_flow_q_flow_destroy(0, 0, &hqatr,
						      bflow[i], &error);
			if (ret) {
				printf("Fail destroy rule:%d, misscount:%u\n",
				       i, miss_count);
				return -1;
			}

			pending_rules++;
			poll_for_comp(0, 0, &pending_rules, BURST_TH,
				      &miss_count, false);
		}

		end = rte_rdtsc();
		printf("K-Rules/Sec: %lf Deletion, miss_count:%d\n",
			(double) ((double) NUM_OF_RULES / 1000) /
			((double) (end - start) / rte_get_tsc_hz()),
			miss_count);
		/* Drain the queue */
		poll_for_comp(0, 0, &pending_rules, BURST_TH,
			      &miss_count, true);
	}
	free(bflow);
	hqatr.drain = 1;
	rte_flow_q_flow_destroy(0, 0, &hqatr, flow, NULL);
	pending_rules = 1;
	poll_for_comp(0, 0, &pending_rules, 1, &miss_count, true);
	rte_flow_table_destroy(0, tbl, NULL);
	rte_flow_table_destroy(0, htbl, NULL);
	rte_flow_action_template_destroy(0, at, NULL);
	rte_flow_action_template_destroy(0, hat, NULL);
	rte_flow_item_template_destroy(0, it, NULL);
	rte_flow_item_template_destroy(0, hit, NULL);
	if (miss_count) {
		printf("Test has miss_count:%d\n", miss_count);
		return -1;
	}
	return 0;
}
