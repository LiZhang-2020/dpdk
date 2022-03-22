/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Nvidia Inc. All rights reserved.
 *
 * This file contain the application main file
 * This application provides the user the ability to test the
 * insertion rate for specific rte_flow rule under stress state ~4M rule/
 *
 * Then it will also provide packet per second measurement after installing
 * all rules, the user may send traffic to test the PPS that match the rules
 * after all rules are installed, to check performance or functionality after
 * the stress.
 *
 * The flows insertion will go for all ports first, then it will print the
 * results, after that the application will go into forwarding packets mode
 * it will start receiving traffic if any and then forwarding it back and
 * gives packet per second measurement.
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>

#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_mtr.h>

#include "config.h"
#include "flow_gen.h"
#include "actions_gen.h"

#define MAX_BATCHES_COUNT          100
#define DEFAULT_RULES_COUNT     400000
#define DEFAULT_RULES_BATCH     100
#define DEFAULT_GROUP                0
#define METER_PROFILE_ALG_SRTCM_RFC2697    "srtcm_rfc2697"
#define METER_PROFILE_ALG_SRTCMP           "srtcmp"
#define DEFAULT_METER_PROFILE_ALG          METER_PROFILE_ALG_SRTCM_RFC2697
#define NB_CT_HAIRPIN           4

static uint8_t flow_group;
static uint64_t delay_ins;
static uint64_t ports_per_ip;

static uint64_t encap_data;
static uint64_t decap_data;

static uint64_t flow_items[MAX_ITEMS_NUM];
static uint64_t flow_actions[MAX_ACTIONS_NUM];
static uint64_t flow_attrs[MAX_ATTRS_NUM];
static uint8_t items_idx, actions_idx, attrs_idx;

static uint64_t ports_mask;
static volatile bool force_quit;
static bool dump_iterations;
static bool delete_flag;
static bool final_iter;
static bool dump_socket_mem_flag;
static bool enable_fwd;
static bool unique_data;
static bool cross_port;
static bool ct_query;
static bool sanity_checks_first;

static struct rte_mempool *mbuf_mp;
static uint32_t nb_lcores;
static uint32_t rules_count;
static uint32_t rules_batch;
static uint32_t hairpin_queues_num; /* total hairpin q number - default: 0 */
static uint32_t nb_lcores;
static uint32_t mtr_profile_alg;
static uint32_t ct_route_id_count;
static struct rte_flow **ct_static_flows;
static struct rte_flow **ct_static_rflows;
static bool has_ct;
static uint64_t nb_iterations = 1;
static bool set_ihl;

bool ct_created;

/* Checkpoints PPS case vars */
static struct rte_flow *chkpnt_static_flows[NB_CHKPNT_PPS_STATIC_FLOWS];
static uint32_t chkpnt_idx;
static bool chkpnt_case = true;

#define MAX_PKT_BURST    32
#define LCORE_MODE_PKT    1
#define LCORE_MODE_STATS  2
#define MAX_STREAMS      64
#define METER_CREATE	  1
#define METER_DELETE	  2

struct stream {
	int tx_port;
	int tx_queue;
	int rx_port;
	int rx_queue;
};

struct lcore_info {
	int mode;
	int streams_nb;
	struct stream streams[MAX_STREAMS];
	/* stats */
	uint64_t tx_pkts;
	uint64_t tx_drops;
	uint64_t rx_pkts;
	struct rte_mbuf *pkts[MAX_PKT_BURST];
} __rte_cache_aligned;

static struct lcore_info lcore_infos[RTE_MAX_LCORE];

struct used_cpu_time {
	double insertion[MAX_PORTS][RTE_MAX_LCORE];
	double deletion[MAX_PORTS][RTE_MAX_LCORE];
};

struct multi_cores_pool {
	uint32_t cores_count;
	uint32_t rules_count;
	struct used_cpu_time meters_record;
	struct used_cpu_time flows_record;
	int64_t last_alloc[RTE_MAX_LCORE];
	int64_t current_alloc[RTE_MAX_LCORE];
} __rte_cache_aligned;

static struct multi_cores_pool mc_pool = {
	.cores_count = 1,
};

static void
usage(char *progname)
{
	printf("\nusage: %s\n", progname);
	printf("\nControl configurations:\n");
	printf("  --rules-count=N: to set the number of needed"
		" rules to insert, default is %d\n", DEFAULT_RULES_COUNT);
	printf("  --rules-batch=N: set number of batched rules,"
		" default is %d\n", DEFAULT_RULES_BATCH);
	printf("  --dump-iterations: To print rates for each"
		" iteration\n");
	printf("  --deletion-rate: Enable deletion rate"
		" calculations\n");
	printf("  --dump-socket-mem: To dump all socket memory\n");
	printf("  --enable-fwd: To enable packets forwarding"
		" after insertion\n");
	printf("  --portmask=N: hexadecimal bitmask of ports used\n");
	printf("  --meter-profile-alg=str: to set the traffic metering"
		" algorithm, default is %s\n", DEFAULT_METER_PROFILE_ALG);
	printf("  --unique-data: flag to set using unique data for all"
		" actions that support data, such as header modify and encap actions\n");
	printf("  --ct-route-id-count: number of CT connections.\n");
	printf("  --cross-port: To insert rules on the port and it's peer in the same time.\n");
	printf("                Note that if set then the number of inserted rules for every pair of ports is 2*rules-count.\n");
	printf("  --iterations=N: The number of insert-delete iterations.");
	printf("  --ct-query: Query CT HW contexts before destroying the rules.");
	printf("  --sanity-checks-first: Add sanity checks in the origin group 0.\n");

	printf("To set flow attributes:\n");
	printf("  --ingress: set ingress attribute in flows\n");
	printf("  --egress: set egress attribute in flows\n");
	printf("  --transfer: set transfer attribute in flows\n");
	printf("  --group=N: set group for all flows,"
		" default is %d\n", DEFAULT_GROUP);
	printf("  --cores=N: to set the number of needed "
		"cores to insert rte_flow rules, default is 1\n");

	printf("To set flow items:\n");
	printf("  --ether: add ether layer in flow items\n");
	printf("  --vlan: add vlan layer in flow items\n");
	printf("  --ipv4: add ipv4 layer in flow items\n");
	printf("  --ipv6: add ipv6 layer in flow items\n");
	printf("  --tcp: add tcp layer in flow items\n");
	printf("  --udp: add udp layer in flow items\n");
	printf("  --vxlan: add vxlan layer in flow items\n");
	printf("  --vxlan-gpe: add vxlan-gpe layer in flow items\n");
	printf("  --gre: add gre layer in flow items\n");
	printf("  --geneve: add geneve layer in flow items\n");
	printf("  --gtp: add gtp layer in flow items\n");
	printf("  --meta: add meta layer in flow items\n");
	printf("  --tag: add tag layer in flow items\n");
	printf("  --icmpv4: add icmpv4 layer in flow items\n");
	printf("  --icmpv6: add icmpv6 layer in flow items\n");
	printf("  --sanity-checks: add sanity checks item in flow items\n");

	printf("To set flow actions:\n");
	printf("  --port-id: add port-id action in flow actions\n");
	printf("  --rss: add rss action in flow actions\n");
	printf("  --queue: add queue action in flow actions\n");
	printf("  --jump: add jump action in flow actions\n");
	printf("  --mark: add mark action in flow actions\n");
	printf("  --count: add count action in flow actions\n");
	printf("  --set-meta: add set meta action in flow actions\n");
	printf("  --set-tag: add set tag action in flow actions\n");
	printf("  --drop: add drop action in flow actions\n");
	printf("  --hairpin-queue=N: add hairpin-queue action in flow actions\n");
	printf("  --hairpin-rss=N: add hairpin-rss action in flow actions\n");
	printf("  --set-src-mac: add set src mac action to flow actions\n"
		"Src mac to be set is random each flow\n");
	printf("  --set-dst-mac: add set dst mac action to flow actions\n"
		 "Dst mac to be set is random each flow\n");
	printf("  --set-src-ipv4: add set src ipv4 action to flow actions\n"
		"Src ipv4 to be set is random each flow\n");
	printf("  --set-dst-ipv4 add set dst ipv4 action to flow actions\n"
		"Dst ipv4 to be set is random each flow\n");
	printf("  --set-src-ipv6: add set src ipv6 action to flow actions\n"
		"Src ipv6 to be set is random each flow\n");
	printf("  --set-dst-ipv6: add set dst ipv6 action to flow actions\n"
		"Dst ipv6 to be set is random each flow\n");
	printf("  --set-src-tp: add set src tp action to flow actions\n"
		"Src tp to be set is random each flow\n");
	printf("  --set-dst-tp: add set dst tp action to flow actions\n"
		"Dst tp to be set is random each flow\n");
	printf("  --inc-tcp-ack: add inc tcp ack action to flow actions\n"
		"tcp ack will be increments by 1\n");
	printf("  --dec-tcp-ack: add dec tcp ack action to flow actions\n"
		"tcp ack will be decrements by 1\n");
	printf("  --inc-tcp-seq: add inc tcp seq action to flow actions\n"
		"tcp seq will be increments by 1\n");
	printf("  --dec-tcp-seq: add dec tcp seq action to flow actions\n"
		"tcp seq will be decrements by 1\n");
	printf("  --set-ttl: add set ttl action to flow actions\n"
		"L3 ttl to be set is random each flow\n");
	printf("  --dec-ttl: add dec ttl action to flow actions\n"
		"L3 ttl will be decrements by 1\n");
	printf("  --set-ipv4-dscp: add set ipv4 dscp action to flow actions\n"
		"ipv4 dscp value to be set is random each flow\n");
	printf("  --set-ipv6-dscp: add set ipv6 dscp action to flow actions\n"
		"ipv6 dscp value to be set is random each flow\n");
	printf("  --flag: add flag action to flow actions\n");
	printf("  --meter: add meter action to flow actions\n");
	printf("  --raw-encap=<data>: add raw encap action to flow actions\n"
		"Data is the data needed to be encaped\n"
		"Example: raw-encap=ether,ipv4,udp,vxlan\n");
	printf("  --raw-decap=<data>: add raw decap action to flow actions\n"
		"Data is the data needed to be decaped\n"
		"Example: raw-decap=ether,ipv4,udp,vxlan\n");
	printf("  --vxlan-encap: add vxlan-encap action to flow actions\n"
		"Encapped data is fixed with pattern: ether,ipv4,udp,vxlan\n"
		"With fixed values\n");
	printf("  --vxlan-decap: add vxlan_decap action to flow actions\n");
	printf("  --vlan-pop: add vlan_pop action to flow actions\n");
	printf("  --ct: add CT action to flow actions\n");
	printf(
		"  --aging-shared: add an aging action as a shared action between a pair of ports.\n");
	printf(
		"                  The user must specify --cross-port when using this option.\n");
}

static inline int
get_action_mask_idx(const uint64_t mask)
{
	int i;

	for (i = 0; i < MAX_ACTIONS_NUM; i++) {
		if (flow_actions[i] == 0)
			break;
		if (flow_actions[i] & mask)
			return i;
	}
	return -1;
}

static void
args_parse(int argc, char **argv)
{
	uint64_t pm;
	char **argvopt;
	char *token;
	char *end;
	int n, opt;
	int opt_idx;
	size_t i;

	static const struct option_dict {
		const char *str;
		const uint64_t mask;
		uint64_t *map;
		uint8_t *map_idx;

	} flow_options[] = {
		{
			.str = "ether",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ETH),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "ipv4",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_IPV4),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "ipv6",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_IPV6),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "vlan",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_VLAN),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "tcp",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_TCP),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "udp",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_UDP),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "vxlan",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_VXLAN),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "vxlan-gpe",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_VXLAN_GPE),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "gre",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_GRE),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "geneve",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_GENEVE),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "gtp",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_GTP),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "meta",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_META),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "tag",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_TAG),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "icmpv4",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ICMP),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "icmpv6",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ICMP6),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "sanity-checks",
			.mask = FLOW_ITEM_MASK(
				RTE_FLOW_ITEM_TYPE_INTEGRITY
			),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "ingress",
			.mask = INGRESS,
			.map = &flow_attrs[0],
			.map_idx = &attrs_idx
		},
		{
			.str = "egress",
			.mask = EGRESS,
			.map = &flow_attrs[0],
			.map_idx = &attrs_idx
		},
		{
			.str = "transfer",
			.mask = TRANSFER,
			.map = &flow_attrs[0],
			.map_idx = &attrs_idx
		},
		{
			.str = "port-id",
			.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_PORT_ID),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "rss",
			.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_RSS),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "queue",
			.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_QUEUE),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "jump",
			.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_JUMP),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "mark",
			.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_MARK),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "count",
			.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_COUNT),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-meta",
			.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_SET_META),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-tag",
			.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_SET_TAG),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "drop",
			.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_DROP),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-src-mac",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_SET_MAC_SRC
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-dst-mac",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_SET_MAC_DST
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-src-ipv4",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-dst-ipv4",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_SET_IPV4_DST
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-src-ipv6",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-dst-ipv6",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_SET_IPV6_DST
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-src-tp",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_SET_TP_SRC
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-dst-tp",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_SET_TP_DST
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "inc-tcp-ack",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_INC_TCP_ACK
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "dec-tcp-ack",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_DEC_TCP_ACK
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "inc-tcp-seq",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_INC_TCP_SEQ
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "dec-tcp-seq",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_DEC_TCP_SEQ
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-ttl",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_SET_TTL
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "dec-ttl",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_DEC_TTL
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-ipv4-dscp",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_SET_IPV4_DSCP
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-ipv6-dscp",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_SET_IPV6_DSCP
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "flag",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_FLAG
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "meter",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_METER
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "vxlan-encap",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "vxlan-decap",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_VXLAN_DECAP
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "vlan-pop",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_OF_POP_VLAN
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "ct",
			.mask = CT_ACTION,
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "aging-shared",
			.mask = AGING_SHARED_ACTION,
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
	};

	static const struct option lgopts[] = {
		/* Control */
		{ "help",                       0, 0, 0 },
		{ "rules-count",                1, 0, 0 },
		{ "rules-batch",                1, 0, 0 },
		{ "dump-iterations",            0, 0, 0 },
		{ "deletion-rate",              0, 0, 0 },
		{ "dump-socket-mem",            0, 0, 0 },
		{ "enable-fwd",                 0, 0, 0 },
		{ "unique-data",                0, 0, 0 },
		{ "portmask",                   1, 0, 0 },
		{ "cores",                      1, 0, 0 },
		{ "meter-profile-alg",          1, 0, 0 },
		{ "ct-route-id-count",          1, 0, 0 },
		{ "cross-port",                 0, 0, 0 },
		{ "iterations",                 1, 0, 0 },
		{ "ct-query",                   0, 0, 0 },
		{ "sanity-checks-first",        0, 0, 0 },
		/* Attributes */
		{ "ingress",                    0, 0, 0 },
		{ "egress",                     0, 0, 0 },
		{ "transfer",                   0, 0, 0 },
		{ "group",                      1, 0, 0 },
		/* Items */
		{ "ether",                      0, 0, 0 },
		{ "vlan",                       0, 0, 0 },
		{ "ipv4",                       0, 0, 0 },
		{ "ipv6",                       0, 0, 0 },
		{ "tcp",                        0, 0, 0 },
		{ "udp",                        0, 0, 0 },
		{ "vxlan",                      0, 0, 0 },
		{ "vxlan-gpe",                  0, 0, 0 },
		{ "gre",                        0, 0, 0 },
		{ "geneve",                     0, 0, 0 },
		{ "gtp",                        0, 0, 0 },
		{ "meta",                       0, 0, 0 },
		{ "tag",                        0, 0, 0 },
		{ "icmpv4",                     0, 0, 0 },
		{ "icmpv6",                     0, 0, 0 },
		{ "sanity-checks",              0, 0, 0 },
		/* Actions */
		{ "port-id",                    0, 0, 0 },
		{ "rss",                        0, 0, 0 },
		{ "queue",                      0, 0, 0 },
		{ "jump",                       0, 0, 0 },
		{ "mark",                       0, 0, 0 },
		{ "count",                      0, 0, 0 },
		{ "set-meta",                   0, 0, 0 },
		{ "set-tag",                    0, 0, 0 },
		{ "drop",                       0, 0, 0 },
		{ "hairpin-queue",              1, 0, 0 },
		{ "hairpin-rss",                1, 0, 0 },
		{ "set-src-mac",                0, 0, 0 },
		{ "set-dst-mac",                0, 0, 0 },
		{ "set-src-ipv4",               0, 0, 0 },
		{ "set-dst-ipv4",               0, 0, 0 },
		{ "set-src-ipv6",               0, 0, 0 },
		{ "set-dst-ipv6",               0, 0, 0 },
		{ "set-src-tp",                 0, 0, 0 },
		{ "set-dst-tp",                 0, 0, 0 },
		{ "inc-tcp-ack",                0, 0, 0 },
		{ "dec-tcp-ack",                0, 0, 0 },
		{ "inc-tcp-seq",                0, 0, 0 },
		{ "dec-tcp-seq",                0, 0, 0 },
		{ "set-ttl",                    0, 0, 0 },
		{ "dec-ttl",                    0, 0, 0 },
		{ "set-ipv4-dscp",              0, 0, 0 },
		{ "set-ipv6-dscp",              0, 0, 0 },
		{ "flag",                       0, 0, 0 },
		{ "meter",		                0, 0, 0 },
		{ "raw-encap",                  1, 0, 0 },
		{ "raw-decap",                  1, 0, 0 },
		{ "vxlan-encap",                0, 0, 0 },
		{ "vxlan-decap",                0, 0, 0 },
		{ "vlan-pop",                   0, 0, 0 },
		{ "ct",                         0, 0, 0 },
		{ "aging-shared",               0, 0, 0 },
	};

	RTE_ETH_FOREACH_DEV(i)
		ports_mask |= 1 << i;

	hairpin_queues_num = 0;
	argvopt = argv;

	printf(":: Flow -> ");
	while ((opt = getopt_long(argc, argvopt, "",
				lgopts, &opt_idx)) != EOF) {
		switch (opt) {
		case 0:
			if (strcmp(lgopts[opt_idx].name, "help") == 0) {
				usage(argv[0]);
				exit(EXIT_SUCCESS);
			}

			if (strcmp(lgopts[opt_idx].name, "group") == 0) {
				n = atoi(optarg);
				if (n >= 0)
					flow_group = n;
				else
					rte_exit(EXIT_FAILURE,
						"flow group should be >= 0\n");
				printf("group %d / ", flow_group);
			}

			for (i = 0; i < RTE_DIM(flow_options); i++)
				if (strcmp(lgopts[opt_idx].name,
						flow_options[i].str) == 0) {
					flow_options[i].map[
					(*flow_options[i].map_idx)++] =
						flow_options[i].mask;
					printf("%s / ", flow_options[i].str);
				}

			if (strcmp(lgopts[opt_idx].name,
					"hairpin-rss") == 0) {
				n = atoi(optarg);
				if (n > 0)
					hairpin_queues_num = n;
				else
					rte_exit(EXIT_FAILURE,
						"Hairpin queues should be > 0\n");

				flow_actions[actions_idx++] =
					HAIRPIN_RSS_ACTION;
				printf("hairpin-rss / ");
			}
			if (strcmp(lgopts[opt_idx].name,
					"hairpin-queue") == 0) {
				n = atoi(optarg);
				if (n > 0)
					hairpin_queues_num = n;
				else
					rte_exit(EXIT_FAILURE,
						"Hairpin queues should be > 0\n");

				flow_actions[actions_idx++] =
					HAIRPIN_QUEUE_ACTION;
				printf("hairpin-queue / ");
			}

			if (strcmp(lgopts[opt_idx].name, "raw-encap") == 0) {
				printf("raw-encap ");
				flow_actions[actions_idx++] =
					FLOW_ITEM_MASK(
						RTE_FLOW_ACTION_TYPE_RAW_ENCAP
					);

				token = strtok(optarg, ",");
				while (token != NULL) {
					for (i = 0; i < RTE_DIM(flow_options); i++) {
						if (strcmp(flow_options[i].str, token) == 0) {
							printf("%s,", token);
							encap_data |= flow_options[i].mask;
							break;
						}
						/* Reached last item with no match */
						if (i == (RTE_DIM(flow_options) - 1))
							rte_exit(EXIT_FAILURE,
								"Invalid encap item: %s\n", token);
					}
					token = strtok(NULL, ",");
				}
				printf(" / ");
			}
			if (strcmp(lgopts[opt_idx].name, "raw-decap") == 0) {
				printf("raw-decap ");
				flow_actions[actions_idx++] =
					FLOW_ITEM_MASK(
						RTE_FLOW_ACTION_TYPE_RAW_DECAP
					);

				token = strtok(optarg, ",");
				while (token != NULL) {
					for (i = 0; i < RTE_DIM(flow_options); i++) {
						if (strcmp(flow_options[i].str, token) == 0) {
							printf("%s,", token);
							decap_data |= flow_options[i].mask;
							break;
						}
						/* Reached last item with no match */
						if (i == (RTE_DIM(flow_options) - 1))
							rte_exit(EXIT_FAILURE,
								"Invalid decap item %s\n", token);
					}
					token = strtok(NULL, ",");
				}
				printf(" / ");
			}
			/* Control */
			if (strcmp(lgopts[opt_idx].name,
					"rules-batch") == 0) {
				n = atoi(optarg);
				if (n >= DEFAULT_RULES_BATCH)
					rules_batch = n;
				else {
					rte_exit(EXIT_FAILURE,
						"rules_batch should be >= %d\n",
						DEFAULT_RULES_BATCH);
				}
			}
			if (strcmp(lgopts[opt_idx].name,
					"rules-count") == 0) {
				n = atoi(optarg);
				if (n >= (int) rules_batch)
					rules_count = n;
				else {
					rte_exit(EXIT_FAILURE,
						"rules_count should be >= %d\n",
						rules_batch);
				}
			}
			if (strcmp(lgopts[opt_idx].name,
					"ct-route-id-count") == 0) {
				n = atoi(optarg);
				ct_route_id_count = n;
			}

			if (strcmp(lgopts[opt_idx].name,
				"cross-port") == 0)
				cross_port = true;
			if (strcmp(lgopts[opt_idx].name,
				"iterations") == 0) {
				n = atoi(optarg);
				nb_iterations = n;
			}
			if (strcmp(lgopts[opt_idx].name,
				"ct-query") == 0)
				ct_query = true;
			if (strcmp(lgopts[opt_idx].name,
				"sanity-checks-first") == 0) {
				sanity_checks_first = true;
			}
			if (strcmp(lgopts[opt_idx].name,
					"dump-iterations") == 0)
				dump_iterations = true;
			if (strcmp(lgopts[opt_idx].name,
					"unique-data") == 0)
				unique_data = true;
			if (strcmp(lgopts[opt_idx].name,
					"deletion-rate") == 0)
				delete_flag = true;
			if (strcmp(lgopts[opt_idx].name,
					"dump-socket-mem") == 0)
				dump_socket_mem_flag = true;
			if (strcmp(lgopts[opt_idx].name,
					"enable-fwd") == 0)
				enable_fwd = true;
			if (strcmp(lgopts[opt_idx].name,
					"portmask") == 0) {
				/* parse hexadecimal string */
				end = NULL;
				pm = strtoull(optarg, &end, 16);
				if ((optarg[0] == '\0') || (end == NULL) || (*end != '\0'))
					rte_exit(EXIT_FAILURE, "Invalid fwd port mask\n");
				ports_mask = pm;
			}
			if (strcmp(lgopts[opt_idx].name, "cores") == 0) {
				n = atoi(optarg);
				if ((int) rte_lcore_count() <= n) {
					rte_exit(EXIT_FAILURE,
						"Error: you need %d cores to run on multi-cores\n"
						"Existing cores are: %d\n", n, rte_lcore_count());
				}
				if (n <= RTE_MAX_LCORE && n > 0)
					mc_pool.cores_count = n;
				else {
					rte_exit(EXIT_FAILURE,
						"Error: cores count must be > 0 and < %d\n",
						RTE_MAX_LCORE);
				}
			}
			if (strcmp(lgopts[opt_idx].name,
					"meter-profile-alg") == 0) {
				if (strcmp(optarg, "srtcm_rfc2697") == 0)
					mtr_profile_alg = RTE_MTR_SRTCM_RFC2697;
				else
					rte_exit(EXIT_FAILURE, "\nError: not supported meter profile algorithm %s\n"
						 "Current supported algorithms are: [%s]\n",
						 optarg, METER_PROFILE_ALG_SRTCM_RFC2697);
			}
			break;
		default:
			usage(argv[0]);
			rte_exit(EXIT_FAILURE, "Invalid option: %s\n",
					argv[optind]);
			break;
		}
	}
	printf("end_flow\n");

	if (ct_route_id_count || chkpnt_case) {
		if (hairpin_queues_num < NB_CT_HAIRPIN)
			hairpin_queues_num = NB_CT_HAIRPIN;
		n = get_action_mask_idx
			(FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_SET_TAG));
		if (n < 0)
			printf(
				"WARNING: ct-route-id-count flag specified, but no set-tag action was specified.\n");
		else
			flow_actions[n] = CT_ROUTE_ID_ACTION;
		if (chkpnt_case) {
			ct_route_id_count = NB_CHKPNT_PPS_ROUTE_ID;
			set_ihl = true;
		}
	}
}

/* Dump the socket memory statistics on console */
static size_t
dump_socket_mem(FILE *f)
{
	struct rte_malloc_socket_stats socket_stats;
	unsigned int i = 0;
	size_t total = 0;
	size_t alloc = 0;
	size_t free = 0;
	unsigned int n_alloc = 0;
	unsigned int n_free = 0;
	bool active_nodes = false;


	for (i = 0; i < RTE_MAX_NUMA_NODES; i++) {
		if (rte_malloc_get_socket_stats(i, &socket_stats) ||
		    !socket_stats.heap_totalsz_bytes)
			continue;
		active_nodes = true;
		total += socket_stats.heap_totalsz_bytes;
		alloc += socket_stats.heap_allocsz_bytes;
		free += socket_stats.heap_freesz_bytes;
		n_alloc += socket_stats.alloc_count;
		n_free += socket_stats.free_count;
		if (dump_socket_mem_flag) {
			fprintf(f, "::::::::::::::::::::::::::::::::::::::::");
			fprintf(f,
				"\nSocket %u:\nsize(M) total: %.6lf\nalloc:"
				" %.6lf(%.3lf%%)\nfree: %.6lf"
				"\nmax: %.6lf"
				"\ncount alloc: %u\nfree: %u\n",
				i,
				socket_stats.heap_totalsz_bytes / 1.0e6,
				socket_stats.heap_allocsz_bytes / 1.0e6,
				(double)socket_stats.heap_allocsz_bytes * 100 /
				(double)socket_stats.heap_totalsz_bytes,
				socket_stats.heap_freesz_bytes / 1.0e6,
				socket_stats.greatest_free_size / 1.0e6,
				socket_stats.alloc_count,
				socket_stats.free_count);
				fprintf(f, "::::::::::::::::::::::::::::::::::::::::");
		}
	}
	if (dump_socket_mem_flag && active_nodes) {
		fprintf(f,
			"\nTotal: size(M)\ntotal: %.6lf"
			"\nalloc: %.6lf(%.3lf%%)\nfree: %.6lf"
			"\ncount alloc: %u\nfree: %u\n",
			total / 1.0e6, alloc / 1.0e6,
			(double)alloc * 100 / (double)total, free / 1.0e6,
			n_alloc, n_free);
		fprintf(f, "::::::::::::::::::::::::::::::::::::::::\n");
	}
	return alloc;
}

static void
print_flow_error(struct rte_flow_error error)
{
	printf("Flow can't be created %d message: %s\n",
		error.type,
		error.message ? error.message : "(no stated reason)");
}

static inline void
print_rules_batches(double *cpu_time_per_batch)
{
	uint8_t idx;
	double delta;
	double rate;

	for (idx = 0; idx < MAX_BATCHES_COUNT; idx++) {
		if (!cpu_time_per_batch[idx])
			break;
		delta = (double)(rules_batch / cpu_time_per_batch[idx]);
		rate = delta / 1000; /* Save rate in K unit. */
		printf(":: Rules batch #%d: %d rules "
			"in %f sec[ Rate = %f K Rule/Sec ]\n",
			idx, rules_batch,
			cpu_time_per_batch[idx], rate);
	}
}

static inline int
has_meter(void)
{
	return get_action_mask_idx
		(FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_METER)) > 0;
}

static inline int
has_ct_action(void)
{
	return get_action_mask_idx(CT_ACTION) > 0;
}

static void
create_meter_rule(int port_id, uint32_t counter)
{
	int ret;
	struct rte_mtr_params params;
	uint32_t default_prof_id = DEFAULT_METER_PROF_ID;
	struct rte_mtr_error error;

	memset(&params, 0, sizeof(struct rte_mtr_params));
	params.meter_enable = 1;
	params.stats_mask = 0xffff;
	params.use_prev_mtr_color = 0;
	params.dscp_table = NULL;

	/*create meter*/
	params.meter_profile_id = default_prof_id;
	ret = rte_mtr_create(port_id, counter, &params, 1, &error);
	if (ret != 0) {
		printf("Port %u create meter idx(%d) error(%d) message: %s\n",
			port_id, counter, error.type,
			error.message ? error.message : "(no stated reason)");
		rte_exit(EXIT_FAILURE, "Error in creating meter\n");
	}
}

static void
destroy_meter_rule(int port_id, uint32_t counter)
{
	struct rte_mtr_error error;

	if (rte_mtr_destroy(port_id, counter, &error)) {
		printf("Port %u destroy meter(%d) error(%d) message: %s\n",
			port_id, counter, error.type,
			error.message ? error.message : "(no stated reason)");
		rte_exit(EXIT_FAILURE, "Error in deleting meter rule\n");
	}
}

static void
meters_handler(int port_id, uint8_t core_id, uint8_t ops)
{
	uint64_t start_batch;
	double cpu_time_used, insertion_rate;
	int rules_count_per_core, rules_batch_idx;
	uint32_t counter, start_counter = 0, end_counter;
	double cpu_time_per_batch[MAX_BATCHES_COUNT] = { 0 };

	rules_count_per_core = rules_count / mc_pool.cores_count;

	if (core_id)
		start_counter = core_id * rules_count_per_core;
	end_counter = (core_id + 1) * rules_count_per_core;

	cpu_time_used = 0;
	start_batch = rte_get_timer_cycles();
	for (counter = start_counter; counter < end_counter; counter++) {
		if (ops == METER_CREATE)
			create_meter_rule(port_id, counter);
		else
			destroy_meter_rule(port_id, counter);
		/*
		 * Save the insertion rate for rules batch.
		 * Check if the insertion reached the rules
		 * patch counter, then save the insertion rate
		 * for this batch.
		 */
		if (!((counter + 1) % rules_batch)) {
			rules_batch_idx = ((counter + 1) / rules_batch) - 1;
			cpu_time_per_batch[rules_batch_idx] =
				((double)(rte_get_timer_cycles() - start_batch))
				/ rte_get_timer_hz();
			cpu_time_used += cpu_time_per_batch[rules_batch_idx];
			start_batch = rte_get_timer_cycles();
		}
	}

	/* Print insertion rates for all batches */
	if (dump_iterations)
		print_rules_batches(cpu_time_per_batch);

	insertion_rate =
		((double) (rules_count_per_core / cpu_time_used) / 1000);

	/* Insertion rate for all rules in one core */
	printf(":: Port %d :: Core %d Meter %s :: start @[%d] - end @[%d],"
		" use:%.02fs, rate:%.02fk Rule/Sec\n",
		port_id, core_id, ops == METER_CREATE ? "create" : "delete",
		start_counter, end_counter - 1,
		cpu_time_used, insertion_rate);

	if (ops == METER_CREATE)
		mc_pool.meters_record.insertion[port_id][core_id]
			= cpu_time_used;
	else
		mc_pool.meters_record.deletion[port_id][core_id]
			= cpu_time_used;
}

static void
destroy_meter_profile(void)
{
	struct rte_mtr_error error;
	uint16_t nr_ports;
	int port_id;

	nr_ports = rte_eth_dev_count_avail();
	for (port_id = 0; port_id < nr_ports; port_id++) {
		/* If port outside portmask */
		if (!((ports_mask >> port_id) & 0x1))
			continue;

		if (rte_mtr_meter_profile_delete
			(port_id, DEFAULT_METER_PROF_ID, &error)) {
			printf("Port %u del profile error(%d) message: %s\n",
				port_id, error.type,
				error.message ? error.message : "(no stated reason)");
			rte_exit(EXIT_FAILURE, "Error: Destroy meter profile Failed!\n");
		}
	}
}

static void
create_meter_profile(void)
{
	uint16_t nr_ports;
	int ret, port_id;
	struct rte_mtr_meter_profile mp;
	struct rte_mtr_error error;

	/*
	 *currently , only create one meter file for one port
	 *1 meter profile -> N meter rules -> N rte flows
	 */
	memset(&mp, 0, sizeof(struct rte_mtr_meter_profile));
	nr_ports = rte_eth_dev_count_avail();
	for (port_id = 0; port_id < nr_ports; port_id++) {
		/* If port outside portmask */
		if (!((ports_mask >> port_id) & 0x1))
			continue;
		mp.alg = RTE_MTR_SRTCM_RFC2697;
		mp.srtcm_rfc2697.cir = METER_CIR;
		mp.srtcm_rfc2697.cbs = METER_CIR / 8;
		mp.srtcm_rfc2697.ebs = 0;

		ret = rte_mtr_meter_profile_add
			(port_id, DEFAULT_METER_PROF_ID, &mp, &error);
		if (ret != 0) {
			printf("Port %u create Profile error(%d) message: %s\n",
				port_id, error.type,
				error.message ? error.message : "(no stated reason)");
			rte_exit(EXIT_FAILURE, "Error: Creation meter profile Failed!\n");
		}
	}
}

static inline void
destroy_flows(int port_id, uint8_t core_id, struct rte_flow **flows_list,
	struct rte_flow **rflows_list)
{
	struct rte_flow_error error;
	clock_t start_batch, end_batch;
	double cpu_time_used = 0;
	double deletion_rate;
	double cpu_time_per_batch[MAX_BATCHES_COUNT] = { 0 };
	double delta;
	uint32_t i;
	int rules_batch_idx;
	int rules_count_per_core;
	int rport_id = port_id;

	if (cross_port)
		rport_id = port_id ^ 1;

	rules_count_per_core = rules_count / mc_pool.cores_count;
	/* If group > 0 , should add 1 flow which created in group 0 */
	if (flow_group > 0 && core_id == 0)
		rules_count_per_core++;

	start_batch = rte_get_timer_cycles();
	for (i = 1; i < (uint32_t) rules_count_per_core; i++) {
		if (flows_list[i] == 0)
			break;

		memset(&error, 0x33, sizeof(error));
		if (ct_query && query_ct_object(core_id, i, port_id, &error)) {
			print_flow_error(error);
			rte_exit(EXIT_FAILURE, "Error querying CT HW context");
		}
		if (rte_flow_destroy(port_id, flows_list[i], &error)) {
			print_flow_error(error);
			rte_exit(EXIT_FAILURE, "Error in deleting flow\n");
		}
		if ((has_ct || cross_port) &&
			rte_flow_destroy(rport_id, rflows_list[i], &error)) {
			print_flow_error(error);
			rte_exit(EXIT_FAILURE, "Error in deleting rflow");
		}

		/*
		 * Save the deletion rate for rules batch.
		 * Check if the deletion reached the rules
		 * patch counter, then save the deletion rate
		 * for this batch.
		 */
		if (!((i + 1) % rules_batch)) {
			end_batch = rte_get_timer_cycles();
			delta = (double) (end_batch - start_batch);
			rules_batch_idx = ((i + 1) / rules_batch) - 1;
			cpu_time_per_batch[rules_batch_idx] = delta / rte_get_timer_hz();
			cpu_time_used += cpu_time_per_batch[rules_batch_idx];
			start_batch = rte_get_timer_cycles();
		}
	}

	/* Print deletion rates for all batches */
	if (dump_iterations)
		print_rules_batches(cpu_time_per_batch);

	/* Deletion rate for all rules */
	deletion_rate = ((double) (rules_count_per_core / cpu_time_used) / 1000);
	printf(":: Port %d :: Core %d :: Rules deletion rate -> %f K Rule/Sec\n",
		port_id, core_id, deletion_rate);
	printf(":: Port %d :: Core %d :: The time for deleting %d rules is %f seconds\n",
		port_id, core_id, rules_count_per_core, cpu_time_used);

	mc_pool.flows_record.deletion[port_id][core_id] = cpu_time_used;
}

static void
create_ct_static_flows(uint16_t port_id)
{
	struct rte_flow_error error;
	uint32_t priority;
	uint64_t items[MAX_ITEMS_NUM] = { 0 };
	uint64_t actions[MAX_ACTIONS_NUM] = { 0 };
	uint16_t nb_hairpin = NB_CT_HAIRPIN;
	uint32_t counter;
	struct rte_flow *flow = NULL;
	struct rte_flow *rflow = NULL;
	int rport_id = port_id;

	if (cross_port)
		rport_id = port_id ^ 1;

	ct_static_flows = rte_zmalloc("ct_static_flows",
		sizeof(struct rte_flow *) * (ct_route_id_count + 1), 0);
	if (ct_static_flows == NULL)
		rte_exit(EXIT_FAILURE, "No Memory available!");

	if (has_ct || cross_port) {
		ct_static_rflows = rte_zmalloc("ct_static_rflows",
			sizeof(struct rte_flow *) * (ct_route_id_count + 1), 0);
		if (ct_static_rflows == NULL)
			rte_exit(EXIT_FAILURE, "No Memory available!");
	}

	priority = ATTR_DEFAULT_PRIORITY;

	items[0] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ETH);
	items[1] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_CONNTRACK);
	items[2] = FLOW_ITEM_MASK(CT_TAG_ITEM);

	actions[0] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_SET_MAC_SRC);
	actions[1] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_SET_MAC_DST);
	actions[2] = HAIRPIN_QUEUE_ACTION;

	for (counter = 0; counter < ct_route_id_count + 1; ++counter) {
		if (counter == ct_route_id_count) {
			/* Default catch all rule */
			priority = 1;
			nb_hairpin = 0;

			items[0] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ETH);
			items[1] = 0;

			actions[0] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_RSS);
			actions[1] = 0;
		}
		flow = generate_flow(port_id, JUMP_ACTION_TABLE, priority,
			flow_attrs, items, actions,
			JUMP_ACTION_TABLE, counter, nb_hairpin, 0,
			0, 0, unique_data, ct_route_id_count,
			cross_port, /*reply_dir=*/false, /*time_to_live=*/-1,
			/*set_ipv4_addrs=*/false, /*no_frag=*/false,
			/*set_ports=*/false, /*l3_type=*/-1, /*set_ihl=*/false,
			ports_per_ip, &error);

		if (flow == NULL) {
			print_flow_error(error);
			rte_exit(EXIT_FAILURE,
				"error in creating ct static flow");
		}
		ct_static_flows[counter] = flow;

		if (has_ct || cross_port) {
			rflow = generate_flow(rport_id, JUMP_ACTION_TABLE,
				priority, flow_attrs, items, actions,
				JUMP_ACTION_TABLE, counter, nb_hairpin, 0,
				0, 0, unique_data, ct_route_id_count,
				cross_port, /*reply_dir=*/false, /*time_to_live=*/-1,
				/*set_ipv4_addrs=*/false, /*no_frag=*/false,
				/*set_ports=*/false, /*l3_type=*/-1, /*set_ihl=*/false,
				ports_per_ip, &error);

			if (rflow == NULL) {
				print_flow_error(error);
				rte_exit(EXIT_FAILURE,
					"error in creating ct static rflow");
			}
			ct_static_rflows[counter] = rflow;
		}
	}
}

static void
destroy_chkpnt_pps_static_flows(uint16_t port_id)
{
	struct rte_flow_error error;
	uint32_t i;

	for (i = 0; i < chkpnt_idx; ++i) {
		memset(&error, 0, sizeof(error));
		if (rte_flow_destroy(port_id, chkpnt_static_flows[i], &error)) {
			print_flow_error(error);
			rte_exit(EXIT_FAILURE,
				"Error in deleting chkpnt static flow");
		}
	}
	chkpnt_idx = 0;
}

static void
insert_chkpnt_pps_group0_flows(uint16_t port_id)
{
	uint16_t group;
	uint32_t priority;
	uint64_t flow_attrs[MAX_ATTRS_NUM] = { 0 };
	uint64_t items[MAX_ITEMS_NUM] = { 0 };
	uint64_t actions[MAX_ACTIONS_NUM] = { 0 };
	struct rte_flow *flow = NULL;
	uint8_t time_to_live;
	struct rte_flow_error error;

	/* All flows should be in group 0 and ingress */
	group = 0;
	flow_attrs[0] = INGRESS;

	/* prio=0 pattern eth / ipv4 ttl=0|1 actions mark=error / rss */
	priority = 0;

	items[0] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ETH);
	items[1] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_IPV4);
	items[2] = 0;

	actions[0] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_MARK);
	actions[1] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_RSS);
	actions[2] = 0;

	for (time_to_live = 0; time_to_live <= 1; ++time_to_live) {
		flow = generate_flow(port_id, group, priority, flow_attrs, items,
			actions, flow_group, CHKPNT_PPS_MARK_ERROR, 0, 0, 0, 0,
			unique_data, ct_route_id_count, cross_port,
			/*reply_dir=*/false, time_to_live, /*set_ipv4_addrs=*/false,
			/*no_frag=*/false, /*set_ports=*/false, /*l3_type=*/-1,
			/*set_ihl=*/false, ports_per_ip, &error);
		if (!flow)
			goto chkpnt_g0_error;
		chkpnt_static_flows[chkpnt_idx++] = flow;
	}

	/* prio=0 pattern eth / ipv4 / UDP / vxlan actions decap vxlan / set_tag / jump 1 */
	items[2] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_UDP);
	items[3] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_VXLAN);
	items[4] = 0;

	actions[0] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_VXLAN_DECAP);
	actions[1] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_SET_TAG);
	actions[2] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_JUMP);
	actions[3] = 0;

	/* Don't match on ttl*/
	time_to_live = -1;

	flow = generate_flow(port_id, group, priority, flow_attrs, items,
		actions, flow_group, 0, 0, 0, 0, 0,
		unique_data, ct_route_id_count, cross_port,
		/*reply_dir=*/false, /*time_to_live=*/-1, /*set_ipv4_addrs=*/false,
		/*no_frag=*/false, /*set_ports=*/false, /*l3_type=*/-1,
		/*set_ihl=*/false, ports_per_ip, &error);
	if (!flow)
		goto chkpnt_g0_error;
	chkpnt_static_flows[chkpnt_idx++] = flow;

	/* prio=1 pattern eth / ipv4 no_frag / UDP / sanity actions jump 1 */
	priority = 1;

	items[2] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_UDP);
	items[3] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_INTEGRITY);
	items[4] = 0;

	actions[0] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_JUMP);
	actions[1] = 0;

	flow = generate_flow(port_id, group, priority, flow_attrs, items,
		actions, flow_group, 0, 0, 0, 0, 0,
		unique_data, ct_route_id_count, cross_port,
		/*reply_dir=*/false, /*time_to_live=*/-1, /*set_ipv4_addrs=*/false,
		/*no_frag=*/true, /*set_ports=*/false, /*l3_type=*/-1,
		/*set_ihl=*/false, ports_per_ip, &error);
	if (!flow)
		goto chkpnt_g0_error;
	chkpnt_static_flows[chkpnt_idx++] = flow;

	/* prio=1 pattern eth / ipv4 no_frag / TCP / sanity actions jump 1 */
	items[2] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_TCP);

	flow = generate_flow(port_id, group, priority, flow_attrs, items,
		actions, flow_group, 0, 0, 0, 0, 0,
		unique_data, ct_route_id_count, cross_port,
		/*reply_dir=*/false, /*time_to_live=*/-1, /*set_ipv4_addrs=*/false,
		/*no_frag=*/true, /*set_ports=*/false, /*l3_type=*/-1,
		/*set_ihl=*/false, ports_per_ip, &error);
	if (!flow)
		goto chkpnt_g0_error;
	chkpnt_static_flows[chkpnt_idx++] = flow;

	/* prio=2 pattern eth actions rss */
	priority = 2;

	items[0] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ETH);
	items[1] = 0;

	actions[0] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_RSS);
	actions[1] = 0;

	flow = generate_flow(port_id, group, priority, flow_attrs, items,
		actions, flow_group, 0, 0, 0, 0, 0,
		unique_data, ct_route_id_count, cross_port,
		/*reply_dir=*/false, /*time_to_live=*/-1, /*set_ipv4_addrs=*/false,
		/*no_frag=*/false, /*set_ports=*/false, /*l3_type=*/-1,
		/*set_ihl=*/false, ports_per_ip, &error);
	if (!flow)
		goto chkpnt_g0_error;
	chkpnt_static_flows[chkpnt_idx++] = flow;

	return;

chkpnt_g0_error:
	destroy_chkpnt_pps_static_flows(port_id);
	print_flow_error(error);
	rte_exit(EXIT_FAILURE,
		"Error in inserting chkpnt group0 static flows");
}

static void
insert_chkpnt_pps_group1_flows(uint16_t port_id)
{
	uint16_t group;
	uint32_t priority;
	uint64_t flow_attrs[MAX_ATTRS_NUM] = { 0 };
	uint64_t items[MAX_ITEMS_NUM] = { 0 };
	uint64_t actions[MAX_ACTIONS_NUM] = { 0 };
	struct rte_flow *flow = NULL;
	struct rte_flow_error error;
	uint16_t l3_type;

	/* All flows should be in group 1 and ingress */
	group = 1;
	flow_attrs[0] = INGRESS;

	/* prio=1 pattern eth / tag actions count / drop */
	priority = 1;

	items[0] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ETH);
	items[1] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_TAG);
	items[2] = 0;

	actions[0] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_COUNT);
	actions[1] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_DROP);
	actions[2] = 0;

	flow = generate_flow(port_id, group, priority, flow_attrs, items,
		actions, flow_group, 0, 0, 0, 0, 0,
		unique_data, ct_route_id_count, cross_port,
		/*reply_dir=*/false, /*time_to_live=*/-1, /*set_ipv4_addrs=*/false,
		/*no_frag=*/false, /*set_ports=*/false, /*l3_type=*/-1,
		/*set_ihl=*/false, ports_per_ip, &error);
	if (!flow)
		goto chkpnt_g1_error;
	chkpnt_static_flows[chkpnt_idx++] = flow;

	/* prio=2 pattern eth / ipv6 / TCP actions count / queue */
	priority = 2;

	items[1] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_IPV6);
	items[2] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_TCP);
	items[3] = 0;

	actions[0] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_COUNT);
	actions[1] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_QUEUE);
	actions[2] = 0;

	flow = generate_flow(port_id, group, priority, flow_attrs, items,
		actions, flow_group, 0, 0, 0, 0, 0,
		unique_data, ct_route_id_count, cross_port,
		/*reply_dir=*/false, /*time_to_live=*/-1, /*set_ipv4_addrs=*/false,
		/*no_frag=*/false, /*set_ports=*/false, /*l3_type=*/-1,
		/*set_ihl=*/false, ports_per_ip, &error);
	if (!flow)
		goto chkpnt_g1_error;
	chkpnt_static_flows[chkpnt_idx++] = flow;

	/* prio=2 pattern eth / ipv4 / TCP actions count / queue */
	priority = 2;

	items[1] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_IPV4);

	flow = generate_flow(port_id, group, priority, flow_attrs, items,
		actions, flow_group, 0, 0, 0, 0, 0,
		unique_data, ct_route_id_count, cross_port,
		/*reply_dir=*/false, /*time_to_live=*/-1, /*set_ipv4_addrs=*/false,
		/*no_frag=*/false, /*set_ports=*/false, /*l3_type=*/-1,
		/*set_ihl=*/false, ports_per_ip, &error);
	if (!flow)
		goto chkpnt_g1_error;
	chkpnt_static_flows[chkpnt_idx++] = flow;

	/* prio=3 pattern eth / ipv4 / UDP actions count / queue */
	priority = 3;

	items[2] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_UDP);

	flow = generate_flow(port_id, group, priority, flow_attrs, items,
		actions, flow_group, 0, 0, 0, 0, 0,
		unique_data, ct_route_id_count, cross_port,
		/*reply_dir=*/false, /*time_to_live=*/-1, /*set_ipv4_addrs=*/false,
		/*no_frag=*/false, /*set_ports=*/false, /*l3_type=*/-1,
		/*set_ihl=*/false, ports_per_ip, &error);
	if (!flow)
		goto chkpnt_g1_error;
	chkpnt_static_flows[chkpnt_idx++] = flow;

	/* prio=3 pattern eth.l3_type=1|2 actions count / queue */
	priority = 3;

	items[0] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ETH);
	items[1] = 0;

	for (l3_type = 1; l3_type <= 2; ++l3_type) {
		flow = generate_flow(port_id, group, priority, flow_attrs, items,
			actions, flow_group, 0, 0, 0, 0, 0,
			unique_data, ct_route_id_count, cross_port,
			/*reply_dir=*/false, /*time_to_live=*/-1, /*set_ipv4_addrs=*/false,
			/*no_frag=*/false, /*set_ports=*/false, l3_type,
			/*set_ihl=*/false, ports_per_ip, &error);
		if (!flow)
			goto chkpnt_g1_error;
		chkpnt_static_flows[chkpnt_idx++] = flow;
	}

	return;

chkpnt_g1_error:
	destroy_chkpnt_pps_static_flows(port_id);
	print_flow_error(error);
	rte_exit(EXIT_FAILURE,
		"Error in inserting chkpnt group1 static flows\n");
}

static void
insert_chkpnt_pps_group2_flows(uint16_t port_id)
{
	uint16_t group;
	uint32_t priority;
	uint64_t flow_attrs[MAX_ATTRS_NUM] = { 0 };
	uint64_t items[MAX_ITEMS_NUM] = { 0 };
	uint64_t actions[MAX_ACTIONS_NUM] = { 0 };
	struct rte_flow *flow = NULL;
	struct rte_flow_error error;
	uint32_t counter;

	/* All flows should be in group 2 and ingress */
	group = 2;
	flow_attrs[0] = INGRESS;

	/* prio=2 pattern eth / ipv6 / TCP actions mark / count / queue */
	priority = 2;

	items[0] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ETH);
	items[1] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_IPV6);
	items[2] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_TCP);
	items[3] = 0;

	actions[0] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_MARK);
	actions[1] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_COUNT);
	actions[2] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_QUEUE);
	actions[3] = 0;

	flow = generate_flow(port_id, group, priority, flow_attrs, items,
		actions, flow_group, 0, 0, 0, 0, 0,
		unique_data, ct_route_id_count, cross_port,
		/*reply_dir=*/false, /*time_to_live=*/-1, /*set_ipv4_addrs=*/false,
		/*no_frag=*/false, /*set_ports=*/false, /*l3_type=*/-1,
		/*set_ihl=*/false, ports_per_ip, &error);
	if (!flow)
		goto chkpnt_g2_error;
	chkpnt_static_flows[chkpnt_idx++] = flow;

	/* prio=2 pattern eth / ipv6 / UDP actions mark / count / queue */
	priority = 2;

	items[2] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_UDP);

	flow = generate_flow(port_id, group, priority, flow_attrs, items,
		actions, flow_group, 0, 0, 0, 0, 0,
		unique_data, ct_route_id_count, cross_port,
		/*reply_dir=*/false, /*time_to_live=*/-1, /*set_ipv4_addrs=*/false,
		/*no_frag=*/false, /*set_ports=*/false, /*l3_type=*/-1,
		/*set_ihl=*/false, ports_per_ip, &error);
	if (!flow)
		goto chkpnt_g2_error;
	chkpnt_static_flows[chkpnt_idx++] = flow;

	/* prio=3 pattern eth actions rss */
	priority = 3;

	items[0] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ETH);
	items[1] = 0;

	actions[0] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_RSS);
	actions[1] = 0;

	flow = generate_flow(port_id, group, priority, flow_attrs, items,
		actions, flow_group, 0, 0, 0, 0, 0,
		unique_data, ct_route_id_count, cross_port,
		/*reply_dir=*/false, /*time_to_live=*/-1, /*set_ipv4_addrs=*/false,
		/*no_frag=*/false, /*set_ports=*/false, /*l3_type=*/-1,
		/*set_ihl=*/false, ports_per_ip, &error);
	if (!flow)
		goto chkpnt_g2_error;
	chkpnt_static_flows[chkpnt_idx++] = flow;

	for (priority = 0; priority <= 1; ++priority) {
		if (priority == 0) {
			/* prio=0 pattern ether / vlan / ether / vlan / tag(rid) / ct_res=valid
			 * actions pop vlan / set_tag / set_smac / set_dmac / hairpin
			 */
			items[0] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ETH);
			items[1] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_VLAN);
			items[2] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_CONNTRACK);
			items[3] = FLOW_ITEM_MASK(CT_TAG_ITEM);
			items[4] = 0;

			actions[0] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_OF_POP_VLAN);
			actions[1] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_SET_TAG);
			actions[2] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_SET_MAC_SRC);
			actions[3] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_SET_MAC_DST);
			actions[4] = HAIRPIN_QUEUE_ACTION;
			actions[5] = 0;
		} else {
			/* prio=1 pattern ether / ipv4 / tag(rid) / ct_res=valid
			 * actions set_tag / set_smac / set_dmac / hairpin
			 */
			items[0] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ETH);
			items[1] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_IPV4);
			items[2] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_CONNTRACK);
			items[3] = FLOW_ITEM_MASK(CT_TAG_ITEM);
			items[4] = 0;

			actions[0] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_SET_TAG);
			actions[1] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_SET_MAC_SRC);
			actions[2] = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_SET_MAC_DST);
			actions[3] = HAIRPIN_QUEUE_ACTION;
			actions[4] = 0;
		}
		for (counter = 0; counter < ct_route_id_count; ++counter) {
			flow = generate_flow(port_id, group, priority,
				flow_attrs, items, actions,
				flow_group, counter, hairpin_queues_num, 0,
				0, 0, unique_data, ct_route_id_count,
				cross_port, /*reply_dir=*/false, /*time_to_live=*/-1,
				/*set_ipv4_addrs=*/false, /*no_frag=*/false,
				/*set_ports=*/false, /*l3_type=*/-1,
				/*set_ihl=*/false, ports_per_ip, &error);
			if (!flow)
				goto chkpnt_g2_error;
			chkpnt_static_flows[chkpnt_idx++] = flow;
		}
	}

	return;

chkpnt_g2_error:
	destroy_chkpnt_pps_static_flows(port_id);
	print_flow_error(error);
	rte_exit(EXIT_FAILURE,
		"Error in inserting chkpnt group2 static flows\n");
}

static void
insert_chkpnt_pps_static_flows(uint16_t port_id)
{
	insert_chkpnt_pps_group0_flows(port_id);
	insert_chkpnt_pps_group1_flows(port_id);
	insert_chkpnt_pps_group2_flows(port_id);
}

static struct rte_flow **
insert_flows(int port_id, uint8_t core_id, struct rte_flow ***rflows_out)
{
	struct rte_flow **flows_list;
	struct rte_flow *flow = NULL;
	struct rte_flow **rflows_list = NULL;
	struct rte_flow *rflow = NULL;
	struct rte_flow_error error;
	struct rte_flow_error rerror;
	clock_t start_batch, end_batch;
	double first_flow_latency;
	double cpu_time_used;
	double insertion_rate;
	double cpu_time_per_batch[MAX_BATCHES_COUNT] = { 0 };
	double delta;
	uint32_t flow_index;
	uint32_t counter, start_counter = 0, end_counter;
	uint64_t global_items[MAX_ITEMS_NUM] = { 0 };
	uint64_t global_actions[MAX_ACTIONS_NUM] = { 0 };
	int rules_batch_idx;
	int rules_count_per_core;
	int rport_id = port_id;

	if (cross_port)
		rport_id = port_id ^ 1;

	rules_count_per_core = rules_count / mc_pool.cores_count;

	/* Set boundaries of rules for each core. */
	if (core_id)
		start_counter = core_id * rules_count_per_core;
	if (ct_created)
		start_counter += 1;

	end_counter = (core_id + 1) * rules_count_per_core;

	global_items[0] = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ETH);
	if (sanity_checks_first)
		global_items[1] = FLOW_ITEM_MASK(
			RTE_FLOW_ITEM_TYPE_INTEGRITY);
	global_actions[0] = FLOW_ITEM_MASK(RTE_FLOW_ACTION_TYPE_JUMP);


	flows_list = rte_zmalloc("flows_list",
		(sizeof(struct rte_flow *) * rules_count_per_core) + 1, 0);
	if (flows_list == NULL)
		rte_exit(EXIT_FAILURE, "No Memory available!\n");

	if (has_ct || cross_port) {
		printf("WE ARE HERE ANYWAY\n");
		rflows_list = rte_zmalloc("rflows_list",
			(sizeof(struct rte_flow *) * rules_count_per_core) + 1,
			0);
		if (rflows_list == NULL)
			rte_exit(EXIT_FAILURE, "No Memory available!");
	}

	cpu_time_used = 0;
	flow_index = ct_created ? 1 : 0;
	if (flow_group > 0 && core_id == 0 && 0) {
		/*
		 * Create global rule to jump into flow_group,
		 * this way the app will avoid the default rules.
		 *
		 * This rule will be created only once.
		 *
		 * Global rule:
		 * group 0 eth / end actions jump group <flow_group>
		 */
		if (cross_port) {
			rflow = generate_flow
				(rport_id, 0, ATTR_DEFAULT_PRIORITY,
				flow_attrs, global_items, global_actions,
				flow_group, 0, 0, 0, 0, core_id, unique_data,
				0, cross_port, /*reply_dir=*/true, /*time_to_live=*/-1,
				/*set_ipv4_addrs=*/true, /*no_frag=*/false,
				/*set_ports=*/false, /*l3_type=*/-1,
				/*set_ihl=*/false, ports_per_ip, &rerror);

			if (rflow == NULL) {
				print_flow_error(rerror);
				printf("#1");
				rte_exit(EXIT_FAILURE,
					"error in creating rflow");
			}
			rflows_list[rules_count_per_core] = rflow;
		}

		flow = generate_flow(port_id, 0, ATTR_DEFAULT_PRIORITY,
			flow_attrs, global_items, global_actions,
			flow_group, 0, 0, 0, 0, core_id, unique_data,
			0, cross_port, /*reply_dir=*/false,
			/*time_to_live=*/-1, /*set_ipv4_addrs=*/true,
			/*no_frag=*/false, /*set_ports=*/false, /*l3_type=*/-1,
			/*set_ihl=*/false, ports_per_ip, &error);

		if (flow == NULL) {
			print_flow_error(error);
			rte_exit(EXIT_FAILURE, "Error in creating flow\n");
		}
		flows_list[rules_count_per_core] = flow;

	}

	start_batch = rte_get_timer_cycles();
	for (counter = start_counter; counter < end_counter; counter++) {
		flow = generate_flow(port_id, flow_group, ATTR_DEFAULT_PRIORITY,
			flow_attrs, flow_items, flow_actions,
			JUMP_ACTION_TABLE, counter, hairpin_queues_num,
			encap_data, decap_data, core_id, unique_data,
			ct_route_id_count, cross_port, /*reply_dir=*/false,
			/*time_to_live=*/-1, /*set_ipv4_addrs=*/true, /*no_frag=*/false,
			/*set_ports=*/true, /*l3_type=*/-1, set_ihl, ports_per_ip, &error);

		if (has_ct || cross_port) {
			rflow = generate_flow(rport_id, flow_group,
				ATTR_DEFAULT_PRIORITY, flow_attrs,
				flow_items, flow_actions, JUMP_ACTION_TABLE,
				counter, hairpin_queues_num, encap_data,
				decap_data, core_id, unique_data,
				ct_route_id_count, cross_port, /*reply_dir=*/true,
				/*time_to_live=*/-1, /*set_ipv4_addrs=*/true,
				/*no_frag=*/false, /*set_ports=*/true, /*l3_type=*/-1,
				set_ihl, ports_per_ip, &rerror);
		}

		if (!counter) {
			first_flow_latency = (double) (rte_get_timer_cycles() - start_batch);
			first_flow_latency /= rte_get_timer_hz();
			/* In millisecond */
			first_flow_latency *= 1000;
			printf(":: First Flow Latency :: Port %d :: First flow "
				"installed in %f milliseconds\n",
				port_id, first_flow_latency);
		}

		if (force_quit)
			counter = end_counter;

		if (has_ct || cross_port) {
			if (!rflow) {
				print_flow_error(rerror);
				printf("#2 counter %d, core_idx %d\n", counter, core_id);
				rte_exit(EXIT_FAILURE,
					"error in creating rflow");
			}

			rflows_list[flow_index] = rflow;
		}

		if (!flow) {
			printf("\n######### Rule id #%d ########\n", counter);
			print_flow_error(error);
			rte_exit(EXIT_FAILURE, "Error in creating flow\n");
		}

		flows_list[flow_index++] = flow;


		/*
		 * Save the insertion rate for rules batch.
		 * Check if the insertion reached the rules
		 * patch counter, then save the insertion rate
		 * for this batch.
		 */
		if (!((counter + 1) % rules_batch)) {
			end_batch = rte_get_timer_cycles();
			delta = (double) (end_batch - start_batch);
			rules_batch_idx = ((counter + 1) / rules_batch) - 1;
			cpu_time_per_batch[rules_batch_idx] = delta / rte_get_timer_hz();
			cpu_time_used += cpu_time_per_batch[rules_batch_idx];
			start_batch = rte_get_timer_cycles();
		}
	}

	/* Print insertion rates for all batches */
	if (dump_iterations)
		print_rules_batches(cpu_time_per_batch);

	printf(":: Port %d :: Core %d boundaries :: start @[%d] - end @[%d]\n",
		port_id, core_id, start_counter, end_counter - 1);

	/* Insertion rate for all rules in one core */
	insertion_rate = ((double) (rules_count_per_core / cpu_time_used) / 1000);
	printf(":: Port %d :: Core %d :: Rules insertion rate -> %f K Rule/Sec\n",
		port_id, core_id, insertion_rate);
	printf(":: Port %d :: Core %d :: The time for creating %d in rules %f seconds\n",
		port_id, core_id, rules_count_per_core, cpu_time_used);

	mc_pool.flows_record.insertion[port_id][core_id] = cpu_time_used;
	if (has_ct || cross_port)
		*rflows_out = rflows_list;
	return flows_list;
}

static void
flows_handler(uint8_t core_id)
{
	struct rte_flow **flows_list;
	struct rte_flow **rflows_list;
	uint16_t nr_ports;
	int port_id;

	nr_ports = rte_eth_dev_count_avail();

	if (rules_batch > rules_count)
		rules_batch = rules_count;

	printf(":: Rules Count per port: %d\n\n", rules_count);

	for (port_id = 0; port_id < nr_ports; port_id++) {
		/* If port outside portmask */
		if (!((ports_mask >> port_id) & 0x1))
			continue;

		/* Insertion part. */
		mc_pool.last_alloc[core_id] = (int64_t)dump_socket_mem(stdout);
		if (has_meter())
			meters_handler(port_id, core_id, METER_CREATE);
		flows_list = insert_flows(port_id, core_id, &rflows_list);
		if (flows_list == NULL)
			rte_exit(EXIT_FAILURE, "Error: Insertion Failed!\n");
		mc_pool.current_alloc[core_id] = (int64_t)dump_socket_mem(stdout);

		/* Deletion part. */
		if (delete_flag) {
			destroy_flows(port_id, core_id, flows_list,
				rflows_list);
			reset_ct_objects(core_id, /*overwrite=*/!final_iter,
							/*reset_dir=*/false, port_id);
			if (has_meter())
				meters_handler(port_id, core_id, METER_DELETE);
		}

		if (cross_port)
			port_id++;
	}
}

static void
dump_used_cpu_time(const char *item,
		uint16_t port, struct used_cpu_time *used_time)
{
	uint32_t i;
	/* Latency: total count of rte rules divided
	 * over max time used by thread between all
	 * threads time.
	 *
	 * Throughput: total count of rte rules divided
	 * over the average of the time cosumed by all
	 * threads time.
	 */
	double insertion_latency_time;
	double insertion_throughput_time;
	double deletion_latency_time;
	double deletion_throughput_time;
	double insertion_latency, insertion_throughput;
	double deletion_latency, deletion_throughput;

	/* Save first insertion/deletion rates from first thread.
	 * Start comparing with all threads, if any thread used
	 * time more than current saved, replace it.
	 *
	 * Thus in the end we will have the max time used for
	 * insertion/deletion by one thread.
	 *
	 * As for memory consumption, save the min of all threads
	 * of last alloc, and save the max for all threads for
	 * current alloc.
	 */

	insertion_latency_time = used_time->insertion[port][0];
	deletion_latency_time = used_time->deletion[port][0];
	insertion_throughput_time = used_time->insertion[port][0];
	deletion_throughput_time = used_time->deletion[port][0];

	i = mc_pool.cores_count;
	while (i-- > 1) {
		insertion_throughput_time += used_time->insertion[port][i];
		deletion_throughput_time += used_time->deletion[port][i];
		if (insertion_latency_time < used_time->insertion[port][i])
			insertion_latency_time = used_time->insertion[port][i];
		if (deletion_latency_time < used_time->deletion[port][i])
			deletion_latency_time = used_time->deletion[port][i];
	}

	insertion_latency = ((double) (mc_pool.rules_count
				/ insertion_latency_time) / 1000);
	deletion_latency = ((double) (mc_pool.rules_count
				/ deletion_latency_time) / 1000);

	insertion_throughput_time /= mc_pool.cores_count;
	deletion_throughput_time /= mc_pool.cores_count;
	insertion_throughput = ((double) (mc_pool.rules_count
				/ insertion_throughput_time) / 1000);
	deletion_throughput = ((double) (mc_pool.rules_count
				/ deletion_throughput_time) / 1000);

	/* Latency stats */
	printf("\n%s\n:: [Latency | Insertion] All Cores :: Port %d :: ",
		item, port);
	printf("Total flows insertion rate -> %f K Rules/Sec\n",
		insertion_latency);
	printf(":: [Latency | Insertion] All Cores :: Port %d :: ", port);
	printf("The time for creating %d rules is %f seconds\n",
		mc_pool.rules_count, insertion_latency_time);

	/* Throughput stats */
	printf(":: [Throughput | Insertion] All Cores :: Port %d :: ", port);
	printf("Total flows insertion rate -> %f K Rules/Sec\n",
		insertion_throughput);
	printf(":: [Throughput | Insertion] All Cores :: Port %d :: ", port);
	printf("The average time for creating %d rules is %f seconds\n",
		mc_pool.rules_count, insertion_throughput_time);

	if (delete_flag) {
	/* Latency stats */
		printf(":: [Latency | Deletion] All Cores :: Port %d :: Total "
			"deletion rate -> %f K Rules/Sec\n",
			port, deletion_latency);
		printf(":: [Latency | Deletion] All Cores :: Port %d :: ",
			port);
		printf("The time for deleting %d rules is %f seconds\n",
			mc_pool.rules_count, deletion_latency_time);

		/* Throughput stats */
		printf(":: [Throughput | Deletion] All Cores :: Port %d :: Total "
			"deletion rate -> %f K Rules/Sec\n",
			port, deletion_throughput);
		printf(":: [Throughput | Deletion] All Cores :: Port %d :: ",
			port);
		printf("The average time for deleting %d rules is %f seconds\n",
			mc_pool.rules_count, deletion_throughput_time);
	}
}

static void
dump_used_mem(uint16_t port)
{
	uint32_t i;
	int64_t last_alloc, current_alloc;
	int flow_size_in_bytes;

	last_alloc = mc_pool.last_alloc[0];
	current_alloc = mc_pool.current_alloc[0];

	i = mc_pool.cores_count;
	while (i-- > 1) {
		if (last_alloc > mc_pool.last_alloc[i])
			last_alloc = mc_pool.last_alloc[i];
		if (current_alloc < mc_pool.current_alloc[i])
			current_alloc = mc_pool.current_alloc[i];
	}

	flow_size_in_bytes = (current_alloc - last_alloc) / mc_pool.rules_count;
	printf("\n:: Port %d :: rte_flow size in DPDK layer: %d Bytes\n",
		port, flow_size_in_bytes);
}

static int
run_rte_flow_handler_cores(void *data __rte_unused)
{
	uint16_t port;
	int lcore_counter = 0;
	int lcore_id = rte_lcore_id();
	int i;

	RTE_LCORE_FOREACH(i) {
		/*  If core not needed return. */
		if (lcore_id == i) {
			printf(":: lcore %d mapped with index %d\n", lcore_id, lcore_counter);
			if (lcore_counter >= (int) mc_pool.cores_count)
				return 0;
			break;
		}
		lcore_counter++;
	}
	lcore_id = lcore_counter;

	if (lcore_id >= (int) mc_pool.cores_count)
		return 0;

	mc_pool.rules_count = rules_count;

	flows_handler(lcore_id);

	/* Only main core to print total results. */
	if (lcore_id != 0)
		return 0;

	/* Make sure all cores finished insertion/deletion process. */
	rte_eal_mp_wait_lcore();

	RTE_ETH_FOREACH_DEV(port) {
		/* If port outside portmask */
		if (!((ports_mask >> port) & 0x1))
			continue;
		if (has_meter())
			dump_used_cpu_time("Meters:",
				port, &mc_pool.meters_record);
		dump_used_cpu_time("Flows:",
			port, &mc_pool.flows_record);
		dump_used_mem(port);
	}

	return 0;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
					signum);
		printf("Error: Stats are wrong due to sudden signal!\n\n");
		force_quit = true;
	}
}

static inline uint16_t
do_rx(struct lcore_info *li, uint16_t rx_port, uint16_t rx_queue)
{
	uint16_t cnt = 0;
	cnt = rte_eth_rx_burst(rx_port, rx_queue, li->pkts, MAX_PKT_BURST);
	li->rx_pkts += cnt;
	return cnt;
}

static inline void
do_tx(struct lcore_info *li, uint16_t cnt, uint16_t tx_port,
			uint16_t tx_queue)
{
	uint16_t nr_tx = 0;
	uint16_t i;

	nr_tx = rte_eth_tx_burst(tx_port, tx_queue, li->pkts, cnt);
	li->tx_pkts  += nr_tx;
	li->tx_drops += cnt - nr_tx;

	for (i = nr_tx; i < cnt; i++)
		rte_pktmbuf_free(li->pkts[i]);
}

/*
 * Method to convert numbers into pretty numbers that easy
 * to read. The design here is to add comma after each three
 * digits and set all of this inside buffer.
 *
 * For example if n = 1799321, the output will be
 * 1,799,321 after this method which is easier to read.
 */
static char *
pretty_number(uint64_t n, char *buf)
{
	char p[6][4];
	int i = 0;
	int off = 0;

	while (n > 1000) {
		sprintf(p[i], "%03d", (int)(n % 1000));
		n /= 1000;
		i += 1;
	}

	sprintf(p[i++], "%d", (int)n);

	while (i--)
		off += sprintf(buf + off, "%s,", p[i]);
	buf[strlen(buf) - 1] = '\0';

	return buf;
}

static void
packet_per_second_stats(void)
{
	struct lcore_info *old;
	struct lcore_info *li, *oli;
	int nr_lines = 0;
	int i;

	old = rte_zmalloc("old",
		sizeof(struct lcore_info) * RTE_MAX_LCORE, 0);
	if (old == NULL)
		rte_exit(EXIT_FAILURE, "No Memory available!\n");

	memcpy(old, lcore_infos,
		sizeof(struct lcore_info) * RTE_MAX_LCORE);

	while (!force_quit) {
		uint64_t total_tx_pkts = 0;
		uint64_t total_rx_pkts = 0;
		uint64_t total_tx_drops = 0;
		uint64_t tx_delta, rx_delta, drops_delta;
		char buf[3][32];
		int nr_valid_core = 0;

		sleep(1);

		if (nr_lines) {
			char go_up_nr_lines[16];

			sprintf(go_up_nr_lines, "%c[%dA\r", 27, nr_lines);
			printf("%s\r", go_up_nr_lines);
		}

		printf("\n%6s %16s %16s %16s\n", "core", "tx", "tx drops", "rx");
		printf("%6s %16s %16s %16s\n", "------", "----------------",
			"----------------", "----------------");
		nr_lines = 3;
		for (i = 0; i < RTE_MAX_LCORE; i++) {
			li  = &lcore_infos[i];
			oli = &old[i];
			if (li->mode != LCORE_MODE_PKT)
				continue;

			tx_delta    = li->tx_pkts  - oli->tx_pkts;
			rx_delta    = li->rx_pkts  - oli->rx_pkts;
			drops_delta = li->tx_drops - oli->tx_drops;
			printf("%6d %16s %16s %16s\n", i,
				pretty_number(tx_delta,    buf[0]),
				pretty_number(drops_delta, buf[1]),
				pretty_number(rx_delta,    buf[2]));

			total_tx_pkts  += tx_delta;
			total_rx_pkts  += rx_delta;
			total_tx_drops += drops_delta;

			nr_valid_core++;
			nr_lines += 1;
		}

		if (nr_valid_core > 1) {
			printf("%6s %16s %16s %16s\n", "total",
				pretty_number(total_tx_pkts,  buf[0]),
				pretty_number(total_tx_drops, buf[1]),
				pretty_number(total_rx_pkts,  buf[2]));
			nr_lines += 1;
		}

		memcpy(old, lcore_infos,
			sizeof(struct lcore_info) * RTE_MAX_LCORE);
	}
}

static int
start_forwarding(void *data __rte_unused)
{
	int lcore = rte_lcore_id();
	int stream_id;
	uint16_t cnt;
	struct lcore_info *li = &lcore_infos[lcore];

	if (!li->mode)
		return 0;

	if (li->mode == LCORE_MODE_STATS) {
		printf(":: started stats on lcore %u\n", lcore);
		packet_per_second_stats();
		return 0;
	}

	while (!force_quit)
		for (stream_id = 0; stream_id < MAX_STREAMS; stream_id++) {
			if (li->streams[stream_id].rx_port == -1)
				continue;

			cnt = do_rx(li,
					li->streams[stream_id].rx_port,
					li->streams[stream_id].rx_queue);
			if (cnt)
				do_tx(li, cnt,
					li->streams[stream_id].tx_port,
					li->streams[stream_id].tx_queue);
		}
	return 0;
}

static void
init_lcore_info(void)
{
	int i, j;
	unsigned int lcore;
	uint16_t nr_port;
	uint16_t queue;
	int port;
	int stream_id = 0;
	int streams_per_core;
	int unassigned_streams;
	int nb_fwd_streams;
	nr_port = rte_eth_dev_count_avail();

	/* First logical core is reserved for stats printing */
	lcore = rte_get_next_lcore(-1, 0, 0);
	lcore_infos[lcore].mode = LCORE_MODE_STATS;

	/*
	 * Initialize all cores
	 * All cores at first must have -1 value in all streams
	 * This means that this stream is not used, or not set
	 * yet.
	 */
	for (i = 0; i < RTE_MAX_LCORE; i++)
		for (j = 0; j < MAX_STREAMS; j++) {
			lcore_infos[i].streams[j].tx_port = -1;
			lcore_infos[i].streams[j].rx_port = -1;
			lcore_infos[i].streams[j].tx_queue = -1;
			lcore_infos[i].streams[j].rx_queue = -1;
			lcore_infos[i].streams_nb = 0;
		}

	/*
	 * Calculate the total streams count.
	 * Also distribute those streams count between the available
	 * logical cores except first core, since it's reserved for
	 * stats prints.
	 */
	nb_fwd_streams = nr_port * RXQ_NUM;
	if ((int)(nb_lcores - 1) >= nb_fwd_streams)
		for (i = 0; i < (int)(nb_lcores - 1); i++) {
			lcore = rte_get_next_lcore(lcore, 0, 0);
			lcore_infos[lcore].streams_nb = 1;
		}
	else {
		streams_per_core = nb_fwd_streams / (nb_lcores - 1);
		unassigned_streams = nb_fwd_streams % (nb_lcores - 1);
		for (i = 0; i < (int)(nb_lcores - 1); i++) {
			lcore = rte_get_next_lcore(lcore, 0, 0);
			lcore_infos[lcore].streams_nb = streams_per_core;
			if (unassigned_streams) {
				lcore_infos[lcore].streams_nb++;
				unassigned_streams--;
			}
		}
	}

	/*
	 * Set the streams for the cores according to each logical
	 * core stream count.
	 * The streams is built on the design of what received should
	 * forward as well, this means that if you received packets on
	 * port 0 queue 0 then the same queue should forward the
	 * packets, using the same logical core.
	 */
	lcore = rte_get_next_lcore(-1, 0, 0);
	for (port = 0; port < nr_port; port++) {
		/* Create FWD stream */
		for (queue = 0; queue < RXQ_NUM; queue++) {
			if (!lcore_infos[lcore].streams_nb ||
				!(stream_id % lcore_infos[lcore].streams_nb)) {
				lcore = rte_get_next_lcore(lcore, 0, 0);
				lcore_infos[lcore].mode = LCORE_MODE_PKT;
				stream_id = 0;
			}
			lcore_infos[lcore].streams[stream_id].rx_queue = queue;
			lcore_infos[lcore].streams[stream_id].tx_queue = queue;
			lcore_infos[lcore].streams[stream_id].rx_port = port;
			lcore_infos[lcore].streams[stream_id].tx_port = port;
			stream_id++;
		}
	}

	/* Print all streams */
	printf(":: Stream -> core id[N]: (rx_port, rx_queue)->(tx_port, tx_queue)\n");
	for (i = 0; i < RTE_MAX_LCORE; i++)
		for (j = 0; j < MAX_STREAMS; j++) {
			/* No streams for this core */
			if (lcore_infos[i].streams[j].tx_port == -1)
				break;
			printf("Stream -> core id[%d]: (%d,%d)->(%d,%d)\n",
				i,
				lcore_infos[i].streams[j].rx_port,
				lcore_infos[i].streams[j].rx_queue,
				lcore_infos[i].streams[j].tx_port,
				lcore_infos[i].streams[j].tx_queue);
		}
}

static void
set_ports_per_ip(void)
{
	/*
	 * Starting by 10 IPs, and when 10 IPs are not enough
	 * increase another 10 IPs.
	 *
	 * Example:
	 * 1M = 10 IPs * 50000 per port
	 */
	int ips_range = 10;
	ports_per_ip = rules_count / ips_range;
	while (ports_per_ip > 65000) {
		ips_range += 10;
		ports_per_ip = rules_count / ips_range;
	}
	rules_batch = rules_count / 10;
	printf("\n::: Number of IPs: %d\n::: Port per IP: %ld\n", ips_range, ports_per_ip);
}

static void
init_port(void)
{
	int ret;
	uint16_t std_queue;
	uint16_t hairpin_queue;
	uint16_t port_id;
	uint16_t nr_ports;
	uint16_t nr_queues;
	struct rte_eth_hairpin_conf hairpin_conf = {
		.peer_count = 1,
	};
	struct rte_eth_conf port_conf = {
		.rx_adv_conf = {
			.rss_conf.rss_hf =
				GET_RSS_HF(),
		}
	};
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_dev_info dev_info;
	bool hp_peer_port;

	nr_queues = RXQ_NUM;
	if (hairpin_queues_num != 0)
		nr_queues = RXQ_NUM + hairpin_queues_num;

	nr_ports = rte_eth_dev_count_avail();
	if (nr_ports == 0)
		rte_exit(EXIT_FAILURE, "Error: no port detected\n");

	mbuf_mp = rte_pktmbuf_pool_create("mbuf_pool",
					TOTAL_MBUF_NUM, MBUF_CACHE_SIZE,
					0, MBUF_SIZE,
					rte_socket_id());
	if (mbuf_mp == NULL)
		rte_exit(EXIT_FAILURE, "Error: can't init mbuf pool\n");

	hp_peer_port = cross_port || (chkpnt_case && (nr_ports > 1));

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
		for (std_queue = 0; std_queue < RXQ_NUM; std_queue++) {
			ret = rte_eth_rx_queue_setup(port_id, std_queue, NR_RXD,
					rte_eth_dev_socket_id(port_id),
					&rxq_conf,
					mbuf_mp);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					":: Rx queue setup failed: err=%d, port=%u\n",
					ret, port_id);
		}

		txq_conf = dev_info.default_txconf;
		for (std_queue = 0; std_queue < TXQ_NUM; std_queue++) {
			ret = rte_eth_tx_queue_setup(port_id, std_queue, NR_TXD,
					rte_eth_dev_socket_id(port_id),
					&txq_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					":: Tx queue setup failed: err=%d, port=%u\n",
					ret, port_id);
		}

		/* Catch all packets from traffic generator. */
		ret = rte_eth_promiscuous_enable(port_id);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				":: promiscuous mode enable failed: err=%s, port=%u\n",
				rte_strerror(-ret), port_id);

		if (hairpin_queues_num != 0) {
			if (hp_peer_port) {
				hairpin_conf.manual_bind = 1;
				hairpin_conf.tx_explicit = 1;
			}
			/*
			 * Configure peer which represents hairpin Tx.
			 * Hairpin queue numbers start after standard queues
			 * (RXQ_NUM and TXQ_NUM).
			 */
			for (hairpin_queue = RXQ_NUM, std_queue = 0;
					hairpin_queue < nr_queues;
					hairpin_queue++, std_queue++) {
				hairpin_conf.peers[0].port = hp_peer_port ?
					port_id ^ 1 : port_id;
				hairpin_conf.peers[0].queue =
					std_queue + TXQ_NUM;
				ret = rte_eth_rx_hairpin_queue_setup(
						port_id, hairpin_queue,
						NR_RXD, &hairpin_conf);
				if (ret != 0)
					rte_exit(EXIT_FAILURE,
						":: Hairpin rx queue setup failed: err=%d, port=%u\n",
						ret, port_id);
			}

			for (hairpin_queue = TXQ_NUM, std_queue = 0;
					hairpin_queue < nr_queues;
					hairpin_queue++, std_queue++) {
				hairpin_conf.peers[0].port = hp_peer_port ?
					port_id ^ 1 : port_id;
				hairpin_conf.peers[0].queue =
					std_queue + RXQ_NUM;
				ret = rte_eth_tx_hairpin_queue_setup(
						port_id, hairpin_queue,
						NR_TXD, &hairpin_conf);
				if (ret != 0)
					rte_exit(EXIT_FAILURE,
						":: Hairpin tx queue setup failed: err=%d, port=%u\n",
						ret, port_id);
			}
		}
		ret = rte_eth_dev_start(port_id);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"rte_eth_dev_start:err=%d, port=%u\n",
				ret, port_id);

		printf(":: initializing port: %d done\n", port_id);
	}
	if (hp_peer_port)
		for (port_id = 0; port_id < nr_ports; ++port_id) {
			ret = rte_eth_hairpin_bind(port_id, port_id ^ 1);
			if (ret < 0) {
				rte_exit(EXIT_FAILURE,
					"Error during binding hairpin Tx port %u to %u: %s\n",
						port_id, port_id ^ 1,
						rte_strerror(-ret));
			}
		}
}

int
main(int argc, char **argv)
{
	int ret;
	uint16_t port;
	struct rte_flow_error error;
	uint64_t iter;
	delay_ins = 0;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "EAL init failed\n");

	force_quit = false;
	dump_iterations = false;
	rules_count = DEFAULT_RULES_COUNT;
	rules_batch = DEFAULT_RULES_BATCH;
	delete_flag = false;
	dump_socket_mem_flag = false;
	flow_group = DEFAULT_GROUP;
	unique_data = false;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	argc -= ret;
	argv += ret;
	if (argc > 1)
		args_parse(argc, argv);

	init_port();

	nb_lcores = rte_lcore_count();
	if (nb_lcores <= 1)
		rte_exit(EXIT_FAILURE, "This app needs at least two cores\n");

	printf(":: Flows Count per port: %d\n\n", rules_count);

	set_ports_per_ip();

	has_ct = has_ct_action();

	if (has_meter())
		create_meter_profile();

	if (chkpnt_case) {
		printf("here");
		insert_chkpnt_pps_static_flows(0);
		insert_chkpnt_pps_static_flows(1);
	} else if (ct_route_id_count) {
		printf("here as well");
		create_ct_static_flows(0);
		create_ct_static_flows(1);
	}

	final_iter = false;
	for (iter = 0; iter < nb_iterations; iter++) {
		printf("\n\n############### Iteration #%ld ###############\n", iter);
		if (iter == nb_iterations - 1) {
			delete_flag = !enable_fwd;
			final_iter = true;
		}
		rte_eal_mp_remote_launch(run_rte_flow_handler_cores, NULL, CALL_MAIN);
		ct_created = true;
	}

	if (enable_fwd) {
		init_lcore_info();
		rte_eal_mp_remote_launch(start_forwarding, NULL, CALL_MAIN);
	}
	if (has_meter() && delete_flag)
		destroy_meter_profile();

#ifndef BING
	RTE_ETH_FOREACH_DEV(port)
		rte_flow_flush(port, &error);
	RTE_ETH_FOREACH_DEV(port) {
		if (rte_eth_dev_stop(port) != 0)
			printf("Failed to stop device on port %u\n", port);
		rte_eth_dev_close(port);
	}
#else
	RTE_ETH_FOREACH_DEV(port) {
		rte_flow_flush(port, &error);
		if (rte_eth_dev_stop(port) != 0)
			printf("Failed to stop device on port %u\n", port);
		rte_eth_dev_close(port);
	}
#endif
	printf("\nBye ...\n");
	return 0;
}
