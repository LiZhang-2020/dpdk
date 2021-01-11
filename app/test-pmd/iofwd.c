/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <arpa/inet.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_memcpy.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>
#include <rte_flow.h>
#include <rte_sft.h>

#include "testpmd.h"

static void
tsft_print_mbuf_status(const struct rte_mbuf *mbuf,
		       const struct rte_sft_flow_status *status,
		       struct rte_sft_error *error)
{
	struct rte_sft_7tuple stpl;
	struct sft_mbuf_info mif = { .m = mbuf, };
	char l3_src[INET6_ADDRSTRLEN], l3_dst[INET6_ADDRSTRLEN];

	sft_parse_mbuf(&mif, error);
	rte_sft_mbuf_stpl(&mif, status->zone, &stpl, error);
	if (!stpl.flow_5tuple.is_ipv6) {
		inet_ntop(AF_INET, &stpl.flow_5tuple.ipv4.src_addr,
			  l3_src, sizeof(l3_src));
		inet_ntop(AF_INET, &stpl.flow_5tuple.ipv4.dst_addr,
			  l3_dst, sizeof(l3_dst));
	} else {
		inet_ntop(AF_INET6, &stpl.flow_5tuple.ipv6.src_addr,
			  l3_src, sizeof(l3_src));
		inet_ntop(AF_INET6, &stpl.flow_5tuple.ipv6.dst_addr,
			  l3_dst, sizeof(l3_dst));
	}
	printf("%u: %s.%u > %s.%u %s zone %d fid %d\n", mbuf->port,
		l3_src, rte_be_to_cpu_16(stpl.flow_5tuple.src_port),
		l3_dst, rte_be_to_cpu_16(stpl.flow_5tuple.dst_port),
		stpl.flow_5tuple.proto == IPPROTO_TCP ? "tcp" :
					  IPPROTO_UDP ? "udp" : "err",
		status->zone_valid ? status->zone : 0,
		status->fid);
}

static void
reverse_stpl(const struct fwd_stream *fs, struct rte_sft_7tuple *rstpl,
	     const struct rte_sft_7tuple *stpl)
{
	rstpl->flow_5tuple.is_ipv6 = stpl->flow_5tuple.is_ipv6;
	rstpl->flow_5tuple.proto = stpl->flow_5tuple.proto;
	rstpl->flow_5tuple.ipv4.src_addr = stpl->flow_5tuple.ipv4.dst_addr;
	rstpl->flow_5tuple.ipv4.dst_addr = stpl->flow_5tuple.ipv4.src_addr;
	rstpl->flow_5tuple.src_port = stpl->flow_5tuple.dst_port;
	rstpl->flow_5tuple.dst_port = stpl->flow_5tuple.src_port;
	rstpl->zone = stpl->zone;
	rstpl->port_id = fs->tx_port;
}

static uint16_t
sft_process_rx(const struct fwd_stream *fs, uint16_t num, struct rte_mbuf **m_in)
{
	int ret;
	uint16_t i;
	struct rte_mbuf *m_out = NULL;
	struct rte_sft_error error;

	for (i = 0; i < num; i++) {
		struct rte_sft_flow_status sft_status = {0, };
		struct sft_mbuf_info mif = { .m = m_in[i] };
		struct rte_sft_7tuple stpl, rstpl;

		sft_parse_mbuf(&mif, &error);
		ret = rte_sft_process_mbuf(0, m_in[i], &m_out,
					   &sft_status, &error);
		tsft_print_mbuf_status(m_out, &sft_status, &error);
		if (sft_status.fid) {
			continue;
		}
		if (!sft_status.zone_valid) {
			m_out = NULL;
			ret = rte_sft_process_mbuf_with_zone
					(0, m_in[i], 0xcafe, &m_out,
					 &sft_status, &error);
			if (ret) exit(-1);
			tsft_print_mbuf_status(m_out, &sft_status, &error);
		}
		if (!sft_status.fid) {
			rte_sft_mbuf_stpl(&mif, sft_status.zone, &stpl, &error);
			reverse_stpl(fs, &rstpl, &stpl);
			rte_sft_flow_activate(0, 0xcafe, m_in[i],
			&rstpl, 11, NULL, 0, NULL, 0, 0, &m_out,
			&sft_status, &error);
			tsft_print_mbuf_status(m_out, &sft_status, &error);
		}
	};

	return i;
}

/*
 * Forwarding of packets in I/O mode.
 * Forward packets "as-is".
 * This is the fastest possible forwarding operation, as it does not access
 * to packets data.
 */
static void
pkt_burst_io_forward(struct fwd_stream *fs)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	uint16_t nb_rx;
	uint16_t nb_tx;
	uint32_t retry;
	uint64_t start_tsc = 0;

	get_start_cycles(&start_tsc);

	/*
	 * Receive a burst of packets and forward them.
	 */
	nb_rx = rte_eth_rx_burst(fs->rx_port, fs->rx_queue,
			pkts_burst, nb_pkt_per_burst);
	inc_rx_burst_stats(fs, nb_rx);
	if (unlikely(nb_rx == 0))
		return;
	fs->rx_packets += nb_rx;

	if (sft) {
		nb_rx = sft_process_rx(fs, nb_rx, pkts_burst);
	}

	nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue,
			pkts_burst, nb_rx);
	/*
	 * Retry if necessary
	 */
	if (unlikely(nb_tx < nb_rx) && fs->retry_enabled) {
		retry = 0;
		while (nb_tx < nb_rx && retry++ < burst_tx_retry_num) {
			rte_delay_us(burst_tx_delay_time);
			nb_tx += rte_eth_tx_burst(fs->tx_port, fs->tx_queue,
					&pkts_burst[nb_tx], nb_rx - nb_tx);
		}
	}
	fs->tx_packets += nb_tx;
	inc_tx_burst_stats(fs, nb_tx);
	if (unlikely(nb_tx < nb_rx)) {
		fs->fwd_dropped += (nb_rx - nb_tx);
		do {
			rte_pktmbuf_free(pkts_burst[nb_tx]);
		} while (++nb_tx < nb_rx);
	}

	get_end_cycles(fs, start_tsc);
}

struct fwd_engine io_fwd_engine = {
	.fwd_mode_name  = "io",
	.port_fwd_begin = NULL,
	.port_fwd_end   = NULL,
	.packet_fwd     = pkt_burst_io_forward,
};
