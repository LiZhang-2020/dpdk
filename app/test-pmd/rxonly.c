/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_net.h>
#include <rte_flow.h>

#include "testpmd.h"

/*
 * Process a burst of received packets from same stream.
 */
static void
rxonly_forward_stream(struct fwd_stream *fs, uint16_t nb_rx,
		      struct rte_mbuf **pkts_burst)
{
	RTE_SET_USED(fs);
	rte_pktmbuf_free_bulk(pkts_burst, nb_rx);
}


/*
 * Wrapper of real fwd engine.
 */
static void
pkt_burst_receive(struct fwd_stream *fs)
{
	return do_burst_fwd(fs, rxonly_forward_stream);
}

struct fwd_engine rx_only_engine = {
	.fwd_mode_name  = "rxonly",
	.port_fwd_begin = NULL,
	.port_fwd_end   = NULL,
	.packet_fwd     = pkt_burst_receive,
};
