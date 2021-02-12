/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <rte_byteorder.h>
#include <rte_lhash.h>
#include <rte_tcp.h>
#include <rte_malloc.h>
#include <arpa/inet.h>
#include "rte_sft.h"
#include "sft_utils.h"

#ifndef SFT_CT_DEBUG
#define SFT_CT_DEBUG 1
#endif
struct tcp_segment {
	uint32_t head; /**< head sequence */
	uint32_t tail; /**< tail sequence */
};

/*
 * <=====prev====><---data--->
 */
static inline bool
tcp_seg_tangent(const struct tcp_segment *data, const struct tcp_segment *prev)
{
	return data->head - prev->tail == 1;
}

/*
 *  h                        t
 *  |--- data ---------------|
 *                 |=====next=====|
 *                 h              t
 * @return
 * number of shared sequences in @data suffix and @next prefix
 */
static inline uint32_t
tcp_seg_fore_cross(const struct tcp_segment *data,
		   const struct tcp_segment *next)
{
	return data->head < next->head && data->tail > next->head &&
	       data->tail <= next->tail ? data->tail - next->head + 1 : 0;
}

/*
 * h                         t
 * |========prev=============|
 *                      |---------data---------|
 *                      h                      t
 */
static inline long
tcp_seg_aft_cross(const struct tcp_segment *data,
		  const struct tcp_segment *prev)
{
	return tcp_seg_fore_cross(prev, data);
}

/*
 * |-----data-----|   |====next=====|
 */
static inline bool
tcp_seg_behind(const struct tcp_segment *data, const struct tcp_segment *next)
{
	return data->tail + 1 < next->head;
}

/*
 * |-----------s------------------|
 *       |------data-----|
 */
static inline bool
tcp_seg_contained(const struct tcp_segment *data, const struct tcp_segment *s)
{
	return data->head >= s->head && data->tail <= s->tail;
}

static inline bool
tcp_seg_match(const struct tcp_segment *a, const struct tcp_segment *b)
{
	return a->head == b->head && a->tail == b->tail;
}

/*
 * segment @a starts before segment @b OR
 * in case @a and @b start at the same location, @a has more data
 *
 * |--------a-------|       |------a-------|
 *       |-------b-------|  |-----b-----|
 */
static bool
tcp_seg_before(const struct tcp_segment *a, const struct tcp_segment *b)
{
	return (a->head < b->head) ||
	       ((a->head == b->head) && (a->tail > b->tail));
}

/*
 * @b extends @a if
 */
static bool
tcp_seg_extend_right(const struct tcp_segment *a, const struct tcp_segment *b)
{
	return (b->tail > a->tail) && !(b->head > a->tail);
}

static bool
tcp_seg_extend_left(const struct tcp_segment *a, const struct tcp_segment *b)
{
	return (b->head < a->head) && !(b->tail < a->head);
}

struct tcp_stashed_segment {
	const struct rte_mbuf *mbuf; /**< out-of-order packet */
	struct tcp_segment seg;
	CIRCLEQ_ENTRY(tcp_stashed_segment) chain; /**< linked list entry */
};
struct tcp_stash {
	struct tcp_segment missing; /**< first missing segment */
	struct tcp_segment cont_seg; /**< contiguous stashed segment */
	CIRCLEQ_HEAD(, tcp_stashed_segment) stash;
};
struct ct_ctx {
	enum rte_tcp_state sock_state; /**< sender socket state. estimated */
	/**< max sender sequence.
	 * updated by sender
	 * can incremented in bursts before ACK
	 */
	uint32_t max_sent_seq;
	uint32_t ack_seq; /**< ACK sequence - updated by peer */
	struct tcp_segment rcv_wnd; /**< updated by peer each ACK */
	/* TCP options */
	uint16_t max_seg_size;
	uint8_t wnd_scale;
	uint8_t sack_permitted:1;
	struct tcp_stash *stash; /**< for out-of-order packets */
#ifdef SFT_CT_DEBUG
	uint32_t syn_seq;
#endif
};
struct sft_tcp_ct {
	uint32_t fid;
	uint32_t pkt_num;
	struct ct_ctx conn_ctx[2];
	enum sft_ct_state conn_state;
};

/*
 * @return
 * 0 - success, non-zero otherwise
 */
static int
tcp_parse_options(const struct rte_tcp_hdr *tcp, struct ct_ctx *sender)
{
	const uint8_t *tcp_opt = (typeof(tcp_opt))tcp + RTE_TCP_MIN_HDR_LEN;
	const uint8_t *tcp_data = (typeof(tcp_data))tcp + rte_tcp_hdr_len(tcp);
	int ret;
parse:
	switch ((enum rte_tcp_opt)tcp_opt[0]) {
	default:
		RTE_SFT_LOG(ERR, "invalid TCP option %u\n", tcp_opt[0]);
		ret = -1;
		goto out;
	case RTE_TCP_OPT_END:
		ret = 0;
		goto out;
	case RTE_TCP_OPT_NOP:
		tcp_opt++;
		break;
	case RTE_TCP_OPT_MSS:
		sender->max_seg_size = ((uint16_t)tcp_opt[2]) << 8 | tcp_opt[3];
		tcp_opt += tcp_opt[1];
		break;
	case RTE_TCP_OPT_WND_SCALE:
		sender->wnd_scale = tcp_opt[2];
		tcp_opt += tcp_opt[1];
		break;
	case RTE_TCP_OPT_SACK_PERMITTED:
		sender->sack_permitted = 1;
		tcp_opt += tcp_opt[1];
		break;
	case RTE_TCP_OPT_SACK:
		RTE_SFT_LOG(ERR, "TCP option SACK not implemented\n");
		ret = -1;
		break;
	case RTE_TCP_OPT_TIMESTAMP:
		tcp_opt += tcp_opt[1];
		break;
	}
	if (tcp_opt == tcp_data) {
		ret = 0;
		goto out;
	} else if (tcp_opt < tcp_data) {
		goto parse;
	} else {
		RTE_SFT_LOG(ERR, "missed TCP END option\n");
		ret = -1;
	}
out:
	return ret;
}

static enum sft_ct_error
sft_tcp_handle_syn(struct sft_tcp_ct *ct, const struct rte_tcp_hdr *tcp,
		   struct ct_ctx *sender, struct ct_ctx *peer)
{
	switch (peer->sock_state) {
	case RTE_TCP_CLOSE:
	case RTE_TCP_SYN_SENT:
		break;
	default:
		goto err;
	}
	switch (sender->sock_state) {
	case RTE_TCP_CLOSE:
	case RTE_TCP_SYN_SENT:
	case RTE_TCP_SYN_RECV:
		sender->max_sent_seq = rte_be_to_cpu_32(tcp->sent_seq);
		sender->sock_state =
			tcp->ack ? RTE_TCP_SYN_RECV : RTE_TCP_SYN_SENT;
#ifdef SFT_CT_DEBUG
		sender->syn_seq = sender->max_sent_seq;
#endif
		break;
	default:
		goto err;
	}
	if (rte_tcp_hdr_len(tcp) > RTE_TCP_MIN_HDR_LEN)
		if (tcp_parse_options(tcp, sender))
			goto err;
	ct->conn_state = SFT_CT_STATE_ESTABLISHING;
	return SFT_CT_ERROR_NONE;
err:
	ct->conn_state = SFT_CT_STATE_ERROR;
	return SFT_CT_ERROR_TCP_SYN;
}

static enum sft_ct_error
sft_tcp_handle_fin(struct sft_tcp_ct *ct, const struct rte_tcp_hdr *tcp,
		   struct ct_ctx *sender, struct ct_ctx *peer)
{
	RTE_SET_USED(ct);
	RTE_SET_USED(tcp);
	sender->sock_state = RTE_TCP_CLOSING;
	if (peer->sock_state == RTE_TCP_CLOSING)
		ct->conn_state = SFT_CT_STATE_CLOSING;
	sender->max_sent_seq++;
	return SFT_CT_ERROR_NONE;
}

static enum sft_ct_error
sft_tcp_handle_rst(struct sft_tcp_ct *ct, const struct rte_tcp_hdr *tcp,
		   struct ct_ctx *sender, struct ct_ctx *peer)
{
	RTE_SET_USED(tcp);
	RTE_SET_USED(peer);
	sender->sock_state = RTE_TCP_CLOSE;
	ct->conn_state = SFT_CT_STATE_CLOSING;
	sender->max_sent_seq++;
	return SFT_CT_ERROR_NONE;
}

static inline void
tcp_reset_ct_window(struct ct_ctx *sender, struct ct_ctx *peer,
		    const struct rte_tcp_hdr *tcp)
{
	uint32_t wlen = (rte_be_to_cpu_16(tcp->rx_win) << sender->wnd_scale);
	peer->rcv_wnd.head = peer->ack_seq;
	peer->rcv_wnd.tail = peer->ack_seq + 1 + wlen;
}

static enum sft_ct_error
sft_tcp_handle_ack(struct sft_tcp_ct *ct, const struct rte_tcp_hdr *tcp,
		   struct ct_ctx *sender, struct ct_ctx *peer)
{
	uint32_t ack_seq = rte_be_to_cpu_32(tcp->recv_ack);
	enum sft_ct_error ct_error;
	if (ack_seq <= peer->max_sent_seq) {
		/* retransmit - do not change state */
	} else if (ack_seq - peer->max_sent_seq > 1) {
		ct_error = SFT_CT_ERROR_TCP_ACK_SEQ;
		peer->ack_seq = ack_seq;
		goto err;
	}
	/*
	 * If sender posts several segments in a burst,
	 * received ACK can be less than the last transmitted sequence.
	 */
	peer->ack_seq = ack_seq;
	switch (sender->sock_state) {
	case RTE_TCP_SYN_SENT:
		if (tcp->tcp_flags == RTE_TCP_ACK_FLAG) {
			sender->sock_state = RTE_TCP_ESTABLISHED;
			peer->sock_state = RTE_TCP_ESTABLISHED;
			ct->conn_state = SFT_CT_STATE_TRACKING;
		} else {
			ct_error = SFT_CT_ERROR_TCP_SYN;
			goto err;
		}
		break;
	case RTE_TCP_CLOSE:
	case RTE_TCP_SYN_RECV:
		if (tcp->tcp_flags == (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG)) {
			sender->sock_state = RTE_TCP_SYN_RECV;
			ct->conn_state = SFT_CT_STATE_ESTABLISHING;
		} else {
			ct_error = SFT_CT_ERROR_TCP_SYN;
			goto err;
		}
		break;
	case RTE_TCP_ESTABLISHED:
		/* fall through */
	case RTE_TCP_CLOSING:
		if (tcp->fin) {
			sender->sock_state = RTE_TCP_CLOSING;
			ct->conn_state = SFT_CT_STATE_CLOSING;
		}
		break;
	default:
		RTE_SFT_LOG(ERR, "unknown ACK transition\n");
		ct->conn_state = SFT_CT_STATE_ERROR;
		ct_error = SFT_CT_ERROR_BAD_PROTOCOL;
		RTE_VERIFY(false);
	}
	switch (peer->sock_state) {
	case RTE_TCP_CLOSING:
		if (tcp->tcp_flags == RTE_TCP_ACK_FLAG) {
			if (sender->sock_state == RTE_TCP_CLOSING)
				ct->conn_state = SFT_CT_STATE_CLOSING;
		}
		break;
	default:
		break;
	}
	tcp_reset_ct_window(sender, peer, tcp);
	return SFT_CT_ERROR_NONE;
err:
	RTE_SFT_LOG(WARNING, "invalid ACK transition\n");
	ct->conn_state = SFT_CT_STATE_ERROR;
	return ct_error;
}

/*
 * @return
 * number of packets in contiguous TCP segment
 * returned packets can span larger TCP segment
 * than the original missing segment
 */
static uint32_t
tcp_stashed_pkt_num(const struct tcp_stash *stash)
{
	uint32_t num = 0;
	typeof(stash->stash) *head = &stash->stash;
	struct tcp_segment seg;
	const struct tcp_stashed_segment *var, *next;
	seg.head = CIRCLEQ_FIRST(head)->seg.head;
	if (CIRCLEQ_FIRST(head) == CIRCLEQ_LAST(head)) {
		num = 1;
		var = CIRCLEQ_FIRST(head);
		goto out;
	}
	CIRCLEQ_FOREACH(var, head, chain) {
		num++;
		next = CIRCLEQ_NEXT(var, chain);
		if (tcp_seg_behind(&var->seg, &next->seg))
			break;
	}
out:
	seg.tail = var->seg.tail;
	RTE_VERIFY(tcp_seg_contained(&stash->missing, &seg));
	return num;
}

static int
tcp_create_stash(uint32_t tcp_seq, struct ct_ctx *sender)
{
	struct tcp_stash *stash;
	if (!sender->stash) {
		stash = rte_calloc("sft_tcp_stash", 1, sizeof(*stash), 0);
		if (!stash)
			return -ENOMEM;
		CIRCLEQ_INIT(&stash->stash);
		sender->stash = stash;
	} else {
		stash = sender->stash;
	}
	stash->missing.head = sender->max_sent_seq + 1;
	stash->missing.tail = tcp_seq - 1;
	return 0;
}

static void
tcp_discard_stashed_segment(struct tcp_stashed_segment *stashed)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	rte_mbuf_raw_free((struct rte_mbuf *)stashed->mbuf);
#pragma GCC diagnostic pop
	rte_free(stashed);
}

/*
 * mbuf with overlapping segments can be safely released because
 * SFT TCP CT already updated peer receive window
 */
static void
tcp_stash_sort(struct tcp_stash *stash, struct tcp_stashed_segment *new)
{
	typeof(stash->stash) *head = &stash->stash;
	struct tcp_stashed_segment *var;
	if (CIRCLEQ_EMPTY(head)) {
		CIRCLEQ_INSERT_HEAD(head, new, chain);
		stash->cont_seg = new->seg;
		return;
	}
	CIRCLEQ_FOREACH(var, head, chain) {
		if (tcp_seg_match(&var->seg, &new->seg)) {
			tcp_discard_stashed_segment(new);
			return;
		} else if (tcp_seg_before(&new->seg, &var->seg)) {
			CIRCLEQ_INSERT_BEFORE(head, var, new, chain);
			goto rescan;
		}
	}
	CIRCLEQ_INSERT_TAIL(head, new, chain);
rescan:
	/* remove overlapping segments */
	CIRCLEQ_FOREACH(var, head, chain) {
		if (var == new)
			continue;
		if (tcp_seg_contained(&var->seg, &new->seg)) {
			CIRCLEQ_REMOVE(head, var, chain);
			tcp_discard_stashed_segment(var);
			goto rescan;
		} else if (tcp_seg_contained(&new->seg, &var->seg)) {
			CIRCLEQ_REMOVE(head, new, chain);
			tcp_discard_stashed_segment(new);
			break;
		}
	};
	if (tcp_seg_extend_right(&stash->cont_seg, &new->seg))
		stash->cont_seg.tail = new->seg.tail;
	if (tcp_seg_extend_left(&stash->cont_seg, &new->seg))
		stash->cont_seg.head = new->seg.head;
}

static int
tcp_stash_mbuf(const struct rte_mbuf *mbuf, const struct tcp_segment *segment,
	       struct ct_ctx *sender)
{
	struct tcp_stash *stash = sender->stash;
	struct tcp_stashed_segment
		*new = rte_malloc("sft_seq_stash", sizeof(*new), 0);
	if (!new)
		return -ENOMEM;
	new->mbuf = mbuf;
	new->seg = *segment;
	tcp_stash_sort(stash, new);
	return tcp_seg_contained(&stash->cont_seg, &stash->missing) ? 0 :
	       -ENODATA;
}

static enum sft_ct_error
sft_tcp_handle_data(struct sft_mbuf *smb, struct rte_sft_mbuf_info *mif,
		    struct ct_ctx *sender, struct rte_sft_flow_status *status)
{
	long ret;
	int err;
	enum sft_ct_error ct_error = SFT_CT_ERROR_NONE;
	uint32_t tcp_seq = rte_be_to_cpu_32(mif->tcp->sent_seq);
	struct tcp_stashed_segment *stashed_head;
	struct tcp_segment segment = {
		.head = tcp_seq, .tail = tcp_seq + mif->data_len - 1,
	};
	if (tcp_seg_contained(&segment, &sender->rcv_wnd))
		goto wnd_ok;
	if (tcp_seg_behind(&segment, &sender->rcv_wnd))
		return SFT_CT_ERROR_NONE;
	else if (tcp_seg_behind(&sender->rcv_wnd, &segment))
		return SFT_CT_ERROR_TCP_RCV_WND_SIZE;
	ret = tcp_seg_fore_cross(&segment, &sender->rcv_wnd);
	if (ret > 0) {
		/* |--segment------|
		 *             |=====rcv wnd===|
		 **/
		segment.head = sender->rcv_wnd.head;
		status->data_offset = sender->rcv_wnd.head - tcp_seq;
	}
	ret = tcp_seg_aft_cross(&segment, &sender->rcv_wnd);
	if (ret > 0) {
		/* |====rcv wnd========|
		 *              |--------segment---|
		 **/
		status->data_offset = -(segment.tail - sender->rcv_wnd.tail);
		segment.tail = sender->rcv_wnd.tail;
	}
wnd_ok:
	/* segment within receive window */
	if (likely(!sender->stash)) {
		const struct tcp_segment topmost = {
			.head = 0, .tail = sender->max_sent_seq,
		};
		if (likely(tcp_seg_tangent(&segment, &topmost))) {
			RTE_VERIFY(segment.tail - sender->max_sent_seq ==
				   mif->data_len);
			sender->max_sent_seq = segment.tail;
		} else {
			err = tcp_create_stash(segment.head, sender);
			if (err) {
				rte_errno = -err;
				return SFT_CT_ERROR_SYS;
			}
			status->out_of_order = 1;
			goto stash;
		}
	} else {
stash:
		err = tcp_stash_mbuf(smb->m_in, &segment, sender);
		switch (err) {
		case 0:
			stashed_head = CIRCLEQ_FIRST(&sender->stash->stash);
			CIRCLEQ_REMOVE(&sender->stash->stash, stashed_head,
				       chain);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
			smb->m_out = (void *)stashed_head->mbuf;
#pragma GCC diagnostic pop
			status->out_of_order = 0;
			status->nb_in_order_mbufs =
				tcp_stashed_pkt_num(sender->stash);
			break;
		case ENODATA:
			smb->m_out = NULL;
			break;
		case ENOMEM:
			ct_error = SFT_CT_ERROR_SYS;
			break;
		}
		rte_errno = -err;
	}
	return ct_error;
}

static bool
sft_tcp_validate_flags(const struct rte_tcp_hdr *tcp)
{
	if (tcp->tcp_flags == UINT8_MAX)
		return false;
	else if (tcp->syn)
		return tcp->tcp_flags > (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG) ?
		       false : true;
	else if (tcp->fin)
		return tcp->tcp_flags > (RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG) ?
		       false : true;
	else if (tcp->rst)
		return tcp->tcp_flags > (RTE_TCP_RST_FLAG | RTE_TCP_ACK_FLAG) ?
		       false : true;
	return true;
}

/*
 *
 */
static void
sft_basic_tcp_valiation(struct sft_tcp_ct *ct, const struct rte_tcp_hdr *tcp,
			struct ct_ctx *sender, struct ct_ctx *peer,
			int data_len, struct rte_sft_flow_status *status)
{
	RTE_SET_USED(ct);
	RTE_SET_USED(sender);
	RTE_SET_USED(peer);
	RTE_SET_USED(data_len);
	if (!sft_tcp_validate_flags(tcp))
		status->ct_error = SFT_CT_ERROR_TCP_FLAGS;
	else if ((tcp->syn || tcp->fin || tcp->rst) && data_len)
		status->ct_error = SFT_CT_ERROR_BAD_PROTOCOL;
	else
		status->ct_error = SFT_CT_ERROR_NONE;
}

static void
sft_drain_stash(struct ct_ctx *ctx)
{
	typeof(ctx->stash->stash) *head = &ctx->stash->stash;
	while (!CIRCLEQ_EMPTY(head)) {
		struct tcp_stashed_segment *var = CIRCLEQ_FIRST(head);
		CIRCLEQ_REMOVE(head, var, chain);
		tcp_discard_stashed_segment(var);
	}
}

static void
tcp_log_header(const struct sft_mbuf *smb, const struct rte_sft_mbuf_info *mif,
	       const struct sft_lib_entry *entry,
	       struct rte_sft_flow_status *status, uint32_t data_len)
{
	char initiator[INET6_ADDRSTRLEN], peer[INET6_ADDRSTRLEN];
	const void *src, *dst;
	int af;
	const struct rte_sft_5tuple *tpl = &entry->stpl[0].flow_5tuple;
	const struct sft_tcp_ct *ct = entry->ct_obj;
	if (mif->eth_type == RTE_ETHER_TYPE_IPV4) {
		af = AF_INET;
		src = (const void *)&tpl->ipv4.src_addr;
		dst = (const void *)&tpl->ipv4.dst_addr;
	} else {
		af = AF_INET6;
		src = (const void *)tpl->ipv6.src_addr;
		dst = (const void *)tpl->ipv6.dst_addr;
	}
	inet_ntop(af, src, initiator, sizeof(initiator));
	inet_ntop(af, dst, peer, sizeof(peer));
	RTE_SFT_LOG(DEBUG, "sft ct:%u:%u:%s %s %s fid=%u data_len=%u\n",
		    ct->pkt_num, smb->m_in->port, initiator,
		    status->initiator ? ">" : "<", peer, entry->fid, data_len);
}

static __always_inline void
tcp_dbg_log_header(const struct sft_mbuf *smb,
		   const struct rte_sft_mbuf_info *mif,
		   const struct sft_lib_entry *entry,
		   struct rte_sft_flow_status *status, uint32_t data_len)
{
	if (rte_log_can_log(sft_logtype, RTE_LOG_DEBUG))
		tcp_log_header(smb, mif, entry, status, data_len);
}

int
sft_tcp_drain_mbuf(struct sft_lib_entry *entry,
		   const struct rte_mbuf **mbuf_out, uint16_t nb_out,
		   struct rte_sft_flow_status *status)
{
	uint16_t i;
	struct sft_tcp_ct *ct = entry->ct_obj;
	struct ct_ctx
		*sender = status->initiator ? ct->conn_ctx : ct->conn_ctx + 1;
	typeof(sender->stash->stash) *stash = &sender->stash->stash;
	bool loop;
	if (CIRCLEQ_EMPTY(stash)) {
		status->out_of_order = 0;
		status->nb_in_order_mbufs = 0;
		return 0;
	}
	for (i = 0, loop = true; i < nb_out && loop; i++) {
		struct tcp_stashed_segment *cur = CIRCLEQ_FIRST(stash);
		mbuf_out[i] = cur->mbuf;
		sender->max_sent_seq = cur->seg.tail;
		CIRCLEQ_REMOVE(stash, cur, chain);
		if (!CIRCLEQ_EMPTY(stash)) {
			struct tcp_stashed_segment *next;
			next = CIRCLEQ_FIRST(stash);
			status->out_of_order =
				tcp_seg_behind(&cur->seg, &next->seg);
			loop = next && !status->out_of_order;
		}
		rte_free(cur);
	}
	status->nb_in_order_mbufs -= i;
	if (CIRCLEQ_EMPTY(stash)) {
		rte_free(sender->stash);
		sender->stash = NULL;
		RTE_VERIFY(!status->nb_in_order_mbufs);
	}
	return i;
}

void
sft_tcp_track_conn(struct sft_mbuf *smb, struct rte_sft_mbuf_info *mif,
		   const struct sft_lib_entry *entry,
		   struct rte_sft_flow_status *status,
		   struct rte_sft_error *error)
{
	struct ct_ctx *sender;
	struct ct_ctx *peer;
	struct sft_tcp_ct *ct = entry->ct_obj;
	const struct rte_tcp_hdr *tcp = mif->tcp;
	enum sft_ct_state entry_conn_state = ct->conn_state;
#ifdef SFT_CT_DEBUG
	struct sft_tcp_ct dbg_ct = *ct;
#endif
	ct->pkt_num++;
	if (status->initiator) {
		sender = ct->conn_ctx;
		peer = ct->conn_ctx + 1;
	} else {
		sender = ct->conn_ctx + 1;
		peer = ct->conn_ctx;
	}
	sft_basic_tcp_valiation(ct, tcp, sender, peer, mif->data_len, status);
	if (status->ct_error)
		goto ct_err;
	tcp_dbg_log_header(smb, mif, entry, status, mif->data_len);
	if (tcp->syn) {
		status->ct_error = sft_tcp_handle_syn(ct, tcp, sender, peer);
		RTE_SFT_LOG(DEBUG, "    SYN:%u:0\n", sender->max_sent_seq);
		if (status->ct_error)
			goto ct_err;
	} else if (tcp->fin) {
		status->ct_error = sft_tcp_handle_fin(ct, tcp, sender, peer);
		RTE_SFT_LOG(DEBUG, "    FIN\n");
		if (status->ct_error)
			goto ct_err;
	} else if (tcp->rst) {
		status->ct_error = sft_tcp_handle_rst(ct, tcp, sender, peer);
		RTE_SFT_LOG(DEBUG, "    RST\n");
		if (status->ct_error)
			goto ct_err;
	}
	/*
	 * check ACK flag before data.
	 * if packet will be stashed due to out-of-order condition
	 * reversed data flow could continue
	 */
	if (tcp->ack) {
		status->ct_error = sft_tcp_handle_ack(ct, tcp, sender, peer);
		RTE_SFT_LOG(DEBUG, "    ACK:%u:%u\n", peer->ack_seq,
			    peer->ack_seq - peer->syn_seq);
		if (status->ct_error)
			goto ct_err;
	}
	if (mif->data_len) {
		status->ct_error = sender->sock_state == RTE_TCP_ESTABLISHED ?
				   sft_tcp_handle_data(smb, mif, sender,
						       status) :
				   SFT_CT_ERROR_BAD_PROTOCOL;
		if (status->ct_error)
			goto ct_err;
		RTE_SFT_LOG(DEBUG, "    DATA len=%u last seq=%u:%u\n",
			    mif->data_len, rte_be_to_cpu_32(tcp->sent_seq),
			    sender->max_sent_seq);
	}
	RTE_SFT_LOG(DEBUG, "    %s:%s:%s->%s:%s:%s\n",
		    sft_ct_state_name(dbg_ct.conn_state),
		    rte_tcp_state_name(dbg_ct.conn_ctx[0].sock_state),
		    rte_tcp_state_name(dbg_ct.conn_ctx[1].sock_state),
		    sft_ct_state_name(ct->conn_state),
		    rte_tcp_state_name(ct->conn_ctx[0].sock_state),
		    rte_tcp_state_name(ct->conn_ctx[1].sock_state));
	if (entry_conn_state != ct->conn_state)
		status->proto_state_change = 1;
	status->proto_state = ct->conn_state;
	return;
ct_err:
	status->proto_state = SFT_CT_STATE_ERROR;
	status->proto_state_change = 1;
	rte_sft_error_set(error, EINVAL, RTE_SFT_ERROR_CONN_TRACK, NULL,
			  "failed to track TCP connection");
}

int
sft_tcp_stop_conn_track(const struct sft_lib_entry *entry,
			struct rte_sft_error *error)
{
	struct sft_tcp_ct *ct = entry->ct_obj;
	RTE_SET_USED(error);
	RTE_SFT_LOG(DEBUG, "sft ct: stop track fid=%u\n", entry->fid);
	if (ct->conn_ctx[0].stash)
		sft_drain_stash(ct->conn_ctx);
	if (ct->conn_ctx[1].stash)
		sft_drain_stash(ct->conn_ctx + 1);
	rte_free(entry->ct_obj);
	return 0;
}

int
sft_tcp_start_track(struct sft_lib_entry *entry, struct rte_sft_error *error)
{
	struct sft_tcp_ct *ct = rte_zmalloc("sft tcp ct", sizeof(*ct), 0);
	if (!ct)
		return rte_sft_error_set(error, ENOMEM,
					 RTE_SFT_ERROR_CONN_TRACK, NULL,
					 "cannot allocate new ct context");
	ct->fid = entry->fid;
	ct->conn_ctx[0].sock_state = RTE_TCP_CLOSE;
	ct->conn_ctx[0].wnd_scale = 1;
	ct->conn_ctx[1].sock_state = RTE_TCP_CLOSE;
	ct->conn_ctx[1].wnd_scale = 1;
	entry->ct_obj = ct;
	RTE_SFT_LOG(DEBUG, "sft ct: start track fid=%u\n", entry->fid);
	return 0;
}
