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

/*
 * enable SFT TCP CT debug logs with EAL parameter:
 *  --log-level=lib.sft:debug
 */
RTE_LOG_REGISTER(sft_tcp,     sft.tcp,     NOTICE);
RTE_LOG_REGISTER(sft_tcp_ord, sft.tcp_ord, NOTICE);

#define SFT_TCP_LOG(level, ...) \
rte_log(RTE_LOG_ ## level, sft_tcp, "" __VA_ARGS__)
#define SFT_TCP_ORD_LOG(level, ...) \
rte_log(RTE_LOG_ ## level, sft_tcp_ord, "" __VA_ARGS__)

struct tcp_segment {
	uint32_t head; /**< head sequence */
	uint32_t tail; /**< tail sequence */
};

static __rte_always_inline bool
no_wrap(const struct tcp_segment *s)
{
	return s->tail > s->head;
}

static __rte_always_inline bool
tcp_seg_match(const struct tcp_segment *a, const struct tcp_segment *b)
{
	return a->head == b->head && a->tail == b->tail;
}

static __rte_always_inline uint32_t
tcp_seg_len(const struct tcp_segment *s)
{
	return s->tail - s->head + 1;
}

/**
 *
 * @param seg
 * @param seq
 * @return
 *  - if @seq belongs to @seg return distance from @seg beginning
 *  - UINT32_MAX if @seq in not part if @seg
 */
static __rte_always_inline uint32_t
tcp_sequence_offset(const struct tcp_segment *seg, uint32_t seq)
{
	const struct tcp_segment aux = { .head = seg->head, .tail = seq };
	uint32_t len = tcp_seg_len(&aux);

	return len <= tcp_seg_len(seg) ? len : UINT32_MAX;
}

static __rte_always_inline bool
tcp_inside_sequence(const struct tcp_segment *seg, uint32_t seq)
{
	return tcp_sequence_offset(seg, seq) != UINT32_MAX;
}

/**
 * Compare 2 SENT sequences within receive window.
 *
 * @param rcv_wnd
 * @param a
 * @param b
 * @return :
 *  0 if sequences are equal
 *  ret > 0 if a > b
 *  ret < 0 if a < b
 */
static inline int
tcp_sequence_cmp(const struct tcp_segment *rcv_wnd, uint32_t a, uint32_t b)
{
	const struct tcp_segment seg_a = { .head = rcv_wnd->head, .tail = a };
	const struct tcp_segment seg_b = { .head = rcv_wnd->head, .tail = b };

	return a == b ? 0 : tcp_seg_len(&seg_a) - tcp_seg_len(&seg_b);
}

/*
 * <=====prev====><---data--->
 *
 * 32bit wraparound OK
 */
static __rte_always_inline bool
tcp_seg_follows(const struct tcp_segment *prev, const struct tcp_segment *next)
{
	return next->head == prev->tail + 1 || next->head == prev->tail;
}

/*
 * |-----------s------------------|
 *       |------data-----|
 *
 * 32bit wraparound OK
 */

static __rte_always_inline bool
__seg_contained(const struct tcp_segment *data, const struct tcp_segment *s)
{
	return data->head >= s->head && data->tail <= s->tail;
}

static inline bool
tcp_seg_contained(const struct tcp_segment *data, const struct tcp_segment *s)
{
	bool verdict;
	if (likely(no_wrap(s))) {
		verdict = __seg_contained(data, s);
	} else if (no_wrap(data)) { /* only s wraps */
		struct tcp_segment _s;
		_s = (data->tail <= UINT32_MAX) ?
		     (typeof(_s)) { .head = s->head, .tail = UINT32_MAX } :
		     (typeof(_s)) { .head = 0,       .tail = s->tail };
		verdict = __seg_contained(data, &_s);
	} else {
		verdict = __seg_contained(data, s);
	}

	return verdict;
}

/*
 * segment @a starts before segment @b OR
 * in case @a and @b start at the same location, @a has more data
 *
 * |--------a-------|       |------a-------|
 *       |-------b-------|  |-----b-----|
 */
static bool
tcp_seg_before(const struct tcp_segment *rcv_wnd, const struct tcp_segment *a,
	       const struct tcp_segment *b)
{
	bool verdict;
	if (unlikely(a->head == b->head)) {
		verdict = tcp_seg_len(a) >= tcp_seg_len(b);
	} else {
		verdict = tcp_sequence_cmp(rcv_wnd, a->head, b->head) < 0;
	}

	return verdict;
}

struct tcp_stashed_segment {
	const struct rte_mbuf *mbuf; /**< out-of-order packet */
	struct tcp_segment seg;
	CIRCLEQ_ENTRY(tcp_stashed_segment) chain; /**< linked list entry */
};
struct tcp_stash {
	struct tcp_segment missing; /**< first missing segment */
	CIRCLEQ_HEAD(, tcp_stashed_segment) stash;
	uint32_t size;
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
};

struct sft_tcp_ct {
	uint32_t fid;
	uint32_t pkt_num;
	struct ct_ctx conn_ctx[2];
	enum sft_ct_state conn_state;
};

static __rte_always_inline uint32_t
tcp_wnd_size(const struct rte_tcp_hdr *tcp, struct ct_ctx *sender)
{
	return (rte_be_to_cpu_16(tcp->rx_win) << sender->wnd_scale);
}

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
		SFT_TCP_LOG(ERR, "invalid TCP option %u\n", tcp_opt[0]);
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
		SFT_TCP_LOG(ERR, "TCP option SACK not implemented\n");
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
		SFT_TCP_LOG(ERR, "missed TCP END option\n");
		ret = -1;
	}
out:
	return ret;
}

static void
sft_tcp_handle_syn(struct sft_tcp_ct *ct, const struct rte_tcp_hdr *tcp,
		   struct ct_ctx *sender, struct ct_ctx *peer,
		   struct rte_sft_flow_status *status)
{
	switch (sender->sock_state) {
	case RTE_TCP_CLOSE:
	case RTE_TCP_SYN_SENT:
		sender->max_sent_seq = rte_be_to_cpu_32(tcp->sent_seq);
		sender->ack_seq = sender->max_sent_seq;
		sender->sock_state = RTE_TCP_SYN_SENT;
		break;
	default:
		goto err;
	}
	if (rte_tcp_hdr_len(tcp) > RTE_TCP_MIN_HDR_LEN)
		if (tcp_parse_options(tcp, sender))
			goto err;
	ct->conn_state = SFT_CT_STATE_ESTABLISHING;
	return;
err:
	status->protocol_error = 1;
	status->ct_info = SFT_CT_ERROR_TCP_FLAGS;

	RTE_SET_USED(peer);
}

static void
sft_tcp_handle_fin(struct sft_tcp_ct *ct, const struct rte_tcp_hdr *tcp,
		   struct ct_ctx *sender, struct ct_ctx *peer,
		   struct rte_sft_flow_status *status)
{
	RTE_SET_USED(peer);

	sender->max_sent_seq++;
	switch (sender->sock_state) {
	case RTE_TCP_ESTABLISHED:
		sender->sock_state = RTE_TCP_CLOSING;
		if (ct->conn_state == SFT_CT_STATE_TRACKING) {
			ct->conn_state = SFT_CT_STATE_HALF_DUPLEX;
		} else if (ct->conn_state == SFT_CT_STATE_HALF_DUPLEX) {
			ct->conn_state = SFT_CT_STATE_CLOSING;
		} else {
			SFT_TCP_LOG(INFO, "invalid FIN\n");
			goto err;
		}

		break;
	case RTE_TCP_CLOSING:
		break;
	default:
		goto err;
	}

	return;

err:
	status->packet_error = 1;
	status->ct_info = SFT_CT_ERROR_TCP_FLAGS;

	RTE_SET_USED(tcp);
}

static void
sft_tcp_handle_rst(struct sft_tcp_ct *ct, const struct rte_tcp_hdr *tcp,
		   struct ct_ctx *sender, struct ct_ctx *peer,
		   struct rte_sft_flow_status *status)
{
	RTE_SET_USED(tcp);

	sender->max_sent_seq++;
	sender->sock_state = RTE_TCP_CLOSE;
	peer->sock_state = RTE_TCP_CLOSE;
	ct->conn_state = SFT_CT_STATE_CLOSED;
	status->ct_info = SFT_CT_RESET;
}

static inline void
tcp_reset_ct_window(struct ct_ctx *sender, struct ct_ctx *peer,
		    const struct rte_tcp_hdr *tcp)
{
	uint32_t wlen = tcp_wnd_size(tcp, sender);
	peer->rcv_wnd.head = peer->ack_seq;
	peer->rcv_wnd.tail = peer->ack_seq + 1 + wlen;
}

static __rte_always_inline bool
repeated_ack(uint32_t ack_seq, struct ct_ctx *peer)
{
	const struct tcp_segment lim = {
		.head = peer->rcv_wnd.head, .tail = peer->ack_seq - 1
	};
	return tcp_inside_sequence(&lim, ack_seq);
}

static __rte_always_inline bool
expected_ctrl_ack(uint32_t ack_seq, const struct ct_ctx *peer)
{
	return peer->max_sent_seq + 1 == ack_seq;
}

static __rte_always_inline bool
expected_ack(uint32_t ack_seq, const struct ct_ctx *peer)
{
	const struct tcp_segment lim = {
		.head = peer->ack_seq, .tail = peer->max_sent_seq + 1
	};
	return tcp_inside_sequence(&lim, ack_seq);
}

static void
sft_tcp_handle_ack(struct sft_tcp_ct *ct, const struct rte_tcp_hdr *tcp,
		   struct ct_ctx *sender, struct ct_ctx *peer,
		   struct rte_sft_flow_status *status)
{
	uint32_t ack_seq = rte_be_to_cpu_32(tcp->recv_ack);

	/*
	 * If sender posts several segments in a burst,
	 * received ACK can be less than the last transmitted sequence.
	 */
	switch (peer->sock_state) {
	case RTE_TCP_ESTABLISHED:
		if (likely(expected_ack(ack_seq, peer))) {
			peer->ack_seq = ack_seq;
			tcp_reset_ct_window(sender, peer, tcp);
		} else if (repeated_ack(ack_seq, peer)) {
			/* nothing to do */
		} else {
			goto err;
		}
		break;
	case RTE_TCP_SYN_SENT:
		if (expected_ctrl_ack(ack_seq, peer)) {
			peer->sock_state = RTE_TCP_ESTABLISHED;
			if (sender->sock_state == RTE_TCP_ESTABLISHED)
				ct->conn_state = SFT_CT_STATE_TRACKING;
			peer->ack_seq = ack_seq;
		} else {
			goto err;
		}
		break;
	case RTE_TCP_CLOSING:
		if (expected_ctrl_ack(ack_seq, peer)) {
			peer->ack_seq = ack_seq;
			peer->sock_state = RTE_TCP_CLOSE;
			if (sender->sock_state == RTE_TCP_CLOSE)
				ct->conn_state = SFT_CT_STATE_CLOSED;
		} else if (!expected_ack(ack_seq, peer) &&
			   !repeated_ack(ack_seq, peer)) {
			goto err;
		}
		break;
	case RTE_TCP_CLOSE:
		if (!expected_ctrl_ack(ack_seq, peer) &&
		    !repeated_ack(ack_seq, peer)) {
			goto err;
		}
		break;
	default:
		goto err;
	}
	return;
err:
	status->packet_error = 1;
	status->ct_info = SFT_CT_ERROR_TCP_ACK_SEQ;
	SFT_TCP_LOG(INFO,
		    "ACK %u max sent %u %s:%s flags %02x \n", ack_seq,
		    peer->max_sent_seq,
		    rte_tcp_state_name(sender->sock_state),
		    rte_tcp_state_name(peer->sock_state),
		    tcp->tcp_flags);
}

static int
tcp_create_stash(uint32_t tcp_seq, struct ct_ctx *sender)
{
	static int dbg_stash_num = 1;

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
	SFT_TCP_ORD_LOG(DEBUG, "new stash(%d) missing seq %u:%u\n",
			dbg_stash_num++, sender->max_sent_seq + 1, tcp_seq - 1);
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
tcp_stash_sort(struct tcp_stash *stash,
	       const struct tcp_segment *rcv_wnd,
	       struct tcp_stashed_segment *new)
{
	typeof(stash->stash) *head = &stash->stash;
	struct tcp_stashed_segment *var;
	if (CIRCLEQ_EMPTY(head)) {
		CIRCLEQ_INSERT_HEAD(head, new, chain);
		return;
	}
	CIRCLEQ_FOREACH(var, head, chain) {
		if (tcp_seg_match(&var->seg, &new->seg)) {
			tcp_discard_stashed_segment(new);
			return;
		} else if (tcp_seg_before(rcv_wnd, &new->seg, &var->seg)) {
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
}

/**
 * Verify how many packets can be pulled out from stash, starting form
 * the minimal missing sequence. Pulled packets must cover continuous
 * data range although sequences in these packets can overlap.
 *
 * @param sender
 * @param segment
 * @return
 */
static int
tcp_check_stash(struct ct_ctx *sender, struct tcp_segment *segment)
{
	int num = 0;
	uint32_t next_seq = sender->max_sent_seq + 1;
	struct tcp_stash *stash = sender->stash;
	typeof(stash->stash) *head = &stash->stash;
	const struct tcp_stashed_segment *var;

	CIRCLEQ_FOREACH(var, head, chain) {
		if (!tcp_inside_sequence(&var->seg, next_seq))
			break;
		num++;
		next_seq = var->seg.tail + 1;
		segment->tail = var->seg.tail;
	}
	segment->head = CIRCLEQ_FIRST(head)->seg.head;

	return num;
}


static int
tcp_unstash_mbuf(struct ct_ctx *sender, const struct rte_mbuf **mbuf,
		 uint32_t num)
{
	uint32_t i = 0;
	uint32_t next_seq = sender->max_sent_seq + 1;
	struct tcp_stash *stash = sender->stash;
	typeof(stash->stash) *head = &stash->stash;
	uint32_t first_seq;

	if (CIRCLEQ_EMPTY(head))
		return 0;
	first_seq = CIRCLEQ_FIRST(head)->seg.head;
	do {
		struct tcp_stashed_segment *var = CIRCLEQ_FIRST(head);
		if (!tcp_inside_sequence(&var->seg, next_seq))
			break;
		CIRCLEQ_REMOVE(head, var, chain);
		mbuf[i] = var->mbuf;
		sender->max_sent_seq = var->seg.tail;
		next_seq = var->seg.tail;
		rte_free(var);
	} while (++i < num && !CIRCLEQ_EMPTY(head));
	SFT_TCP_ORD_LOG(DEBUG, "unstash[%u] %u:%u\n", i, first_seq,
			sender->max_sent_seq);
	if (CIRCLEQ_EMPTY(head)) {
		rte_free(sender->stash);
		sender->stash = NULL;
		SFT_TCP_ORD_LOG(DEBUG, "@@stash is gone\n");
	}
	return i;
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
	tcp_stash_sort(stash, &sender->rcv_wnd, new);
	SFT_TCP_ORD_LOG(DEBUG, "stash(%u) %u:%u rcv_wnd:%u:%u\n",
			++stash->size, segment->head, segment->tail,
			sender->rcv_wnd.head, sender->rcv_wnd.tail);

	return 0;
}

static void
sft_tcp_handle_data(struct sft_mbuf *smb, struct rte_sft_mbuf_info *mif,
		    struct ct_ctx *sender, struct rte_sft_flow_status *status)
{
	int err;
	enum sft_ct_info ct_error = SFT_CT_ERROR_NONE;
	uint32_t tcp_seq = rte_be_to_cpu_32(mif->tcp->sent_seq);
	struct tcp_segment segment = {
		.head = tcp_seq, .tail = tcp_seq + mif->data_len - 1,
	};

	/* sender posts new data in ESTABLISHED state only.
	 * FIN can follow TCP data in the same packet.
	 * therefore, repeated data sequences can arrive while SFT sender
	 * is in CLOSING state.
	 */
	if (!tcp_seg_contained(&segment, &sender->rcv_wnd)) {
		ct_error = SFT_CT_ERROR_TCP_RCV_WND_SIZE;
		goto out;
	}
	/* segment within receive window */
	if (tcp_sequence_cmp(&sender->rcv_wnd, sender->max_sent_seq,
			     segment.tail) >= 0) {
		ct_error = SFT_CT_RETRANSMIT;
		goto out; /* repeated sequences */
	}
	if (sender->sock_state != RTE_TCP_ESTABLISHED) {
		status->protocol_error = 1;
		ct_error = SFT_CT_ERROR_BAD_PROTOCOL;
		goto out;
	}
	if (likely(!sender->stash)) {
		const struct tcp_segment topmost = {
			.head = sender->rcv_wnd.head,
			.tail = sender->max_sent_seq,
		};
		if (likely(tcp_seg_follows(&topmost, &segment))) {
			sender->max_sent_seq = segment.tail;
		} else {
			err = tcp_create_stash(segment.head, sender);
			if (err) {
				rte_errno = -err;
				ct_error = SFT_CT_ERROR_SYS;
				goto out;
			}
			goto stash;
		}
	} else {
stash:
		err = tcp_stash_mbuf(smb->m_in, &segment, sender);
		if (err < 0) {
			ct_error = SFT_CT_ERROR_SYS;
			rte_errno = -err;
		}
		err = tcp_check_stash(sender, &segment);
		if (err > 0) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
			const struct rte_mbuf **m = (typeof(m))&smb->m_out;
#pragma GCC diagnostic pop
			RTE_VERIFY(!(tcp_sequence_cmp(&sender->rcv_wnd,
						      segment.head,
						      sender->max_sent_seq) >
				     1));
			tcp_unstash_mbuf(sender, m, 1);
			status->out_of_order = 1;
			status->nb_in_order_mbufs = err - 1;
			ct_error = SFT_CT_ERROR_NONE;
		} else if (!err) {
			status->out_of_order = 1;
			smb->m_out = NULL;
			ct_error = SFT_CT_ERROR_NONE;
		}
	}
out:
	status->ct_info = ct_error;
}

static bool
sft_tcp_validate_flags(const struct rte_tcp_hdr *tcp)
{
	return tcp->tcp_flags != UINT8_MAX;
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
	RTE_SET_USED(peer);

	if (!sft_tcp_validate_flags(tcp))
		status->ct_info = SFT_CT_ERROR_TCP_FLAGS;
	else if (tcp->syn && data_len)
		status->ct_info = SFT_CT_ERROR_BAD_PROTOCOL;
	else if (data_len && sender->sock_state != RTE_TCP_ESTABLISHED)
		status->ct_info = SFT_CT_ERROR_BAD_PROTOCOL;
	else
		status->ct_info = SFT_CT_ERROR_NONE;
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
	       struct rte_sft_flow_status *status,
	       const struct ct_ctx *sender, const struct ct_ctx *peer)
{
	char initiator[INET6_ADDRSTRLEN], receiver[INET6_ADDRSTRLEN];
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
	inet_ntop(af, dst, receiver, sizeof(receiver));
	SFT_TCP_LOG(DEBUG, "sft tcp:%u:%u:%s %s %s fid %u flags %02x seq %u ack %u data len %u\n",
		    ct->pkt_num, smb->m_in->port, initiator,
		    status->initiator ? ">" : "<", receiver, entry->fid,
		    mif->tcp->tcp_flags, rte_be_to_cpu_32(mif->tcp->sent_seq),
		    rte_be_to_cpu_32(mif->tcp->recv_ack), mif->data_len);
	SFT_TCP_LOG(DEBUG, "    sender: max_sent %u ack %u rcv_wnd %u:%u\n",
		    sender->max_sent_seq, sender->ack_seq, sender->rcv_wnd.head,
		    sender->rcv_wnd.tail);
	SFT_TCP_LOG(DEBUG, "    peer: max_sent %u ack %u rcv_wnd %u:%u\n",
		    peer->max_sent_seq, peer->ack_seq, peer->rcv_wnd.head,
		    peer->rcv_wnd.tail);

}

static __always_inline void
tcp_dbg_log_header(const struct sft_mbuf *smb,
		   const struct rte_sft_mbuf_info *mif,
		   const struct sft_lib_entry *entry,
		   struct rte_sft_flow_status *status,
		   const struct ct_ctx *sender, const struct ct_ctx *peer)
{
	if (rte_log_can_log(sft_tcp, RTE_LOG_DEBUG))
		tcp_log_header(smb, mif, entry, status, sender, peer);
}

int
sft_tcp_drain_mbuf(struct sft_lib_entry *entry,
		   const struct rte_mbuf **mbuf_out, uint16_t nb_out,
		   struct rte_sft_flow_status *status)
{
	uint16_t i;
	struct sft_tcp_ct *ct = entry->ct_obj;
	struct ct_ctx *sender = status->initiator ?
				ct->conn_ctx : ct->conn_ctx + 1;

	i = tcp_unstash_mbuf(sender, mbuf_out, nb_out);
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
	struct sft_tcp_ct dbg_ct = *ct;

	ct->pkt_num++;
	if (ct->conn_state == SFT_CT_STATE_ERROR) {
		smb->m_out = NULL;
		return;
	}
	if (status->initiator) {
		sender = ct->conn_ctx;
		peer = ct->conn_ctx + 1;
	} else {
		sender = ct->conn_ctx + 1;
		peer = ct->conn_ctx;
	}
	tcp_dbg_log_header(smb, mif, entry, status, sender, peer);
	sft_basic_tcp_valiation(ct, tcp, sender, peer, mif->data_len, status);
	if (status->ct_info != SFT_CT_ERROR_NONE) {
		status->protocol_error = 1;
		SFT_TCP_LOG(DEBUG, "    FAILED TCP validation\n");
		goto ct_err;
	}
	/*
	 * check ACK flag before data.
	 * if packet will be stashed due to out-of-order condition
	 * reversed data flow could continue
	 */
	if (tcp->ack) {
		sft_tcp_handle_ack(ct, tcp, sender, peer, status);
		SFT_TCP_LOG(DEBUG, "    ACK:%u max_sent %u\n", peer->ack_seq,
			    peer->max_sent_seq);
	}
	if (mif->data_len) {
		sft_tcp_handle_data(smb, mif, sender, status);
		SFT_TCP_LOG(DEBUG, "    DATA len=%u last seq=%u:%u\n",
			    mif->data_len, rte_be_to_cpu_32(tcp->sent_seq),
			    sender->max_sent_seq);
		if (status->ct_info < 0) {
			status->packet_error = 1;
			goto ct_err;
		}
	}
	if (tcp->syn) {
		sft_tcp_handle_syn(ct, tcp, sender, peer, status);
		SFT_TCP_LOG(DEBUG, "    SYN max_sent:%u\n",
			    sender->max_sent_seq);
		if (status->ct_info < 0) {
			status->protocol_error = 1;
			goto ct_err;
		}
	} else if (tcp->fin) {
		sft_tcp_handle_fin(ct, tcp, sender, peer, status);
		SFT_TCP_LOG(DEBUG, "    FIN max_sent:%u\n",
			    sender->max_sent_seq);
	} else if (tcp->rst) {
		sft_tcp_handle_rst(ct, tcp, sender, peer, status);
		SFT_TCP_LOG(DEBUG, "    RST max_sent:%u\n",
			    sender->max_sent_seq);
	}
	status->proto_state_change = !!(entry_conn_state != ct->conn_state);
	status->proto_state = ct->conn_state;
ct_err:
#ifdef	SFT_CT_DEBUG
	status->max_sent_seq = sender->max_sent_seq;
#endif
	if (status->packet_error || status->protocol_error) {
		smb->m_out = NULL;
		if (status->protocol_error) {
			status->proto_state = SFT_CT_STATE_ERROR;
			status->proto_state_change = 1;
		}
	}
	SFT_TCP_LOG(DEBUG, "    %s:%s:%s->%s:%s:%s\n",
		    sft_ct_state_name(dbg_ct.conn_state),
		    rte_tcp_state_name(dbg_ct.conn_ctx[0].sock_state),
		    rte_tcp_state_name(dbg_ct.conn_ctx[1].sock_state),
		    sft_ct_state_name(ct->conn_state),
		    rte_tcp_state_name(ct->conn_ctx[0].sock_state),
		    rte_tcp_state_name(ct->conn_ctx[1].sock_state));
	if (status->packet_error)
		SFT_TCP_LOG(DEBUG, "    packet ERROR\n");
	if (status->protocol_error)
		SFT_TCP_LOG(DEBUG, "    protocol ERROR\n");

	return;
	RTE_SET_USED(error);
}

int
sft_tcp_stop_conn_track(const struct sft_lib_entry *entry,
			struct rte_sft_error *error)
{
	struct sft_tcp_ct *ct = entry->ct_obj;
	RTE_SET_USED(error);
	SFT_TCP_LOG(DEBUG, "sft tcp: stop track fid=%u\n", entry->fid);
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
	SFT_TCP_LOG(DEBUG, "sft tcp: start track fid=%u\n", entry->fid);
	return 0;
}
