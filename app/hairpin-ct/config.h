/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Nvidia Inc. All rights reserved.
 */

#define FLOW_ITEM_MASK(_x) (UINT64_C(1) << _x)
#define FLOW_ACTION_MASK(_x) (UINT64_C(1) << _x)
#define FLOW_ATTR_MASK(_x) (UINT64_C(1) << _x)
#define GET_RSS_HF() (ETH_RSS_IP)

/* Configuration */
#define RXQ_NUM 4
#define TXQ_NUM 4
#define TOTAL_MBUF_NUM 32000
#define MBUF_SIZE 2048
#define MBUF_CACHE_SIZE 512
#define NR_RXD  256
#define NR_TXD  256
#define MAX_PORTS 64
#define METER_CIR 1250000
#define DEFAULT_METER_PROF_ID 100

/* Items/Actions parameters */
#define ATTR_DEFAULT_PRIORITY 0
#define JUMP_ACTION_TABLE 2
#define VLAN_VALUE 1
#define VNI_VALUE 1
#define META_DATA 1
#define TAG_INDEX 0
#define TAG_INDEX_REPLY 1
#define PORT_ID_DST 1
#define TEID_VALUE 1
#define CT_ITEM_RESULT RTE_FLOW_CONNTRACK_PKT_STATE_VALID
#define AGING_SHARED_TIMEOUT 300

/* Flow items/acctions max size */
#define MAX_ITEMS_NUM 32
#define MAX_ACTIONS_NUM 32
#define MAX_ATTRS_NUM 16

/* Checkpoints PPS case config */
#define NB_CHKPNT_PPS_ROUTE_ID 10
#define NB_CHKPNT_PPS_STATIC_FLOWS ((24 + (NB_CHKPNT_PPS_ROUTE_ID * 2)) * 2)
#define CHKPNT_PPS_MARK_ERROR 7
#define FIXED_DST_PORT 5
#define PORTS_PER_IP 100

/* CT context default configuration */
#define CT_LIVE_CONNECTION       1
#define CT_SELECTIVE_ACK         1
#define CT_CHALLENGE_ACK_PASSED  0
#define CT_LAST_DIRECTION        0
#define CT_LIBERAL_MODE          0
#define CT_STATE                 RTE_FLOW_CONNTRACK_STATE_ESTABLISHED
#define CT_MAX_ACK_WINDOW        7
#define CT_RETRANSMITION_LIMIT   5
#define CT_ORIG_SCALE            7
#define CT_ORIG_CLOSE_INITIATED  0
#define CT_ORIG_LAST_ACK_SEEN    1
#define CT_ORIG_DATA_UNACKED     0
#define CT_ORIG_SENT_END         2632987379
#define CT_ORIG_REPLY_END        (2632987379 + 28960)
#define CT_ORIG_MAX_WIN          28960
#define CT_ORIG_MAX_ACK          2632987379
#define CT_REPLY_SCALE           7
#define CT_REPLY_CLOSE_INITIATED 0
#define CT_REPLY_LAST_ACK_SEEN   1
#define CT_REPLY_DATA_UNACKED    0
#define CT_REPLY_SENT_END        (2532480966 + 1)
#define CT_REPLY_REPLY_END       (2532480967 + (510 << 7))
#define CT_REPLY_MAX_WIN         (510 << 7)
#define CT_REPLY_MAX_ACK         2532480967
#define CT_LAST_WINDOW           510
#define CT_LAST_INDEX            RTE_FLOW_CONNTRACK_FLAG_ACK
#define CT_LAST_SEQ              2632987379
#define CT_LAST_ACK              2532480967
#define CT_LAST_END              2632987379
