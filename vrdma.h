#ifndef __VRDMA_API_H__
#define __VRDMA_API_H__

#include <stdint.h>
#include <infiniband/verbs.h>

/* more states need mlnx to fill */
enum vrdma_dev_state {
	rdev_state_free = 0,
	rdev_state_idle,
	rdev_state_ready,
	rdev_state_max,
};

/* more fields need mlnx to fill */
struct vrdma_dev {
	uint32_t rdev_idx;
	uint64_t rdev_ver;
	enum vrdma_dev_state state;

	char uuid[20];
	char mac[20];
	char veth[64];
	uint8_t gid[16];

	uint32_t input_pkt_num;
	uint32_t output_pkt_num;

} __attribute__((packed));
struct vrdma_query_device_req {
};

struct vrdma_query_device_resp {
	uint64_t fw_ver;

	uint32_t max_pd;
	uint32_t max_qp;
	uint32_t max_cq;
	uint32_t max_sq_depth;
	uint32_t max_rq_depth;
	uint32_t max_cq_depth;
	uint32_t max_mr;
	uint32_t max_ah;

	uint16_t max_qp_rd_atom;
	uint16_t max_ee_rd_atom;
	uint16_t max_res_rd_atom;
	uint16_t max_qp_init_rd_atom;
	uint16_t max_ee_init_rd_atom;
	uint16_t atomic_cap;
	uint16_t sub_cqs_per_cq;

	uint32_t err_code:8;
	uint32_t err_hint:24;
} __attribute__((packed));

struct vrdma_query_port_req {
	enum ibv_port_state     state;
	enum ibv_mtu            max_mtu;
	enum ibv_mtu            active_mtu;
	int                     gid_tbl_len;
	uint32_t                max_msg_sz;
	uint16_t                lid;
	uint8_t                 active_speed;
	uint8_t                 link_layer;
};

struct vrdma_query_port_resp {

} __attribute__((packed));

struct vrdma_query_gid_req {
};

struct vrdma_query_gid_resp {
	uint8_t gid[16];
	uint32_t err_code:8;
	uint32_t err_hint:24;
} __attribute__((packed));

struct vrdma_create_ceq_req {
	uint32_t depth;
	uint64_t queue_addr;
	uint16_t vector_idx;
} __attribute__((packed));

struct vrdma_create_ceq_resp {
	uint32_t ceq_handle;
	uint32_t err_code:8;
	uint32_t err_hint:24;
} __attribute__((packed));

struct vrdma_modify_ceq_req {
};

struct vrdma_modify_ceq_resp {
};
struct vrdma_destroy_ceq_req {
};

struct vrdma_destroy_ceq_resp {
};

struct vrdma_create_pd_req {
};

struct vrdma_create_pd_resp {
	uint32_t pd_handle;
	uint32_t err_code:8;
	uint32_t err_hint:24;
} __attribute__((packed));

struct vrdma_destroy_pd_req {
	uint32_t pd_handle;
} __attribute__((packed));

struct vrdma_destroy_pd_resp { 
	uint32_t err_code:8;
	uint32_t err_hint:24;
} __attribute__((packed));

struct vrdma_create_mr_req {
	uint32_t pd_handle;
	uint32_t mr_type:3;
	uint32_t access_flags:8;
	uint32_t pagesize:5;
	uint32_t hop:2;
	uint32_t reserved:14;
	uint64_t l0_paddr; 
	uint64_t length; 
	uint64_t vaddr; 

} __attribute__((packed));

struct vrdma_create_mr_resp {
	uint32_t lkey;
	uint32_t rkey;
	uint32_t err_code:8;
	uint32_t err_hint:24;
} __attribute__((packed));

struct vrdma_destroy_mr_req {
	uint32_t lkey;
} __attribute__((packed));

struct vrdma_destroy_mr_resp {
	uint32_t err_code:8;
	uint32_t err_hint:24;
} __attribute__((packed));

struct vrdma_create_cq_req {
	uint32_t cqe_entry_num:16; 
	uint32_t cqe_size:4; 
	uint32_t pagesize:5;
	uint32_t hop:2;
	uint32_t interrupt_mode:1;
	uint32_t reserved:4;
	uint32_t ceq_handle;
	uint64_t l0_pa; 
} __attribute__((packed));

struct vrdma_create_cq_resp {
	uint32_t cq_handle;
	uint32_t err_code:8;
	uint32_t err_hint:24;
} __attribute__((packed));

struct vrdma_destroy_cq_req {
	uint32_t cq_handle;
} __attribute__((packed));

struct vrdma_destroy_cq_resp { 
	uint32_t err_code:8;
	uint32_t err_hint:24;
};

struct vrdma_create_qp_req {
	uint32_t pd_handle;

	uint32_t qp_type:3;
	uint32_t sq_sig_all:1;
	uint32_t sq_wqebb_size:2; /* based on 64 * (sq_wqebb_size + 1) */
	uint32_t sq_pagesize:5; /* 12, 21, 30 | 2 ^ (n) */
	uint32_t sq_hop:2;
	uint32_t rq_wqebb_size:2; /* based on 64 * (rq_wqebb_size + 1) */
	uint32_t rq_pagesize:5; /* 2^n */
	uint32_t rq_hop:2;
	uint32_t reserved:5;

	uint32_t sq_wqebb_cnt:16; /* sqe entry cnt */
	uint32_t rq_wqebb_cnt:16; /* rqe entry cnt */

	uint32_t sq_cqn;
	uint32_t rq_cqn;

	//uint64_t qpc_l0_paddr; /* qpc buffer vm phy addr */
	uint64_t sq_l0_paddr;  /* sqe buffer vm phy addr */
	uint64_t rq_l0_paddr;  /* rqe buffer vm phy addr */
	uint64_t rq_pi_paddr;
} __attribute__((packed));

struct vrdma_create_qp_resp {
	uint32_t qp_handle;
	uint32_t err_code:8;
	uint32_t err_hint:24;
} __attribute__((packed));

struct vrdma_destroy_qp_req {
	uint32_t qp_handle;
} __attribute__((packed));

struct vrdma_destroy_qp_resp { 
	uint32_t err_code:8;
	uint32_t err_hint:24;
} __attribute__((packed));

struct vrdma_query_qp_req {
	uint32_t qp_attr_mask;
	uint32_t qp_handle;
} __attribute__((packed));

struct vrdma_query_qp_resp {
	uint32_t qp_state;
	uint32_t rq_psn;
	uint32_t sq_psn;
	uint32_t dest_qp_num;
	uint32_t sq_draining;
	uint32_t qkey;
	uint32_t err_code:8;
	uint32_t err_hint:24;
} __attribute__((packed));

struct vrdma_modify_qp_req {
	uint32_t qp_attr_mask;
	uint32_t qp_handle;
	uint32_t qp_state;
	uint32_t rq_psn;
	uint32_t sq_psn;
	uint32_t dest_qp_num;
	uint32_t sip;
	uint32_t dip;
	uint32_t qkey;
	uint32_t timeout;
	uint32_t min_rnr_timer;
	uint32_t timeout_retry_cnt;
	uint32_t rnr_retry_cnt;
} __attribute__((packed));

struct vrdma_modify_qp_resp { 
	uint32_t err_code:8;
	uint32_t err_hint:24;
} __attribute__((packed));

struct vrdma_create_ah_req {
	uint32_t pd_handle;
    uint32_t dip;
} __attribute__((packed));

struct vrdma_create_ah_resp {
	uint32_t ah_handle;
	uint32_t err_code:8;
	uint32_t err_hint:24;
} __attribute__((packed));

struct vrdma_destroy_ah_req {
	uint32_t ah_handle;
} __attribute__((packed));

struct vrdma_destroy_ah_resp {
	uint32_t err_code:8;
	uint32_t err_hint:24;
} __attribute__((packed));

struct vrdma_admin_cmd_hdr {
	uint64_t seq;
	uint32_t magic; /* 0xAA88 */
	uint32_t version;
	uint32_t opcode;
} __attribute((packed));

struct vrdma_admin_cmd {
	struct vrdma_admin_cmd_hdr hdr;
	union {
		char buf[512];
		uint64_t cur_seq;
		struct vrdma_query_gid_req query_gid_req;
		struct vrdma_query_gid_resp query_gid_resp;
		struct vrdma_create_ceq_req create_ceq_req;
		struct vrdma_create_ceq_resp create_ceq_resp;
		struct vrdma_modify_ceq_req modify_ceq_req;
		struct vrdma_modify_ceq_resp modify_ceq_resp;
		struct vrdma_destroy_ceq_req destroy_ceq_req;
		struct vrdma_destroy_ceq_resp destroy_ceq_resp;
		struct vrdma_create_pd_req	create_pd_req;
		struct vrdma_create_pd_resp create_pd_resp;
		struct vrdma_destroy_pd_req destroy_pd_req;
		struct vrdma_destroy_pd_resp destroy_pd_resp;
		struct vrdma_create_mr_req create_mr_req;
		struct vrdma_create_mr_resp create_mr_resp;
		struct vrdma_destroy_mr_req destroy_mr_req;
		struct vrdma_destroy_mr_resp destroy_mr_resp;
		struct vrdma_create_cq_req create_cq_req;
		struct vrdma_create_cq_resp create_cq_resp;
		struct vrdma_destroy_cq_req destroy_cq_req;
		struct vrdma_destroy_cq_resp destroy_cq_resp;
		struct vrdma_create_qp_req create_qp_req;
		struct vrdma_create_qp_resp create_qp_resp;
		struct vrdma_destroy_qp_req destroy_qp_req;
		struct vrdma_destroy_qp_resp destroy_qp_resp;
		struct vrdma_query_qp_req query_qp_req;
		struct vrdma_query_qp_resp query_qp_resp;
		struct vrdma_modify_qp_req modify_qp_req;
		struct vrdma_modify_qp_resp modify_qp_resp;
		struct vrdma_create_ah_req create_ah_req;
		struct vrdma_create_ah_resp create_ah_resp;
		struct vrdma_destroy_ah_req destroy_ah_req;
		struct vrdma_destroy_ah_resp destroy_ah_resp;
	} payload;
	//uint64_t tsc_begin;
} __attribute__((packed));

struct vrdma_create_pd_req_param {
	uint32_t pd_handle;  /* pd handle need to be created in vrdev and passed to vservice */
};

struct vrdma_create_mr_req_param {
	uint32_t mr_handle; /* mr handle, lkey, rkey need to be created in vrdev and passed to vservice */
	uint32_t lkey;
	uint32_t rkey;
};

struct vrdma_destroy_mr_req_param {
	uint32_t mr_handle; /* mr handle need to be created in vrdev and passed to vservice */
};

struct vrdma_cmd_param {
	union {
		char buf[12];
		struct vrdma_create_pd_req_param create_pd_param;
		struct vrdma_create_mr_req_param create_mr_param;
		struct vrdma_destroy_mr_req_param destroy_mr_param;
	}param;
};

// based on mlx sqe
struct sqe {
} __attribute__((packed));

// based on mlx rqe
struct rqe {
	
} __attribute__((packed));

// based on mlx cqe
struct cqe {
	
} __attribute__((packed));

// based on mlx eqe
struct ceqe {
	
} __attribute__((packed));

typedef int (*vrdma_device_probe_op)(struct vrdma_dev *rdev);

typedef int (*vrdma_admin_query_gid_op)(struct vrdma_dev *rdev, 
										struct vrdma_admin_cmd *cmd);
typedef int (*vrdma_admin_create_eq_op)(struct vrdma_dev *rdev, 
										struct vrdma_admin_cmd *cmd);
typedef int (*vrdma_admin_modify_eq_op)(struct vrdma_dev *rdev, 
										struct vrdma_admin_cmd *cmd);
typedef int (*vrdma_admin_destroy_eq_op)(struct vrdma_dev *rdev, 
										struct vrdma_admin_cmd *cmd);
typedef int (*vrdma_admin_create_pd_op)(struct vrdma_dev *rdev, 
										struct vrdma_admin_cmd *cmd, 
										struct vrdma_cmd_param *param);
typedef int (*vrdma_admin_destroy_pd_op)(struct vrdma_dev *rdev, 
										struct vrdma_admin_cmd *cmd);
typedef int (*vrdma_admin_create_mr_op)(struct vrdma_dev *rdev, 
										struct vrdma_admin_cmd *cmd, 
										struct vrdma_cmd_param *param);
typedef int (*vrdma_admin_destroy_mr_op)(struct vrdma_dev *rdev, 
										struct vrdma_admin_cmd *cmd, 
										struct vrdma_cmd_param *param);
typedef int (*vrdma_admin_create_cq_op)(struct vrdma_dev *rdev, 
										struct vrdma_admin_cmd *cmd);
typedef int (*vrdma_admin_destroy_cq_op)(struct vrdma_dev *rdev, 
										struct vrdma_admin_cmd *cmd);
typedef int (*vrdma_admin_create_qp_op)(struct vrdma_dev *rdev, 
										struct vrdma_admin_cmd *cmd);
typedef int (*vrdma_admin_destroy_qp_op)(struct vrdma_dev *rdev, 
										struct vrdma_admin_cmd *cmd);
typedef int (*vrdma_admin_query_qp_op)(struct vrdma_dev *rdev, 
										struct vrdma_admin_cmd *cmd, 
										struct vrdma_cmd_param *param);
typedef int (*vrdma_admin_modify_qp_op)(struct vrdma_dev *rdev, 
										struct vrdma_admin_cmd *cmd);
typedef int (*vrdma_admin_create_ah_op)(struct vrdma_dev *rdev, 
										struct vrdma_admin_cmd *cmd);
typedef int (*vrdma_admin_destroy_ah_op)(struct vrdma_dev *rdev, 
										struct vrdma_admin_cmd *cmd);

/* vrdma ops call back exposed to vrdma device */
typedef struct vRdmaServiceOps {
    /* device probing to vrdma service */
	vrdma_device_probe_op vrdma_device_probe;
    /* admin callback */
	vrdma_admin_query_gid_op vrdma_device_query_gid;
	vrdma_admin_create_eq_op vrdma_device_create_eq;
	vrdma_admin_modify_eq_op vrdma_device_modify_eq;
	vrdma_admin_destroy_eq_op vrdma_device_destroy_eq;
	vrdma_admin_create_pd_op vrdma_device_create_pd;
	vrdma_admin_destroy_pd_op vrdma_device_destroy_pd;
	vrdma_admin_create_mr_op vrdma_device_create_mr;
	vrdma_admin_destroy_mr_op vrdma_device_destroy_mr;
	vrdma_admin_create_cq_op vrdma_device_create_cq;
	vrdma_admin_destroy_cq_op vrdma_device_destroy_cq;
	vrdma_admin_create_qp_op vrdma_device_create_qp;
	vrdma_admin_destroy_qp_op vrdma_device_destroy_qp;
	vrdma_admin_query_qp_op vrdma_device_query_qp;
	vrdma_admin_modify_qp_op vrdma_device_modify_qp;
	vrdma_admin_create_ah_op vrdma_device_create_ah;
	vrdma_admin_destroy_ah_op vrdma_device_destroy_ah;
} vRdmaServiceOps;


// Assume vrdma service checks the pi,ci boundaries.
// Fetch SQ WQEs
// ret: address of sq wqe
void * fetch_sq_wqe(struct vrdma_dev *dev, uint32_t qp_handle, uint32_t idx); 

//return the number of wqes vdev can provide, maybe less than num param
uint16_t fetch_sq_wqe_batch(struct vrdma_dev *dev, uint32_t qp_handle, uint32_t idx, uint16_t num, void* swqe_head); 

// Fetch RQ WQEs
// ret: address of rq wqe
void * fetch_rq_wqe(struct vrdma_dev *dev, uint32_t qp_handle, uint32_t idx);

//return the number of wqes vdev can provide, maybe less than num param
uint16_t fetch_rq_wqe_batch(struct vrdma_dev *dev, uint32_t qp_handle, uint32_t idx, uint16_t num, void* swqe_head);

// Generate a CQE
// ret: struct cqe * 
bool gen_cqe(struct vrdma_dev *dev, uint32_t cq_handle, struct cqe * c);

//assume the cqes are continuous
//return the number of wqes vdev can provide, maybe less than num param
uint16_t gen_cqe_batch(struct vrdma_dev *dev, uint32_t cq_handle, uint32_t idx, uint16_t num, struct cqe * c, bool *is_succ);

// Generate EQE Element
// ret: struct eqe * 
bool gen_ceqe(struct vrdma_dev *dev, uint32_t ceq_handle, struct ceqe * e); 
//batch
//return the number of wqes vdev can provide, maybe less than num param
uint16_t gen_ceqe_batch(struct vrdma_dev *dev, uint32_t ceq_handle, uint32_t idx, uint16_t num, struct cqe * e, bool *is_succ);

// Generate Interrupt for CEQ:
bool gen_ceq_msi(struct vrdma_dev *dev, uint32_t cqe_vector);

// Get SQ PI
//RQ PI should be an attribute cached in vdev.qp.rq, to avoid read from host mem dbr every time
uint16_t get_sq_pi(struct vrdma_dev *dev, uint32_t qp_handle);

// Get RQ PI
//RQ PI should be an attribute cached in vdev.qp.rq, to avoid read from host mem dbr every time
uint16_t get_rq_pi(struct vrdma_dev *dev, uint32_t qp_handle);

// Get CEQ CI
//EQ CI should be an attribute cached in vdev.eq, to avoid read from host mem dbr every time
uint16_t get_eq_ci(struct vrdma_dev *dev, uint32_t eq_handle);

// Replicate data from HostMemory toSoCMemory
bool mem_move_h2d(struct vrdma_dev *dev, void *src, uint32_t skey, void *dst, int32_t dkey, size_t len);

// Replicate data from SoCMemory to HostMemory
bool mem_move_d2h(struct vrdma_dev *dev, uint32_t skey, void *src, uint32_t dkey, void *dst, size_t len);


#endif
