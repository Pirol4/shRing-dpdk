/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 6WIND S.A.
 * Copyright 2021 Mellanox Technologies, Ltd
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_prefetch.h>
#include <rte_common.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_cycles.h>
#include <rte_flow.h>

#include <mlx5_prm.h>
#include <mlx5_common.h>

#include "mlx5_autoconf.h"
#include "mlx5_defs.h"
#include "mlx5.h"
#include "mlx5_mr.h"
#include "mlx5_utils.h"
#include "mlx5_rxtx.h"
#include "mlx5_rx.h"
#include "mlx5_rxatomics.h"


static __rte_always_inline uint32_t
rxq_cq_to_pkt_type(struct mlx5_rxq_data *rxq, volatile struct mlx5_cqe *cqe,
		   volatile struct mlx5_mini_cqe8 *mcqe);

static __rte_always_inline int
mlx5_rx_poll_len(struct mlx5_rxq_data *rxq, volatile struct mlx5_cqe *cqe,
		 uint16_t cqe_cnt, volatile struct mlx5_mini_cqe8 **mcqe);

static __rte_always_inline uint32_t
rxq_cq_to_ol_flags(volatile struct mlx5_cqe *cqe);

static __rte_always_inline void
rxq_cq_to_mbuf(struct mlx5_rxq_data *rxq, struct rte_mbuf *pkt,
	       volatile struct mlx5_cqe *cqe,
	       volatile struct mlx5_mini_cqe8 *mcqe);

static inline void
mlx5_lro_update_tcp_hdr(struct rte_tcp_hdr *__rte_restrict tcp,
			volatile struct mlx5_cqe *__rte_restrict cqe,
			uint32_t phcsum, uint8_t l4_type);

static inline void
mlx5_lro_update_hdr(uint8_t *__rte_restrict padd,
		    volatile struct mlx5_cqe *__rte_restrict cqe,
		    volatile struct mlx5_mini_cqe8 *mcqe,
		    struct mlx5_rxq_data *rxq, uint32_t len);


/**
 * Internal function to compute the number of used descriptors in an RX queue.
 *
 * @param rxq
 *   The Rx queue.
 *
 * @return
 *   The number of used Rx descriptor.
 */
static uint32_t
rx_queue_count(struct mlx5_rxq_data *rxq)
{
	struct rxq_zip *zip = &rxq->zip;
	volatile struct mlx5_cqe *cqe;
	const unsigned int cqe_n = (1 << rxq->cqe_n);
	const unsigned int sges_n = (1 << rxq->sges_n);
	const unsigned int elts_n = (1 << rxq->elts_n);
	const unsigned int strd_n = (1 << rxq->strd_num_n);
	const unsigned int cqe_cnt = cqe_n - 1;
	unsigned int cq_ci, used;

	/* if we are processing a compressed cqe */
	if (zip->ai) {
		used = zip->cqe_cnt - zip->ai;
		cq_ci = zip->cq_ci;
	} else {
		used = 0;
		cq_ci = rxq->cq_ci;
	}
	cqe = &(*rxq->cqes)[cq_ci & cqe_cnt];
	while (check_cqe(cqe, cqe_n, cq_ci) != MLX5_CQE_STATUS_HW_OWN) {
		int8_t op_own;
		unsigned int n;

		op_own = cqe->op_own;
		if (MLX5_CQE_FORMAT(op_own) == MLX5_COMPRESSED)
			n = rte_be_to_cpu_32(cqe->byte_cnt);
		else
			n = 1;
		cq_ci += n;
		used += n;
		cqe = &(*rxq->cqes)[cq_ci & cqe_cnt];
	}
	used = RTE_MIN(used * sges_n, elts_n * strd_n);
	return used;
}

/**
 * DPDK callback to check the status of a Rx descriptor.
 *
 * @param rx_queue
 *   The Rx queue.
 * @param[in] offset
 *   The index of the descriptor in the ring.
 *
 * @return
 *   The status of the Rx descriptor.
 */
int
mlx5_rx_descriptor_status(void *rx_queue, uint16_t offset)
{
	struct mlx5_rxq_data *rxq = rx_queue;
	struct mlx5_rxq_ctrl *rxq_ctrl =
			container_of(rxq, struct mlx5_rxq_ctrl, rxq);
	struct rte_eth_dev *dev = ETH_DEV(rxq_ctrl->priv);

	if (dev->rx_pkt_burst == NULL ||
	    dev->rx_pkt_burst == removed_rx_burst) {
		rte_errno = ENOTSUP;
		return -rte_errno;
	}
	if (offset >= (1 << rxq->cqe_n)) {
		rte_errno = EINVAL;
		return -rte_errno;
	}
	if (offset < rx_queue_count(rxq))
		return RTE_ETH_RX_DESC_DONE;
	return RTE_ETH_RX_DESC_AVAIL;
}

/**
 * DPDK callback to get the RX queue information.
 *
 * @param dev
 *   Pointer to the device structure.
 *
 * @param rx_queue_id
 *   Rx queue identificator.
 *
 * @param qinfo
 *   Pointer to the RX queue information structure.
 *
 * @return
 *   None.
 */

void
mlx5_rxq_info_get(struct rte_eth_dev *dev, uint16_t rx_queue_id,
		  struct rte_eth_rxq_info *qinfo)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_rxq_data *rxq = (*priv->rxqs)[rx_queue_id];
	struct mlx5_rxq_ctrl *rxq_ctrl =
		container_of(rxq, struct mlx5_rxq_ctrl, rxq);

	if (!rxq)
		return;
	qinfo->mp = mlx5_rxq_mprq_enabled(rxq) ?
					rxq->mprq_mp : rxq->mp;
	qinfo->conf.rx_thresh.pthresh = 0;
	qinfo->conf.rx_thresh.hthresh = 0;
	qinfo->conf.rx_thresh.wthresh = 0;
	qinfo->conf.rx_free_thresh = rxq->rq_repl_thresh;
	qinfo->conf.rx_drop_en = 1;
	qinfo->conf.rx_deferred_start = rxq_ctrl ? 0 : 1;
	qinfo->conf.offloads = dev->data->dev_conf.rxmode.offloads;
	qinfo->scattered_rx = dev->data->scattered_rx;
	qinfo->nb_desc = mlx5_rxq_mprq_enabled(rxq) ?
		(1 << rxq->elts_n) * (1 << rxq->strd_num_n) :
		(1 << rxq->elts_n);
}

/**
 * DPDK callback to get the RX packet burst mode information.
 *
 * @param dev
 *   Pointer to the device structure.
 *
 * @param rx_queue_id
 *   Rx queue identificatior.
 *
 * @param mode
 *   Pointer to the burts mode information.
 *
 * @return
 *   0 as success, -EINVAL as failure.
 */
int
mlx5_rx_burst_mode_get(struct rte_eth_dev *dev,
		       uint16_t rx_queue_id __rte_unused,
		       struct rte_eth_burst_mode *mode)
{
	eth_rx_burst_t pkt_burst = dev->rx_pkt_burst;
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_rxq_data *rxq;

	rxq = (*priv->rxqs)[rx_queue_id];
	if (!rxq) {
		rte_errno = EINVAL;
		return -rte_errno;
	}
	if (pkt_burst == mlx5_rx_burst) {
		snprintf(mode->info, sizeof(mode->info), "%s", "Scalar");
	} else if (pkt_burst == mlx5_rx_burst_rmp) {
		snprintf(mode->info, sizeof(mode->info), "%s", "RMP Scalar RQ");
	} else if (pkt_burst == mlx5_rx_burst_fill) {
		snprintf(mode->info, sizeof(mode->info), "%s", "FILL-ring Scalar");
	} else if (pkt_burst == mlx5_rx_burst_rmp_mprq) {
		snprintf(mode->info, sizeof(mode->info), "%s", "RMP Multi-Packet RQ");
	} else if (pkt_burst == mlx5_rx_burst_mprq) {
		snprintf(mode->info, sizeof(mode->info), "%s", "Multi-Packet RQ");
	} else if (pkt_burst == mlx5_rx_burst_vec) {
#if defined RTE_ARCH_X86_64
		snprintf(mode->info, sizeof(mode->info), "%s", "Vector SSE");
#elif defined RTE_ARCH_ARM64
		snprintf(mode->info, sizeof(mode->info), "%s", "Vector Neon");
#elif defined RTE_ARCH_PPC_64
		snprintf(mode->info, sizeof(mode->info), "%s", "Vector AltiVec");
#else
		return -EINVAL;
#endif
	} else if (pkt_burst == mlx5_rx_burst_mprq_vec) {
#if defined RTE_ARCH_X86_64
		snprintf(mode->info, sizeof(mode->info), "%s", "MPRQ Vector SSE");
#elif defined RTE_ARCH_ARM64
		snprintf(mode->info, sizeof(mode->info), "%s", "MPRQ Vector Neon");
#elif defined RTE_ARCH_PPC_64
		snprintf(mode->info, sizeof(mode->info), "%s", "MPRQ Vector AltiVec");
#else
		return -EINVAL;
#endif
	} else {
		return -EINVAL;
	}
	return 0;
}

/**
 * DPDK callback to get the number of used descriptors in a RX queue.
 *
 * @param dev
 *   Pointer to the device structure.
 *
 * @param rx_queue_id
 *   The Rx queue.
 *
 * @return
 *   The number of used rx descriptor.
 *   -EINVAL if the queue is invalid
 */
uint32_t
mlx5_rx_queue_count(struct rte_eth_dev *dev, uint16_t rx_queue_id)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_rxq_data *rxq;

	if (dev->rx_pkt_burst == NULL ||
	    dev->rx_pkt_burst == removed_rx_burst) {
		rte_errno = ENOTSUP;
		return -rte_errno;
	}
	rxq = (*priv->rxqs)[rx_queue_id];
	if (!rxq) {
		rte_errno = EINVAL;
		return -rte_errno;
	}
	return rx_queue_count(rxq);
}

int mlx5_get_monitor_addr(void *rx_queue, struct rte_power_monitor_cond *pmc)
{
	struct mlx5_rxq_data *rxq = rx_queue;
	const unsigned int cqe_num = 1 << rxq->cqe_n;
	const unsigned int cqe_mask = cqe_num - 1;
	const uint16_t idx = rxq->cq_ci & cqe_num;
	volatile struct mlx5_cqe *cqe = &(*rxq->cqes)[rxq->cq_ci & cqe_mask];

	if (unlikely(rxq->cqes == NULL)) {
		rte_errno = EINVAL;
		return -rte_errno;
	}
	pmc->addr = &cqe->op_own;
	pmc->val =  !!idx;
	pmc->mask = MLX5_CQE_OWNER_MASK;
	pmc->size = sizeof(uint8_t);
	return 0;
}

/**
 * Translate RX completion flags to packet type.
 *
 * @param[in] rxq
 *   Pointer to RX queue structure.
 * @param[in] cqe
 *   Pointer to CQE.
 *
 * @note: fix mlx5_dev_supported_ptypes_get() if any change here.
 *
 * @return
 *   Packet type for struct rte_mbuf.
 */
static inline uint32_t
rxq_cq_to_pkt_type(struct mlx5_rxq_data *rxq, volatile struct mlx5_cqe *cqe,
				   volatile struct mlx5_mini_cqe8 *mcqe)
{
	uint8_t idx;
	uint8_t ptype;
	uint8_t pinfo = (cqe->pkt_info & 0x3) << 6;

	/* Get l3/l4 header from mini-CQE in case L3/L4 format*/
	if (mcqe == NULL ||
	    rxq->mcqe_format != MLX5_CQE_RESP_FORMAT_L34H_STRIDX)
		ptype = (cqe->hdr_type_etc & 0xfc00) >> 10;
	else
		ptype = mcqe->hdr_type >> 2;
	/*
	 * The index to the array should have:
	 * bit[1:0] = l3_hdr_type
	 * bit[4:2] = l4_hdr_type
	 * bit[5] = ip_frag
	 * bit[6] = tunneled
	 * bit[7] = outer_l3_type
	 */
	idx = pinfo | ptype;
	return mlx5_ptype_table[idx] | rxq->tunnel * !!(idx & (1 << 6));
}

/**
 * Move the buffers a FILL-ring queue holds to the first slots of its ring.
 *
 * The NIC restarts from WQE 0 whenever the RQ leaves the reset state, while
 * the buffers held at that moment sit wherever the posted window happened to
 * be. They are all empty and interchangeable, so their order is not kept.
 *
 * @param[in] rxq
 *   Pointer to RX queue structure.
 *
 * @return
 *   Number of buffers held, now in slots [0, return value).
 */
static unsigned int
mlx5_rxq_fill_rewind(struct mlx5_rxq_data *rxq)
{
	const unsigned int wqe_n = 1 << rxq->elts_n;
	unsigned int held = 0;
	unsigned int i;

	for (i = 0; i != wqe_n; ++i) {
		struct rte_mbuf *buf = (*rxq->elts)[i];

		if (buf == NULL)
			continue;
		/* held <= i, so a slot not yet visited is never overwritten. */
		(*rxq->elts)[i] = NULL;
		(*rxq->elts)[held++] = buf;
	}
	return held;
}

/**
 * Initialize Rx WQ and indexes of a queue in FILL-ring mode: only the
 * buffers the queue holds are posted, not the whole ring.
 *
 * @param[in] rxq
 *   Pointer to RX queue structure.
 */
static void
mlx5_rxq_fill_initialize(struct mlx5_rxq_data *rxq)
{
	const unsigned int wqe_n = 1 << rxq->elts_n;
	volatile struct mlx5_wqe_data_seg *wqes =
		(volatile struct mlx5_wqe_data_seg *)rxq->wqes;
	const unsigned int held = mlx5_rxq_fill_rewind(rxq);
	unsigned int i;

	/*
	 * mlx5_rxq_fill_post() only writes the address of a WQE, so every
	 * WQE gets its size and lkey here, posted or not. Slots without a
	 * buffer borrow the lkey of the first one: with a single MR it is
	 * the right one, and with several the post path rewrites it. No
	 * buffer at all can only happen on a re-initialization, where the
	 * WQEs keep what the first one wrote.
	 */
	for (i = 0; held != 0 && i != wqe_n; ++i) {
		struct rte_mbuf *buf = (*rxq->elts)[i];
		struct rte_mbuf *mr_owner = buf ? buf : (*rxq->elts)[0];
		const uintptr_t addr = buf ? rte_pktmbuf_mtod(buf, uintptr_t) : 0;

		wqes[i] = (struct mlx5_wqe_data_seg){
			.addr = rte_cpu_to_be_64(addr),
			.byte_count = rte_cpu_to_be_32(rxq->rxseg[0].length),
			.lkey = mlx5_rx_mb2mr(rxq, mr_owner),
		};
	}
	rxq->consumed_strd = 0;
	rxq->decompressed = 0;
	rxq->zip = (struct rxq_zip){
		.ai = 0,
	};
	rxq->elts_ci = 0;
	/* Nothing consumed yet; the doorbell hands over what is held. */
	rxq->rq_pi = 0;
	rxq->rq_ci = held;
	rte_io_wmb();
	*rxq->rq_db = rte_cpu_to_be_32(rxq->rq_ci);
	DRV_LOG(INFO, "port %u Rx queue %u: FILL-ring mode, %u of %u WQEs"
		" posted (budget %u)", rxq->port_id, rxq->idx, held, wqe_n,
		rxq->fill_budget);
}

/**
 * Initialize Rx WQ and indexes.
 *
 * @param[in] rxq
 *   Pointer to RX queue structure.
 */
void
mlx5_rxq_initialize(struct mlx5_rxq_data *rxq)
{
	const unsigned int wqe_n = 1 << rxq->elts_n;
	unsigned int i;

	printf("%s idx %d rmp %p\n", __func__, rxq->idx, (void *)rxq->rmpsh);
	if (rxq->fill_budget) {
		mlx5_rxq_fill_initialize(rxq);
		return;
	}
	for (i = 0; (i != wqe_n); ++i) {
		volatile struct mlx5_wqe_data_seg *scat;
		uintptr_t addr;
		uint32_t byte_count;

		if (rxq->rmp && mlx5_rxq_mprq_enabled(rxq)) {
			struct mlx5_mprq_buf *buf = (*rxq->mprq_bufs)[i];
			volatile struct mlx5_wqe_srq_next_seg *next;
			const uint32_t wq_mask = (1 << rxq->elts_n) - 1;

			next = &((volatile struct mlx5_wqe_mprq *)
				rxq->wqes)[i].next_seg;
			next->next_wqe_index = htons((i + 1) & wq_mask);

			scat = &((volatile struct mlx5_wqe_mprq *)
				rxq->wqes)[i].dseg;
			addr = (uintptr_t)mlx5_mprq_buf_addr(buf,
							 1 << rxq->strd_num_n);
			byte_count = (1 << rxq->strd_sz_n) *
					(1 << rxq->strd_num_n);
		} else if (rxq->rmp && !mlx5_rxq_mprq_enabled(rxq)) {
			struct rte_mbuf *buf = (*rxq->rmpsh->elts)[i];
			volatile struct mlx5_wqe_srq_next_seg *next;
			const uint32_t wq_mask = (1 << rxq->elts_n) - 1;

			next = &((volatile struct mlx5_wqe_rmp *)
				rxq->wqes)[i].next_seg;
			next->next_wqe_index = htons((i + 1) & wq_mask);
			/* Experiment with reverse WQE order -> low performance */
			// next->next_wqe_index = htons((i - 1) & wq_mask);
			// printf("creating %p[%d]->next = %d\n", rxq->wqes, i, ntohs(next->next_wqe_index));

			scat = &((volatile struct mlx5_wqe_rmp *)
					rxq->wqes)[i].dseg;
			addr = rte_pktmbuf_mtod(buf, uintptr_t);
			byte_count = DATA_LEN(buf);
		} else if (mlx5_rxq_mprq_enabled(rxq)) {
			struct mlx5_mprq_buf *buf = (*rxq->mprq_bufs)[i];

			scat = &((volatile struct mlx5_wqe_mprq *)
				rxq->wqes)[i].dseg;
			addr = (uintptr_t)mlx5_mprq_buf_addr(buf,
							 1 << rxq->strd_num_n);
			byte_count = (1 << rxq->strd_sz_n) *
					(1 << rxq->strd_num_n);
		} else {
			struct rte_mbuf *buf = (*rxq->elts)[i];

			scat = &((volatile struct mlx5_wqe_data_seg *)
					rxq->wqes)[i];
			addr = rte_pktmbuf_mtod(buf, uintptr_t);
			byte_count = DATA_LEN(buf);
		}
		/* scat->addr must be able to store a pointer. */
		MLX5_ASSERT(sizeof(scat->addr) >= sizeof(uintptr_t));
		*scat = (struct mlx5_wqe_data_seg){
			.addr = rte_cpu_to_be_64(addr),
			.byte_count = rte_cpu_to_be_32(byte_count),
			.lkey = mlx5_rx_addr2mr(rxq, addr),
		};
	}
	rxq->consumed_strd = 0;
	rxq->decompressed = 0;
	rxq->zip = (struct rxq_zip){
		.ai = 0,
	};
	rxq->elts_ci = mlx5_rxq_mprq_enabled(rxq) ?
		(wqe_n >> rxq->sges_n) * (1 << rxq->strd_num_n) : 0;
	/* Update doorbell counter. */
	if (rxq->rmpsh) { // one less for free item in list
		printf("initializing rq ci/pi\n");
		rxq->rmpsh->rq_pi = 0;
		rxq->rmpsh->rq_ci = (wqe_n - 1) >> rxq->sges_n;
		rxq->rmpsh->head = (wqe_n - 1) >> rxq->sges_n;
		printf("initializing head %d\n", rxq->rmpsh->head);
		printf("ci %d %d %d\n", rxq->rq_ci, wqe_n, rxq->sges_n);
		rte_io_wmb();
		*rxq->rq_db = rte_cpu_to_be_32(rxq->rmpsh->rq_ci);
	} else {
		rxq->rq_pi = 0;
		rxq->rq_ci = wqe_n >> rxq->sges_n;
		rte_io_wmb();
		*rxq->rq_db = rte_cpu_to_be_32(rxq->rq_ci);
	}
}

/**
 * Handle a Rx error.
 * The function inserts the RQ state to reset when the first error CQE is
 * shown, then drains the CQ by the caller function loop. When the CQ is empty,
 * it moves the RQ state to ready and initializes the RQ.
 * Next CQE identification and error counting are in the caller responsibility.
 *
 * @param[in] rxq
 *   Pointer to RX queue structure.
 * @param[in] vec
 *   1 when called from vectorized Rx burst, need to prepare mbufs for the RQ.
 *   0 when called from non-vectorized Rx burst.
 *
 * @return
 *   -1 in case of recovery error, otherwise the CQE status.
 */
int
mlx5_rx_err_handle(struct mlx5_rxq_data *rxq, uint8_t vec)
{
	const uint16_t cqe_n = 1 << rxq->cqe_n;
	const uint16_t cqe_mask = cqe_n - 1;
	const uint16_t wqe_n = 1 << rxq->elts_n;
	const uint16_t strd_n = 1 << rxq->strd_num_n;
	struct mlx5_rxq_ctrl *rxq_ctrl =
			container_of(rxq, struct mlx5_rxq_ctrl, rxq);
	union {
		volatile struct mlx5_cqe *cqe;
		volatile struct mlx5_err_cqe *err_cqe;
	} u = {
		.cqe = &(*rxq->cqes)[rxq->cq_ci & cqe_mask],
	};
	struct mlx5_mp_arg_queue_state_modify sm;
	int ret;

	switch (rxq->err_state) {
	case MLX5_RXQ_ERR_STATE_NO_ERROR:
		rxq->err_state = MLX5_RXQ_ERR_STATE_NEED_RESET;
		/* Fall-through */
	case MLX5_RXQ_ERR_STATE_NEED_RESET:
		sm.is_wq = 1;
		sm.queue_id = rxq->idx;
		sm.state = IBV_WQS_RESET;
		if (mlx5_queue_state_modify(ETH_DEV(rxq_ctrl->priv), &sm))
			return -1;
		if (rxq_ctrl->dump_file_n <
		    rxq_ctrl->priv->config.max_dump_files_num) {
			MKSTR(err_str, "Unexpected CQE error syndrome "
			      "0x%02x CQN = %u RQN = %u wqe_counter = %u"
			      " rq_ci = %u cq_ci = %u", u.err_cqe->syndrome,
			      rxq->cqn, rxq_ctrl->wqn,
			      rte_be_to_cpu_16(u.err_cqe->wqe_counter),
			      rxq->rq_ci << rxq->sges_n, rxq->cq_ci);
			MKSTR(name, "dpdk_mlx5_port_%u_rxq_%u_%u",
			      rxq->port_id, rxq->idx, (uint32_t)rte_rdtsc());
			mlx5_dump_debug_information(name, NULL, err_str, 0);
			mlx5_dump_debug_information(name, "MLX5 Error CQ:",
						    (const void *)((uintptr_t)
								    rxq->cqes),
						    sizeof(*u.cqe) * cqe_n);
			mlx5_dump_debug_information(name, "MLX5 Error RQ:",
						    (const void *)((uintptr_t)
								    rxq->wqes),
						    16 * wqe_n);
			rxq_ctrl->dump_file_n++;
		}
		rxq->err_state = MLX5_RXQ_ERR_STATE_NEED_READY;
		/* Fall-through */
	case MLX5_RXQ_ERR_STATE_NEED_READY:
		ret = check_cqe(u.cqe, cqe_n, rxq->cq_ci);
		if (ret == MLX5_CQE_STATUS_HW_OWN) {
			rte_io_wmb();
			*rxq->cq_db = rte_cpu_to_be_32(rxq->cq_ci);
			rte_io_wmb();
			/*
			 * The RQ consumer index must be zeroed while moving
			 * from RESET state to RDY state.
			 */
			*rxq->rq_db = rte_cpu_to_be_32(0);
			rte_io_wmb();
			sm.is_wq = 1;
			sm.queue_id = rxq->idx;
			sm.state = IBV_WQS_RDY;
			if (mlx5_queue_state_modify(ETH_DEV(rxq_ctrl->priv),
						    &sm))
				return -1;
			if (vec) {
				const uint32_t elts_n =
					mlx5_rxq_mprq_enabled(rxq) ?
					wqe_n * strd_n : wqe_n;
				const uint32_t e_mask = elts_n - 1;
				uint32_t elts_ci =
					mlx5_rxq_mprq_enabled(rxq) ?
					rxq->elts_ci : rxq->rq_ci;
				uint32_t elt_idx;
				struct rte_mbuf **elt;
				int i;
				unsigned int n = elts_n - (elts_ci -
							  rxq->rq_pi);

				for (i = 0; i < (int)n; ++i) {
					elt_idx = (elts_ci + i) & e_mask;
					elt = &(*rxq->elts)[elt_idx];
					*elt = rte_mbuf_raw_alloc(rxq->mp);
					if (!*elt) {
						for (i--; i >= 0; --i) {
							elt_idx = (elts_ci +
								   i) & elts_n;
							elt = &(*rxq->elts)
								[elt_idx];
							rte_pktmbuf_free_seg
								(*elt);
						}
						return -1;
					}
				}
				for (i = 0; i < (int)elts_n; ++i) {
					elt = &(*rxq->elts)[i];
					DATA_LEN(*elt) =
						(uint16_t)((*elt)->buf_len -
						rte_pktmbuf_headroom(*elt));
				}
				/* Padding with a fake mbuf for vec Rx. */
				for (i = 0; i < MLX5_VPMD_DESCS_PER_LOOP; ++i)
					(*rxq->elts)[elts_n + i] =
								&rxq->fake_mbuf;
			}
			mlx5_rxq_initialize(rxq);
			rxq->err_state = MLX5_RXQ_ERR_STATE_NO_ERROR;
		}
		return ret;
	default:
		return -1;
	}
}

/**
 * Get size of the next packet for a given CQE. For compressed CQEs, the
 * consumer index is updated only once all packets of the current one have
 * been processed.
 *
 * @param rxq
 *   Pointer to RX queue.
 * @param cqe
 *   CQE to process.
 * @param[out] mcqe
 *   Store pointer to mini-CQE if compressed. Otherwise, the pointer is not
 *   written.
 *
 * @return
 *   0 in case of empty CQE, otherwise the packet size in bytes.
 */
static inline int
mlx5_rx_poll_len(struct mlx5_rxq_data *rxq, volatile struct mlx5_cqe *cqe,
		 uint16_t cqe_cnt, volatile struct mlx5_mini_cqe8 **mcqe)
{
	struct rxq_zip *zip = &rxq->zip;
	uint16_t cqe_n = cqe_cnt + 1;
	int len;
	uint16_t idx, end;

	do {
		len = 0;
		/* Process compressed data in the CQE and mini arrays. */
		if (zip->ai) {
			volatile struct mlx5_mini_cqe8 (*mc)[8] =
				(volatile struct mlx5_mini_cqe8 (*)[8])
				(uintptr_t)(&(*rxq->cqes)[zip->ca &
							  cqe_cnt].pkt_info);
			len = rte_be_to_cpu_32((*mc)[zip->ai & 7].byte_cnt &
					       rxq->byte_mask);
			*mcqe = &(*mc)[zip->ai & 7];
			if ((++zip->ai & 7) == 0) {
				/* Invalidate consumed CQEs */
				idx = zip->ca;
				end = zip->na;
				while (idx != end) {
					(*rxq->cqes)[idx & cqe_cnt].op_own =
						MLX5_CQE_INVALIDATE;
					++idx;
				}
				/*
				 * Increment consumer index to skip the number
				 * of CQEs consumed. Hardware leaves holes in
				 * the CQ ring for software use.
				 */
				zip->ca = zip->na;
				zip->na += 8;
			}
			if (unlikely(rxq->zip.ai == rxq->zip.cqe_cnt)) {
				/* Invalidate the rest */
				idx = zip->ca;
				end = zip->cq_ci;

				while (idx != end) {
					(*rxq->cqes)[idx & cqe_cnt].op_own =
						MLX5_CQE_INVALIDATE;
					++idx;
				}
				rxq->cq_ci = zip->cq_ci;
				zip->ai = 0;
			}
		/*
		 * No compressed data, get next CQE and verify if it is
		 * compressed.
		 */
		} else {
			int ret;
			int8_t op_own;
			uint32_t cq_ci;

			ret = check_cqe(cqe, cqe_n, rxq->cq_ci);
			if (unlikely(ret != MLX5_CQE_STATUS_SW_OWN)) {
				if (unlikely(ret == MLX5_CQE_STATUS_ERR ||
					     rxq->err_state)) {
					ret = mlx5_rx_err_handle(rxq, 0);
					if (ret == MLX5_CQE_STATUS_HW_OWN ||
					    ret == -1)
						return 0;
				} else {
					return 0;
				}
			}
			/*
			 * Introduce the local variable to have queue cq_ci
			 * index in queue structure always consistent with
			 * actual CQE boundary (not pointing to the middle
			 * of compressed CQE session).
			 */
			cq_ci = rxq->cq_ci + 1;
			op_own = cqe->op_own;
			if (MLX5_CQE_FORMAT(op_own) == MLX5_COMPRESSED) {
				volatile struct mlx5_mini_cqe8 (*mc)[8] =
					(volatile struct mlx5_mini_cqe8 (*)[8])
					(uintptr_t)(&(*rxq->cqes)
						[cq_ci & cqe_cnt].pkt_info);

				/* Fix endianness. */
				zip->cqe_cnt = rte_be_to_cpu_32(cqe->byte_cnt);
				/*
				 * Current mini array position is the one
				 * returned by check_cqe64().
				 *
				 * If completion comprises several mini arrays,
				 * as a special case the second one is located
				 * 7 CQEs after the initial CQE instead of 8
				 * for subsequent ones.
				 */
				zip->ca = cq_ci;
				zip->na = zip->ca + 7;
				/* Compute the next non compressed CQE. */
				zip->cq_ci = rxq->cq_ci + zip->cqe_cnt;
				/* Get packet size to return. */
				len = rte_be_to_cpu_32((*mc)[0].byte_cnt &
						       rxq->byte_mask);
				*mcqe = &(*mc)[0];
				zip->ai = 1;
				/* Prefetch all to be invalidated */
				idx = zip->ca;
				end = zip->cq_ci;
				while (idx != end) {
					rte_prefetch0(&(*rxq->cqes)[(idx) &
								    cqe_cnt]);
					++idx;
				}
			} else {
				rxq->cq_ci = cq_ci;
				len = rte_be_to_cpu_32(cqe->byte_cnt);
			}
		}
		if (unlikely(rxq->err_state)) {
			cqe = &(*rxq->cqes)[rxq->cq_ci & cqe_cnt];
			++rxq->stats.idropped;
		} else {
			return len;
		}
	} while (1);
}

/**
 * Translate RX completion flags to offload flags.
 *
 * @param[in] cqe
 *   Pointer to CQE.
 *
 * @return
 *   Offload flags (ol_flags) for struct rte_mbuf.
 */
static inline uint32_t
rxq_cq_to_ol_flags(volatile struct mlx5_cqe *cqe)
{
	uint32_t ol_flags = 0;
	uint16_t flags = rte_be_to_cpu_16(cqe->hdr_type_etc);

	ol_flags =
		TRANSPOSE(flags,
			  MLX5_CQE_RX_L3_HDR_VALID,
			  PKT_RX_IP_CKSUM_GOOD) |
		TRANSPOSE(flags,
			  MLX5_CQE_RX_L4_HDR_VALID,
			  PKT_RX_L4_CKSUM_GOOD);
	return ol_flags;
}

/**
 * Fill in mbuf fields from RX completion flags.
 * Note that pkt->ol_flags should be initialized outside of this function.
 *
 * @param rxq
 *   Pointer to RX queue.
 * @param pkt
 *   mbuf to fill.
 * @param cqe
 *   CQE to process.
 * @param rss_hash_res
 *   Packet RSS Hash result.
 */
static inline void
rxq_cq_to_mbuf(struct mlx5_rxq_data *rxq, struct rte_mbuf *pkt,
	       volatile struct mlx5_cqe *cqe,
	       volatile struct mlx5_mini_cqe8 *mcqe)
{
	/* Update packet information. */
	pkt->packet_type = rxq_cq_to_pkt_type(rxq, cqe, mcqe);

	if (rxq->rss_hash) {
		uint32_t rss_hash_res = 0;

		/* If compressed, take hash result from mini-CQE. */
		if (mcqe == NULL ||
		    rxq->mcqe_format != MLX5_CQE_RESP_FORMAT_HASH)
			rss_hash_res = rte_be_to_cpu_32(cqe->rx_hash_res);
		else
			rss_hash_res = rte_be_to_cpu_32(mcqe->rx_hash_result);
		if (rss_hash_res) {
			pkt->hash.rss = rss_hash_res;
			pkt->ol_flags |= PKT_RX_RSS_HASH;
		}
	}
	if (rxq->mark) {
		uint32_t mark = 0;

		/* If compressed, take flow tag from mini-CQE. */
		if (mcqe == NULL ||
		    rxq->mcqe_format != MLX5_CQE_RESP_FORMAT_FTAG_STRIDX)
			mark = cqe->sop_drop_qpn;
		else
			mark = ((mcqe->byte_cnt_flow & 0xff) << 8) |
				(mcqe->flow_tag_high << 16);
		if (MLX5_FLOW_MARK_IS_VALID(mark)) {
			pkt->ol_flags |= PKT_RX_FDIR;
			if (mark != RTE_BE32(MLX5_FLOW_MARK_DEFAULT)) {
				pkt->ol_flags |= PKT_RX_FDIR_ID;
				pkt->hash.fdir.hi = mlx5_flow_mark_get(mark);
			}
		}
	}
	if (rxq->dynf_meta) {
		uint32_t meta = cqe->flow_table_metadata &
				rxq->flow_meta_port_mask;

		if (meta) {
			pkt->ol_flags |= rxq->flow_meta_mask;
			*RTE_MBUF_DYNFIELD(pkt, rxq->flow_meta_offset,
						uint32_t *) = meta;
		}
	}
	if (rxq->csum)
		pkt->ol_flags |= rxq_cq_to_ol_flags(cqe);
	if (rxq->vlan_strip) {
		bool vlan_strip;

		if (mcqe == NULL ||
		    rxq->mcqe_format != MLX5_CQE_RESP_FORMAT_L34H_STRIDX)
			vlan_strip = cqe->hdr_type_etc &
				     RTE_BE16(MLX5_CQE_VLAN_STRIPPED);
		else
			vlan_strip = mcqe->hdr_type &
				     RTE_BE16(MLX5_CQE_VLAN_STRIPPED);
		if (vlan_strip) {
			pkt->ol_flags |= PKT_RX_VLAN | PKT_RX_VLAN_STRIPPED;
			pkt->vlan_tci = rte_be_to_cpu_16(cqe->vlan_info);
		}
	}
	if (rxq->hw_timestamp) {
		uint64_t ts = rte_be_to_cpu_64(cqe->timestamp);

		if (rxq->rt_timestamp)
			ts = mlx5_txpp_convert_rx_ts(rxq->sh, ts);
		mlx5_timestamp_set(pkt, rxq->timestamp_offset, ts);
		pkt->ol_flags |= rxq->timestamp_rx_flag;
	}
}

/**
 * DPDK callback for RX.
 *
 * @param dpdk_rxq
 *   Generic pointer to RX queue structure.
 * @param[out] pkts
 *   Array to store received packets.
 * @param pkts_n
 *   Maximum number of packets in array.
 *
 * @return
 *   Number of packets successfully received (<= pkts_n).
 */
uint16_t
mlx5_rx_burst(void *dpdk_rxq, struct rte_mbuf **pkts, uint16_t pkts_n)
{
	struct mlx5_rxq_data *rxq = dpdk_rxq;
	const unsigned int wqe_cnt = (1 << rxq->elts_n) - 1;
	const unsigned int cqe_cnt = (1 << rxq->cqe_n) - 1;
	const unsigned int sges_n = rxq->sges_n;
	struct rte_mbuf *pkt = NULL;
	struct rte_mbuf *seg = NULL;
	volatile struct mlx5_cqe *cqe =
		&(*rxq->cqes)[rxq->cq_ci & cqe_cnt];
	unsigned int i = 0;
	unsigned int rq_ci = rxq->rq_ci << sges_n;
	int len = 0; /* keep its value across iterations. */

	while (pkts_n) {
		unsigned int idx = rq_ci & wqe_cnt;
		volatile struct mlx5_wqe_data_seg *wqe =
			&((volatile struct mlx5_wqe_data_seg *)rxq->wqes)[idx];
		struct rte_mbuf *rep = (*rxq->elts)[idx];
		volatile struct mlx5_mini_cqe8 *mcqe = NULL;

		if (pkt)
			NEXT(seg) = rep;
		seg = rep;
		rte_prefetch0(seg);
		rte_prefetch0(cqe);
		rte_prefetch0(wqe);
		/* Allocate the buf from the same pool. */
		rep = rte_mbuf_raw_alloc(seg->pool);
		if (unlikely(rep == NULL)) {
			++rxq->stats.rx_nombuf;
			if (!pkt) {
				/*
				 * no buffers before we even started,
				 * bail out silently.
				 */
				break;
			}
			while (pkt != seg) {
				MLX5_ASSERT(pkt != (*rxq->elts)[idx]);
				rep = NEXT(pkt);
				NEXT(pkt) = NULL;
				NB_SEGS(pkt) = 1;
				rte_mbuf_raw_free(pkt);
				pkt = rep;
			}
			rq_ci >>= sges_n;
			++rq_ci;
			rq_ci <<= sges_n;
			break;
		}
		if (!pkt) {
			cqe = &(*rxq->cqes)[rxq->cq_ci & cqe_cnt];
			len = mlx5_rx_poll_len(rxq, cqe, cqe_cnt, &mcqe);
			if (!len) {
				rte_mbuf_raw_free(rep);
				break;
			}
			pkt = seg;
			MLX5_ASSERT(len >= (rxq->crc_present << 2));
			pkt->ol_flags &= EXT_ATTACHED_MBUF;
			rxq_cq_to_mbuf(rxq, pkt, cqe, mcqe);
			if (rxq->crc_present)
				len -= RTE_ETHER_CRC_LEN;
			PKT_LEN(pkt) = len;
			if (cqe->lro_num_seg > 1) {
				mlx5_lro_update_hdr
					(rte_pktmbuf_mtod(pkt, uint8_t *), cqe,
					 mcqe, rxq, len);
				pkt->ol_flags |= PKT_RX_LRO;
				pkt->tso_segsz = len / cqe->lro_num_seg;
			}
		}
		DATA_LEN(rep) = DATA_LEN(seg);
		PKT_LEN(rep) = PKT_LEN(seg);
		SET_DATA_OFF(rep, DATA_OFF(seg));
		PORT(rep) = PORT(seg);
		(*rxq->elts)[idx] = rep;
		/*
		 * Fill NIC descriptor with the new buffer. The lkey and size
		 * of the buffers are already known, only the buffer address
		 * changes.
		 */
		wqe->addr = rte_cpu_to_be_64(rte_pktmbuf_mtod(rep, uintptr_t));
		/* If there's only one MR, no need to replace LKey in WQE. */
		if (unlikely(mlx5_mr_btree_len(&rxq->mr_ctrl.cache_bh) > 1))
			wqe->lkey = mlx5_rx_mb2mr(rxq, rep);
		if (len > DATA_LEN(seg)) {
			len -= DATA_LEN(seg);
			++NB_SEGS(pkt);
			++rq_ci;
			continue;
		}
		DATA_LEN(seg) = len;
#ifdef MLX5_PMD_SOFT_COUNTERS
		/* Increment bytes counter. */
		rxq->stats.ibytes += PKT_LEN(pkt);
#endif
		/* Return packet. */
		*(pkts++) = pkt;
		pkt = NULL;
		--pkts_n;
		++i;
		/* Align consumer index to the next stride. */
		rq_ci >>= sges_n;
		++rq_ci;
		rq_ci <<= sges_n;
	}
	if (unlikely(i == 0 && ((rq_ci >> sges_n) == rxq->rq_ci)))
		return 0;
	/* Update the consumer index. */
	rxq->rq_ci = rq_ci >> sges_n;
	rte_io_wmb();
	*rxq->cq_db = rte_cpu_to_be_32(rxq->cq_ci);
	rte_io_wmb();
	*rxq->rq_db = rte_cpu_to_be_32(rxq->rq_ci);
#ifdef MLX5_PMD_SOFT_COUNTERS
	/* Increment packets counter. */
	rxq->stats.ipackets += i;
#endif
	return i;
}

/*
 * FILL-ring Rx path.
 *
 * mlx5_rx_burst() refills every WQE in place, so the RQ always holds as many
 * posted buffers as it has entries and one index, rq_ci, is both the position
 * packets are read from and the count of WQEs posted. Here the two are kept
 * apart, the way AF_XDP separates its FILL and RX rings:
 *
 *   rq_pi - WQEs consumed: where the next received packet is read from
 *           (RX ring consumer).
 *   rq_ci - WQEs posted: where the next empty buffer goes, and the value
 *           written to the RQ doorbell (FILL ring producer).
 *
 * rq_ci - rq_pi buffers are owned by the NIC or hold a packet not yet read.
 * The queue keeps that at fill_budget, which may be far below the ring size:
 * the ring stays large enough to grow into, while the I/O working set is the
 * budget. Only slots in [rq_pi, rq_ci) of the elts array hold an mbuf; the
 * others are NULL.
 */

/**
 * Post empty buffers until the queue holds its budget again.
 *
 * A failed allocation leaves the queue short; the next call makes up for it,
 * because the shortfall is recomputed from the indices every time.
 *
 * @param rxq
 *   Pointer to RX queue structure.
 */
static __rte_always_inline void
mlx5_rxq_fill_post(struct mlx5_rxq_data *rxq)
{
	const unsigned int wqe_mask = (1 << rxq->elts_n) - 1;
	volatile struct mlx5_wqe_data_seg *wqes =
		(volatile struct mlx5_wqe_data_seg *)rxq->wqes;
	const struct mlx5_eth_rxseg *seg = &rxq->rxseg[0];
	uint32_t rq_ci = rxq->rq_ci;
	const unsigned int posted = rq_ci - rxq->rq_pi;
	unsigned int missing;

	/* A budget that was just lowered is reached by not posting. */
	if (posted >= rxq->fill_budget)
		return;
	missing = rxq->fill_budget - posted;
	while (missing--) {
		const unsigned int idx = rq_ci & wqe_mask;
		struct rte_mbuf *buf = rte_mbuf_raw_alloc(seg->mp);

		if (unlikely(buf == NULL)) {
			++rxq->stats.rx_nombuf;
			break;
		}
		MLX5_ASSERT((*rxq->elts)[idx] == NULL);
		SET_DATA_OFF(buf, seg->offset);
		PORT(buf) = rxq->port_id;
		DATA_LEN(buf) = seg->length;
		PKT_LEN(buf) = seg->length;
		(*rxq->elts)[idx] = buf;
		/*
		 * The size and, with a single MR, the lkey of every WQE were
		 * written at initialization; only the address changes.
		 */
		wqes[idx].addr =
			rte_cpu_to_be_64(rte_pktmbuf_mtod(buf, uintptr_t));
		if (unlikely(mlx5_mr_btree_len(&rxq->mr_ctrl.cache_bh) > 1))
			wqes[idx].lkey = mlx5_rx_mb2mr(rxq, buf);
		++rq_ci;
	}
	if (rq_ci == rxq->rq_ci)
		return;
	rxq->rq_ci = rq_ci;
	rte_io_wmb();
	*rxq->rq_db = rte_cpu_to_be_32(rq_ci);
}

/*
 * FILL-ring credits (fill_dyn).
 *
 * A credit is the right to keep one buffer posted. The queues of a port share
 * fill_budget credits each; a queue holds only what its recent backlog calls
 * for and leaves the rest in the port's pool, so the posted total follows the
 * load and never exceeds what static budgets would post.
 *
 * The backlog is what a burst finds waiting: the buffers the NIC used while
 * the lcore was away. A queue wants MLX5_FILL_HEADROOM times the largest
 * backlog of the last one to two windows, and twice its budget when the
 * backlog used every posted buffer, since packets were then probably dropped
 * and the real need is unknown. It takes credits from the pool when it holds
 * less and gives them back at the end of a window when it holds more.
 *
 * Only the queue's own lcore writes its ring, so a credit is given back by
 * not re-posting: fill_held counts the credits still tied up, the budget or
 * what remains posted above it, and only the difference returns to the pool.
 * The pool is the one word the queues share and it is touched when a budget
 * changes, never per packet.
 *
 * Credits up to fill_entitled are the queue's own; what it holds above that
 * is borrowed. A queue that the pool leaves below its entitlement draws one
 * of the borrowers, with a chance proportional to what each has borrowed
 * (the inverse lottery of lottery scheduling, over the credits no ticket
 * covers), and leaves it a debt. The borrower pays at its next burst by
 * lowering its budget, whatever its own backlog says, and the credits reach
 * the pool as its buffers are read. A queue above its entitlement cannot ask.
 */

/**
 * Count the completions waiting in the CQ, up to a known bound.
 *
 * Without CQE compression every received packet is one CQE and the NIC writes
 * them in order, so the CQEs owned by software form a prefix: a binary search
 * on the ownership bit finds its length.
 *
 * @param rxq
 *   Pointer to RX queue structure.
 * @param max
 *   Upper bound: the buffers currently posted.
 *
 * @return
 *   Number of completions not yet read, at most max.
 */
static uint16_t
mlx5_rxq_fill_pending(struct mlx5_rxq_data *rxq, uint16_t max)
{
	const unsigned int cqe_n = 1 << rxq->cqe_n;
	const unsigned int cqe_mask = cqe_n - 1;
	uint16_t lo = 0;
	uint16_t hi = max;

	while (lo != hi) {
		const uint16_t mid = (lo + hi + 1) / 2;
		const uint32_t ci = rxq->cq_ci + mid - 1;

		if (check_cqe(&(*rxq->cqes)[ci & cqe_mask], cqe_n, ci) !=
		    MLX5_CQE_STATUS_HW_OWN)
			lo = mid;
		else
			hi = mid - 1;
	}
	return lo;
}

/**
 * Take credits from the pool of the port.
 *
 * @param pool
 *   Pointer to the pool.
 * @param want
 *   Credits wanted.
 *
 * @return
 *   Credits taken, possibly 0.
 */
static uint16_t
mlx5_fill_pool_take(int32_t *pool, uint16_t want)
{
	int32_t avail = __atomic_load_n(pool, __ATOMIC_RELAXED);
	int32_t got;

	do {
		got = RTE_MIN((int32_t)want, avail);
		if (got <= 0)
			return 0;
	} while (!__atomic_compare_exchange_n(pool, &avail, avail - got, 1,
					      __ATOMIC_RELAXED,
					      __ATOMIC_RELAXED));
	return got;
}

/**
 * Ask a borrower to give credits back to the pool.
 *
 * @param rxq
 *   Pointer to RX queue structure: a queue below its entitlement.
 * @param want
 *   Credits wanted.
 */
static void
mlx5_rxq_fill_reclaim(struct mlx5_rxq_data *rxq, uint16_t want)
{
	struct mlx5_priv *priv =
		container_of(rxq, struct mlx5_rxq_ctrl, rxq)->priv;
	uint32_t borrowed[2] = { 0, 0 };
	uint32_t draw = 0;
	unsigned int pass;
	unsigned int i;

	/* First pass: how much is borrowed. Second: whose credit is drawn. */
	for (pass = 0; pass != 2; ++pass) {
		for (i = 0; i != priv->rxqs_n; ++i) {
			struct mlx5_rxq_data *other = (*priv->rxqs)[i];
			uint32_t over;
			int32_t debt;

			if (other == NULL || other == rxq ||
			    other->fill_pool == NULL ||
			    other->fill_held <= other->fill_entitled)
				continue;
			over = other->fill_held - other->fill_entitled;
			borrowed[pass] += over;
			if (pass == 0 || borrowed[1] <= draw)
				continue;
			/* Asking twice for the same credits is one debt. */
			want = RTE_MIN((uint32_t)want, over);
			debt = __atomic_load_n(&other->fill_debt,
					       __ATOMIC_RELAXED);
			while (debt < want &&
			       !__atomic_compare_exchange_n(&other->fill_debt,
							    &debt, want, 1,
							    __ATOMIC_RELAXED,
							    __ATOMIC_RELAXED))
				;
			++rxq->fill_stats.reclaims;
			return;
		}
		if (borrowed[0] == 0)
			return;
		/* xorshift32 */
		rxq->fill_rng ^= rxq->fill_rng << 13;
		rxq->fill_rng ^= rxq->fill_rng >> 17;
		rxq->fill_rng ^= rxq->fill_rng << 5;
		draw = rxq->fill_rng % borrowed[0];
	}
}

/**
 * Pay a debt: give back borrowed credits another queue is entitled to.
 *
 * What cannot be paid from borrowed credits is dropped; the queue that asked
 * will ask again if it is still short.
 *
 * @param rxq
 *   Pointer to RX queue structure.
 */
static __rte_noinline void
mlx5_rxq_fill_pay(struct mlx5_rxq_data *rxq)
{
	const int32_t debt = __atomic_exchange_n(&rxq->fill_debt, 0,
						 __ATOMIC_RELAXED);
	const int32_t over = (int32_t)rxq->fill_budget - rxq->fill_entitled;
	const int32_t pay = RTE_MIN(debt, over);

	if (pay <= 0)
		return;
	rxq->fill_budget -= pay;
	rxq->fill_stats.paid += pay;
	/* They are another queue's now, though still posted here. */
	rxq->fill_owed += pay;
}

/**
 * Move the budget of a queue towards what its backlog calls for.
 *
 * @param rxq
 *   Pointer to RX queue structure.
 * @param saturated
 *   The last backlog used every posted buffer.
 * @param may_shrink
 *   Lower the budget if it is above the target: only at the end of a window.
 */
static __rte_noinline void
mlx5_rxq_fill_rebudget(struct mlx5_rxq_data *rxq, bool saturated,
		       bool may_shrink)
{
	const uint32_t ring = 1 << rxq->elts_n;
	const uint32_t peak = RTE_MAX(rxq->fill_peak[0], rxq->fill_peak[1]);
	uint32_t target = peak * MLX5_FILL_HEADROOM_NUM / MLX5_FILL_HEADROOM_DEN;
	uint16_t budget = rxq->fill_budget;

	rxq->fill_short = 0;
	if (saturated)
		target = RTE_MAX(target, 2u * budget);
	target = RTE_MIN(RTE_MAX(target, (uint32_t)rxq->fill_floor), ring);
	if (target > budget) {
		uint16_t want = target - budget;
		/*
		 * Credits given up at the end of a window and still posted
		 * can be taken back first; those paid to a debt cannot.
		 */
		const uint16_t back = RTE_MIN(want, rxq->fill_held - budget -
						    rxq->fill_owed);
		const uint16_t got = mlx5_fill_pool_take(rxq->fill_pool,
							 want - back);

		rxq->fill_held += got;
		budget += back + got;
		want -= back + got;
		if (back + got != 0)
			++rxq->fill_stats.grows;
		if (want != 0) {
			rxq->fill_short = 1;
			++rxq->fill_stats.denied;
			if (budget < rxq->fill_entitled)
				mlx5_rxq_fill_reclaim(rxq,
					RTE_MIN(want, rxq->fill_entitled -
						      budget));
		}
	} else if (may_shrink && target < budget) {
		budget = target;
		++rxq->fill_stats.shrinks;
	}
	rxq->fill_budget = budget;
	if (budget > rxq->fill_stats.budget_max)
		rxq->fill_stats.budget_max = budget;
}

/**
 * Close a window if its time is up: forget the older peak and let the budget
 * come down to what the last window needed.
 *
 * @param rxq
 *   Pointer to RX queue structure.
 */
static __rte_noinline void
mlx5_rxq_fill_tick(struct mlx5_rxq_data *rxq)
{
	const uint64_t now = rte_rdtsc();

	rxq->fill_stats.budget_sum += rxq->fill_budget;
	++rxq->fill_stats.samples;
	if (now < rxq->fill_window_end) {
		/*
		 * Short of its own credits: what it asked back may be in the
		 * pool by now. Borrowed credits are only sought on a new peak.
		 */
		if (rxq->fill_short && rxq->fill_budget < rxq->fill_entitled)
			mlx5_rxq_fill_rebudget(rxq, false, false);
		return;
	}
	rxq->fill_window_end = now + rxq->fill_window_tsc;
	rxq->fill_peak[0] = rxq->fill_peak[1];
	rxq->fill_peak[1] = 0;
	mlx5_rxq_fill_rebudget(rxq, false, true);
}

/**
 * Account for one burst of a queue whose budget follows the load.
 *
 * @param rxq
 *   Pointer to RX queue structure.
 * @param nb_rx
 *   Packets the burst returned.
 * @param pkts_n
 *   Packets the burst was asked for.
 * @param posted_before
 *   Buffers that were posted when the burst started.
 */
static __rte_always_inline void
mlx5_rxq_fill_credits(struct mlx5_rxq_data *rxq, uint16_t nb_rx,
		      uint16_t pkts_n, uint32_t posted_before)
{
	const uint32_t posted = rxq->rq_ci - rxq->rq_pi;
	uint32_t backlog = nb_rx;
	uint16_t tied;
	bool saturated;

	if (unlikely(__atomic_load_n(&rxq->fill_debt, __ATOMIC_RELAXED) != 0))
		mlx5_rxq_fill_pay(rxq);
	tied = RTE_MAX((uint32_t)rxq->fill_budget, posted);
	/* Credits given up reach the pool once their buffers are read. */
	if (unlikely(rxq->fill_held > tied)) {
		const uint16_t freed = rxq->fill_held - tied;

		__atomic_add_fetch(rxq->fill_pool, freed, __ATOMIC_RELAXED);
		rxq->fill_held = tied;
		rxq->fill_owed -= RTE_MIN(rxq->fill_owed, freed);
	}
	if (unlikely(++rxq->fill_polls == 0))
		mlx5_rxq_fill_tick(rxq);
	if (likely(nb_rx != pkts_n)) {
		rxq->fill_full_run = 0;
	} else if (rxq->fill_full_run++ % MLX5_FILL_RECOUNT == 0) {
		/* A full burst may have left more behind. */
		backlog += mlx5_rxq_fill_pending(rxq, posted);
	}
	saturated = backlog >= posted_before;
	if (backlog > rxq->fill_stats.peak_max)
		rxq->fill_stats.peak_max = backlog;
	/*
	 * A backlog that used every posted buffer only says the need is
	 * larger. Remember one that calls for the doubled budget, or the end
	 * of the window would shrink the queue back under what just failed.
	 */
	if (unlikely(saturated))
		backlog = RTE_MAX(backlog, (2 * posted_before *
					    MLX5_FILL_HEADROOM_DEN +
					    MLX5_FILL_HEADROOM_NUM - 1) /
					   MLX5_FILL_HEADROOM_NUM);
	if (likely(backlog <= rxq->fill_peak[1]))
		return;
	rxq->fill_peak[1] = RTE_MIN(backlog, (uint32_t)UINT16_MAX);
	mlx5_rxq_fill_rebudget(rxq, saturated, false);
}

/**
 * Report how the budget of a queue moved, when the queue stops.
 *
 * @param rxq
 *   Pointer to RX queue structure.
 */
void
mlx5_rxq_fill_stats_log(const struct mlx5_rxq_data *rxq)
{
	if (rxq->fill_pool == NULL || rxq->fill_stats.samples == 0)
		return;
	DRV_LOG(INFO, "port %u Rx queue %u: FILL credits: budget %u now,"
		" %" PRIu64 " mean, %u max (floor %u); peak backlog %u;"
		" %u grows, %u shrinks, %u denied, %u reclaims, %u paid;"
		" pool %d",
		rxq->port_id, rxq->idx, rxq->fill_budget,
		rxq->fill_stats.budget_sum / rxq->fill_stats.samples,
		rxq->fill_stats.budget_max, rxq->fill_floor,
		rxq->fill_stats.peak_max, rxq->fill_stats.grows,
		rxq->fill_stats.shrinks, rxq->fill_stats.denied,
		rxq->fill_stats.reclaims, rxq->fill_stats.paid,
		__atomic_load_n(rxq->fill_pool, __ATOMIC_RELAXED));
}

/**
 * DPDK callback for RX in FILL-ring mode: single-segment packets only.
 *
 * @param dpdk_rxq
 *   Generic pointer to RX queue structure.
 * @param[out] pkts
 *   Array to store received packets.
 * @param pkts_n
 *   Maximum number of packets in array.
 *
 * @return
 *   Number of packets successfully received (<= pkts_n).
 */
uint16_t
mlx5_rx_burst_fill(void *dpdk_rxq, struct rte_mbuf **pkts, uint16_t pkts_n)
{
	struct mlx5_rxq_data *rxq = dpdk_rxq;
	const unsigned int wqe_mask = (1 << rxq->elts_n) - 1;
	const unsigned int cqe_mask = (1 << rxq->cqe_n) - 1;
	const uint32_t cq_ci = rxq->cq_ci;
	const uint32_t posted_before = rxq->rq_ci - rxq->rq_pi;
	uint16_t i = 0;

	MLX5_ASSERT(rxq->sges_n == 0);
	while (i != pkts_n) {
		const unsigned int idx = rxq->rq_pi & wqe_mask;
		volatile struct mlx5_cqe *cqe =
			&(*rxq->cqes)[rxq->cq_ci & cqe_mask];
		volatile struct mlx5_mini_cqe8 *mcqe = NULL;
		struct rte_mbuf *pkt = (*rxq->elts)[idx];
		int len;

		rte_prefetch0(pkt);
		rte_prefetch0(cqe);
		len = mlx5_rx_poll_len(rxq, cqe, cqe_mask, &mcqe);
		if (!len)
			break;
		/*
		 * While the queue recovers from an error the CQ is drained
		 * with the RQ in reset: those completions carry no packet,
		 * and the posted buffers are kept for re-initialization.
		 */
		if (unlikely(rxq->err_state != MLX5_RXQ_ERR_STATE_NO_ERROR))
			continue;
		MLX5_ASSERT(pkt != NULL);
		MLX5_ASSERT(len >= (rxq->crc_present << 2));
		/* The slot is empty until a buffer is posted to it again. */
		(*rxq->elts)[idx] = NULL;
		++rxq->rq_pi;
		pkt->ol_flags &= EXT_ATTACHED_MBUF;
		rxq_cq_to_mbuf(rxq, pkt, cqe, mcqe);
		if (rxq->crc_present)
			len -= RTE_ETHER_CRC_LEN;
		if (cqe->lro_num_seg > 1) {
			mlx5_lro_update_hdr(rte_pktmbuf_mtod(pkt, uint8_t *),
					    cqe, mcqe, rxq, len);
			pkt->ol_flags |= PKT_RX_LRO;
			pkt->tso_segsz = len / cqe->lro_num_seg;
		}
		MLX5_ASSERT(len <= DATA_LEN(pkt));
		PKT_LEN(pkt) = len;
		DATA_LEN(pkt) = len;
#ifdef MLX5_PMD_SOFT_COUNTERS
		/* Increment bytes counter. */
		rxq->stats.ibytes += len;
#endif
		pkts[i++] = pkt;
	}
	if (rxq->cq_ci != cq_ci) {
		rte_io_wmb();
		*rxq->cq_db = rte_cpu_to_be_32(rxq->cq_ci);
	}
	if (rxq->fill_pool != NULL &&
	    likely(rxq->err_state == MLX5_RXQ_ERR_STATE_NO_ERROR))
		mlx5_rxq_fill_credits(rxq, i, pkts_n, posted_before);
	mlx5_rxq_fill_post(rxq);
#ifdef MLX5_PMD_SOFT_COUNTERS
	/* Increment packets counter. */
	rxq->stats.ipackets += i;
#endif
	return i;
}

////////////////////////////////////////////////////////////////////////////////////////////////
// RMP WIP - maintains original list structure - TODO support struggler threads
// ////////////////////////////////////////////////////////////////////////////////////////////////

#define THRESHOLD		(64)
static inline bool after(uint32_t seq1, uint32_t seq2, uint32_t mask) {
	return (seq1 > seq2) ?
		((seq1 - seq2) >= THRESHOLD) :
		((seq1 + mask - seq2) >= THRESHOLD);
}

uint16_t
mlx5_rx_burst_rmp(void *dpdk_rxq, struct rte_mbuf **pkts, uint16_t pkts_n)
{
	struct mlx5_rxq_data *rxq = dpdk_rxq;
	const unsigned int wqe_cnt = (1 << rxq->elts_n) - 1;
	const unsigned int cqe_cnt = (1 << rxq->cqe_n) - 1;
	struct rte_mbuf *pkt = NULL;
	struct rte_mbuf *seg = NULL;
	volatile struct mlx5_cqe *cqe;
	unsigned int i = 0;
	int len = 0; /* keep its value across iterations. */
	uint16_t idx;
	uint64_t lbmp = 0;
	uint16_t lbmp_idx = 0;

	while (pkts_n) {
		volatile struct mlx5_wqe_data_seg *wqe;
		struct rte_mbuf *rep;
		volatile struct mlx5_mini_cqe8 *mcqe = NULL;

		cqe = &(*rxq->cqes)[rxq->cq_ci & cqe_cnt];
		rte_prefetch0(cqe);
		len = mlx5_rx_poll_len(rxq, cqe, cqe_cnt, &mcqe);
		if (!len)
			break;
		idx = rte_be_to_cpu_16(cqe->wqe_counter);
		wqe = &((volatile struct mlx5_wqe_rmp *)rxq->wqes)[idx].dseg;
		rep = (*rxq->rmpsh->elts)[idx];

		#define IDX2QWORD(x)		((x) >> 6)
		#define IDX2BIT(x)		(1ULL << ((x) & 63))
		#define IDX2MASKLO(x)		(IDX2BIT((x)+1) - 1)
		#define IDX2MASKHI(x)		(~IDX2MASKLO(x))
		if (lbmp_idx != IDX2QWORD(idx)) {
			if (lbmp) {
				uint64_t base = __atomic_load_n(&rxq->rmpsh->uwbmp[lbmp_idx], __ATOMIC_RELAXED);
				uint64_t new = base | lbmp;
				if (new == 0xffffffffffffffff) {
					__atomic_store_n(&rxq->rmpsh->uwbmp[lbmp_idx], new, __ATOMIC_RELEASE);
				} else {
					while (!__atomic_compare_exchange_n(&rxq->rmpsh->uwbmp[lbmp_idx],
								   &base, new, 0,
								   __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
						base = __atomic_load_n(&rxq->rmpsh->uwbmp[lbmp_idx], __ATOMIC_RELAXED);
						new = base | lbmp;
					}
				}
				// // Debug prints
				// printf("[%d] update1 uwbmp[%d] = 0x%016llx/0x%016llx uwbmp[%d] = 0x%016llx\n",
				//        rxq->idx, lbmp_idx,
				//        rxq->rmpsh->uwbmp[lbmp_idx],
				//        lbmp,
				//        lbmp_idx+1,
				//        rxq->rmpsh->uwbmp[lbmp_idx+1]);
			}
			lbmp_idx = IDX2QWORD(idx);
			lbmp = 0;
		}
		lbmp |= IDX2BIT(idx);

		seg = rep;
		rte_prefetch0(seg);
		rte_prefetch0(wqe);

		rep = rte_mbuf_raw_alloc(seg->pool);
		if (unlikely(rep == NULL)) {
			++rxq->stats.rx_nombuf;
			printf("rxq %d nombuf!!!\n", rxq->idx);
			if (!pkt) {
				/*
				 * no buffers before we even started,
				 * bail out silently.
				 */
				break;
			}
		}

		pkt = seg;
		MLX5_ASSERT(len >= (rxq->crc_present << 2));
		pkt->ol_flags &= EXT_ATTACHED_MBUF;
		rxq_cq_to_mbuf(rxq, pkt, cqe, mcqe);
		if (rxq->crc_present)
			len -= RTE_ETHER_CRC_LEN;
		PKT_LEN(pkt) = len;

		///////////////////////////////
		DATA_LEN(rep) = DATA_LEN(seg);
		PKT_LEN(rep) = PKT_LEN(seg);
		SET_DATA_OFF(rep, DATA_OFF(seg));
		PORT(rep) = PORT(seg);
		(*rxq->rmpsh->elts)[idx] = rep;
		/*
		 * Fill NIC descriptor with the new buffer. The lkey and size
		 * of the buffers are already known, only the buffer address
		 * changes.
		 */
		wqe->addr = rte_cpu_to_be_64(rte_pktmbuf_mtod(rep, uintptr_t));
		/* If there's only one MR, no need to replace LKey in WQE. */
		if (unlikely(mlx5_mr_btree_len(&rxq->mr_ctrl.cache_bh) > 1))
			wqe->lkey = mlx5_rx_mb2mr(rxq, rep);
		if (len > DATA_LEN(seg)) {
			len -= DATA_LEN(seg);
			++NB_SEGS(pkt);
			continue;
		}
		DATA_LEN(seg) = len;
#ifdef MLX5_PMD_SOFT_COUNTERS
		/* Increment bytes counter. */
		rxq->stats.ibytes += PKT_LEN(pkt);
#endif
		/* Return packet. */
		*(pkts++) = pkt;
		pkt = NULL;
		--pkts_n;
		++i;
		/* Align consumer index to the next stride. */
	}
	if (unlikely(i == 0))
		return 0;

	if (lbmp) {
		uint64_t base = __atomic_load_n(&rxq->rmpsh->uwbmp[lbmp_idx], __ATOMIC_RELAXED);
		uint64_t new = base | lbmp;
		if (new == 0xffffffffffffffff) {
			__atomic_store_n(&rxq->rmpsh->uwbmp[lbmp_idx], new, __ATOMIC_RELEASE);
		} else {
			while (!__atomic_compare_exchange_n(&rxq->rmpsh->uwbmp[lbmp_idx],
							   &base, new, 0,
							   __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
				base = __atomic_load_n(&rxq->rmpsh->uwbmp[lbmp_idx], __ATOMIC_RELAXED);
				new = base | lbmp;
			}
		}
		// // Debug prints
		// printf("[%d] update uwbmp[%d] = 0x%016llx/0x%016llx uwbmp[%d] = 0x%016llx\n",
		//        rxq->idx, lbmp_idx,
		//        rxq->rmpsh->uwbmp[lbmp_idx],
		//        lbmp,
		//        lbmp_idx+1,
		//        rxq->rmpsh->uwbmp[lbmp_idx+1]);
	}

	*rxq->cq_db = rte_cpu_to_be_32(rxq->cq_ci);
	rte_io_wmb();

	/////////////////////////////////////////////////////////////////////////////////
	// once 64 in-sequence packets are received, ring doorbell and zeroize bitmap
	////////////////////////////////////////////////////////////////////////////////
	int head = rxq->rmpsh->head;
	int head_idx = head & wqe_cnt;
	uint64_t blk, mask;
	bool flag = true;
	// printf("[%d] idx - head = %d (idx %d head %d)\n", rxq->idx, (idx - head_idx) & wqe_cnt, idx, head_idx);
	while (flag && after(idx, (head_idx + THRESHOLD), 1 + wqe_cnt)) {
		blk = __atomic_load_n(&rxq->rmpsh->uwbmp[IDX2QWORD((head_idx + 1) & wqe_cnt)], __ATOMIC_RELAXED);
		mask = IDX2MASKHI(head_idx);
		// printf("[%d] idx - head = %d (idx %d head %d) idx %d\n", rxq->idx, (idx - head_idx) & wqe_cnt, idx, head_idx, IDX2QWORD((head_idx + 1) & wqe_cnt));
		if ((blk & mask) == mask) {
			/* TODO: hidden assumption about (THRESHOLD % 64 == 0) */
			__atomic_store_n(&rxq->rmpsh->uwbmp[IDX2QWORD((head_idx + 1) & wqe_cnt)], 0, __ATOMIC_ACQUIRE);
			if (__atomic_compare_exchange_n(&rxq->rmpsh->head, &head,
							 head+THRESHOLD, 0, __ATOMIC_ACQUIRE,
							 __ATOMIC_RELAXED)) {
				/* Update the consumer index. */
				*rxq->rq_db = rte_cpu_to_be_32(rxq->rmpsh->head);
			} else {
				rxq->stats.contention++;
			}
		} else {
			flag = false;
		}
		head = rxq->rmpsh->head;
		head_idx = head & wqe_cnt;
	}
#ifdef MLX5_PMD_SOFT_COUNTERS
	/* Increment packets counter. */
	rxq->stats.ipackets += i;
#endif
	return i;
}

////////////////////////////////////////////////////////////////////////////////////////////////
// RMP works with one atomic_add_fetch per burst - 19Gbps one core
// Any solution with out-of-sequence WQEs will degrade performance
////////////////////////////////////////////////////////////////////////////////////////////////
// uint16_t
// mlx5_rx_burst_rmp(void *dpdk_rxq, struct rte_mbuf **pkts, uint16_t pkts_n)
// {
// 	struct mlx5_rxq_data *rxq = dpdk_rxq;
// 	// const unsigned int wqe_cnt = (1 << rxq->elts_n) - 1;
// 	const unsigned int cqe_cnt = (1 << rxq->cqe_n) - 1;
// 	const unsigned int sges_n = rxq->sges_n;
// 	struct rte_mbuf *pkt = NULL;
// 	struct rte_mbuf *seg = NULL;
// 	volatile struct mlx5_cqe *cqe;
// 	unsigned int i = 0;
// 	unsigned int rq_ci = rxq->rmpsh->rq_ci << sges_n;
// 	unsigned int org_rq_ci = rq_ci;
// 	int len = 0; /* keep its value across iterations. */
// 	volatile struct mlx5_wqe_srq_next_seg *tail = NULL;
// 	uint16_t head_idx;
// 	uint16_t idx;
// 
// 	while (pkts_n) {
// 		volatile struct mlx5_wqe_data_seg *wqe;
// 		struct rte_mbuf *rep;
// 		volatile struct mlx5_mini_cqe8 *mcqe = NULL;
// 
// 		cqe = &(*rxq->cqes)[rxq->cq_ci & cqe_cnt];
// 		rte_prefetch0(cqe);
// 		len = mlx5_rx_poll_len(rxq, cqe, cqe_cnt, &mcqe);
// 		if (!len)
// 			break;
// 		idx = rte_be_to_cpu_16(cqe->wqe_counter);
// 		wqe = &((volatile struct mlx5_wqe_rmp *)rxq->wqes)[idx].dseg;
// 		rep = (*rxq->rmpsh->elts)[idx];
// 		// rte_hexdump(stdout, "hex", cqe, 64);
// 		seg = rep;
// 		rte_prefetch0(seg);
// 		rte_prefetch0(wqe);
// 
// 		rep = rte_mbuf_raw_alloc(seg->pool);
// 		if (unlikely(rep == NULL)) {
// 			++rxq->stats.rx_nombuf;
// 			printf("rxq %d nombuf!!!\n", rxq->idx);
// 			if (!pkt) {
// 				/*
// 				 * no buffers before we even started,
// 				 * bail out silently.
// 				 */
// 				break;
// 			}
// 		}
// 
// 		pkt = seg;
// 		MLX5_ASSERT(len >= (rxq->crc_present << 2));
// 		pkt->ol_flags &= EXT_ATTACHED_MBUF;
// 		rxq_cq_to_mbuf(rxq, pkt, cqe, mcqe);
// 		if (rxq->crc_present)
// 			len -= RTE_ETHER_CRC_LEN;
// 		PKT_LEN(pkt) = len;
// 
// 		///////////////////////////////
// 		DATA_LEN(rep) = DATA_LEN(seg);
// 		PKT_LEN(rep) = PKT_LEN(seg);
// 		SET_DATA_OFF(rep, DATA_OFF(seg));
// 		PORT(rep) = PORT(seg);
// 		/* get linked list head wqe */
// 		{
// 			if (unlikely(tail == NULL)) {
// 				head_idx = idx;
// 				tail = &((volatile struct mlx5_wqe_rmp *)rxq->wqes)[idx].next_seg;
// 			} else {
// 				tail->next_wqe_index = htons(idx);
// 				tail = &((volatile struct mlx5_wqe_rmp *)rxq->wqes)[idx].next_seg;
// 			}
// 			(*rxq->rmpsh->elts)[idx] = rep;
// 			// printf("buf[%d] = %p\n", idx, rte_cpu_to_be_64(rte_pktmbuf_mtod(rep, uintptr_t)));
// 		}
// 		/*
// 		 * Fill NIC descriptor with the new buffer. The lkey and size
// 		 * of the buffers are already known, only the buffer address
// 		 * changes.
// 		 */
// 		wqe->addr = rte_cpu_to_be_64(rte_pktmbuf_mtod(rep, uintptr_t));
// 		/* If there's only one MR, no need to replace LKey in WQE. */
// 		if (unlikely(mlx5_mr_btree_len(&rxq->mr_ctrl.cache_bh) > 1))
// 			wqe->lkey = mlx5_rx_mb2mr(rxq, rep);
// 		if (len > DATA_LEN(seg)) {
// 			len -= DATA_LEN(seg);
// 			++NB_SEGS(pkt);
// 			++rq_ci;
// 			continue;
// 		}
// 		DATA_LEN(seg) = len;
// #ifdef MLX5_PMD_SOFT_COUNTERS
// 		/* Increment bytes counter. */
// 		rxq->stats.ibytes += PKT_LEN(pkt);
// #endif
// 		/* Return packet. */
// 		*(pkts++) = pkt;
// 		pkt = NULL;
// 		--pkts_n;
// 		++i;
// 		/* Align consumer index to the next stride. */
// 		rq_ci >>= sges_n;
// 		++rq_ci;
// 		rq_ci <<= sges_n;
// 	}
// 	if (unlikely(i == 0 && ((rq_ci >> sges_n) == org_rq_ci)))
// 		return 0;
// 
// 	{
// 		int next_idx = rxq->rmpsh->head;
// 		volatile struct mlx5_wqe_srq_next_seg *next;
// 		next = &((volatile struct mlx5_wqe_rmp *)rxq->wqes)[next_idx].next_seg;
// 
// 		while (!__atomic_compare_exchange_n(&rxq->rmpsh->head, &next_idx,
// 						    idx, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
// 			next_idx = rxq->rmpsh->head;
// 			// printf("contention on rxq next_idx q %d\n", rxq->idx);
// 			rxq->stats.contention++;
// 		}
// 
// 		next = &((volatile struct mlx5_wqe_rmp *)rxq->wqes)[next_idx].next_seg;
// 		next->next_wqe_index = htons(head_idx);
// 		// {
// 		// 	int j = 0;
// 		// 	printf("!!!!!!!!!!!!!!!!!!!!!!\n");
// 		// 	for (j = 0; j < 1024; j++) {
// 		// 		printf("%p[%d] = %d\n", rxq->wqes, j,
// 		// 		       ntohs(((volatile struct mlx5_wqe_rmp *)rxq->wqes)[j].next_seg.next_wqe_index));
// 		// 	}
// 		// }
// 	}
// 	/* Update the consumer index. */
// 	// rxq->rq_ci = rq_ci >> sges_n;
// 	/* TODO: check if another process is running and avoid MMIO if possible */
// 	__atomic_add_fetch(&rxq->rmpsh->rq_ci, rq_ci - org_rq_ci, __ATOMIC_ACQUIRE);
// 	rte_io_wmb();
// 	*rxq->cq_db = rte_cpu_to_be_32(rxq->cq_ci);
// 	rte_io_wmb();
// 	// *rxq->rq_db = rte_cpu_to_be_32(rxq->rq_ci);
// 	// if (rq_ci - org_rq_ci > 0) printf("rq %d inc %d (/%d)\n", rxq->idx, rq_ci - org_rq_ci, rxq->rmpsh->rq_ci);
// 	*rxq->rq_db = rte_cpu_to_be_32(rxq->rmpsh->rq_ci);
// #ifdef MLX5_PMD_SOFT_COUNTERS
// 	/* Increment packets counter. */
// 	rxq->stats.ipackets += i;
// #endif
// 	return i;
// }

////////////////////////////////////////////////////////////////////////////////////////////////
// RMP works first attempt
// ////////////////////////////////////////////////////////////////////////////////////////////////
// uint16_t
// mlx5_rx_burst_rmp(void *dpdk_rxq, struct rte_mbuf **pkts, uint16_t pkts_n)
// {
// 	struct mlx5_rxq_data *rxq = dpdk_rxq;
// 	const unsigned int wqe_cnt = (1 << rxq->elts_n) - 1;
// 	const unsigned int cqe_cnt = (1 << rxq->cqe_n) - 1;
// 	const unsigned int sges_n = rxq->sges_n;
// 	struct rte_mbuf *pkt = NULL;
// 	struct rte_mbuf *seg = NULL;
// 	volatile struct mlx5_cqe *cqe;
// 	unsigned int i = 0;
// 	unsigned int rq_ci = rxq->rmpsh->rq_ci << sges_n;
// 	unsigned int org_rq_ci = rq_ci;
// 	int len = 0; /* keep its value across iterations. */
// 
// 	while (pkts_n) {
// 		uint16_t idx;
// 		volatile struct mlx5_wqe_data_seg *wqe;
// 		struct rte_mbuf *rep;
// 		volatile struct mlx5_mini_cqe8 *mcqe = NULL;
// 
// 		cqe = &(*rxq->cqes)[rxq->cq_ci & cqe_cnt];
// 		rte_prefetch0(cqe);
// 		len = mlx5_rx_poll_len(rxq, cqe, cqe_cnt, &mcqe);
// 		if (!len)
// 			break;
// 		idx = rte_be_to_cpu_16(cqe->wqe_counter);
// 		wqe = &((volatile struct mlx5_wqe_rmp *)rxq->wqes)[idx].dseg;
// 		rep = (*rxq->rmpsh->elts)[idx];
// 		// rte_hexdump(stdout, "hex", cqe, 64);
// 		seg = rep;
// 		rte_prefetch0(seg);
// 		rte_prefetch0(wqe);
// 
// 		rep = rte_mbuf_raw_alloc(seg->pool);
// 		if (unlikely(rep == NULL)) {
// 			++rxq->stats.rx_nombuf;
// 			printf("rxq %d nombuf!!!\n", rxq->idx);
// 			if (!pkt) {
// 				/*
// 				 * no buffers before we even started,
// 				 * bail out silently.
// 				 */
// 				break;
// 			}
// 		}
// 
// 		pkt = seg;
// 		MLX5_ASSERT(len >= (rxq->crc_present << 2));
// 		pkt->ol_flags &= EXT_ATTACHED_MBUF;
// 		rxq_cq_to_mbuf(rxq, pkt, cqe, mcqe);
// 		if (rxq->crc_present)
// 			len -= RTE_ETHER_CRC_LEN;
// 		PKT_LEN(pkt) = len;
// 
// 		///////////////////////////////
// 		DATA_LEN(rep) = DATA_LEN(seg);
// 		PKT_LEN(rep) = PKT_LEN(seg);
// 		SET_DATA_OFF(rep, DATA_OFF(seg));
// 		PORT(rep) = PORT(seg);
// 		/* get linked list head wqe */
// 		{
// 			int next_idx = rxq->rmpsh->head;
// 			// printf("rxq %d head before %d ", rxq->idx, rxq->rmpsh->head);
// 			while (!__atomic_compare_exchange_n(&rxq->rmpsh->head, &next_idx,
// 						idx, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
// 				next_idx = rxq->rmpsh->head;
// 				// printf("contention on rxq next_idx q %d\n", rxq->idx);
// 				rxq->stats.contention++;
// 			}
// 			// printf("head after %d ", rxq->rmpsh->head);
// 			volatile struct mlx5_wqe_srq_next_seg *next =
// 				&((volatile struct mlx5_wqe_rmp *)rxq->wqes)[next_idx].next_seg;
// 			wqe = &((volatile struct mlx5_wqe_rmp *)rxq->wqes)[next_idx].dseg;
// 			next->next_wqe_index = htons(idx);
// 			(*rxq->rmpsh->elts)[next_idx] = rep;
// 
//      		// volatile struct mlx5_wqe_srq_next_seg *next =
//      		//			&((volatile struct mlx5_wqe_rmp *)rxq->wqes)[next_idx].next_seg;
//      		//		next->next_wqe_index = htons(idx);
//      		//		 (*rxq->rmpsh->elts)[idx] = rep;
// 		}
// 		/*
// 		 * Fill NIC descriptor with the new buffer. The lkey and size
// 		 * of the buffers are already known, only the buffer address
// 		 * changes.
// 		 */
// 		wqe->addr = rte_cpu_to_be_64(rte_pktmbuf_mtod(rep, uintptr_t));
// 		/* If there's only one MR, no need to replace LKey in WQE. */
// 		if (unlikely(mlx5_mr_btree_len(&rxq->mr_ctrl.cache_bh) > 1))
// 			wqe->lkey = mlx5_rx_mb2mr(rxq, rep);
// 		if (len > DATA_LEN(seg)) {
// 			len -= DATA_LEN(seg);
// 			++NB_SEGS(pkt);
// 			++rq_ci;
// 			continue;
// 		}
// 		DATA_LEN(seg) = len;
// #ifdef MLX5_PMD_SOFT_COUNTERS
// 		/* Increment bytes counter. */
// 		rxq->stats.ibytes += PKT_LEN(pkt);
// #endif
// 		/* Return packet. */
// 		*(pkts++) = pkt;
// 		pkt = NULL;
// 		--pkts_n;
// 		++i;
// 		/* Align consumer index to the next stride. */
// 		rq_ci >>= sges_n;
// 		++rq_ci;
// 		rq_ci <<= sges_n;
// 	}
// 	if (unlikely(i == 0 && ((rq_ci >> sges_n) == org_rq_ci)))
// 		return 0;
// 	/* Update the consumer index. */
// 	// rxq->rq_ci = rq_ci >> sges_n;
// 	/* TODO: check if another process is running and avoid MMIO if possible */
// 	__atomic_add_fetch(&rxq->rmpsh->rq_ci, rq_ci - org_rq_ci, __ATOMIC_ACQUIRE);
// 	rte_io_wmb();
// 	*rxq->cq_db = rte_cpu_to_be_32(rxq->cq_ci);
// 	rte_io_wmb();
// 	// *rxq->rq_db = rte_cpu_to_be_32(rxq->rq_ci);
// 	// if (rq_ci - org_rq_ci > 0) printf("rq %d inc %d (/%d)\n", rxq->idx, rq_ci - org_rq_ci, rxq->rmpsh->rq_ci);
// 	*rxq->rq_db = rte_cpu_to_be_32(rxq->rmpsh->rq_ci);
// #ifdef MLX5_PMD_SOFT_COUNTERS
// 	/* Increment packets counter. */
// 	rxq->stats.ipackets += i;
// #endif
// 	return i;
// }

/**
 * Update LRO packet TCP header.
 * The HW LRO feature doesn't update the TCP header after coalescing the
 * TCP segments but supplies information in CQE to fill it by SW.
 *
 * @param tcp
 *   Pointer to the TCP header.
 * @param cqe
 *   Pointer to the completion entry.
 * @param phcsum
 *   The L3 pseudo-header checksum.
 */
static inline void
mlx5_lro_update_tcp_hdr(struct rte_tcp_hdr *__rte_restrict tcp,
			volatile struct mlx5_cqe *__rte_restrict cqe,
			uint32_t phcsum, uint8_t l4_type)
{
	/*
	 * The HW calculates only the TCP payload checksum, need to complete
	 * the TCP header checksum and the L3 pseudo-header checksum.
	 */
	uint32_t csum = phcsum + cqe->csum;

	if (l4_type == MLX5_L4_HDR_TYPE_TCP_EMPTY_ACK ||
	    l4_type == MLX5_L4_HDR_TYPE_TCP_WITH_ACL) {
		tcp->tcp_flags |= RTE_TCP_ACK_FLAG;
		tcp->recv_ack = cqe->lro_ack_seq_num;
		tcp->rx_win = cqe->lro_tcp_win;
	}
	if (cqe->lro_tcppsh_abort_dupack & MLX5_CQE_LRO_PUSH_MASK)
		tcp->tcp_flags |= RTE_TCP_PSH_FLAG;
	tcp->cksum = 0;
	csum += rte_raw_cksum(tcp, (tcp->data_off >> 4) * 4);
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
	csum = (~csum) & 0xffff;
	if (csum == 0)
		csum = 0xffff;
	tcp->cksum = csum;
}

/**
 * Update LRO packet headers.
 * The HW LRO feature doesn't update the L3/TCP headers after coalescing the
 * TCP segments but supply information in CQE to fill it by SW.
 *
 * @param padd
 *   The packet address.
 * @param cqe
 *   Pointer to the completion entry.
 * @param len
 *   The packet length.
 */
static inline void
mlx5_lro_update_hdr(uint8_t *__rte_restrict padd,
		    volatile struct mlx5_cqe *__rte_restrict cqe,
		    volatile struct mlx5_mini_cqe8 *mcqe,
		    struct mlx5_rxq_data *rxq, uint32_t len)
{
	union {
		struct rte_ether_hdr *eth;
		struct rte_vlan_hdr *vlan;
		struct rte_ipv4_hdr *ipv4;
		struct rte_ipv6_hdr *ipv6;
		struct rte_tcp_hdr *tcp;
		uint8_t *hdr;
	} h = {
		.hdr = padd,
	};
	uint16_t proto = h.eth->ether_type;
	uint32_t phcsum;
	uint8_t l4_type;

	h.eth++;
	while (proto == RTE_BE16(RTE_ETHER_TYPE_VLAN) ||
	       proto == RTE_BE16(RTE_ETHER_TYPE_QINQ)) {
		proto = h.vlan->eth_proto;
		h.vlan++;
	}
	if (proto == RTE_BE16(RTE_ETHER_TYPE_IPV4)) {
		h.ipv4->time_to_live = cqe->lro_min_ttl;
		h.ipv4->total_length = rte_cpu_to_be_16(len - (h.hdr - padd));
		h.ipv4->hdr_checksum = 0;
		h.ipv4->hdr_checksum = rte_ipv4_cksum(h.ipv4);
		phcsum = rte_ipv4_phdr_cksum(h.ipv4, 0);
		h.ipv4++;
	} else {
		h.ipv6->hop_limits = cqe->lro_min_ttl;
		h.ipv6->payload_len = rte_cpu_to_be_16(len - (h.hdr - padd) -
						       sizeof(*h.ipv6));
		phcsum = rte_ipv6_phdr_cksum(h.ipv6, 0);
		h.ipv6++;
	}
	if (mcqe == NULL ||
	    rxq->mcqe_format != MLX5_CQE_RESP_FORMAT_L34H_STRIDX)
		l4_type = (rte_be_to_cpu_16(cqe->hdr_type_etc) &
			   MLX5_CQE_L4_TYPE_MASK) >> MLX5_CQE_L4_TYPE_SHIFT;
	else
		l4_type = (rte_be_to_cpu_16(mcqe->hdr_type) &
			   MLX5_CQE_L4_TYPE_MASK) >> MLX5_CQE_L4_TYPE_SHIFT;
	mlx5_lro_update_tcp_hdr(h.tcp, cqe, phcsum, l4_type);
}

void
mlx5_mprq_buf_free_cb(void *addr __rte_unused, void *opaque)
{
	struct mlx5_mprq_buf *buf = opaque;

	if (__atomic_load_n(&buf->refcnt, __ATOMIC_RELAXED) == 1) {
		rte_mempool_put(buf->mp, buf);
	} else if (unlikely(__atomic_sub_fetch(&buf->refcnt, 1,
					       __ATOMIC_RELAXED) == 0)) {
		__atomic_store_n(&buf->refcnt, 1, __ATOMIC_RELAXED);
		rte_mempool_put(buf->mp, buf);
	}
}

void
mlx5_mprq_buf_free(struct mlx5_mprq_buf *buf)
{
	mlx5_mprq_buf_free_cb(NULL, buf);
}

/**
 * DPDK callback for RX with Multi-Packet RQ support.
 *
 * @param dpdk_rxq
 *   Generic pointer to RX queue structure.
 * @param[out] pkts
 *   Array to store received packets.
 * @param pkts_n
 *   Maximum number of packets in array.
 *
 * @return
 *   Number of packets successfully received (<= pkts_n).
 */
uint16_t
mlx5_rx_burst_mprq(void *dpdk_rxq, struct rte_mbuf **pkts, uint16_t pkts_n)
{
	struct mlx5_rxq_data *rxq = dpdk_rxq;
	const uint32_t strd_n = 1 << rxq->strd_num_n;
	const uint32_t strd_sz = 1 << rxq->strd_sz_n;
	const uint32_t cq_mask = (1 << rxq->cqe_n) - 1;
	const uint32_t wq_mask = (1 << rxq->elts_n) - 1;
	volatile struct mlx5_cqe *cqe = &(*rxq->cqes)[rxq->cq_ci & cq_mask];
	unsigned int i = 0;
	uint32_t rq_ci = rxq->rq_ci;
	uint16_t consumed_strd = rxq->consumed_strd;
	struct mlx5_mprq_buf *buf = (*rxq->mprq_bufs)[rq_ci & wq_mask];

	while (i < pkts_n) {
		struct rte_mbuf *pkt;
		int ret;
		uint32_t len;
		uint16_t strd_cnt;
		uint16_t strd_idx;
		uint32_t byte_cnt;
		volatile struct mlx5_mini_cqe8 *mcqe = NULL;
		enum mlx5_rqx_code rxq_code;

		if (consumed_strd == strd_n) {
			/* Replace WQE if the buffer is still in use. */
			mprq_buf_replace(rxq, rq_ci & wq_mask);
			/* Advance to the next WQE. */
			consumed_strd = 0;
			++rq_ci;
			buf = (*rxq->mprq_bufs)[rq_ci & wq_mask];
		}
		cqe = &(*rxq->cqes)[rxq->cq_ci & cq_mask];
		ret = mlx5_rx_poll_len(rxq, cqe, cq_mask, &mcqe);
		if (!ret)
			break;
		byte_cnt = ret;
		len = (byte_cnt & MLX5_MPRQ_LEN_MASK) >> MLX5_MPRQ_LEN_SHIFT;
		MLX5_ASSERT((int)len >= (rxq->crc_present << 2));
		if (rxq->crc_present)
			len -= RTE_ETHER_CRC_LEN;
		if (mcqe &&
		    rxq->mcqe_format == MLX5_CQE_RESP_FORMAT_FTAG_STRIDX)
			strd_cnt = (len / strd_sz) + !!(len % strd_sz);
		else
			strd_cnt = (byte_cnt & MLX5_MPRQ_STRIDE_NUM_MASK) >>
				   MLX5_MPRQ_STRIDE_NUM_SHIFT;
		MLX5_ASSERT(strd_cnt);
		consumed_strd += strd_cnt;
		if (byte_cnt & MLX5_MPRQ_FILLER_MASK)
			continue;
		strd_idx = rte_be_to_cpu_16(mcqe == NULL ?
					cqe->wqe_counter :
					mcqe->stride_idx);
		MLX5_ASSERT(strd_idx < strd_n);
		MLX5_ASSERT(!((rte_be_to_cpu_16(cqe->wqe_id) ^ rq_ci) &
			    wq_mask));
		pkt = rte_pktmbuf_alloc(rxq->mp);
		if (unlikely(pkt == NULL)) {
			++rxq->stats.rx_nombuf;
			break;
		}
		len = (byte_cnt & MLX5_MPRQ_LEN_MASK) >> MLX5_MPRQ_LEN_SHIFT;
		MLX5_ASSERT((int)len >= (rxq->crc_present << 2));
		if (rxq->crc_present)
			len -= RTE_ETHER_CRC_LEN;
		rxq_code = mprq_buf_to_pkt(rxq, pkt, len, buf,
					   strd_idx, strd_cnt);
		if (unlikely(rxq_code != MLX5_RXQ_CODE_EXIT)) {
			rte_pktmbuf_free_seg(pkt);
			if (rxq_code == MLX5_RXQ_CODE_DROPPED) {
				++rxq->stats.idropped;
				continue;
			}
			if (rxq_code == MLX5_RXQ_CODE_NOMBUF) {
				++rxq->stats.rx_nombuf;
				break;
			}
		}
		printf("%s ci %d cons_strd %d/%d len %d\n",
			__func__, rq_ci, consumed_strd, strd_n, len);
		rxq_cq_to_mbuf(rxq, pkt, cqe, mcqe);
		if (cqe->lro_num_seg > 1) {
			mlx5_lro_update_hdr(rte_pktmbuf_mtod(pkt, uint8_t *),
					    cqe, mcqe, rxq, len);
			pkt->ol_flags |= PKT_RX_LRO;
			pkt->tso_segsz = len / cqe->lro_num_seg;
		}
		PKT_LEN(pkt) = len;
		PORT(pkt) = rxq->port_id;
#ifdef MLX5_PMD_SOFT_COUNTERS
		/* Increment bytes counter. */
		rxq->stats.ibytes += PKT_LEN(pkt);
#endif
		/* Return packet. */
		*(pkts++) = pkt;
		++i;
	}
	/* Update the consumer indexes. */
	rxq->consumed_strd = consumed_strd;
	rte_io_wmb();
	*rxq->cq_db = rte_cpu_to_be_32(rxq->cq_ci);
	if (rq_ci != rxq->rq_ci) {
		rxq->rq_ci = rq_ci;
		rte_io_wmb();
		*rxq->rq_db = rte_cpu_to_be_32(rxq->rq_ci);
	}
#ifdef MLX5_PMD_SOFT_COUNTERS
	/* Increment packets counter. */
	rxq->stats.ipackets += i;
#endif
	return i;
}

/**
 * DPDK callback for RX with RMP and Multi-Packet RQ support.
 *
 * @param dpdk_rxq
 *   Generic pointer to RX queue structure.
 * @param[out] pkts
 *   Array to store received packets.
 * @param pkts_n
 *   Maximum number of packets in array.
 *
 * @return
 *   Number of packets successfully received (<= pkts_n).
 */
uint16_t
mlx5_rx_burst_rmp_mprq(void *dpdk_rxq, struct rte_mbuf **pkts, uint16_t pkts_n)
{
	struct mlx5_rxq_data *rxq = dpdk_rxq;
	const uint32_t strd_n = 1 << rxq->strd_num_n;
	const uint32_t strd_sz = 1 << rxq->strd_sz_n;
	const uint32_t cq_mask = (1 << rxq->cqe_n) - 1;
	const uint32_t wq_mask = (1 << rxq->elts_n) - 1;
	volatile struct mlx5_cqe *cqe = &(*rxq->cqes)[rxq->cq_ci & cq_mask];
	unsigned int i = 0;
	uint32_t rq_ci = rxq->rmpsh->rq_ci;
	uint32_t org_rq_ci = rxq->rmpsh->rq_ci;
	uint32_t wqe_rq_ci = rte_be_to_cpu_16(cqe->wqe_id);
	uint16_t consumed_strd = rxq->rmpsh->consumed_strd;
	struct mlx5_mprq_buf *buf = (*rxq->mprq_bufs)[wqe_rq_ci & wq_mask];

	printf("!!! mprq + rmp is broken!!!\n");
	while (i < pkts_n) {
		struct rte_mbuf *pkt;
		int ret;
		uint32_t len;
		uint16_t strd_cnt;
		uint16_t strd_idx;
		uint32_t byte_cnt;
		volatile struct mlx5_mini_cqe8 *mcqe = NULL;
		enum mlx5_rqx_code rxq_code;

		if (consumed_strd == strd_n) {
			/* Replace WQE if the buffer is still in use. */
			mprq_buf_replace(rxq, wqe_rq_ci & wq_mask);
			/* Advance to the next WQE. */
			// consumed_strd = 0;
			__atomic_sub_fetch(&rxq->rmpsh->consumed_strd, strd_n, __ATOMIC_RELAXED);
			++rq_ci;
		}
		cqe = &(*rxq->cqes)[rxq->cq_ci & cq_mask];
		wqe_rq_ci = rte_be_to_cpu_16(cqe->wqe_id);
		buf = (*rxq->mprq_bufs)[wqe_rq_ci & wq_mask];
		ret = mlx5_rx_poll_len(rxq, cqe, cq_mask, &mcqe);
		if (!ret)
			break;
		byte_cnt = ret;
		len = (byte_cnt & MLX5_MPRQ_LEN_MASK) >> MLX5_MPRQ_LEN_SHIFT;
		MLX5_ASSERT((int)len >= (rxq->crc_present << 2));
		if (rxq->crc_present)
			len -= RTE_ETHER_CRC_LEN;
		if (mcqe &&
		    rxq->mcqe_format == MLX5_CQE_RESP_FORMAT_FTAG_STRIDX)
			strd_cnt = (len / strd_sz) + !!(len % strd_sz);
		else
			strd_cnt = (byte_cnt & MLX5_MPRQ_STRIDE_NUM_MASK) >>
				   MLX5_MPRQ_STRIDE_NUM_SHIFT;
		MLX5_ASSERT(strd_cnt);
		consumed_strd += strd_cnt;
		if (byte_cnt & MLX5_MPRQ_FILLER_MASK)
			continue;
		strd_idx = rte_be_to_cpu_16(mcqe == NULL ?
					cqe->wqe_counter :
					mcqe->stride_idx);
		MLX5_ASSERT(strd_idx < strd_n);
		MLX5_ASSERT(!((rte_be_to_cpu_16(cqe->wqe_id) ^ wqe_rq_ci) &
			    wq_mask));
		pkt = rte_pktmbuf_alloc(rxq->mp);
		if (unlikely(pkt == NULL)) {
			++rxq->stats.rx_nombuf;
			break;
		}
		len = (byte_cnt & MLX5_MPRQ_LEN_MASK) >> MLX5_MPRQ_LEN_SHIFT;
		MLX5_ASSERT((int)len >= (rxq->crc_present << 2));
		if (rxq->crc_present)
			len -= RTE_ETHER_CRC_LEN;
		rxq_code = mprq_buf_to_pkt(rxq, pkt, len, buf,
					   strd_idx, strd_cnt);
		if (unlikely(rxq_code != MLX5_RXQ_CODE_EXIT)) {
			rte_pktmbuf_free_seg(pkt);
			if (rxq_code == MLX5_RXQ_CODE_DROPPED) {
				++rxq->stats.idropped;
				continue;
			}
			if (rxq_code == MLX5_RXQ_CODE_NOMBUF) {
				++rxq->stats.rx_nombuf;
				break;
			}
		}
		printf("%s rq %d ci %d (%d) cons_strd %d/%d len %d\n",
			__func__, rxq->idx, wqe_rq_ci, rq_ci, consumed_strd, strd_n, len);
		rxq_cq_to_mbuf(rxq, pkt, cqe, mcqe);
		if (cqe->lro_num_seg > 1) {
			mlx5_lro_update_hdr(rte_pktmbuf_mtod(pkt, uint8_t *),
					    cqe, mcqe, rxq, len);
			pkt->ol_flags |= PKT_RX_LRO;
			pkt->tso_segsz = len / cqe->lro_num_seg;
		}
		PKT_LEN(pkt) = len;
		PORT(pkt) = rxq->port_id;
#ifdef MLX5_PMD_SOFT_COUNTERS
		/* Increment bytes counter. */
		rxq->stats.ibytes += PKT_LEN(pkt);
#endif
		/* Return packet. */
		*(pkts++) = pkt;
		++i;
	}
	/* Update the consumer indexes. */
	rxq->consumed_strd = consumed_strd;
	rte_io_wmb();
	*rxq->cq_db = rte_cpu_to_be_32(rxq->cq_ci);
	if (rq_ci != org_rq_ci) {
		__atomic_add_fetch(&rxq->rmpsh->rq_ci, rq_ci - org_rq_ci,__ATOMIC_ACQUIRE);
		rte_io_wmb();
		*rxq->rq_db = rte_cpu_to_be_32(rxq->rmpsh->rq_ci);
	}
#ifdef MLX5_PMD_SOFT_COUNTERS
	/* Increment packets counter. */
	rxq->stats.ipackets += i;
#endif
	return i;
}

/**
 * Dummy DPDK callback for RX.
 *
 * This function is used to temporarily replace the real callback during
 * unsafe control operations on the queue, or in case of error.
 *
 * @param dpdk_rxq
 *   Generic pointer to RX queue structure.
 * @param[out] pkts
 *   Array to store received packets.
 * @param pkts_n
 *   Maximum number of packets in array.
 *
 * @return
 *   Number of packets successfully received (<= pkts_n).
 */
uint16_t
removed_rx_burst(void *dpdk_rxq __rte_unused,
		 struct rte_mbuf **pkts __rte_unused,
		 uint16_t pkts_n __rte_unused)
{
	rte_mb();
	return 0;
}

/*
 * Vectorized Rx routines are not compiled in when required vector instructions
 * are not supported on a target architecture.
 * The following null stubs are needed for linkage when those are not included
 * outside of this file (e.g. mlx5_rxtx_vec_sse.c for x86).
 */

__rte_weak uint16_t
mlx5_rx_burst_vec(void *dpdk_rxq __rte_unused,
		  struct rte_mbuf **pkts __rte_unused,
		  uint16_t pkts_n __rte_unused)
{
	return 0;
}

__rte_weak uint16_t
mlx5_rx_burst_mprq_vec(void *dpdk_rxq __rte_unused,
		       struct rte_mbuf **pkts __rte_unused,
		       uint16_t pkts_n __rte_unused)
{
	return 0;
}

__rte_weak int
mlx5_rxq_check_vec_support(struct mlx5_rxq_data *rxq __rte_unused)
{
	return -ENOTSUP;
}

__rte_weak int
mlx5_check_vec_rx_support(struct rte_eth_dev *dev __rte_unused)
{
	return -ENOTSUP;
}

