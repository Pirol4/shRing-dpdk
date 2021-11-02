/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#ifndef RTE_PMD_MLX5_COMMON_DEVX_H_
#define RTE_PMD_MLX5_COMMON_DEVX_H_

#include "mlx5_devx_cmds.h"

// TODO: seperate to read-only and shared cachelines
struct rmp_shared {
	uint32_t refcount;
	int rmpn;
	uint32_t rq_ci;
	uint32_t rq_pi;
	uint16_t consumed_strd;
	uint16_t head; /* bounces between cores */

	/* start new cacheline here */
	uint64_t *uwbmp __rte_cache_aligned; // used wqe bitmap
	struct mlx5dv_devx_umem *umem_obj;
	void *umem_buf;
	struct rte_mbuf *(*elts)[];
	struct mlx5_mprq_buf *(*mprq_bufs)[];
};

/* The standard page size */
#define MLX5_LOG_PAGE_SIZE 12

/* DevX Completion Queue structure. */
struct mlx5_devx_cq {
	struct mlx5_devx_obj *cq; /* The CQ DevX object. */
	void *umem_obj; /* The CQ umem object. */
	union {
		volatile void *umem_buf;
		volatile struct mlx5_cqe *cqes; /* The CQ ring buffer. */
	};
	volatile uint32_t *db_rec; /* The CQ doorbell record. */
};

/* DevX Send Queue structure. */
struct mlx5_devx_sq {
	struct mlx5_devx_obj *sq; /* The SQ DevX object. */
	void *umem_obj; /* The SQ umem object. */
	union {
		volatile void *umem_buf;
		volatile struct mlx5_wqe *wqes; /* The SQ ring buffer. */
		volatile struct mlx5_aso_wqe *aso_wqes;
	};
	volatile uint32_t *db_rec; /* The SQ doorbell record. */
};

/* DevX Receive Queue structure. */
struct mlx5_devx_rq {
	struct mlx5_devx_obj *rmp; /* The RMP DevX object. */
	struct mlx5_devx_obj *rq; /* The RQ DevX object. */
	void *umem_obj; /* The RQ umem object. */
	volatile void *umem_buf;
	volatile uint32_t *db_rec; /* The RQ doorbell record. */
};

/* mlx5_common_devx.c */

__rte_internal
void mlx5_devx_cq_destroy(struct mlx5_devx_cq *cq);

__rte_internal
int mlx5_devx_cq_create(void *ctx, struct mlx5_devx_cq *cq_obj,
			uint16_t log_desc_n,
			struct mlx5_devx_cq_attr *attr, int socket);

__rte_internal
void mlx5_devx_sq_destroy(struct mlx5_devx_sq *sq);

__rte_internal
int mlx5_devx_sq_create(void *ctx, struct mlx5_devx_sq *sq_obj,
			uint16_t log_wqbb_n,
			struct mlx5_devx_create_sq_attr *attr, int socket);

__rte_internal
void mlx5_devx_rq_destroy(struct mlx5_devx_rq *rq);

__rte_internal
int mlx5_devx_rq_create(void *ctx, struct mlx5_devx_rq *rq_obj,
		    struct rmp_shared *rmpsh,
		    uint32_t wqe_size,
		    uint16_t log_wqbb_n,
		    struct mlx5_devx_create_rq_attr *attr,
		    struct mlx5_devx_create_rmp_attr *rmp_attr,
		    int socket);

#endif /* RTE_PMD_MLX5_COMMON_DEVX_H_ */
