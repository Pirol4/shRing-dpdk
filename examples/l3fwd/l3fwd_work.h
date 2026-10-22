/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Filipe Pirola
 */

/*
 * Synthetic per-packet work and Rx ring occupancy for the evaluation.
 *
 * Work: each received packet costs its lcore N random 8-byte reads from one
 * buffer shared by all lcores (40 MiB by default, larger than the LLC), like
 * the synthetic NF of the shRing and rxBisect papers (FastClick WorkPackage),
 * optionally after reading the packet's payload, one word per cache line.
 * One lcore can be given another N (the papers' "target core"). With every
 * knob unset the main loop is stock l3fwd plus two predictable branches.
 *
 * Occupancy: every L3FWD_OCCUPANCY_US the lcore counts the completions
 * waiting on its Rx queue (rte_eth_rx_queue_count), i.e. packets received by
 * the NIC and not yet read: the ring occupancy of the papers' Fig. 9c/10c.
 * Samples are taken only while packets arrive, so gaps between traffic
 * windows do not count.
 *
 * Environment (read once at start-up):
 *   L3FWD_WORK_ACCESSES=N         random reads per packet on every lcore
 *   L3FWD_WORK_TARGET=<lcore>:<N> that lcore does N instead
 *   L3FWD_WORK_MIB=M              buffer size in MiB (default 40)
 *   L3FWD_WORK_PAYLOAD=1          also read the payload of every packet
 *   L3FWD_OCCUPANCY_US=U          occupancy sample period (0, default: off)
 * Only the LPM main loop (l3fwd's default) runs them.
 */

#ifndef __L3FWD_WORK_H__
#define __L3FWD_WORK_H__

#include <stdint.h>

#include <rte_branch_prediction.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>

/* Per-lcore state, written only by its lcore after start-up. */
struct l3fwd_work {
	uint32_t accesses;     /* random reads per packet */
	uint64_t rng;          /* xorshift64 state, never 0 */
	uint64_t sink;         /* keeps the reads from being optimised away */
	uint64_t cycles;       /* TSC spent in the work, same span as rx_pkts */
	uint64_t occ_period;   /* TSC between occupancy samples, 0 = off */
	uint64_t occ_next;     /* TSC of the next sample */
	uint64_t occ_last_pkts; /* rx_pkts at the previous sample */
	uint64_t occ_sum;
	uint64_t occ_samples;
	uint32_t occ_max;
};

/* Shared, read-only once the lcores run. */
extern uint64_t *l3fwd_work_buf;
extern uint64_t l3fwd_work_words;
extern int l3fwd_work_payload;

/* Parse the environment, allocate the buffer, fill every lcore's state. */
void l3fwd_work_init(void);

/* Sample the occupancy of the lcore's Rx queues if a period has passed. */
void l3fwd_work_sample_occupancy(unsigned int lcore_id, uint64_t now,
				 uint64_t rx_pkts);

/* Forget what was counted so far (with l3fwd's own counters). */
void l3fwd_work_reset(struct l3fwd_work *w);

/* Print the lcore's WORK and OCCUPANCY results at exit. */
void l3fwd_work_report(unsigned int lcore_id, uint64_t rx_pkts);

static inline uint64_t
l3fwd_work_next(uint64_t *x)
{
	*x ^= *x << 13;
	*x ^= *x >> 7;
	*x ^= *x << 17;
	return *x;
}

/* An index in [0, words) without a division: the high half of x * words. */
static inline uint64_t
l3fwd_work_index(uint64_t x, uint64_t words)
{
	return (uint64_t)(((unsigned __int128)x * words) >> 64);
}

static inline uint64_t
l3fwd_work_read_payload(const struct rte_mbuf *m)
{
	const uint8_t *data = rte_pktmbuf_mtod(m, const uint8_t *);
	uint64_t sum = 0;
	uint32_t off;

	for (off = 0; off + sizeof(uint64_t) <= m->data_len;
	     off += RTE_CACHE_LINE_SIZE)
		sum += *(const uint64_t *)(data + off);
	return sum;
}

/* The work of one non-empty burst; its time goes to w->cycles. */
static inline void
l3fwd_work_do(struct l3fwd_work *w, struct rte_mbuf **pkts, int nb_rx)
{
	uint64_t start, sum, x;
	uint32_t i;
	int p;

	if (likely(w->accesses == 0 && !l3fwd_work_payload))
		return;
	start = rte_rdtsc();
	sum = w->sink;
	x = w->rng;
	for (p = 0; p < nb_rx; p++) {
		if (l3fwd_work_payload)
			sum += l3fwd_work_read_payload(pkts[p]);
		for (i = 0; i < w->accesses; i++)
			sum += l3fwd_work_buf[l3fwd_work_index(
					l3fwd_work_next(&x), l3fwd_work_words)];
	}
	w->rng = x;
	w->sink = sum;
	w->cycles += rte_rdtsc() - start;
}

#endif /* __L3FWD_WORK_H__ */
