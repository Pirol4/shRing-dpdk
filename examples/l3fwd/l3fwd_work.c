/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Filipe Pirola
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#include "l3fwd.h"
#include "l3fwd_work.h"

#define WORK_MIB_DEFAULT 40
#define WORK_MIB_MAX 4096
#define WORK_ACCESSES_MAX 100000
#define OCCUPANCY_US_MAX 1000000

uint64_t *l3fwd_work_buf;
uint64_t l3fwd_work_words;
int l3fwd_work_payload;

/* An unsigned number from the environment, `fallback` when unset. */
static unsigned long
env_number(const char *name, unsigned long fallback, unsigned long max)
{
	const char *env = getenv(name);
	char *end;
	unsigned long value;

	if (env == NULL || *env == '\0')
		return fallback;
	value = strtoul(env, &end, 10);
	if (*end != '\0' || value > max)
		rte_exit(EXIT_FAILURE, "%s=%s: want 0-%lu\n", name, env, max);
	return value;
}

/* L3FWD_WORK_TARGET=<lcore>:<accesses>; *lcore = RTE_MAX_LCORE when unset. */
static void
env_target(unsigned int *lcore, uint32_t *accesses)
{
	const char *env = getenv("L3FWD_WORK_TARGET");
	unsigned long id, n;
	char *end;

	*lcore = RTE_MAX_LCORE;
	*accesses = 0;
	if (env == NULL || *env == '\0')
		return;
	id = strtoul(env, &end, 10);
	if (*end != ':' || id >= RTE_MAX_LCORE)
		goto bad;
	n = strtoul(end + 1, &end, 10);
	if (*end != '\0' || n > WORK_ACCESSES_MAX)
		goto bad;
	*lcore = id;
	*accesses = n;
	return;
bad:
	rte_exit(EXIT_FAILURE, "L3FWD_WORK_TARGET=%s: want <lcore>:<0-%u>\n",
		 env, WORK_ACCESSES_MAX);
}

/* Touch every word, so no page is first faulted in during a measurement. */
static void
work_buffer_alloc(unsigned long mib)
{
	uint64_t i;

	l3fwd_work_words = (uint64_t)mib * 1024 * 1024 / sizeof(uint64_t);
	l3fwd_work_buf = rte_malloc("l3fwd_work", l3fwd_work_words *
				    sizeof(uint64_t), RTE_CACHE_LINE_SIZE);
	if (l3fwd_work_buf == NULL)
		rte_exit(EXIT_FAILURE, "cannot allocate %lu MiB of work buffer\n",
			 mib);
	for (i = 0; i < l3fwd_work_words; i++)
		l3fwd_work_buf[i] = i * 0x9e3779b97f4a7c15ULL;
}

void
l3fwd_work_init(void)
{
	unsigned long accesses, mib, occupancy_us;
	unsigned int target_lcore, lcore_id;
	uint32_t target_accesses;

	accesses = env_number("L3FWD_WORK_ACCESSES", 0, WORK_ACCESSES_MAX);
	mib = env_number("L3FWD_WORK_MIB", WORK_MIB_DEFAULT, WORK_MIB_MAX);
	l3fwd_work_payload = env_number("L3FWD_WORK_PAYLOAD", 0, 1);
	occupancy_us = env_number("L3FWD_OCCUPANCY_US", 0, OCCUPANCY_US_MAX);
	env_target(&target_lcore, &target_accesses);
	if (mib == 0)
		rte_exit(EXIT_FAILURE, "L3FWD_WORK_MIB must be at least 1\n");

	if (accesses > 0 || target_accesses > 0)
		work_buffer_alloc(mib);

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		struct l3fwd_work *w = &lcore_conf[lcore_id].work;

		memset(w, 0, sizeof(*w));
		w->accesses = lcore_id == target_lcore ? target_accesses
						       : accesses;
		w->rng = 0x2545f4914f6cdd1dULL * (lcore_id + 1);
		w->occ_period = occupancy_us * rte_get_tsc_hz() / US_PER_S;
	}
	printf("WORK: %lu random reads per packet in %lu MiB", accesses, mib);
	if (target_lcore < RTE_MAX_LCORE)
		printf(", %u on target lcore %u", target_accesses, target_lcore);
	printf("; payload read %s; occupancy every %lu us%s\n",
	       l3fwd_work_payload ? "on" : "off", occupancy_us,
	       occupancy_us ? "" : " (off)");
}

void
l3fwd_work_sample_occupancy(unsigned int lcore_id, uint64_t now,
			    uint64_t rx_pkts)
{
	struct lcore_conf *qconf = &lcore_conf[lcore_id];
	struct l3fwd_work *w = &qconf->work;
	uint32_t waiting = 0;
	int i, n;

	w->occ_next = now + w->occ_period;
	/* No packet since the last sample: no traffic, nothing to measure. */
	if (rx_pkts == w->occ_last_pkts)
		return;
	w->occ_last_pkts = rx_pkts;
	for (i = 0; i < qconf->n_rx_queue; i++) {
		n = rte_eth_rx_queue_count(qconf->rx_queue_list[i].port_id,
					   qconf->rx_queue_list[i].queue_id);
		if (n < 0) {
			printf("OCCUPANCY lcore %u: rx_queue_count failed (%d), "
			       "sampling off\n", lcore_id, n);
			w->occ_period = 0;
			return;
		}
		waiting += n;
	}
	w->occ_sum += waiting;
	w->occ_samples++;
	if (waiting > w->occ_max)
		w->occ_max = waiting;
}

void
l3fwd_work_reset(struct l3fwd_work *w)
{
	w->cycles = 0;
	w->occ_sum = 0;
	w->occ_samples = 0;
	w->occ_max = 0;
}

void
l3fwd_work_report(unsigned int lcore_id, uint64_t rx_pkts)
{
	const struct lcore_conf *qconf = &lcore_conf[lcore_id];
	const struct l3fwd_work *w = &qconf->work;

	if (w->accesses > 0 || l3fwd_work_payload)
		printf("WORK lcore %u: accesses=%u work_cyc/pkt=%.1f sink=%" PRIx64 "\n",
		       lcore_id, w->accesses,
		       rx_pkts ? (double)w->cycles / rx_pkts : 0.0, w->sink);
	if (w->occ_samples > 0)
		printf("OCCUPANCY lcore %u queue %u: samples=%" PRIu64
		       " mean=%.1f max=%u\n", lcore_id,
		       qconf->rx_queue_list[0].queue_id, w->occ_samples,
		       (double)w->occ_sum / w->occ_samples, w->occ_max);
}
