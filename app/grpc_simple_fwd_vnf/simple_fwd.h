/*
 * Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#ifndef SIMPLE_FWD_H_
#define SIMPLE_FWD_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#include <doca_flow.h>

#include "simple_fwd_pkt.h"
#include "simple_fwd_port.h"

#define SIMPLE_FWD_PORTS (2)
#define SIMPLE_FWD_MAX_FLOWS (8096)

struct simple_fwd_app {
	struct simple_fwd_ft *ft;
	uint16_t hairpin_peer[SIMPLE_FWD_PORTS];
	struct doca_flow_port *port[SIMPLE_FWD_PORTS];
	struct doca_flow_pipe *pipe_vxlan[SIMPLE_FWD_PORTS];
	struct doca_flow_pipe *pipe_gre[SIMPLE_FWD_PORTS];
	struct doca_flow_pipe *pipe_gtp[SIMPLE_FWD_PORTS];
	struct doca_flow_pipe *pipe_control[SIMPLE_FWD_PORTS];
	struct doca_flow_pipe *pipe_notun[SIMPLE_FWD_PORTS];
	/* flow age query item buffer */
	uint16_t nb_queues;
	struct doca_flow_aged_query *query_array[0];
};

struct simple_fwd_pipe_entry {
	bool is_hw;
	uint64_t total_pkts;
	uint64_t total_bytes;
	struct doca_flow_pipe_entry *hw_entry;
};

struct app_vnf*
simple_fwd_get_vnf(void);
int manully_add_entry(struct doca_flow_match* match, struct doca_flow_actions* action, struct doca_flow_fwd* fwd, struct doca_flow_error *error);


#ifdef __cplusplus
}
#endif

#endif /* SIMPLE_FWD_H_ */
