/*
 * Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
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

#ifndef FIREWALL_CORE_H_
#define FIREWALL_CORE_H_

#include <doca_flow_grpc_client.h>
#include <doca_argp.h>

#include <utils.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_FILE_NAME 255

struct firewall_cfg {
	bool interactive_mode;         /* Run application with interactive mode */
	bool static_mode;              /* Run application with static mode */
	char json_path[MAX_FILE_NAME]; /* Path to the JSON file with 5-tuple rules to drop */
	bool has_json;                 /* true when a json file path was given */
};

struct rule_match {
	uint8_t protocol;
	doca_be32_t src_ip;
	doca_be32_t dst_ip;
	int src_port;
	int dst_port;
};

void register_firewall_params(void);
struct rule_match *init_drop_rules(char *file_path, int *n_rules);
void firewall_ports_init(char *grpc_address, struct application_dpdk_config *dpdk_config);
void firewall_pipes_init(struct rule_match *drop_rules, int n_rules);
doca_be32_t parse_ipv4_str(const char *str_ip);
uint8_t parse_protocol_string(const char *protocol_str);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIREWALL_CORE_H_ */
