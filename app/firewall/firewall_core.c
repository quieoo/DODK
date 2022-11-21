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

#include <bsd/string.h>

#include <json-c/json.h>
#include <rte_byteorder.h>
#include <rte_ethdev.h>

#include <doca_argp.h>
#include <doca_log.h>

#include <utils.h>

#include "firewall_core.h"

DOCA_LOG_REGISTER(FIREWALL_CORE);

#define BE_IPV4_ADDR(a, b, c, d) (RTE_BE32((a << 24) + (b << 16) + (c << 8) + d))

#define FIREWALL_MAX_FLOWS 8096
#define MAX_PORT_STR 128
#define MAX_IP_ADDRESS 16
#define PROTOCOL_LEN 4

static void
interactive_callback(void *config, void *param)
{
	struct firewall_cfg *firewall_cfg = (struct firewall_cfg *)config;

	firewall_cfg->interactive_mode = *(bool *) param;
}

static void
static_callback(void *config, void *param)
{
	struct firewall_cfg *firewall_cfg = (struct firewall_cfg *)config;

	firewall_cfg->static_mode = *(bool *) param;
}

static void
firewall_rules_callback(void *config, void *param)
{
	struct firewall_cfg *firewall_cfg = (struct firewall_cfg *)config;
	char *json_path = (char *)param;

	if (strnlen(json_path, MAX_FILE_NAME) == MAX_FILE_NAME)
		APP_EXIT("JSON file name is too long - MAX=%d", MAX_FILE_NAME - 1);
	if (access(json_path, F_OK) == -1)
		APP_EXIT("JSON file was not found %s", json_path);
	strlcpy(firewall_cfg->json_path, json_path, MAX_FILE_NAME);
	firewall_cfg->has_json = true;
}

static void
firewall_args_validation_callback(void *config, void *param)
{
	struct firewall_cfg *firewall_cfg = (struct firewall_cfg *) config;

	if (!firewall_cfg->interactive_mode && !firewall_cfg->static_mode) {
		DOCA_LOG_ERR("Missing firewall mode type");
		doca_argp_usage();
	}

	if (firewall_cfg->interactive_mode && firewall_cfg->static_mode) {
		DOCA_LOG_ERR("need to use only one firewall mode: interactive/static");
		doca_argp_usage();
	}

	if (firewall_cfg->static_mode && !firewall_cfg->has_json) {
		DOCA_LOG_ERR("Missing rules file path for static mode");
		doca_argp_usage();
	}
}

void
register_firewall_params()
{
	struct doca_argp_param interactive_param = {
		.short_flag = "i",
		.long_flag = "interactive",
		.arguments = NULL,
		.description = "Run application with interactive mode",
		.callback = interactive_callback,
		.arg_type = DOCA_ARGP_TYPE_BOOLEAN,
		.is_mandatory = false,
		.is_cli_only = false
	};

	struct doca_argp_param static_param = {
		.short_flag = "s",
		.long_flag = "static",
		.arguments = NULL,
		.description = "Run application with static mode",
		.callback = static_callback,
		.arg_type = DOCA_ARGP_TYPE_BOOLEAN,
		.is_mandatory = false,
		.is_cli_only = false
	};

	struct doca_argp_param rules_param = {
		.short_flag = "r",
		.long_flag = "firewall-rules",
		.arguments = "<path>",
		.description = "Path to the JSON file with 5-tuple rules when running with static mode",
		.callback = firewall_rules_callback,
		.arg_type = DOCA_ARGP_TYPE_STRING,
		.is_mandatory = false,
		.is_cli_only = false};

	doca_argp_register_param(&interactive_param);
	doca_argp_register_param(&static_param);
	doca_argp_register_param(&rules_param);
	doca_argp_register_version_callback(sdk_version_callback);
	doca_argp_register_validation_callback(firewall_args_validation_callback);
}

static void
create_protocol(struct json_object *cur_rule, struct rule_match *rule)
{
	struct json_object *protocol;
	const char *protocol_str;

	if (!json_object_object_get_ex(cur_rule, "protocol", &protocol))
		DOCA_LOG_ERR("Missing protocol type");
	if (json_object_get_type(protocol) != json_type_string)
		DOCA_LOG_ERR("Expecting a string value for \"protocol-ip\"");

	protocol_str = json_object_get_string(protocol);
	rule->protocol = parse_protocol_string(protocol_str);
}

static void
create_src_ip(struct json_object *cur_rule, struct rule_match *rule)
{
	struct json_object *src_ip;

	if (!json_object_object_get_ex(cur_rule, "src-ip", &src_ip))
		APP_EXIT("Missing src-ip");
	if (json_object_get_type(src_ip) != json_type_string)
		DOCA_LOG_ERR("Expecting a string value for \"src-ip\"");

	rule->src_ip = parse_ipv4_str(json_object_get_string(src_ip));
}

static void
create_dst_ip(struct json_object *cur_rule, struct rule_match *rule)
{
	struct json_object *dst_ip;

	if (!json_object_object_get_ex(cur_rule, "dst-ip", &dst_ip))
		APP_EXIT("Missing dst-ip");
	if (json_object_get_type(dst_ip) != json_type_string)
		DOCA_LOG_ERR("Expecting a string value for \"dst-ip\"");

	rule->dst_ip = parse_ipv4_str(json_object_get_string(dst_ip));
}

static void
create_src_port(struct json_object *cur_rule, struct rule_match *rule)
{
	struct json_object *src_port;

	if (!json_object_object_get_ex(cur_rule, "src-port", &src_port))
		APP_EXIT("Missing src-port");
	if (json_object_get_type(src_port) != json_type_int)
		DOCA_LOG_ERR("Expecting a int value for \"src-port\"");

	rule->src_port = json_object_get_int(src_port);
}

static void
create_dst_port(struct json_object *cur_rule, struct rule_match *rule)
{
	struct json_object *dst_port;

	if (!json_object_object_get_ex(cur_rule, "dst-port", &dst_port))
		APP_EXIT("Missing dst-port");
	if (json_object_get_type(dst_port) != json_type_int)
		DOCA_LOG_ERR("Expecting a int value for \"dst-port\"");

	rule->dst_port = json_object_get_int(dst_port);
}

static struct rule_match *
create_drop_rules(struct json_object *rules, int *n_rules)
{
	int i;
	struct json_object *cur_rule;
	struct rule_match *rules_arr = NULL;
	*n_rules = json_object_array_length(rules);

	DOCA_LOG_DBG("num of rules in input file: %d", *n_rules);

	rules_arr = (struct rule_match *)calloc(*n_rules, sizeof(struct rule_match));
	if (rules_arr == NULL) {
		DOCA_LOG_ERR("calloc() function failed");
		return NULL;
	}

	for (i = 0; i < *n_rules; i++) {
		cur_rule = json_object_array_get_idx(rules, i);
		create_protocol(cur_rule, &rules_arr[i]);
		create_src_ip(cur_rule, &rules_arr[i]);
		create_dst_ip(cur_rule, &rules_arr[i]);
		create_src_port(cur_rule, &rules_arr[i]);
		create_dst_port(cur_rule, &rules_arr[i]);
	}
	return rules_arr;
}

static int
allocate_json_buffer_dynamic(FILE *fp, size_t *file_length, char **json_data)
{
	ssize_t buf_len = 0;

	/* use fseek to put file counter to the end, and calculate file length */
	if (fseek(fp, 0L, SEEK_END) == 0) {
		buf_len = ftell(fp);
		if (buf_len < 0) {
			DOCA_LOG_ERR("ftell() function failed");
			return -1;
		}

		/* dynamic allocation */
		*json_data = (char *)calloc((buf_len + 1), sizeof(char));
		if (*json_data == NULL) {
			DOCA_LOG_ERR("calloc() function failed");
			return -1;
		}

		/* return file counter to the beginning */
		if (fseek(fp, 0L, SEEK_SET) != 0) {
			free(*json_data);
			*json_data = NULL;
			DOCA_LOG_ERR("fseek() function failed");
			return -1;
		}
	}
	*file_length = buf_len;
	return 0;
}

struct rule_match *
init_drop_rules(char *file_path, int *n_rules)
{
	FILE *json_fp;
	size_t file_length;
	char *json_data = NULL;
	struct json_object *parsed_json;
	struct json_object *rules;
	int res;

	json_fp = fopen(file_path, "r");
	if (json_fp == NULL)
		APP_EXIT("JSON file open failed");

	res = allocate_json_buffer_dynamic(json_fp, &file_length, &json_data);
	if (res < 0) {
		fclose(json_fp);
		APP_EXIT("Failed to allocate data buffer for the json file");
	}

	if (fread(json_data, file_length, 1, json_fp) < file_length)
		DOCA_LOG_DBG("EOF reached");
	fclose(json_fp);

	parsed_json = json_tokener_parse(json_data);
	if (!json_object_object_get_ex(parsed_json, "rules", &rules))
		DOCA_LOG_ERR("missing \"rules\" parameter");

	free(json_data);
	return create_drop_rules(rules, n_rules);
}

static uint64_t
build_hairpin_pipe(uint16_t port_id)
{
	struct doca_flow_match match;
	struct doca_flow_fwd fwd;
	struct doca_flow_grpc_fwd client_fwd;
	struct doca_flow_actions actions;
	struct doca_flow_pipe_cfg pipe_cfg = {0};
	struct doca_flow_grpc_pipe_cfg client_cfg;
	struct doca_flow_grpc_response response;
	uint64_t pipe_id;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&fwd, 0, sizeof(fwd));
	memset(&pipe_cfg, 0, sizeof(pipe_cfg));

	pipe_cfg.attr.name = "HAIRPIN_PIPE";
	pipe_cfg.match = &match;
	pipe_cfg.actions = &actions;
	client_cfg.cfg = &pipe_cfg;
	client_cfg.port_id = port_id;

	fwd.type = DOCA_FLOW_FWD_PORT;
	fwd.port_id = port_id ^ 1;
	client_fwd.fwd = &fwd;

	response = doca_flow_grpc_create_pipe(&client_cfg, &client_fwd, NULL);
	if (!response.success)
		APP_EXIT("failed to create pipe: %s", response.error.message);

	pipe_id = response.pipe_id;
	response = doca_flow_grpc_pipe_add_entry(0, pipe_id, &match, &actions,
						   NULL, &client_fwd, DOCA_FLOW_NO_WAIT);
	if (!response.success)
		APP_EXIT("failed to add entry: %s", response.error.message);

	return pipe_id;
}

static uint64_t
build_drop_pipe(uint16_t port_id, uint64_t next_pipe_id, uint8_t protocol_type)
{
	struct doca_flow_match match;
	struct doca_flow_fwd fwd;
	struct doca_flow_grpc_fwd client_fwd;
	struct doca_flow_fwd miss_fwd;
	struct doca_flow_grpc_fwd client_miss_fwd;
	struct doca_flow_actions actions;
	struct doca_flow_pipe_cfg pipe_cfg = {0};
	struct doca_flow_grpc_pipe_cfg client_cfg;
	struct doca_flow_grpc_response response;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&fwd, 0, sizeof(fwd));
	memset(&pipe_cfg, 0, sizeof(pipe_cfg));

	pipe_cfg.attr.name = "DROP_PIPE";
	pipe_cfg.match = &match;
	pipe_cfg.actions = &actions;
	pipe_cfg.attr.is_root = true;
	client_cfg.cfg = &pipe_cfg;
	client_cfg.port_id = port_id;

	match.out_l4_type = protocol_type;
	match.out_dst_ip.ipv4_addr = 0xffffffff;
	match.out_src_ip.ipv4_addr = 0xffffffff;
	match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_src_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_dst_port = 0xffff;
	match.out_src_port = 0xffff;

	fwd.type = DOCA_FLOW_FWD_DROP;
	client_fwd.fwd = &fwd;
	miss_fwd.type = DOCA_FLOW_FWD_PIPE;
	client_miss_fwd.fwd = &miss_fwd;
	client_miss_fwd.next_pipe_id = next_pipe_id;

	response = doca_flow_grpc_create_pipe(&client_cfg, &client_fwd, &client_miss_fwd);
	if (!response.success)
		APP_EXIT("failed to create pipe: %s", response.error.message);

	return response.pipe_id;
}

static void
add_drop_entries(uint32_t port_id, uint64_t tcp_pipe_id, uint64_t udp_pipe_id,
		 struct rule_match *drop_rules, int n_rules)
{
	struct doca_flow_match match;
	struct doca_flow_grpc_fwd client_fwd;
	struct doca_flow_fwd fwd;
	struct doca_flow_actions actions;
	struct doca_flow_grpc_response response;
	uint64_t pipe_id;
	int i;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&fwd, 0, sizeof(fwd));

	fwd.type = DOCA_FLOW_FWD_DROP;
	client_fwd.fwd = &fwd;

	match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_src_ip.type = DOCA_FLOW_IP4_ADDR;

	for (i = 0; i < n_rules; i++) {
		/* build 5-tuple rule match */
		if (drop_rules[i].protocol == IPPROTO_TCP)
			pipe_id = tcp_pipe_id;
		else
			pipe_id = udp_pipe_id;
		match.out_l4_type = drop_rules[i].protocol;
		match.out_dst_ip.ipv4_addr = drop_rules[i].dst_ip;
		match.out_src_ip.ipv4_addr = drop_rules[i].src_ip;
		match.out_dst_port = rte_cpu_to_be_16(drop_rules[i].dst_port);
		match.out_src_port = rte_cpu_to_be_16(drop_rules[i].src_port);

		/* add entry to drop pipe*/
		response = doca_flow_grpc_pipe_add_entry(0, pipe_id, &match,
							   &actions, NULL, &client_fwd, DOCA_FLOW_NO_WAIT);
		if (!response.success)
			APP_EXIT("failed to add entry: %s", response.error.message);
	}
}

void
firewall_pipes_init(struct rule_match *drop_rules, int n_rules)
{
	int nb_ports = 2;
	uint16_t port_id;
	uint64_t hairpin_pipe_id;
	uint64_t tcp_drop_pipe_id;
	uint64_t udp_drop_pipe_id;

	for (port_id = 0; port_id < nb_ports; port_id++) {
		/* create doca flow hairpin pipe */
		hairpin_pipe_id = build_hairpin_pipe(port_id);
		// printf("hairpin_pipe_id: %d\n", hairpin_pipe_id);
		/* create doca flow drop pipe with 5-tuple match*/
		tcp_drop_pipe_id = build_drop_pipe(port_id, hairpin_pipe_id, IPPROTO_TCP);
		udp_drop_pipe_id = build_drop_pipe(port_id, hairpin_pipe_id, IPPROTO_UDP);
		add_drop_entries(port_id, tcp_drop_pipe_id, udp_drop_pipe_id,
				drop_rules, n_rules);
	}
	free(drop_rules);
}

uint8_t
parse_protocol_string(const char *protocol_str)
{
	if (strcmp(protocol_str, "tcp") == 0)
		return IPPROTO_TCP;
	else if (strcmp(protocol_str, "udp") == 0)
		return IPPROTO_UDP;
	DOCA_LOG_ERR("protocol type %s is not supported", protocol_str);
	return 0;
}

doca_be32_t
parse_ipv4_str(const char *str_ip)
{
	char *ptr;
	int i;
	int ips[4];

	if (strcmp(str_ip, "0xffffffff") == 0)
		return 0xffffffff;
	for (i = 0; i < 3; i++) {
		ips[i] = atoi(str_ip);
		ptr = strchr(str_ip, '.');
		if (ptr == NULL)
			APP_EXIT("Wrong format of ip string");
		str_ip = ++ptr;
	}
	ips[3] = atoi(ptr);
	return BE_IPV4_ADDR(ips[0], ips[1], ips[2], ips[3]);
}

void
firewall_ports_init(char *grpc_address, struct application_dpdk_config *dpdk_config)
{
	int nb_ports = 2;
	int nb_queues = 8;
	uint16_t port_id;
	struct doca_flow_cfg cfg = {0};
	struct doca_flow_grpc_response response;

	cfg.queues = nb_queues;
	cfg.mode_args = "vnf";
	cfg.aging = false;
	doca_flow_grpc_client_create(grpc_address);

	response = doca_flow_grpc_env_init(dpdk_config);
	if (!response.success)
		APP_EXIT("dpdk init failed: %s", response.error.message);

	response = doca_flow_grpc_init(&cfg);
	if (!response.success)
		APP_EXIT("failed to init doca: %s", response.error.message);

	for (port_id = 0; port_id < nb_ports; port_id++) {
		/* create doca flow port */
		struct doca_flow_port_cfg port_cfg;
		char port_id_str[MAX_PORT_STR];

		port_cfg.port_id = port_id;
		port_cfg.type = DOCA_FLOW_PORT_DPDK_BY_ID;
		snprintf(port_id_str, MAX_PORT_STR, "%d", port_id);
		port_cfg.devargs = port_id_str;
		port_cfg.priv_data_size = 0;
		response = doca_flow_grpc_port_start(&port_cfg);
		if (!response.success)
			APP_EXIT("failed to build doca port: %s", response.error.message);

		/* Pair ports should be done in the following order: port0 with port1, port2 with port3 etc. */
		if (!port_id || !(port_id % 2))
			continue;
		/* pair odd port with previous port */
		response = doca_flow_grpc_port_pair(port_id, port_id ^ 1);
		if (!response.success)
			APP_EXIT("failed to pair doca ports: %s", response.error.message);

	}
}
