/*
 * Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
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

#include "nat_core.h"
#include <unistd.h>

DOCA_LOG_REGISTER(NAT_CORE);

#define BE_IPV4_ADDR(a, b, c, d) (RTE_BE32(((a) << 24) + ((b) << 16) + ((c) << 8) + (d)))	/* Convert IPv4 address to big endian */
#define MAX_PORT_STR 128									/* Maximum length of the string name of the port */
#define NAT_PORTS_NUM 2										/* number of needed port for NAT application */
#define MAX_PORT_STR_LEN 128									/* Maximal length of port name */
#define DEFAULT_TIMEOUT_US (10000)								/* Timeout for processing pipe entries */
#define NUM_OF_SUPPORTED_PROTOCOLS 2								/* number of support L4 protocols */
#define NB_ACTIONS_ARR (1)									/* default number of actions in pipe */
#define MAX_PORT_NAME 30									/* Maximal length of port name */

struct doca_flow_port *ports[NAT_PORTS_NUM];

/*
 * ARGP Callback - Handle nat mode parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
nat_mode_callback(void *param, void *config)
{
	struct nat_cfg *nat_cfg = (struct nat_cfg *)config;
	char *mode = (char *) param;

	if (strcmp(mode, "static") == 0)
		nat_cfg->mode = STATIC;
	else if (strcmp(mode, "pat") == 0)
		nat_cfg->mode = PAT;
	else {
		nat_cfg->mode = NAT_INVALID_MODE;
		DOCA_LOG_ERR("illegal nat mode = %s", mode);
		return DOCA_ERROR_INVALID_VALUE;
	}
	DOCA_LOG_DBG("mode = %s, app_cfg mode = %d", mode, nat_cfg->mode);
	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle lan interface parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
lan_intf_callback(void *param, void *config)
{
	struct nat_cfg *nat_cfg = (struct nat_cfg *)config;
	char *lan_intf = (char *)param;

	/*
	if (strnlen(lan_intf, MAX_INTF_NAME+1) == MAX_INTF_NAME+1) {
		DOCA_LOG_ERR("lan interface name is too long - MAX=%d", MAX_INTF_NAME);
		return DOCA_ERROR_INVALID_VALUE;
	}

	if (strstr(lan_intf, "sf") != lan_intf) {
		DOCA_LOG_ERR("lan interface expected format sfxxx");
		return DOCA_ERROR_INVALID_VALUE;
	}*/


	nat_cfg->lan_intf = lan_intf;
	return DOCA_SUCCESS;	
}

/*
 * ARGP Callback - Handle wan interface parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
wan_intf_callback(void *param, void *config)
{
	struct nat_cfg *nat_cfg = (struct nat_cfg *)config;
	char *wan_intf = (char *)param;
	/*
	if (strnlen(wan_intf, MAX_INTF_NAME+1) == MAX_INTF_NAME+1) {
		DOCA_LOG_ERR("wan interface name is too long - MAX=%d", MAX_INTF_NAME);
		return DOCA_ERROR_INVALID_VALUE;
	}
	if (strstr(wan_intf, "sf") != wan_intf) {
		DOCA_LOG_ERR("wan interface expected format - sfxxx");
		return DOCA_ERROR_INVALID_VALUE;
	}*/

	nat_cfg->wan_intf = wan_intf;
	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle nat rules config file parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
nat_rules_callback(void *param, void *config)
{
	struct nat_cfg *nat_cfg = (struct nat_cfg *)config;
	char *json_path = (char *)param;

	if (strnlen(json_path, MAX_FILE_NAME) == MAX_FILE_NAME) {
		DOCA_LOG_ERR("JSON file name is too long - MAX=%d", MAX_FILE_NAME - 1);
		return DOCA_ERROR_INVALID_VALUE;
	}
	if (access(json_path, F_OK) == -1) {
		DOCA_LOG_ERR("JSON file was not found %s", json_path);
		return DOCA_ERROR_NOT_FOUND;
	}
	strlcpy(nat_cfg->json_path, json_path, MAX_FILE_NAME);
	nat_cfg->has_json = true;
	return DOCA_SUCCESS;
}

/*
 * ARGP validation Callback - check if lan and wan sfs are different
 *
 * @config [in]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
nat_args_validation_callback(void *config)
{
	struct nat_cfg *nat_cfg = (struct nat_cfg *) config;


	if (strcmp(nat_cfg->lan_intf, nat_cfg->wan_intf)==0) {
		DOCA_LOG_ERR("lan interface cant be equal to wan interface");
		return DOCA_ERROR_INVALID_VALUE;
	}

	return DOCA_SUCCESS;
}

doca_error_t
register_nat_params()
{
	doca_error_t result;
	struct doca_argp_param *nat_mode, *rules_param, *lan_intf, *wan_intf;

	/* Create and register static mode param */
	result = doca_argp_param_create(&nat_mode);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	
	doca_argp_param_set_short_name(nat_mode, "m");
	doca_argp_param_set_long_name(nat_mode, "mode");
	doca_argp_param_set_arguments(nat_mode, "<mode>");
	doca_argp_param_set_description(nat_mode, "set nat mode");
	doca_argp_param_set_callback(nat_mode, nat_mode_callback);
	doca_argp_param_set_type(nat_mode, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(nat_mode);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register rules file path param */
	result = doca_argp_param_create(&rules_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(rules_param, "r");
	doca_argp_param_set_long_name(rules_param, "nat-rules");
	doca_argp_param_set_arguments(rules_param, "<path>");
	doca_argp_param_set_description(rules_param, "Path to the JSON file with nat rules");
	doca_argp_param_set_callback(rules_param, nat_rules_callback);
	doca_argp_param_set_type(rules_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(rules_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register lan interface param */
	result = doca_argp_param_create(&lan_intf);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(lan_intf, "lan");
	doca_argp_param_set_long_name(lan_intf, "lan-intf");
	doca_argp_param_set_arguments(lan_intf, "<lan intf>");
	doca_argp_param_set_description(lan_intf, "name of lan interface");
	doca_argp_param_set_callback(lan_intf, lan_intf_callback);
	doca_argp_param_set_type(lan_intf, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(lan_intf);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register wan interface param */
	result = doca_argp_param_create(&wan_intf);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(wan_intf, "wan");
	doca_argp_param_set_long_name(wan_intf, "wan-intf");
	doca_argp_param_set_arguments(wan_intf, "<wan intf>");
	doca_argp_param_set_description(wan_intf, "name of wan interface");
	doca_argp_param_set_callback(wan_intf, wan_intf_callback);
	doca_argp_param_set_type(wan_intf, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(wan_intf);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}
	/* Register version callback for DOCA SDK & RUNTIME */
	result = doca_argp_register_version_callback(sdk_version_callback);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register version callback: %s", doca_get_error_string(result));
		return result;
	}

	/* Register application callback */
	result = doca_argp_register_validation_callback(nat_args_validation_callback);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program validation callback: %s", doca_get_error_string(result));
		return result;
	}

	return result;
}

/*
 * parse and set local ip from json file to nat rule struct
 *
 * @cur_rule [in]: rule in json object format
 * @rule [out]: rule in app structure format.
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
create_local_ip(struct json_object *cur_rule, struct nat_rule_match *rule)
{
	doca_error_t result;
	struct json_object *local_ip;

	if (!json_object_object_get_ex(cur_rule, "local ip", &local_ip)) {
		DOCA_LOG_ERR("Missing local ip");
		return DOCA_ERROR_INVALID_VALUE;
	}
	if (json_object_get_type(local_ip) != json_type_string) {
		DOCA_LOG_ERR("Expecting a string value for \"local ip\"");
		return DOCA_ERROR_INVALID_VALUE;
	}

	result = parse_ipv4_str(json_object_get_string(local_ip), &rule->local_ip);
	if (result != DOCA_SUCCESS)
		return result;
	return DOCA_SUCCESS;
}
/*
 * parse and set global ip from json file to nat rule struct
 *
 * @cur_rule [in]: rule in json object format
 * @rule [out]: rule in app structure format.
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
create_global_ip(struct json_object *cur_rule, struct nat_rule_match *rule)
{
	doca_error_t result;
	struct json_object *global_ip;

	if (!json_object_object_get_ex(cur_rule, "global ip", &global_ip)) {
		DOCA_LOG_ERR("Missing global ip");
		return DOCA_ERROR_INVALID_VALUE;
	}
	if (json_object_get_type(global_ip) != json_type_string) {
		DOCA_LOG_ERR("Expecting a string value for \"global ip\"");
		return DOCA_ERROR_INVALID_VALUE;
	}

	result = parse_ipv4_str(json_object_get_string(global_ip), &rule->global_ip);
	if (result != DOCA_SUCCESS)
		return result;
	return DOCA_SUCCESS;
}

/*
 * parse and set local port from json file to nat rule struct
 *
 * @cur_rule [in]: rule in json object format
 * @rule [out]: rule in app structure format.
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
create_local_port(struct json_object *cur_rule, struct nat_rule_match *rule)
{
	struct json_object *local_port;

	if (!json_object_object_get_ex(cur_rule, "local port", &local_port)) {
		DOCA_LOG_ERR("Missing local port");
		return DOCA_ERROR_INVALID_VALUE;
	}
	if (json_object_get_type(local_port) != json_type_int) {
		DOCA_LOG_ERR("Expecting an int value for \"local port\"");
		return DOCA_ERROR_INVALID_VALUE;
	}

	rule->local_port = json_object_get_int(local_port);
	return DOCA_SUCCESS;
}

/*
 * parse and set global port from json file to nat rule struct
 *
 * @cur_rule [in]: rule in json object format
 * @rule [out]: rule in app structure format.
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
create_global_port(struct json_object *cur_rule, struct nat_rule_match *rule)
{
	struct json_object *global_port;

	if (!json_object_object_get_ex(cur_rule, "global port", &global_port)) {
		DOCA_LOG_ERR("Missing global port");
		return DOCA_ERROR_INVALID_VALUE;
	}
	if (json_object_get_type(global_port) != json_type_int) {
		DOCA_LOG_ERR("Expecting an int value for \"global port\"");
		return DOCA_ERROR_INVALID_VALUE;
	}

	rule->global_port = json_object_get_int(global_port);
	return DOCA_SUCCESS;
}

/*
 * Create doca flow ports
 *
 * @portid [in]: port id to create
 * @return: doca_flow_port strucure of the new port
 */
static struct doca_flow_port *
nat_port_create(uint8_t portid)
{
	char port_id_str[MAX_PORT_STR_LEN];
	struct doca_flow_error err = {0};
	struct doca_flow_port *port;
	struct doca_flow_port_cfg port_cfg = {0};

	port_cfg.port_id = portid;
	port_cfg.type = DOCA_FLOW_PORT_DPDK_BY_ID;
	snprintf(port_id_str, MAX_PORT_STR_LEN, "%d", port_cfg.port_id);
	port_cfg.devargs = port_id_str;
	port = doca_flow_port_start(&port_cfg, &err);
	if (port == NULL) {
		DOCA_LOG_ERR("failed to initialize doca flow port: %s", err.message);
		return NULL;
	}
	return port;
}

/*
 * destroy doca ports
 *
 * @nb_ports [in]: number of ports
 */
static void
nat_destroy_ports(int nb_ports)
{
	int portid;

	for (portid = 0; portid < nb_ports; portid++) {
		if (ports[portid])
			doca_flow_port_destroy(ports[portid]);
	}
}

void
nat_destroy(int nb_ports, struct nat_rule_match *nat_rules)
{
	nat_destroy_ports(nb_ports);
	doca_flow_destroy();
	if (nat_rules != NULL)
		free(nat_rules);
}

/*
 * Create and update rules array for static mode
 *
 * @parsed_json [in]: rules in json object format
 * @nat_num_rules [out]: num of rules to configure
 * @nat_rules [out]: array of rules
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
create_static_mode_rules(struct json_object *parsed_json, int *nat_num_rules, struct nat_rule_match **nat_rules)
{
	int i;
	doca_error_t result;
	struct json_object *rules;
	struct json_object *cur_rule;
	struct nat_rule_match *rules_arr = NULL;

	if (!json_object_object_get_ex(parsed_json, "rules", &rules)) {
		DOCA_LOG_ERR("missing \"rules\" parameter");
		return DOCA_ERROR_INVALID_VALUE;
	}

	*nat_num_rules = json_object_array_length(rules);

	DOCA_LOG_INFO("num of rules in input file: %d", *nat_num_rules);

	rules_arr = (struct nat_rule_match *)calloc(*nat_num_rules, sizeof(struct nat_rule_match));
	if (rules_arr == NULL) {
		DOCA_LOG_ERR("calloc() function failed");
		return DOCA_ERROR_NO_MEMORY;
	}

	for (i = 0; i < *nat_num_rules; i++) {
		cur_rule = json_object_array_get_idx(rules, i);
		result = create_local_ip(cur_rule, &rules_arr[i]);
		if (result != DOCA_SUCCESS) {
			free(rules_arr);
			return result;
		}
		result = create_global_ip(cur_rule, &rules_arr[i]);
		if (result != DOCA_SUCCESS) {
			free(rules_arr);
			return result;
		}
	}
	*nat_rules = rules_arr;
	return DOCA_SUCCESS;
}

/*
 * Create and update rules array for pat mode
 *
 * @parsed_json [in]: rules in json object format
 * @nat_num_rules [out]: num of rules to configure
 * @nat_rules [out]: array of rules
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
create_pat_mode_rules(struct json_object *parsed_json, int *nat_num_rules, struct nat_rule_match **nat_rules)
{
	int i;
	doca_error_t result;
	struct json_object *cur_rule;
	struct json_object *global_ip;
	struct json_object *rules;
	struct nat_rule_match *rules_arr = NULL;
	doca_be32_t parsed_global_ip;

	if (!json_object_object_get_ex(parsed_json, "global ip", &global_ip)) {
		DOCA_LOG_ERR("Missing global ip");
		return DOCA_ERROR_INVALID_VALUE;
	}
	if (json_object_get_type(global_ip) != json_type_string) {
		DOCA_LOG_ERR("Expecting a string value for \"global ip\"");
		return DOCA_ERROR_INVALID_VALUE;
	}

	result = parse_ipv4_str(json_object_get_string(global_ip), &parsed_global_ip);
	if (result != DOCA_SUCCESS)
		return result;
	DOCA_LOG_DBG("PAT global ip = %d.%d.%d.%d", (parsed_global_ip & 0xff), (parsed_global_ip >> 8 & 0xff), (parsed_global_ip >> 16 & 0xff), (parsed_global_ip >> 24 & 0xff));

	if (!json_object_object_get_ex(parsed_json, "rules", &rules)) {
		DOCA_LOG_ERR("missing \"rules\" parameter");
		return DOCA_ERROR_INVALID_VALUE;
	}

	*nat_num_rules = json_object_array_length(rules);

	DOCA_LOG_DBG("num of rules in input file: %d", *nat_num_rules);

	rules_arr = (struct nat_rule_match *)calloc(*nat_num_rules, sizeof(struct nat_rule_match));
	if (rules_arr == NULL) {
		DOCA_LOG_ERR("calloc() function failed");
		return DOCA_ERROR_NO_MEMORY;
	}

	for (i = 0; i < *nat_num_rules; i++) {
		cur_rule = json_object_array_get_idx(rules, i);
		result = create_local_ip(cur_rule, &rules_arr[i]);
		if (result != DOCA_SUCCESS) {
			free(rules_arr);
			return result;
		}
		result = create_local_port(cur_rule, &rules_arr[i]);
		if (result != DOCA_SUCCESS) {
			free(rules_arr);
			return result;
		}
		result = create_global_port(cur_rule, &rules_arr[i]);
		if (result != DOCA_SUCCESS) {
			free(rules_arr);
			return result;
		}
		rules_arr[i].global_ip = parsed_global_ip;
	}
	*nat_rules = rules_arr;
	return DOCA_SUCCESS;
}

/*
 * Check the input file size and allocate a buffer to read it
 *
 * @fp [in]: file pointer to the input rules file
 * @file_length [out]: total bytes in file
 * @json_data [out]: allocated buffer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
allocate_json_buffer_dynamic(FILE *fp, size_t *file_length, char **json_data)
{
	ssize_t buf_len = 0;

	/* use fseek to put file counter to the end, and calculate file length */
	if (fseek(fp, 0L, SEEK_END) == 0) {
		buf_len = ftell(fp);
		if (buf_len < 0) {
			DOCA_LOG_ERR("ftell() function failed");
			return DOCA_ERROR_IO_FAILED;
		}

		/* dynamic allocation */
		*json_data = (char *)malloc(buf_len + 1);
		if (*json_data == NULL) {
			DOCA_LOG_ERR("malloc() function failed");
			return DOCA_ERROR_NO_MEMORY;
		}

		/* return file counter to the beginning */
		if (fseek(fp, 0L, SEEK_SET) != 0) {
			free(*json_data);
			*json_data = NULL;
			DOCA_LOG_ERR("fseek() function failed");
			return DOCA_ERROR_IO_FAILED;
		}
	}
	*file_length = buf_len;
	return DOCA_SUCCESS;
}

doca_error_t
parsing_nat_rules(char *file_path, enum nat_mode mode, int *nat_num_rules, struct nat_rule_match **nat_rules)
{
	FILE *json_fp;
	size_t file_length;
	char *json_data = NULL;
	struct json_object *parsed_json;
	doca_error_t result;

	json_fp = fopen(file_path, "r");
	if (json_fp == NULL) {
		DOCA_LOG_ERR("JSON file open failed");
		return DOCA_ERROR_IO_FAILED;
	}

	result = allocate_json_buffer_dynamic(json_fp, &file_length, &json_data);
	if (result != DOCA_SUCCESS) {
		fclose(json_fp);
		DOCA_LOG_ERR("Failed to allocate data buffer for the json file");
		return result;
	}

	if (fread(json_data, file_length, 1, json_fp) < file_length)
		DOCA_LOG_DBG("EOF reached");
	fclose(json_fp);
	parsed_json = json_tokener_parse(json_data);

	free(json_data);

	switch (mode) {
	case STATIC:
		result = create_static_mode_rules(parsed_json, nat_num_rules, nat_rules);
		break;
	case PAT:
		result = create_pat_mode_rules(parsed_json, nat_num_rules, nat_rules);
		break;
	default:
		DOCA_LOG_ERR("Invalid nat mode");
		return DOCA_ERROR_INVALID_VALUE;
	}
	return result;
}

int
nat_init(struct nat_cfg *app_cfg, struct application_dpdk_config *dpdk_config)
{
	int ret;
	uint16_t nb_ports;
	struct doca_flow_error err = {0};
	struct doca_flow_cfg nat_flow_cfg = {0};
	int portid;

	/* Initialize doca framework */
	nat_flow_cfg.queues = dpdk_config->port_config.nb_queues;
	nat_flow_cfg.mode_args = "vnf,hws";

	nb_ports = dpdk_config->port_config.nb_ports;


	if (doca_flow_init(&nat_flow_cfg, &err) < 0) {
		DOCA_LOG_ERR("failed to init doca flow ports: %s", err.message);
		return -1;
	}

	for (portid = 0; portid < nb_ports; portid++) {
		/* Create doca flow port */
		ports[portid] = nat_port_create(portid);
		if (ports[portid] == NULL) {
			nat_destroy_ports(portid);
			doca_flow_destroy();
			return -1;
		}

		/* Pair ports should be the same as dpdk hairpin binding order */
		if (!portid || !(portid % 2))
			continue;
		ret = doca_flow_port_pair(ports[portid], ports[portid ^ 1]);
		if (ret < 0) {
			DOCA_LOG_ERR("pair port %u %u fail", portid, portid ^ 1);
			nat_destroy_ports(portid + 1);
			doca_flow_destroy();
			return ret;
		}
	}

	DOCA_LOG_DBG("Application configuration and rules offload done");
	return 0;
}

/*
 * build pipe for data come from LAN in NAT static mode
 *
 * @port_id [in]: port id to build the pipe for
 * @nat_rules [in]: rules defintion to configure
 * @nat_num_rules [in]: number of rules to configure
 * @return: 0 on success and negative value otherwise
 */
static int
build_static_local_pipe(uint16_t port_id, struct nat_rule_match *nat_rules, int nat_num_rules)
{
	struct doca_flow_match match;
	struct doca_flow_fwd fwd;
	struct doca_flow_fwd miss_fwd;
	struct doca_flow_actions actions, *actions_arr[NB_ACTIONS_ARR];
	struct doca_flow_pipe_cfg pipe_cfg;
	struct doca_flow_pipe *nat_pipe;
	struct doca_flow_error error = {0};
	struct doca_flow_pipe_entry *entry;
	uint16_t ruleid;
	int num_of_entries = 1;
	int ret;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&fwd, 0, sizeof(fwd));
	memset(&miss_fwd, 0, sizeof(miss_fwd));
	memset(&pipe_cfg, 0, sizeof(pipe_cfg));

	pipe_cfg.attr.name = "NAT_STATIC_PIPE";
	pipe_cfg.match = &match;
	actions_arr[0] = &actions;
	pipe_cfg.actions = actions_arr;
	pipe_cfg.attr.nb_actions = NB_ACTIONS_ARR;
	pipe_cfg.attr.is_root = true;
	pipe_cfg.port = ports[port_id];

	match.out_src_ip.ipv4_addr = 0xffffffff;
	match.out_src_ip.type = DOCA_FLOW_IP4_ADDR;

	actions.mod_src_ip.type = DOCA_FLOW_IP4_ADDR;
	actions.mod_src_ip.ipv4_addr = 0xffffffff;

	fwd.type = DOCA_FLOW_FWD_PORT;
	fwd.port_id = port_id ^ 1;

	miss_fwd.type = DOCA_FLOW_FWD_DROP;
	nat_pipe = doca_flow_pipe_create(&pipe_cfg, &fwd, &miss_fwd, &error);
	if (nat_pipe == NULL) {
		DOCA_LOG_ERR("failed to create nat pipe: %s", error.message);
		return -1;
	}

	for (ruleid = 0; ruleid < nat_num_rules; ruleid++) {
		memset(&match, 0, sizeof(match));
		memset(&actions, 0, sizeof(actions));

		match.out_src_ip.ipv4_addr = nat_rules[ruleid].local_ip;
		actions.mod_src_ip.ipv4_addr = nat_rules[ruleid].global_ip;

		entry = doca_flow_pipe_add_entry(0, nat_pipe, &match, &actions, NULL, NULL, 0, NULL, &error);
		ret = doca_flow_entries_process(ports[port_id], 0, DEFAULT_TIMEOUT_US, 1);
		if (ret != num_of_entries || !entry || doca_flow_pipe_entry_get_status(entry) != DOCA_FLOW_ENTRY_STATUS_SUCCESS)
			DOCA_LOG_ERR("entry creation FAILED: %s", error.message);
	}
	return 0;
}

/*
 * build pipe for data come from WAN in NAT static mode
 *
 * @port_id [in]: port id to build the pipe for
 * @nat_rules [in]: rules defintion to configure
 * @nat_num_rules [in]: number of rules to configure
 * @return: 0 on success and negative value otherwise
 */
static int
build_static_global_pipe(uint16_t port_id, struct nat_rule_match *nat_rules, int nat_num_rules)
{
	struct doca_flow_match match;
	struct doca_flow_fwd fwd;
	struct doca_flow_fwd miss_fwd;
	struct doca_flow_actions actions, *actions_arr[NB_ACTIONS_ARR];
	struct doca_flow_pipe_cfg pipe_cfg;
	struct doca_flow_pipe *nat_pipe;
	struct doca_flow_error error = {0};
	struct doca_flow_pipe_entry *entry;
	uint16_t ruleid;
	int num_of_entries = 1;
	int ret;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&fwd, 0, sizeof(fwd));
	memset(&fwd, 0, sizeof(miss_fwd));
	memset(&pipe_cfg, 0, sizeof(pipe_cfg));

	pipe_cfg.attr.name = "NAT_STATIC_PIPE";
	pipe_cfg.match = &match;
	actions_arr[0] = &actions;
	pipe_cfg.actions = actions_arr;
	pipe_cfg.attr.nb_actions = NB_ACTIONS_ARR;
	pipe_cfg.attr.is_root = true;
	pipe_cfg.port = ports[port_id];

	match.out_dst_ip.ipv4_addr = 0xffffffff;
	match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;

	actions.mod_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	actions.mod_dst_ip.ipv4_addr = 0xffffffff;

	fwd.type = DOCA_FLOW_FWD_PORT;
	fwd.port_id = port_id ^ 1;

	miss_fwd.type = DOCA_FLOW_FWD_DROP;
	nat_pipe = doca_flow_pipe_create(&pipe_cfg, &fwd, &miss_fwd, &error);
	if (nat_pipe == NULL) {
		DOCA_LOG_ERR("failed to create nat pipe: %s", error.message);
		return -1;
	}

	for (ruleid = 0; ruleid < nat_num_rules; ruleid++) {
		memset(&match, 0, sizeof(match));
		memset(&actions, 0, sizeof(actions));

		match.out_dst_ip.ipv4_addr = nat_rules[ruleid].global_ip;
		actions.mod_dst_ip.ipv4_addr = nat_rules[ruleid].local_ip;

		entry = doca_flow_pipe_add_entry(0, nat_pipe, &match, &actions, NULL, NULL, 0, NULL, &error);
		ret = doca_flow_entries_process(ports[port_id], 0, DEFAULT_TIMEOUT_US, 1);
		if (ret != num_of_entries || !entry || doca_flow_pipe_entry_get_status(entry) != DOCA_FLOW_ENTRY_STATUS_SUCCESS)
			DOCA_LOG_ERR("entry creation FAILED: %s", error.message);
	}
	return 0;
}

/*
 * Create control pipe as root pipe
 *
 * @port [in]: port to configure the pipe for
 * @pipe [out]: created control pipe
 * @return: 0 on success and negative value otherwise
 */
static int
create_control_pipe(struct doca_flow_port *port, struct doca_flow_pipe **pipe)
{
	struct doca_flow_pipe_cfg pipe_cfg;
	struct doca_flow_error error = {0};

	memset(&pipe_cfg, 0, sizeof(pipe_cfg));

	pipe_cfg.attr.name = "CONTROL_PIPE";
	pipe_cfg.attr.type = DOCA_FLOW_PIPE_CONTROL;
	pipe_cfg.port = port;
	pipe_cfg.attr.is_root = true;

	*pipe = doca_flow_pipe_create(&pipe_cfg, NULL, NULL, &error);
	if (*pipe == NULL) {
		DOCA_LOG_ERR("failed to create pipe: %s", error.message);
		return -1;
	}

	return 0;
}

/*
 * Add the entries to the control pipe. One entry that matches TCP traffic, and one that matches UDP traffic
 * add it to the LAN side port - so check the src address
 *
 * @control_pipe [in]: control pipe
 * @udp_pipe [in]: UDP pipe to forward UDP traffic to
 * @tcp_pipe [in]: TCP pipe to forward TCP traffic to
 * @port [in]: port to configure the pipe for
 * @return: 0 on success and negative value otherwise
 */
static int
add_control_pipe_local_entries(struct doca_flow_pipe *control_pipe,  struct doca_flow_pipe *udp_pipe,  struct doca_flow_pipe *tcp_pipe, struct doca_flow_port *port)
{
	struct doca_flow_match match;
	struct doca_flow_fwd fwd;
	struct doca_flow_pipe_entry *entry;
	struct doca_flow_error error = {0};
	uint8_t priority = 0;

	memset(&match, 0, sizeof(match));
	memset(&fwd, 0, sizeof(fwd));

	match.out_src_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_l4_type = DOCA_PROTO_UDP;

	fwd.type = DOCA_FLOW_FWD_PIPE;
	fwd.next_pipe = udp_pipe;
	entry = doca_flow_pipe_control_add_entry(0, priority, control_pipe, &match,
						 NULL, NULL, NULL, NULL, &fwd, &error);
	if (entry == NULL) {
		DOCA_LOG_ERR("Failed to add control pipe entry - %s (%u)", error.message, error.type);
		return -1;
	}

	match.out_src_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_l4_type = DOCA_PROTO_TCP;

	fwd.type = DOCA_FLOW_FWD_PIPE;
	fwd.next_pipe = tcp_pipe;
	entry = doca_flow_pipe_control_add_entry(0, priority, control_pipe, &match,
						 NULL, NULL, NULL, NULL, &fwd, &error);
	if (entry == NULL) {
		DOCA_LOG_ERR("Failed to add control pipe entry - %s (%u)", error.message, error.type);
		return -1;
	}

	return 0;
}

/*
 * build pipe for data come from LAN in NAT PAT mode
 *
 * @port_id [in]: port id to build the pipe for
 * @nat_rules [in]: rules defintion to configure
 * @nat_num_rules [in]: number of rules to configure
 * @return: 0 on success and negative value otherwise
 */
static int
build_pat_local_pipe(uint16_t port_id, struct nat_rule_match *nat_rules, int nat_num_rules)
{
	struct doca_flow_match match;
	struct doca_flow_fwd fwd;
	struct doca_flow_fwd miss_fwd;
	struct doca_flow_actions actions, *actions_arr[NB_ACTIONS_ARR];
	struct doca_flow_pipe_cfg pipe_cfg;
	struct doca_flow_pipe *nat_tcp_pipe, *nat_udp_pipe, *control_pipe;
	struct doca_flow_error error = {0};
	uint16_t ruleid;
	int ret;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&fwd, 0, sizeof(fwd));
	memset(&miss_fwd, 0, sizeof(miss_fwd));
	memset(&pipe_cfg, 0, sizeof(pipe_cfg));

	pipe_cfg.attr.name = "NAT_PAT_PIPE";
	pipe_cfg.match = &match;
	actions_arr[0] = &actions;
	pipe_cfg.actions = actions_arr;
	pipe_cfg.attr.nb_actions = NB_ACTIONS_ARR;
	pipe_cfg.attr.is_root = false;
	pipe_cfg.port = ports[port_id];

	/* first - set tcp pipe with out_l4_type */
	match.out_src_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_src_ip.ipv4_addr = 0xffffffff;
	match.out_l4_type = DOCA_PROTO_TCP;
	match.out_src_port = 0xffff;

	actions.mod_src_ip.type = DOCA_FLOW_IP4_ADDR;
	actions.mod_src_ip.ipv4_addr = 0xffffffff;
	actions.mod_src_port = 0xffff;

	fwd.type = DOCA_FLOW_FWD_PORT;
	fwd.port_id = port_id ^ 1;

	miss_fwd.type = DOCA_FLOW_FWD_DROP;

	nat_tcp_pipe = doca_flow_pipe_create(&pipe_cfg, &fwd, &miss_fwd, &error);
	if (nat_tcp_pipe == NULL) {
		DOCA_LOG_ERR("failed to create nat tcp pipe: %s", error.message);
		return -1;
	}

	/* add udp pipe */
	match.out_l4_type = DOCA_PROTO_UDP;
	nat_udp_pipe = doca_flow_pipe_create(&pipe_cfg, &fwd, &miss_fwd, &error);
	if (nat_udp_pipe == NULL) {
		DOCA_LOG_ERR("failed to create nat udp pipe: %s", error.message);
		return -1;
	}

	for (ruleid = 0; ruleid < nat_num_rules; ruleid++) {
		memset(&match, 0, sizeof(match));
		memset(&actions, 0, sizeof(actions));
		match.out_src_ip.ipv4_addr = nat_rules[ruleid].local_ip;
		match.out_src_port = rte_cpu_to_be_16(nat_rules[ruleid].local_port);
		actions.mod_src_ip.ipv4_addr = nat_rules[ruleid].global_ip;
		actions.mod_src_port = rte_cpu_to_be_16(nat_rules[ruleid].global_port);
		doca_flow_pipe_add_entry(0, nat_tcp_pipe, &match, &actions, NULL, NULL, 0, NULL, &error);

		/* add the same entry also to UDP pipe */
		doca_flow_pipe_add_entry(0, nat_udp_pipe, &match, &actions, NULL, NULL, 0, NULL, &error);
		ret = doca_flow_entries_process(ports[port_id], 0, DEFAULT_TIMEOUT_US, NUM_OF_SUPPORTED_PROTOCOLS);
		if (ret != NUM_OF_SUPPORTED_PROTOCOLS)
			DOCA_LOG_ERR("rule creation FAILED: %s", error.message);
	}

	ret = create_control_pipe(ports[port_id], &control_pipe);
	if (ret < 0) {
		DOCA_LOG_ERR("failed to create control pipe: %s", error.message);
		return -1;
	}

	ret = add_control_pipe_local_entries(control_pipe, nat_udp_pipe, nat_tcp_pipe, ports[port_id]);
	if (ret < 0) {
		DOCA_LOG_ERR("failed to add control pipe entries: %s", error.message);
		return -1;
	}

	return 0;
}

/*
 * Add the entries to the control pipe. One entry that matches TCP traffic, and one that matches UDP traffic.
 * add it to the WAN side port - so check the dst address
 *
 * @control_pipe [in]: control pipe ID
 * @udp_pipe [in]: UDP pipe to forward UDP traffic to
 * @tcp_pipe [in]: TCP pipe to forward TCP traffic to
 * @port [in]: port to configure the pipe for
 * @return: 0 on success and negative value otherwise
 */
static int
add_control_pipe_global_entries(struct doca_flow_pipe *control_pipe,  struct doca_flow_pipe *udp_pipe,  struct doca_flow_pipe *tcp_pipe, struct doca_flow_port *port)
{
	struct doca_flow_match match;
	struct doca_flow_fwd fwd;
	struct doca_flow_pipe_entry *entry;
	struct doca_flow_error error = {0};
	uint8_t priority = 0;

	memset(&match, 0, sizeof(match));
	memset(&fwd, 0, sizeof(fwd));

	match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_l4_type = DOCA_PROTO_UDP;

	fwd.type = DOCA_FLOW_FWD_PIPE;
	fwd.next_pipe = udp_pipe;
	entry = doca_flow_pipe_control_add_entry(0, priority, control_pipe, &match,
						 NULL, NULL, NULL, NULL, &fwd, &error);
	if (entry == NULL) {
		DOCA_LOG_ERR("Failed to add control pipe entry - %s (%u)", error.message, error.type);
		return -1;
	}

	match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_l4_type = DOCA_PROTO_TCP;

	fwd.type = DOCA_FLOW_FWD_PIPE;
	fwd.next_pipe = tcp_pipe;
	entry = doca_flow_pipe_control_add_entry(0, priority, control_pipe, &match,
						 NULL, NULL, NULL, NULL, &fwd, &error);
	if (entry == NULL) {
		DOCA_LOG_ERR("Failed to add control pipe entry - %s (%u)", error.message, error.type);
		return -1;
	}

	return 0;
}

/*
 * build pipe for data come from WAN in NAT PAT mode
 *
 * @port_id [in]: port id to build the pipe for
 * @nat_rules [in]: rules defintion to configure
 * @nat_num_rules [in]: number of rules to configure
 * @return: 0 on success and negative value otherwise
 */
static int
build_pat_global_pipe(uint16_t port_id, struct nat_rule_match *nat_rules, int nat_num_rules)
{
	struct doca_flow_match match;
	struct doca_flow_fwd fwd;
	struct doca_flow_fwd miss_fwd;
	struct doca_flow_actions actions, *actions_arr[NB_ACTIONS_ARR];
	struct doca_flow_pipe_cfg pipe_cfg;
	struct doca_flow_pipe *nat_tcp_pipe, *nat_udp_pipe, *control_pipe;
	struct doca_flow_error error = {0};
	uint16_t ruleid;
	int ret;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&fwd, 0, sizeof(fwd));
	memset(&fwd, 0, sizeof(miss_fwd));
	memset(&pipe_cfg, 0, sizeof(pipe_cfg));

	pipe_cfg.attr.name = "NAT_PAT_PIPE";
	pipe_cfg.match = &match;
	actions_arr[0] = &actions;
	pipe_cfg.actions = actions_arr;
	pipe_cfg.attr.nb_actions = NB_ACTIONS_ARR;
	pipe_cfg.attr.is_root = false;
	pipe_cfg.port = ports[port_id];

	match.out_dst_ip.ipv4_addr = 0xffffffff;
	match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_l4_type = DOCA_PROTO_TCP;
	match.out_dst_port = 0xffff;

	actions.mod_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	actions.mod_dst_ip.ipv4_addr = 0xffffffff;
	actions.mod_dst_port = 0xffff;

	fwd.type = DOCA_FLOW_FWD_PORT;
	fwd.port_id = port_id ^ 1;

	miss_fwd.type = DOCA_FLOW_FWD_DROP;

	nat_tcp_pipe = doca_flow_pipe_create(&pipe_cfg, &fwd, &miss_fwd, &error);
	if (nat_tcp_pipe == NULL) {
		DOCA_LOG_ERR("failed to create nat tcp pipe: %s", error.message);
		return -1;
	}

	/* now - set udp pipe */
	match.out_l4_type = DOCA_PROTO_UDP;
	nat_udp_pipe = doca_flow_pipe_create(&pipe_cfg, &fwd, &miss_fwd, &error);
	if (nat_udp_pipe == NULL) {
		DOCA_LOG_ERR("failed to create nat udp pipe: %s", error.message);
		return -1;
	}

	for (ruleid = 0; ruleid < nat_num_rules; ruleid++) {
		memset(&match, 0, sizeof(match));
		memset(&actions, 0, sizeof(actions));

		match.out_dst_ip.ipv4_addr = nat_rules[ruleid].global_ip;
		match.out_dst_port = rte_cpu_to_be_16(nat_rules[ruleid].global_port);
		actions.mod_dst_ip.ipv4_addr = nat_rules[ruleid].local_ip;
		actions.mod_dst_port = rte_cpu_to_be_16(nat_rules[ruleid].local_port);

		doca_flow_pipe_add_entry(0, nat_tcp_pipe, &match, &actions, NULL, NULL, 0, NULL, &error);

		/* add the same entry also to UDP pipe */
		doca_flow_pipe_add_entry(0, nat_udp_pipe, &match, &actions, NULL, NULL, 0, NULL, &error);
		ret = doca_flow_entries_process(ports[port_id], 0, DEFAULT_TIMEOUT_US, NUM_OF_SUPPORTED_PROTOCOLS);
		if (ret != NUM_OF_SUPPORTED_PROTOCOLS)
			DOCA_LOG_ERR("rule creation FAILED: %s", error.message);
	}

	ret = create_control_pipe(ports[port_id], &control_pipe);
	if (ret < 0) {
		DOCA_LOG_ERR("failed to create control pipe: %s", error.message);
		return -1;
	}

	ret = add_control_pipe_global_entries(control_pipe, nat_udp_pipe, nat_tcp_pipe, ports[port_id]);
	if (ret < 0) {
		DOCA_LOG_ERR("failed to add control pipe entries: %s", error.message);
		return -1;
	}

	return 0;
}

int
nat_pipes_init(struct nat_rule_match *nat_rules, int nat_num_rules, struct nat_cfg *app_cfg, int nb_ports)
{

	uint16_t portid;
	struct rte_eth_dev_info dev_info = {0};
	int ret;
	char lan_port_intf_name[MAX_PORT_NAME] = {0};
	char wan_port_intf_name[MAX_PORT_NAME] = {0};

	for (portid = 0; portid < nb_ports; portid++) {
		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret < 0) {
			DOCA_LOG_ERR("getting device (port %u) info: %s", portid, strerror(-ret));
			return ret;
		}
		// snprintf(lan_port_intf_name, MAX_PORT_NAME, "mlx5_core.sf.%d", app_cfg->lan_intf_id);
		// snprintf(wan_port_intf_name, MAX_PORT_NAME, "mlx5_core.sf.%d", app_cfg->wan_intf_id);
		snprintf(lan_port_intf_name, MAX_PORT_NAME, "%s", app_cfg->lan_intf);
		snprintf(wan_port_intf_name, MAX_PORT_NAME, "%s", app_cfg->wan_intf);
		
		// printf("	%s-%s,%s\n", dev_info.switch_info.name, lan_port_intf_name, wan_port_intf_name);
		switch (app_cfg->mode) {
		case STATIC:
			if (dev_info.switch_info.name != NULL &&
				strcmp(dev_info.switch_info.name, lan_port_intf_name) == 0) {
				ret = build_static_local_pipe(portid, nat_rules, nat_num_rules);
				if (ret < 0)
					return ret;
			} else if (dev_info.switch_info.name != NULL &&
				strcmp(dev_info.switch_info.name, wan_port_intf_name) == 0) {
				ret = build_static_global_pipe(portid, nat_rules, nat_num_rules);
				if (ret < 0)
					return ret;
			} else {
				DOCA_LOG_ERR("getting interface index (%d) which isn't match to any configured port: %s", portid, strerror(-ret));
				return -1;
			}
			break;
		case DYNAMIC:
			break;
		case PAT:
			if (dev_info.switch_info.name != NULL &&
				strcmp(dev_info.switch_info.name, lan_port_intf_name) == 0) {
				ret = build_pat_local_pipe(portid, nat_rules, nat_num_rules);
				if (ret < 0)
					return ret;
			} else if (dev_info.switch_info.name != NULL &&
				strcmp(dev_info.switch_info.name, wan_port_intf_name) == 0) {
				ret = build_pat_global_pipe(portid, nat_rules, nat_num_rules);
				if (ret < 0)
					return ret;
			} else {
				DOCA_LOG_ERR("getting interface index (%d) which isn't match to any configured port: %s", portid, strerror(-ret));
				return -1;
			}
			break;
		default:
			break;
		}
	}
	return 0;
}
