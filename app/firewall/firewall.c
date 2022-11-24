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

#include <signal.h>
#include <rte_byteorder.h>

#include <doca_argp.h>
#include <doca_log.h>

#include "firewall_core.h"

DOCA_LOG_REGISTER(FIREWALL);

static bool force_quit;		/* Set when signal is received */

/*
 * Signals handler function to handle SIGINT and SIGTERM signals
 *
 * @signum [in]: signal number
 */
static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		DOCA_LOG_INFO("Signal %d received, preparing to exit...", signum);
		force_quit = true;
	}
}

/*
 * Firewall application main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int
main(int argc, char **argv)
{
	doca_log_global_level_set(4);
	doca_error_t result;
	int ret;
	int exit_status = EXIT_SUCCESS;
	const char *grpc_address;
	struct firewall_cfg firewall_cfg = {0};
	struct rule_match *drop_rules;
	int n_rules;
	int nb_ports = 2;

	force_quit = false;
	result = doca_argp_init("firewall", &firewall_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_get_error_string(result));
		return EXIT_FAILURE;
	}
	doca_argp_set_grpc_program();
	result = register_firewall_params();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse application input: %s", doca_get_error_string(result));
		doca_argp_destroy();
		return EXIT_FAILURE;
	}
	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse application input: %s", doca_get_error_string(result));
		doca_argp_destroy();
		return EXIT_FAILURE;
	}
	result = doca_argp_get_grpc_addr(&grpc_address);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to get grpc address");
		doca_argp_destroy();
		return EXIT_FAILURE;
	}
	/* Start the server */
	ret = firewall_ports_init(grpc_address);
	if (ret < 0) {
		exit_status = EXIT_FAILURE;
		goto argp_destroy;
	}
	if (firewall_cfg.mode == FIREWALL_MODE_STATIC) {
		result = init_drop_rules(firewall_cfg.json_path, &n_rules, &drop_rules);
		if (result != DOCA_SUCCESS) {
			exit_status = EXIT_FAILURE;
			goto ports_destroy;
		}
		ret = firewall_pipes_init(drop_rules, n_rules);
		if (ret < 0) {
			exit_status = EXIT_FAILURE;
			goto ports_destroy;
		}

		signal(SIGINT, signal_handler);
		signal(SIGTERM, signal_handler);
		DOCA_LOG_INFO("Waiting for traffic, press Ctrl+C for termination");
		while (!force_quit)
			sleep(1);
	} else if (firewall_cfg.mode == FIREWALL_MODE_INTERACTIVE) {
		register_actions_on_flow_parser();
		result = flow_parser_init("FIREWALL>> ");
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to open CLI");
			exit_status = EXIT_FAILURE;
			goto ports_destroy;
		}
		flow_parser_cleanup();
	}

ports_destroy:
	firewall_ports_destroy(nb_ports);
	doca_flow_grpc_destroy();
argp_destroy:
	/* ARGP cleanup */
	doca_argp_destroy();
	return exit_status;
}
