#include "doca_argp.h"
#include <stdlib.h>
#include <rte_eal.h>
#include <getopt.h>

#define MAX_PARAM_NUM 100

struct doca_argp_param *registered_param[MAX_PARAM_NUM];
int registered = 0;
void *config;

void doca_argp_init(const char *program_name, struct doca_argp_program_type_config *type_config, void *program_config)
{
	config = program_config;
}

void doca_argp_register_param(struct doca_argp_param *input_param)
{
	struct doca_argp_param *p = malloc(sizeof(struct doca_argp_param));
	memcpy(p, input_param, sizeof(struct doca_argp_param));

	registered_param[registered++] = p;
}

void usage(char *programe)
{
	printf("\nusage: %s\n", programe);
	printf("\nRegistered Configuration:\n");
	for (int i = 0; i < registered; i++)
	{
		struct doca_argp_param *p = registered_param[i];
		printf("	-%s, --%s\n", p->short_flag, p->long_flag);
		printf("		%s\n", p->description);
	}
}

static void
set_log_level_callback(void *config, void *param)
{
}

void doca_argp_start(int argc, char **argv, struct doca_argp_program_general_config **general_config)
{
	/*
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
*/
	struct doca_argp_param log_level = {
		.short_flag = "ll",
		.long_flag = "log-level",
		.arguments = "<level>",
		.description = "Set the log level, 0-CRIT, 1-ERROR, 2-WARNING, 3-INFO, 4-DEBUG",
		.callback = set_log_level_callback,
		.arg_type = DOCA_ARGP_TYPE_INT,
		.is_mandatory = false,
		.is_cli_only = false};
	doca_argp_register_param(&log_level);

	int n, opt;
	int opt_idx;
	static struct option lgopts[MAX_PARAM_NUM];
	
	char shortopt[MAX_PARAM_NUM*2];
	int shortopt_point=0;

	for (int i = 0; i < registered; i++)
	{
		struct doca_argp_param *par = registered_param[i];

		lgopts[i].name = par->long_flag;
		lgopts[i].val = par->short_flag[0];
		shortopt[shortopt_point++]=par->short_flag[0];
		if (par->arg_type != DOCA_ARGP_TYPE_BOOLEAN)
		{
			lgopts[i].has_arg = true;
			shortopt[shortopt_point++]=':';
		}
	}
	shortopt[shortopt_point]='\0';
	printf("%d %s\n", sizeof(shortopt),shortopt);
	while ((opt = getopt_long(argc, argv, shortopt, lgopts, NULL)) != -1)
	{
		printf("ch\n");
		printf("%d\n",opt);
		/*
		switch (opt)
		{
		case 'a':
			n = intchar(optarg);
			m = intchar(argv[optind]);
			printf("option: a, %d+%d=%d\n", n, m, n + m);
			break;
		case 's':
			sum = intchar(optarg);
			printf("option: s, %d*%d=%d\n", sum, sum, sum * sum);
			break;
		case 'l':
			printf("file is:%s\n", optarg);
			break;
		case ':':
			printf("option needs a value\n");
			break;
		case '?':
			printf("unknown option: %c\n", optopt);
			break;
		}*/
	}
}

void doca_argp_destroy(void)
{
	for (int i = 0; i < registered; i++)
	{
		free(registered_param[i]);
	}
}

void doca_argp_usage(void) {}

void doca_argp_register_version_callback(callback_func callback) {}

void doca_argp_register_validation_callback(callback_func callback) {}
