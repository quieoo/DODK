#include "doca_argp.h"
#include <stdlib.h>
#include <rte_eal.h>
#include <getopt.h>
#include <doca_log.h>

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
	int level = *(int *) param;
	doca_log_global_level_set(level);
}

/*
	DOCA_ARGP_TYPE_INT
	DOCA_ARGP_TYPE_STRING 
	DOCA_ARGP_TYPE_JSON_OBJ x
*/
void call_function(struct doca_argp_param *opt, char *param){
	if(opt->arg_type==DOCA_ARGP_TYPE_INT){
		int i=0,sum=0;	
		while (param[i]){
			sum=10*sum+param[i]-'0';
			i++;
		}

		opt->callback(config, &sum);
	}else if(opt->arg_type==DOCA_ARGP_TYPE_STRING){
		opt->callback(config, param);
	}
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
		if (par->arg_type != DOCA_ARGP_TYPE_BOOLEAN || strlen(par->short_flag) > 1)
		{
			lgopts[i].has_arg = true;
			shortopt[shortopt_point++]=':';
		}
	}
	shortopt[shortopt_point]='\0';
	while ((opt = getopt_long(argc, argv, shortopt, lgopts, NULL)) != -1)
	{
		bool hit_noce=false;
		for(int i=0;i<registered;i++){
			struct doca_argp_param *p=registered_param[i];
			if(opt == p->short_flag[0]){
				//for those short flag with more than one characters
				bool hit=true;
				int j=0;
				int flag_length=strlen(p->short_flag);
				if(flag_length >= 2){
					if(p->short_flag[1] != *optarg)
						{hit=false;	break;}
					for(;j+2<flag_length;j++){
						if(p->short_flag[j+2] != argv[optind + j])
							{hit=false; break;}
					}
				}
				

				if(hit){
					hit_noce=true;
					if(p->arg_type == DOCA_ARGP_TYPE_BOOLEAN){
						bool _param=true;
						p->callback(config, &(_param));
					}else{
						if(flag_length == 1){
							call_function(p, optarg);
						}else{
							call_function(p, argv[optind + j]);
						}
					}
					break;
				}
			}
		}
		if(!hit_noce){
			usage(argv[0])
		}
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
