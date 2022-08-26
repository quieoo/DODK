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

void usage(void *config, void *param)
{
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

	//copy all args
	int _argc=argc;
	char* _argv[MAX_PARAM_NUM];
	for(int i=0;i<argc;i++){
		char *arg=malloc(100);
		memcpy(arg, argv[i], sizeof(argv[i]));
		_argv[i]=arg;
	}

	printf("arg: %d\n",argc);
	for(int i=0;i<argc;i++){
		printf("	%s\n",argv[i]);
	}

	/*
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
*/

	// add a global args of log_level
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
	struct doca_argp_param help = {
		.short_flag = "h",
		.long_flag = "help",
		.arguments = "<none>",
		.description = "print usage",
		.callback = usage,
		.arg_type = DOCA_ARGP_TYPE_BOOLEAN,
		.is_mandatory = false,
		.is_cli_only = false};

	doca_argp_register_param(&help);

	// parse doca registered args
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

					//if a arg hit doca registered list, remove it from _argv
					int k=0;
					int num_rm;
					if(p->arg_type==DOCA_ARGP_TYPE_BOOLEAN)
						num_rm=1;
					else
						num_rm=2;
					while(k < _argc){
						bool to_remove=false;
						if((argv[k][0]=='-' && _argv[k][1]=='-' && strcmp(_argv[k][2], p->long_flag)==0)
						|| (argv[k][0]=='-' && strcmp(_argv[k][1], p->short_flag)==0))
							to_remove=true;
						if(to_remove){
							for(int j=k;j<i+num_rm;j++)
								free(_argv[k]);
							for(int j=k;j<_argc-num_rm;j++)
								_argv[j]=_argv[j+num_rm];
							_argc-=num_rm;
						}
						k++;
					}

					break;
				}
			}
		}
	}

	printf("_arg: %d\n",_argc);
	for(int i=0;i<_argc;i++){
		printf("	%s\n",_argv[i]);
	}


	int ret = rte_eal_init(_argc, _argv);

	//clean resources
	for(int i=0;i<argc;i++){
		free(_argv[i]);
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
