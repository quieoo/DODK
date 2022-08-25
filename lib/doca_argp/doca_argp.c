#include "doca_argp.h"
#include <stdlib.h>
#include <rte_eal.h>
#include <getopt.h>


#define MAX_PARAM_NUM 100

struct doca_argp_param *registered_param[MAX_PARAM_NUM];
int registered=0;
void *config;

void doca_argp_init(const char *program_name, struct doca_argp_program_type_config *type_config, void *program_config){
	config=program_config;
}

void doca_argp_register_param(struct doca_argp_param *input_param){
	struct doca_argp_param *p=malloc(sizeof(struct doca_argp_param));
	memcpy(p, input_param, sizeof(struct doca_argp_param));
	
	registered_param[registered++]=p;
}

void usage(char* programe){
	printf("\nusage: %s\n", programe);
	printf("\nRegistered Configuration:\n");
	for(int i=0; i<registered; i++){
		struct doca_argp_param *p=registered_param[i];
		printf("	--%s(-%s)=%s \n", p->long_flag, p->short_flag, p->arguments);
	}
}

void doca_argp_start(int argc, char **argv, struct doca_argp_program_general_config **general_config){
    /*
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
*/
	int n, opt;
	int opt_idx;
	static const struct option lgopts[MAX_PARAM_NUM];
	for(int i=0;i<registered;i++){
		struct option _opt;
		struct doca_argp_param *par=registered_param[i];

		_opt.name=_opt.name;
		if(par->arg_type != DOCA_ARGP_TYPE_BOOLEAN){
			_opt.has_arg=true;
		}		
	}

	char **argvopt = argv;
	while ((opt = getopt_long(argc, argvopt, "",
				lgopts, &opt_idx)) != EOF){
					switch (opt)
					{
					case 0:
						break;

					default:
						usage(argv[0]);
						rte_exit(EXIT_FAILURE, "Invalid option: %s\n",argv[optind - 1]);
						break;
					}
				}

}

void doca_argp_destroy(void){
	for(int i=0;i<registered;i++){
		free(registered_param[i]);
	}
}

void doca_argp_usage(void){}

void doca_argp_register_version_callback(callback_func callback){}

void doca_argp_register_validation_callback(callback_func callback){}

