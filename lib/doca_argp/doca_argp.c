#include "doca_argp.h"
#include <stdlib.h>
#include <rte_eal.h>

void doca_argp_init(const char *program_name, struct doca_argp_program_type_config *type_config, void *program_config){
}

void doca_argp_register_param(struct doca_argp_param *input_param){
}

void doca_argp_start(int argc, char **argv, struct doca_argp_program_general_config **general_config){
    int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
}

void doca_argp_destroy(void){

}

void doca_argp_usage(void){}

void doca_argp_register_version_callback(callback_func callback){}

void doca_argp_register_validation_callback(callback_func callback){}

