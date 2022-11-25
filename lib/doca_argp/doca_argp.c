#include "doca_argp.h"
#include <stdlib.h>
#include <rte_eal.h>
#include <getopt.h>
#include <doca_log.h>

#define MAX_PARAM_NUM 100

struct doca_argp_param *registered_param[MAX_PARAM_NUM];
int registered = 0;
void *config;
// struct doca_argp_program_general_config *g_config;
// struct doca_argp_program_type_config *t_config;
char doca_argp_grpc_address [100];

typedef struct doca_argp_param {
	char *short_flag;				/**< Flag long name */
	char *long_flag;				/**< Flag short name */
	char *arguments;				/**< Flag expected arguments */
	char *description;				/**< Flag description */
	callback_func callback;				/**< Flag program callback */
	enum doca_argp_type arg_type;			/**< Flag argument type */
	bool is_mandatory;				/**< Is flag mandatory for the program */
	bool is_cli_only;				/**< Is flag supported only in cli mode */
};

dpdk_callback eal_init;

doca_error_t doca_argp_init(const char *program_name, void *program_config)
{
	config = program_config;
	// t_config=type_config;
	return DOCA_SUCCESS;
}
void doca_argp_set_dpdk_program(dpdk_callback callback){
	eal_init=callback;
}

doca_error_t doca_argp_param_create(struct doca_argp_param **param){
	*param=malloc(sizeof(struct doca_argp_param));
	return DOCA_SUCCESS;
}
void doca_argp_param_set_short_name(struct doca_argp_param *param, const char *name){
	param->short_flag=name;
}

void doca_argp_param_set_long_name(struct doca_argp_param *param, const char *name){
	param->long_flag=name;
}

void doca_argp_param_set_arguments(struct doca_argp_param *param, const char *arguments){
	param->arguments= arguments;
}

void doca_argp_param_set_description(struct doca_argp_param *param, const char *description){
	param->description= description;
}

void doca_argp_param_set_callback(struct doca_argp_param *param, callback_func callback){
	param->callback=callback;
}

void doca_argp_param_set_type(struct doca_argp_param *param, enum doca_argp_type type){
	param->arg_type=type;
}

void doca_argp_param_set_mandatory(struct doca_argp_param *param){
	param->is_mandatory=true;
}

doca_error_t doca_argp_register_param(struct doca_argp_param *input_param)
{
	registered_param[registered++]=input_param;
	return DOCA_SUCCESS;
}



void usage(void *param, void *config)
{
	printf("\nDOCA Registered Configuration:\n");
	for (int i = 0; i < registered; i++)
	{
		struct doca_argp_param *p = registered_param[i];
		printf("	-%s, --%s\n", p->short_flag, p->long_flag);
		printf("		%s\n", p->description);
	}
	printf("\n DPDK Configuration...\n");
	exit(0);
}

static void
set_log_level_callback(void *param, void *config)
{
	int level = *(int *)param;
	doca_log_global_level_set(level);
}

static void set_grpc_address( char *param, void *config){
	/*
	int l=0;
	for(char* i=param;*i!=NULL; i++){
		doca_argp_grpc_address[l++]=*i;
	}*/
	strcpy(doca_argp_grpc_address, param);
}

/*
	DOCA_ARGP_TYPE_INT
	DOCA_ARGP_TYPE_STRING
	DOCA_ARGP_TYPE_JSON_OBJ x
*/
void call_function(struct doca_argp_param *opt, char *param)
{
	if (opt->arg_type == DOCA_ARGP_TYPE_INT)
	{
		int i = 0, sum = 0;
		while (param[i])
		{
			sum = 10 * sum + param[i] - '0';
			i++;
		}

		opt->callback(&sum, config);
	}
	else if (opt->arg_type == DOCA_ARGP_TYPE_STRING)
	{

		opt->callback(param,config);
	}
}

void doca_argp_set_grpc_program(void){
	struct doca_argp_param *grpc;
	doca_argp_param_create(&grpc);
	doca_argp_param_set_short_name(grpc, "g");
	doca_argp_param_set_long_name(grpc, "grpc-address");
	doca_argp_param_set_arguments(grpc, "<ip:port>");
	doca_argp_param_set_description(grpc, "ip address of grpc server, note that default port of orchestrator is 50051 while port of grpc_flow is 50050");
	doca_argp_param_set_callback(grpc, set_grpc_address);
	doca_argp_param_set_type(grpc, DOCA_ARGP_TYPE_STRING);
	doca_argp_register_param(grpc);
}

doca_error_t doca_argp_get_grpc_addr(const char **address){
	/*
	int l=0;
	for(char* i=doca_argp_grpc_address;*i!=NULL; i++){
		(*address)[l++]=*i;
	}
	*/
	*address=doca_argp_grpc_address;
	return DOCA_SUCCESS;
}

doca_error_t doca_argp_start(int argc, char **argv)
{
	/*
	*general_config=malloc(sizeof(struct doca_argp_program_general_config));
	memset(*general_config, 0, sizeof(struct doca_argp_program_general_config));
	g_config=*general_config;*/

/*
	int rett = rte_eal_init(argc, argv);
	if (rett < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	return;
*/
	// add a global args of log_level
	struct doca_argp_param *log, *help;
	doca_argp_param_create(&log);
	doca_argp_param_set_short_name(log, "ll");
	doca_argp_param_set_long_name(log, "log-level");
	doca_argp_param_set_arguments(log, "<level>");
	doca_argp_param_set_description(log, "Set the log level, 20-CRIT, 30-ERROR, 40-WARNING, 50-INFO, 60-DEBUG");
	doca_argp_param_set_callback(log, set_log_level_callback);
	doca_argp_param_set_type(log, DOCA_ARGP_TYPE_INT);
	doca_argp_register_param(log);

	doca_argp_param_create(&help);
	doca_argp_param_set_short_name(help, "h");
	doca_argp_param_set_long_name(help, "help");
	doca_argp_param_set_arguments(help, "<none>");
	doca_argp_param_set_description(help, "print usage");
	doca_argp_param_set_callback(help, usage);
	doca_argp_param_set_type(help, DOCA_ARGP_TYPE_BOOLEAN);
	doca_argp_register_param(help);



	// parse doca registered args
	int i=0;
	while(i<argc)
	{
		struct doca_argp_param *p={0};
		for (int j = 0; j < registered; j++)
		{
			if(argv[i][0]=='-' && argv[i][1]=='-'){
				if((strlen(argv[i])-2 == strlen(registered_param[j]->long_flag))  && 
					(strcmp(argv[i]+2, registered_param[j]->long_flag)==0)){
					p=registered_param[j];
					break;
				}
			}else if(argv[i][0]=='-'){
				if((strlen(argv[i])-1 == strlen(registered_param[j]->short_flag))  && 
					(strcmp(argv[i]+1, registered_param[j]->short_flag)==0)){
					p=registered_param[j];
					break;
				}
			}
		}
		if(p){
			int num_rm;
			// call_backs
			if (p->arg_type == DOCA_ARGP_TYPE_BOOLEAN){
				bool _param = true;
				p->callback(config, &(_param));
				num_rm=1;
			}
			else{
				call_function(p, argv[i+1]);
				num_rm=2;
			}

			//remove doca regisered args
			argc -= num_rm;
			for (int j = i; j < argc; j++)
				argv[j] = argv[j + num_rm];
		}else{
			i++;
		}

	}
	/*
	if(t_config->is_grpc){
		return;
	}*/
	int ret;
	if(eal_init){
		ret=eal_init(argc, argv);
		if(ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	
	}
	return DOCA_SUCCESS;

}

doca_error_t doca_argp_destroy(void)
{
	for (int i = 0; i < registered; i++)
	{
		free(registered_param[i]);
	}
	
	// free(g_config);
}

void doca_argp_usage(void) {}

doca_error_t doca_argp_register_version_callback(callback_func callback) {
	return DOCA_SUCCESS;
}

doca_error_t doca_argp_register_validation_callback(validation_callback callback) {
	return DOCA_SUCCESS;
}
