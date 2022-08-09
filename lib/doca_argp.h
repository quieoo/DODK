
#ifndef DOCA_ARGP_H_
#define DOCA_ARGP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

// #include <doca_compat.h>

/** @brief Maximum length for gRPC serever address string */
#define MAX_SERVER_ADDRESS 24
/** @brief Flag callback function type */
typedef void (*callback_func)(void *, void *);

/**
 * @brief Flag input type
 */
enum doca_argp_type {
	DOCA_ARGP_TYPE_STRING = 0,			/**< Input type is a string */
	DOCA_ARGP_TYPE_INT,				/**< Input type is an integer */
	DOCA_ARGP_TYPE_BOOLEAN,				/**< Input type is a boolean */
	DOCA_ARGP_TYPE_JSON_OBJ,			/**< DPDK Param input type is a json object,
							  * only for json mode */
};

/**
 * @brief DOCA general flags values as provided to the program
 */
struct doca_argp_program_general_config {
	int log_level;					/**< The log level as provided by the user */
	char grpc_address[MAX_SERVER_ADDRESS];		/**< The gRPC server address as provided by the user */
};

/**
 * @brief Information about program configuration
 */
struct doca_argp_program_type_config {
	bool is_dpdk;					/**< Is the program based on DPDK API */
	bool is_grpc;					/**< Is the program based on gRPC API */
};

/**
 * @brief Program flag information
 *
 * @note It is the programmer's responsibility to ensure the callback will copy the content of the param passed to it.
 * The pointer pointing to the param is owned by doca_argp, and it is only valid in the scope of the called callback.
 */
struct doca_argp_param {
	char *short_flag;				/**< Flag long name */
	char *long_flag;				/**< Flag short name */
	char *arguments;				/**< Flag expected arguments */
	char *description;				/**< Flag description */
	callback_func callback;				/**< Flag program callback */
	enum doca_argp_type arg_type;			/**< Flag argument type */
	bool is_mandatory;				/**< Is flag mandatory for the program */
	bool is_cli_only;				/**< Is flag supported only in cli mode */
};

/**
 * @brief Print usage instructions and exit with failure.
 */
void doca_argp_usage(void);

/**
 * @brief Initialize the parser interface.
 *
 * @param program_name
 * Name of current program, using the name for usage print.
 * @param type_config
 * Announce if current program is based on DPDK/gRPC API.
 * @param program_config
 * Program configuration struct.
 */

void doca_argp_init(const char *program_name, struct doca_argp_program_type_config *type_config, void *program_config);

/**
 * @brief Register a program flag.
 *
 * @param input_param
 * Program flag details.
 *
 * @note Value of is_cli_only field may be changed in this function.
 */
void doca_argp_register_param(struct doca_argp_param *input_param);

/**
 * @brief Register an alternative version callback.
 *
 * @param callback
 * Program-specific version callback.
 */
void doca_argp_register_version_callback(callback_func callback);

/**
 * @brief Register program validation callback function.
 *
 * @param callback
 * Program validation callback.
 */
void doca_argp_register_validation_callback(callback_func callback);

/**
 * @brief Parse incoming arguments (cmd line/json).
 *
 * @param argc
 * Number of program command line arguments.
 * @param argv
 * Program command line arguments.
 * @param general_config
 * DOCA wide input arguments (log_level, ...).
 *
 * @note: if the program is DPDK app, doca_argp_start() will parses DPDK flags and calling rte_eal_init().
 */
void doca_argp_start(int argc, char **argv, struct doca_argp_program_general_config **general_config);

/**
 * @brief ARG Parser destroy.
 *
 * cleanup all resources include calling rte_eal_cleanup(),
 * to release EAL resources that has allocated during rte_eal_init().
 *
 * @note After this call, no DPDK function calls may be made.
 */
void doca_argp_destroy(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

/** @} */

#endif /* DOCA_ARGP_H_ */
