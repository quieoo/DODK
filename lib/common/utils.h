
#ifndef COMMON_UTILS_H_
#define COMMON_UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// #include <doca_log.h>

/*
#define APP_EXIT(format, ...)					\
	do {							\
		DOCA_LOG_ERR(format "\n", ##__VA_ARGS__);	\
		exit(1);					\
	} while (0)
*/
#define APP_EXIT(format, ...)					\
	do {							\
		printf(format);	\
		exit(1);					\
	} while (0)

void sdk_version_callback(void *doca_config, void *param);

#endif /* COMMON_UTILS_H_ */
