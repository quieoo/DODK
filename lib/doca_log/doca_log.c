#include "doca_log.h"
#include <stdarg.h>

static int global_log_level=30;
doca_error_t doca_log_stream_redirect(FILE *stream){
    return DOCA_SUCCESS;
}
uint16_t doca_log_get_bucket_time(void){}

void doca_log_set_bucket_time(const uint16_t bucket_time){}
uint16_t doca_log_get_quantity(void){}
void doca_log_set_quantity(const uint16_t quantity){}
doca_error_t doca_log_backend_level_set(struct doca_logger_backend *logger, uint32_t level){
    return DOCA_SUCCESS;
}
doca_error_t doca_log_global_level_set(uint32_t level)
{
    //rte_log_set_global_level(level);
    global_log_level=level;

    return DOCA_SUCCESS;
}
uint32_t doca_log_global_level_get(void){}
doca_error_t doca_log_source_register(const char *source_name, int *source)
{
    *source=rte_log_register(source_name);
    return DOCA_SUCCESS;
}
doca_error_t doca_log_rate_bucket_register(int source, int *bucket){
    return DOCA_SUCCESS;

}
doca_error_t doca_log_create_file_backend(FILE *fptr, struct doca_logger_backend **backend){
    return DOCA_SUCCESS;
}
doca_error_t doca_log_create_fd_backend(int fd, struct doca_logger_backend **backend){
    return DOCA_SUCCESS;
}
doca_error_t doca_log_create_buffer_backend(char *buffer, size_t capacity, log_flush_callback handler,
					    struct doca_logger_backend **backend){
                            return DOCA_SUCCESS;
                        }
doca_error_t doca_log_create_syslog_backend(const char *name, struct doca_logger_backend **backend){
    return DOCA_SUCCESS;
}

doca_error_t doca_log(uint32_t level, int source, int line, const char *format, ...)
{

    /*
    va_list ap;
	int ret;
	va_start(ap, format);
	ret = rte_vlog(level, source, format, ap);
	va_end(ap);*/
    if(level<=global_log_level){
        switch (level)
        {
        case 4:
            printf("LOG_DEBUG: ");
            break;
        case 3:
            printf("LOG_INFO: ");
            break;
        case 2:
            printf("LOG_WARNING: ");
            break;
        case 0:
            printf("LOG_CRIT: ");
            break;
        case 1:
            printf("LOG_ERR: ");
            break;
        default:
            // printf("LOG-%d: ",level);
            break;
        }
        va_list ap;
        va_start(ap, format);

        vfprintf(stdout, format, ap);
        va_end(ap);

        printf("\n");
    }
    return DOCA_SUCCESS;
}
doca_error_t doca_log_developer(uint32_t level, int source, int line, const char *format, ...){
    return DOCA_SUCCESS;
}
doca_error_t doca_log_rate_limit(uint32_t level, int source, int line, int bucket, const char *format, ...){
    return DOCA_SUCCESS;
}
doca_error_t doca_log_source_destroy(int source){
    return DOCA_SUCCESS;
}