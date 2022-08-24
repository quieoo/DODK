#include "doca_log.h"
#include <stdarg.h>
int doca_log_stream_redirect(FILE *stream){

}
uint16_t doca_log_get_bucket_time(void){

}

void doca_log_set_bucket_time(const uint16_t bucket_time){

}
uint16_t doca_log_get_quantity(void){}
void doca_log_set_quantity(const uint16_t quantity){}
void doca_log_backend_level_set(struct doca_logger_backend *logger, uint32_t level){}
void doca_log_global_level_set(uint32_t level)
{
    rte_log_set_global_level(level);
}
uint32_t doca_log_global_level_get(void){}
int doca_log_source_register(const char *source_name)
{
    return rte_log_register(source_name);
}
int doca_log_rate_bucket_register(uint32_t source){}
struct doca_logger_backend *doca_log_create_file_backend(FILE *fptr){}
struct doca_logger_backend *doca_log_create_fd_backend(int fd){}
struct doca_logger_backend *doca_log_create_buffer_backend(char *buffer, size_t capacity, log_flush_callback handler){}
struct doca_logger_backend *doca_log_create_syslog_backend(const char *name){}

int _level;

void doca_log(uint32_t level, uint32_t source, int line, const char *format, ...)
{
    printf(format);
    rte_log(level, source, format);
    /*
    _level=1;
    if(level<=_level){
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
    }*/
}
void doca_log_developer(uint32_t level, uint32_t source, int line, const char *format, ...){}
void doca_log_rate_limit(uint32_t level, uint32_t source, int line, uint32_t bucket_id, const char *format, ...){}
