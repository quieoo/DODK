

/**
 * @file doca_log.h
 * @page logger
 * @defgroup LOGGER Logging Management
 *
 * Define functions for internal and external logging management
 *
 * To add DOCA internal logging compile with "-D DOCA_LOGGING_ALLOW_DLOG"
 *
 * @{
 */

#ifndef DOCA_LOG_H_
#define DOCA_LOG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

#include <doca_compat.h>

/**
 * @brief log levels
 */
enum DOCA_LOG_LEVEL {
	DOCA_LOG_LEVEL_CRIT,	/**< Critical log level */
	DOCA_LOG_LEVEL_ERROR,	/**< Error log level */
	DOCA_LOG_LEVEL_WARNING, /**< Warning log level */
	DOCA_LOG_LEVEL_INFO,	/**< Info log level */
	DOCA_LOG_LEVEL_DEBUG	/**< Debug log level */
};

/**
 * @brief logging backend
 */
struct doca_logger_backend;

/**
 * @brief logging backend flush() handler
 */
typedef void (*log_flush_callback)(char *buffer);

/**
 * @brief Redirect the logger to a different stream.
 *
 * Dynamically change the logger stream of the default logger backend. The default
 * stream is stderr.
 *
 * @param stream
 * Pointer to the stream.
 * @return
 * 0 on success, error code otherwise.
 */
int doca_log_stream_redirect(FILE *stream);

/**
 * @brief Get the timespan of the rate-limit bucket.
 *
 * @return
 * Time (in seconds) of the rate-limit bucket.
 */
uint16_t doca_log_get_bucket_time(void);

/**
 * @brief Set the timespan of the rate-limit bucket.
 *
 * @param bucket_time
 * Time (in seconds) for the rate-limit bucket.
 */
void doca_log_set_bucket_time(const uint16_t bucket_time);

/**
 * @brief Get the quantity of the rate-limit bucket.
 *
 * @return
 * Maximal number of log events for a rate-limit bucket.
 */
uint16_t doca_log_get_quantity(void);

/**
 * @brief Set the quantity of the rate-limit bucket.
 *
 * @param quantity
 * Maximal number of log events for a rate-limit bucket.
 */
void doca_log_set_quantity(const uint16_t quantity);

/**
 * @brief Set the log level of a specific logger backend.
 *
 * Dynamically change the log level of the given logger backend, any log under this
 * level will be shown.
 *
 * @param logger
 * Logger backend to update.
 * @param level
 * Log level enum DOCA_LOG_LEVEL.
 */
void doca_log_backend_level_set(struct doca_logger_backend *logger, uint32_t level);

/**
 * @brief Set the log level of the default logger backend.
 *
 * Dynamically change the log level of the default logger backend, any log under this
 * level will be shown.
 *
 * @param level
 * Log level enum DOCA_LOG_LEVEL.
 */
void doca_log_global_level_set(uint32_t level);

/**
 * @brief Get the log level of the default logger backend.
 *
 * Dynamically query for the log level of the default logger backend, any log under this
 * level will be shown.
 *
 * @return
 * Log level enum DOCA_LOG_LEVEL.
 */
uint32_t doca_log_global_level_get(void);

/**
 * @brief Register a log source.
 *
 * Will return the ID associated with the log source. Log source name will be shown
 * in the logs.
 *
 * @param source_name
 * The string identifying the log source. Should be in an heirarchic form (i.e. DPI::Parser).
 * @return
 * The log source identifier. Negative for err.
 */
int doca_log_source_register(const char *source_name);

/**
 * @brief Register a new rate bucket.
 *
 * Will return the ID associated with the new bucket.
 *
 * @param source
 * The log source identifier defined by doca_log_source_register.
 * @return
 * The bucket identifier. Negative for err.
 */
int doca_log_rate_bucket_register(uint32_t source);

/**
 * @brief Create a logging backend with a FILE* stream.
 *
 * Creates a new logging backend that will be added on top of the default logger.
 *
 * @param fptr
 * The FILE * for the logger's stream.
 * @return
 * struct doca_logger_backend * on success, NULL otherwise.
 */
struct doca_logger_backend *doca_log_create_file_backend(FILE *fptr);

/**
 * @brief Create a logging backend with an fd stream.
 *
 * Creates a new logging backend that will be added on top of the default logger.
 *
 * @param fd
 * The file descriptor (int) for the logger's backend.
 * @return
 * struct doca_logger_backend * on success, NULL otherwise.
 */
struct doca_logger_backend *doca_log_create_fd_backend(int fd);

/**
 * @brief Create a logging backend with a char buffer stream.
 *
 * Creates a new logging backend that will be added on top of the default logger. The
 * logger will write each log record at the beginning of this buffer.
 *
 * @param buffer
 * The char buffer (char *) for the logger's stream.
 * @param capacity
 * Maximal amount of chars that could be written to the stream.
 * @param handler
 * Handler to be called when the log record should be flushed from the stream.
 * @return
 * struct doca_logger_backend * on success, NULL otherwise.
 */
struct doca_logger_backend *doca_log_create_buffer_backend(char *buffer, size_t capacity,
							   log_flush_callback handler);

/**
 * @brief Create a logging backend with a syslog output.
 *
 * Creates a new logging backend that will be added on top of the default logger.
 *
 * @param name
 * The syslog name for the logger's backend.
 * @return
 * struct doca_logger_backend * on success, NULL otherwise.
 */
struct doca_logger_backend *doca_log_create_syslog_backend(const char *name);

/**
 * @brief Generates a log message.
 *
 * The log will be shown in the doca_log_stream_redirect (see default).
 * This should not be used, please prefer using DOCA_LOG...
 *
 * @param level
 * Log level enum DOCA_LOG_LEVEL.
 * @param source
 * The log source identifier defined by doca_log_source_register.
 * @param line
 * The line number this log originated from.
 * @param format
 * printf(3) arguments, format and variables.
 */
void doca_log(uint32_t level, uint32_t source, int line, const char *format, ...) __attribute__ ((format (printf, 4, 5)));

/**
 * @brief Generates a log message for DLOG operations.
 *
 * The log will be shown in the doca_log_stream_redirect (see default).
 * @note This function is thread safe.
 *
 * @param level
 * Log level enum DOCA_LOG_LEVEL.
 * @param source
 * The log source identifier defined by doca_log_source_register.
 * @param line
 * The line number this log originated from.
 * @param format
 * printf(3) arguments, format and variables.
 */
void doca_log_developer(uint32_t level, uint32_t source, int line, const char *format, ...) __attribute__ ((format (printf, 4, 5)));

/**
 * @brief Generates a log message with rate limit.
 *
 * The log will be shown in the doca_log_stream_redirect (see default).
 * This should not be used, please prefer using DOCA_LOG_RATE_LIMIT...
 *
 * @param level
 * Log level enum DOCA_LOG_LEVEL.
 * @param source
 * The log source identifier defined by doca_log_source_register.
 * @param line
 * The line number this log originated from.
 * @param bucket_id
 * The bucket identifier defined by doca_log_rate_bucket_register.
 * @param format
 * printf(3) arguments, format and variables.
 */
void doca_log_rate_limit(uint32_t level, uint32_t source, int line, uint32_t bucket_id,
			 const char *format, ...) __attribute__ ((format (printf, 5, 6)));

/**
 * @brief Generates a log message with rate limit.
 *
 * The DOCA_LOG_RATE_LIMIT calls DOCA_LOG with some rate limit. Implied
 * to be used on hot paths.
 *
 * @param level
 * Log level enum DOCA_LOG_LEVEL (just ERROR, WARNING...).
 * @param format
 * printf(3) arguments, format and variables.
 */
#define DOCA_LOG_RATE_LIMIT(level, format...) \
	do { \
		static int bucket_id = -1; \
		if (bucket_id == -1) { \
			bucket_id = doca_log_rate_bucket_register(log_id); \
		} \
		doca_log_rate_limit(DOCA_LOG_LEVEL_##level, log_id, __LINE__, bucket_id, format); \
	} while (0)

/**
 * @brief Generates a CRITICAL rate limited log message.
 *
 * @param format
 * printf(3) arguments, format and variables.
 */
#define DOCA_LOG_RATE_LIMIT_CRIT(format...) DOCA_LOG_RATE_LIMIT(CRIT, format)

/**
 * @brief Generates an ERROR rate limited log message.
 *
 * @param format
 * printf(3) arguments, format and variables.
 */
#define DOCA_LOG_RATE_LIMIT_ERR(format...) DOCA_LOG_RATE_LIMIT(ERROR, format)

/**
 * @brief Generates a WARNING rate limited log message.
 *
 * @param format
 * printf(3) arguments, format and variables.
 */
#define DOCA_LOG_RATE_LIMIT_WARN(format...) DOCA_LOG_RATE_LIMIT(WARNING, format)

/**
 * @brief Generates an INFO rate limited log message.
 *
 * @param format
 * printf(3) arguments, format and variables.
 */
#define DOCA_LOG_RATE_LIMIT_INFO(format...) DOCA_LOG_RATE_LIMIT(INFO, format)

/**
 * @brief Generates a DEBUG rate limited log message.
 *
 * @param format
 * printf(3) arguments, format and variables.
 */

#define DOCA_LOG_RATE_LIMIT_DBG(format...) DOCA_LOG_RATE_LIMIT(DEBUG, format)
/**
 * @brief Generates a log message.
 *
 * The DOCA_LOG() is the main log function for logging. This call affects the performance.
 * Consider using DOCA_DLOG for the option to remove it on the final compilation.
 * Consider using the specific level DOCA_LOG for better code readability (i.e. DOCA_LOG_ERR).
 *
 * @param level
 * Log level enum DOCA_LOG_LEVEL (just ERROR, WARNING...).
 * @param format
 * printf(3) arguments, format and variables.
 */
#define DOCA_LOG(level, format...)                         \
	doca_log(DOCA_LOG_LEVEL_##level, log_id, __LINE__, format)

/**
 * @brief Generates a CRITICAL log message.
 *
 * Will generate critical log. This call affects the performance.
 * Consider using DOCA_DLOG for the option to remove it on the final compilation.
 *
 * @param format
 * printf(3) arguments, format and variables.
 */
#define DOCA_LOG_CRIT(format...) DOCA_LOG(CRIT, format)

/**
 * @brief Generates an ERROR log message.
 *
 * Will generate error log. This call affects the performance.
 * Consider using DOCA_DLOG for the option to remove it on the final compilation.
 *
 * @param format
 * printf(3) arguments, format and variables.
 */
#define DOCA_LOG_ERR(format...) DOCA_LOG(ERROR, format)

/**
 * @brief Generates a WARNING log message.
 *
 * Will generate warning log. This call affects the performace.
 * Consider using DOCA_DLOG for the option to remove it on the final compilation.
 *
 * @param format
 * printf(3) arguments, format and variables.
 */
#define DOCA_LOG_WARN(format...) DOCA_LOG(WARNING, format)

/**
 * @brief Generates an INFO log message.
 *
 * Will generate info log. This call affects the performance.
 * Consider using DOCA_DLOG for the option to remove it on the final compilation.
 *
 * @param format
 * printf(3) arguments, format and variables.
 */
#define DOCA_LOG_INFO(format...) DOCA_LOG(INFO, format)

/**
 * @brief Generates a DEBUG log message.
 *
 * Will generate debug log. This call affects the performace.
 * Consider using DOCA_DLOG for the option to remove it on the final compilation.
 *
 * @param format
 * printf(3) arguments, format and variables.
 */
#define DOCA_LOG_DBG(format...) DOCA_LOG(DEBUG, format)

#ifdef DOCA_LOGGING_ALLOW_DLOG

/**
 * @brief Generates a development log message.
 *
 * The DOCA_DLOG() is the main log function for development purposes logging.
 * To show the logs, define DOCA_LOGGING_ALLOW_DLOG in the compilation variables.
 * This will not effect performance if compiled without DOCA_LOGGING_ALLOW_DLOG, as
 * it will be removed by the compiler.
 * Consider using the specific level DOCA_LOG for better code readability (i.e. DOCA_DLOG_ERR).
 *
 * @param level
 * Log level enum DOCA_LOG_LEVEL.
 * @param format
 * printf(3) arguments, format and variables.
 */
#define DOCA_DLOG(level, format...) doca_log_developer(DOCA_LOG_LEVEL_##level, log_id, __LINE__, format)

#else

/**
 * @brief Generates a development log message.
 *
 * The DOCA_DLOG() is the main log function for development purposes logging.
 * To show the logs, define DOCA_LOGGING_ALLOW_DLOG in the compilation variables.
 * This will not effect performance if compiled without DOCA_LOGGING_ALLOW_DLOG, as
 * it will be removed by the compiler.
 * Consider using the specific level DOCA_LOG for better code readability (i.e. DOCA_DLOG_ERR).
 *
 * @param level
 * Log level enum DOCA_LOG_LEVEL.
 * @param format
 * printf(3) arguments, format and variables.
 */
#define DOCA_DLOG(level, format...)  \
	do { \
	} while (0)

#endif

/**
 * @brief Generates a CRITICAL development log message.
 *
 * Will generate critical log for development purposes.
 * To show the logs define DOCA_LOGGING_ALLOW_DLOG in the compilation variables.
 * This will not effect performance if compiled without DOCA_LOGGING_ALLOW_DLOG, as
 * it will be removed by the compiler.
 *
 * @param format
 * printf(3) arguments, format and variables.
 */
#define DOCA_DLOG_CRIT(format...) DOCA_DLOG(CRIT, format)

/**
 * @brief Generates an ERROR development log message.
 *
 * Will generate error log for development purposes.
 * To show the logs define DOCA_LOGGING_ALLOW_DLOG in the compilation variables.
 * This will not effect performance if compiled without DOCA_LOGGING_ALLOW_DLOG, as
 * it will be removed by the compiler.
 *
 * @param format
 * printf(3) arguments, format and variables.
 */
#define DOCA_DLOG_ERR(format...) DOCA_DLOG(ERROR, format)

/**
 * @brief Generates a WARNING development log message.
 *
 * Will generate warning log for development purposes.
 * To show the logs define DOCA_LOGGING_ALLOW_DLOG in the compilation variables.
 * This will not effect performance if compiled without DOCA_LOGGING_ALLOW_DLOG, as
 * it will be removed by the compiler.
 *
 * @param format
 * printf(3) arguments, format and variables.
 */
#define DOCA_DLOG_WARN(format...) DOCA_DLOG(WARNING, format)

/**
 * @brief Generates an INFO development log message.
 *
 * Will generate info log for development purposes.
 * To show the logs define DOCA_LOGGING_ALLOW_DLOG in the compilation variables.
 * This will not effect performance if compiled without DOCA_LOGGING_ALLOW_DLOG, as
 * it will be removed by the compiler.
 *
 * @param format
 * printf(3) arguments, format and variables.
 */
#define DOCA_DLOG_INFO(format...) DOCA_DLOG(INFO, format)

/**
 * @brief Generates a DEBUG development log message.
 *
 * Will generate debug log for development purposes.
 * To show the logs define DOCA_LOGGING_ALLOW_DLOG in the compilation variables.
 * This will not effect performance if compiled without DOCA_LOGGING_ALLOW_DLOG, as
 * it will be removed by the compiler.
 *
 * @param format
 * printf(3) arguments, format and variables.
 */
#define DOCA_DLOG_DBG(format...) DOCA_DLOG(DEBUG, format)

/**
 * @brief Registers log source on program start.
 *
 * Should be used to register the log source.
 * For example
 *
 * DOCA_LOG_REGISTER(dpi)
 *
 * void foo {
 *       DOCA_LOG_INFO("Message");
 * }
 *
 * @param SOURCE
 * A string representing the source name.
 */
#define DOCA_LOG_REGISTER(SOURCE)                                        \
static int log_id;                                                       \
/* Use the highest priority so other Ctors will be able to use the log */\
static void __attribute__((constructor(101), used)) __##__LINE__(void)   \
{	                                                                 \
	log_id = doca_log_source_register(#SOURCE);                      \
}

#ifdef __cplusplus
} /* extern "C" */
#endif

/** @} */

#endif /* DOCA_LOG_H_ */
