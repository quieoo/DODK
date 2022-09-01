
/**
 * @file doca_compat.h
 * @page compat
 * @defgroup COMPAT Compatibility Management
 *
 * Lib to define compatibility with current version, define experimental Symbols.
 *
 * To set a Symbol (or specifically a function) as experimental:
 *
 *  * int func_declare(int param1, int param2);
 *
 * To remove warnings of experimental compile with "-D DOCA_ALLOW_EXPERIMENTAL_API"
 *
 * @{
 */

#ifndef DOCA_COMPAT_H_
#define DOCA_COMPAT_H_

#ifdef __cplusplus
extern "C" {
#endif

#define DOCA_EXPORTED __attribute__((visibility("default")))

#ifndef DOCA_ALLOW_EXPERIMENTAL_API

/**
 * @brief To set a Symbol (or specifically a function) as experimental.
 */
#define __DOCA_EXPERIMENTAL                                                                                            \
	__attribute__((deprecated("Symbol is defined as experimental"), section(".text.experimental"))) DOCA_EXPORTED

#else

#define __DOCA_EXPERIMENTAL __attribute__((section(".text.experimental"))) DOCA_EXPORTED

#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

/** @} */

#endif /* DOCA_COMPAT_H_ */
