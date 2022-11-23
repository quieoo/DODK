

#ifndef COMMON_DPDK_UTILS_H_
#define COMMON_DPDK_UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_mbuf.h>
#include <rte_flow.h>

#include "offload_rules.h"
#include "doca_error.h"
#ifdef __cplusplus
extern "C" {
#endif

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250

void dpdk_init(struct application_dpdk_config *app_dpdk_config);

void dpdk_fini(struct application_dpdk_config *app_dpdk_config);

void print_header_info(const struct rte_mbuf *packet, const bool l2, const bool l3, const bool l4);
 
 /* Initialize dpdk ports and queues
 *
 * @app_dpdk_config [in/out]: application dpdk config struct
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t dpdk_queues_and_ports_init(struct application_dpdk_config *app_dpdk_config);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* COMMON_DPDK_UTILS_H_ */
