/*
 * Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#ifndef SWITCH_CORE_H_
#define SWITCH_CORE_H_

#include "flow_parser.h"

/*
 * Count the total number of ports
 *
 * @dpdk_cfg [out]: DPDK configuration
 */
void switch_ports_count(struct application_dpdk_config *dpdk_cfg);

/*
 * Initialize Switch application
 *
 * @dpdk_config [in]: DPDK configuration
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t switch_init(struct application_dpdk_config *dpdk_config);

/*
 * Destroy Switch application resources
 */
void switch_destroy(void);

#endif /* SWITCH_CORE_H_ */
