#include "dpdk_utils.h"
#include <rte_ethdev.h>
#include "utils.h"
#include "doca_error.h"

#define RSS_KEY_LEN 40

static struct rte_mempool *
allocate_mempool(const uint32_t total_nb_mbufs)
{
	struct rte_mempool *mbuf_pool;
	/* Creates a new mempool in memory to hold the mbufs */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", total_nb_mbufs, MBUF_CACHE_SIZE, 0,
										RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		APP_EXIT("Cannot allocate mbuf pool");
	return mbuf_pool;
}

static int
setup_hairpin_queues(uint16_t port_id, uint16_t peer_port_id, uint16_t *reserved_hairpin_q_list, int hairpin_queue_len)
{
	/* Port:
	 *	0. RX queue
	 *	1. RX hairpin queue rte_eth_rx_hairpin_queue_setup
	 *	2. TX hairpin queue rte_eth_tx_hairpin_queue_setup
	 */

	int ret = 0, hairpin_q;
	uint16_t nb_tx_rx_desc = 2048;
	uint32_t manual = 1;
	uint32_t tx_exp = 1;
	struct rte_eth_hairpin_conf hairpin_conf = {
		.peer_count = 1,
		.manual_bind = !!manual,
		.tx_explicit = !!tx_exp,
		.peers[0] = {peer_port_id},
	};

	for (hairpin_q = 0; hairpin_q < hairpin_queue_len; hairpin_q++)
	{
		// TX
		hairpin_conf.peers[0].queue = reserved_hairpin_q_list[hairpin_q];
		ret = rte_eth_tx_hairpin_queue_setup(port_id, reserved_hairpin_q_list[hairpin_q], nb_tx_rx_desc,
											 &hairpin_conf);
		if (ret != 0)
			return ret;
		// RX
		hairpin_conf.peers[0].queue = reserved_hairpin_q_list[hairpin_q];
		ret = rte_eth_rx_hairpin_queue_setup(port_id, reserved_hairpin_q_list[hairpin_q], nb_tx_rx_desc,
											 &hairpin_conf);
		if (ret != 0)
			return ret;
	}
	return ret;
}
#define CHECK_INTERVAL 1000 /* 100ms */
#define MAX_REPEAT_TIMES 90 /* 9s (90 * 100ms) in total */
static void
assert_link_status(uint8_t port)
{
	struct rte_eth_link link;
	uint8_t rep_cnt = MAX_REPEAT_TIMES;
	int link_get_err = -EINVAL;

	memset(&link, 0, sizeof(link));
	do
	{
		link_get_err = rte_eth_link_get(port, &link);
		if (link_get_err == 0 && link.link_status == RTE_ETH_LINK_UP)
			break;
		rte_delay_ms(CHECK_INTERVAL);
	} while (--rep_cnt);

	if (link_get_err < 0)
		rte_exit(EXIT_FAILURE, ":: error: link get is failing: %s\n",
				 rte_strerror(-link_get_err));
	if (link.link_status == RTE_ETH_LINK_DOWN)
		rte_exit(EXIT_FAILURE, ":: error: link is still down\n");
}

static int
port_init(struct rte_mempool *mbuf_pool, uint8_t port, struct application_dpdk_config *app_config)
{
	int ret;
	uint16_t i;
	/* Ethernet port configured with default settings. 8< */
	struct rte_eth_conf port_conf = {
		.rxmode = {
			.split_hdr_size = 0,
		},
		.txmode = {
			.offloads = RTE_ETH_TX_OFFLOAD_VLAN_INSERT | RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM | RTE_ETH_TX_OFFLOAD_TCP_CKSUM | RTE_ETH_TX_OFFLOAD_SCTP_CKSUM | RTE_ETH_TX_OFFLOAD_TCP_TSO,
		},
	};
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_dev_info dev_info;

	ret = rte_eth_dev_info_get(port, &dev_info);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
				 "Error during getting device (port %u) info: %s\n",
				 port, strerror(-ret));

	port_conf.txmode.offloads &= dev_info.tx_offload_capa;
	app_config->port_config.nb_queues=1;
	printf(":: initializing port: %d, nb_queues: %d\n", port, app_config->port_config.nb_queues);
	ret = rte_eth_dev_configure(port,
								app_config->port_config.nb_queues, app_config->port_config.nb_queues, &port_conf);
	if (ret < 0)
	{
		rte_exit(EXIT_FAILURE,
				 ":: cannot configure device: err=%d, port=%u\n",
				 ret, port);
	}

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;
	/* >8 End of ethernet port configured with default settings. */

	/* Configuring number of RX and TX queues connected to single port. 8< */
	for (i = 0; i < app_config->port_config.nb_queues; i++)
	{
		ret = rte_eth_rx_queue_setup(port, i, 512,
									 rte_eth_dev_socket_id(port),
									 &rxq_conf,
									 mbuf_pool);
		if (ret < 0)
		{
			rte_exit(EXIT_FAILURE,
					 ":: Rx queue setup failed: err=%d, port=%u\n",
					 ret, port);
		}
	}
	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.txmode.offloads;

	for (i = 0; i < app_config->port_config.nb_queues; i++)
	{
		ret = rte_eth_tx_queue_setup(port, i, 512,
									 rte_eth_dev_socket_id(port),
									 &txq_conf);
		if (ret < 0)
		{
			rte_exit(EXIT_FAILURE,
					 ":: Tx queue setup failed: err=%d, port=%u\n",
					 ret, port);
		}
	}
	/* >8 End of Configuring RX and TX queues connected to single port. */

	/* Setting the RX port to promiscuous mode. 8< */
	ret = rte_eth_promiscuous_enable(port);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
				 ":: promiscuous mode enable failed: err=%s, port=%u\n",
				 rte_strerror(-ret), port);
	/* >8 End of setting the RX port to promiscuous mode. */

	/* Starting the port. 8< */
	ret = rte_eth_dev_start(port);
	if (ret < 0)
	{
		rte_exit(EXIT_FAILURE,
				 "rte_eth_dev_start:err=%d, port=%u\n",
				 ret, port);
	}
	/* >8 End of starting the port. */

	assert_link_status(port);

	printf(":: initializing port: %d done\n", port);
	return 0;
}

static int
dpdk_ports_init(struct application_dpdk_config *app_config)
{
	int ret;
	uint8_t port_id;
	const uint8_t nb_ports = app_config->port_config.nb_ports;
	const uint32_t total_nb_mbufs = app_config->port_config.nb_queues * nb_ports * NUM_MBUFS;
	struct rte_mempool *mbuf_pool;
	struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
	/* Initialize mbufs mempool */
	mbuf_pool = allocate_mempool(total_nb_mbufs);
	ret = rte_flow_dynf_metadata_register();
	if (ret < 0)
		APP_EXIT("Metadata register failed");
	for (port_id = 0; port_id < nb_ports; port_id++)
	{	
		rte_eth_macaddr_get(port_id, &ports_eth_addr[port_id]);
		printf("Port %u, MAC address: " RTE_ETHER_ADDR_PRT_FMT "\n", port_id, RTE_ETHER_ADDR_BYTES(&ports_eth_addr[port_id]));
		if (port_init(mbuf_pool, port_id, app_config) != 0)
			APP_EXIT("Cannot init port %" PRIu8, port_id);
	}
	return ret;
}

static int
bind_hairpin_queues(uint16_t port_id)
{
	/* Configure the Rx and Tx hairpin queues for the selected port. */
	int ret = 0, peer_port, peer_ports_len;
	uint16_t peer_ports[RTE_MAX_ETHPORTS];

	/* bind current Tx to all peer Rx */
	peer_ports_len = rte_eth_hairpin_get_peer_ports(port_id, peer_ports, RTE_MAX_ETHPORTS, 1);
	if (peer_ports_len < 0)
		return peer_ports_len;
	for (peer_port = 0; peer_port < peer_ports_len; peer_port++)
	{
		ret = rte_eth_hairpin_bind(port_id, peer_ports[peer_port]);
		if (ret < 0)
			return ret;
	}
	/* bind all peer Tx to current Rx */
	peer_ports_len = rte_eth_hairpin_get_peer_ports(port_id, peer_ports, RTE_MAX_ETHPORTS, 0);
	if (peer_ports_len < 0)
		return peer_ports_len;
	for (peer_port = 0; peer_port < peer_ports_len; peer_port++)
	{
		ret = rte_eth_hairpin_bind(peer_ports[peer_port], port_id);
		if (ret < 0)
			return ret;
	}
	return ret;
}

/*
 * bind hairpin queues to all ports
 *
 * @nb_ports [in]: number of ports
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
enable_hairpin_queues(uint8_t nb_ports)
{
	uint16_t port_id;
	uint16_t n = 0;
	doca_error_t result;

	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		if (!rte_eth_dev_is_valid_port(port_id))
			/* the device ID  might not be contiguous */
			continue;
		result = bind_hairpin_queues(port_id);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Hairpin bind failed on port=%u", port_id);
			disable_hairpin_queues(port_id);
			return result;
		}
		if (++n >= nb_ports)
			break;
	}
	return DOCA_SUCCESS;
}
void dpdk_init(struct application_dpdk_config *app_dpdk_config)
{
	int ret = 0;

	/* Check that DPDK enabled the required ports to send/receive on */
	ret = rte_eth_dev_count_avail();
	if (app_dpdk_config->port_config.nb_ports > 0 && ret < app_dpdk_config->port_config.nb_ports)
	{
		APP_EXIT("Application will only function with %u ports, num_of_ports=%d", app_dpdk_config->port_config.nb_ports, ret);
	}

	/* Check for available logical cores */
	ret = rte_lcore_count();
	if (app_dpdk_config->port_config.nb_queues > 0 && ret < app_dpdk_config->port_config.nb_queues)
		APP_EXIT("At least %d cores are needed for the application to run, available_cores=%d", app_dpdk_config->port_config.nb_queues, ret);


	if (app_dpdk_config->reserve_main_thread)
		app_dpdk_config->port_config.nb_queues -= 1;

	if (app_dpdk_config->port_config.nb_ports > 0 && dpdk_ports_init(app_dpdk_config) != 0)
		APP_EXIT("Ports allocation failed");

	/* Enable hairpin queues */
	if (app_dpdk_config->port_config.nb_hairpin_q > 0)
		enable_hairpin_queues(app_dpdk_config->port_config.nb_ports);

	/*
	if (app_dpdk_config->sft_config.enable)
		dpdk_sft_init(app_dpdk_config);
	*/
}

void dpdk_fini(struct application_dpdk_config *app_dpdk_config)
{
	rte_eal_cleanup();
}
void print_header_info(const struct rte_mbuf *packet, const bool l2, const bool l3, const bool l4)
{
}


doca_error_t
dpdk_queues_and_ports_init(struct application_dpdk_config *app_dpdk_config)
{
	doca_error_t result;
	int ret = 0;

	/* Check that DPDK enabled the required ports to send/receive on */
	ret = rte_eth_dev_count_avail();
	if (app_dpdk_config->port_config.nb_ports > 0 && ret < app_dpdk_config->port_config.nb_ports) {
		DOCA_LOG_ERR("Application will only function with %u ports, num_of_ports=%d",
			 app_dpdk_config->port_config.nb_ports, ret);
		return DOCA_ERROR_DRIVER;
	}

	/* Check for available logical cores */
	ret = rte_lcore_count();
	if (app_dpdk_config->port_config.nb_queues > 0 && ret < app_dpdk_config->port_config.nb_queues) {
		DOCA_LOG_ERR("At least %u cores are needed for the application to run, available_cores=%d",
			 app_dpdk_config->port_config.nb_queues, ret);
		return DOCA_ERROR_DRIVER;
	}
	app_dpdk_config->port_config.nb_queues = ret;

	if (app_dpdk_config->reserve_main_thread)
		app_dpdk_config->port_config.nb_queues -= 1;
#ifdef GPU_SUPPORT
	/* Enable GPU device and initialization the resources */
	if (app_dpdk_config->pipe.gpu_support) {
		DOCA_LOG_DBG("Enabling GPU support");
		gpu_init(&app_dpdk_config->pipe);
	}
#endif

	result = dpdk_ports_init(app_dpdk_config);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Ports allocation failed");
		goto gpu_cleanup;
	}

	/* Enable hairpin queues */
	if (app_dpdk_config->port_config.nb_hairpin_q > 0) {
		result = enable_hairpin_queues(app_dpdk_config->port_config.nb_ports);
		if (result != DOCA_SUCCESS)
			goto ports_cleanup;
	}

	if (app_dpdk_config->sft_config.enable) {
		result = dpdk_sft_init(app_dpdk_config);
		if (result != DOCA_SUCCESS)
			goto hairpin_queues_cleanup;
	}

	return DOCA_SUCCESS;

hairpin_queues_cleanup:
	disable_hairpin_queues(RTE_MAX_ETHPORTS);
ports_cleanup:
	dpdk_ports_fini(app_dpdk_config, RTE_MAX_ETHPORTS);
#ifdef GPU_SUPPORT
	if (app_dpdk_config->pipe.gpu_support)
		dpdk_gpu_unmap(app_dpdk_config);
#endif
gpu_cleanup:
#ifdef GPU_SUPPORT
	if (app_dpdk_config->pipe.gpu_support)
		gpu_fini(&(app_dpdk_config->pipe));
#endif
	return result;
}
