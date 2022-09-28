/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2017 Mellanox Technologies, Ltd
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>


#include <rte_eal.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_flow.h>
#include <rte_cycles.h>

#include <soft_flow.h>

static volatile bool force_quit;

static int port_num=4;
static uint16_t nr_queues = 1;
static uint8_t selected_queue = 1;
struct rte_mempool *mbuf_pool;
struct rte_flow *flow;
#define RTE_MAX_ETHPORTS 32
static const char *MBUF_POOL="MBUF_POOL";

static inline void
print_ether_addr(const char *what, struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", what, buf);
}

void get_and_print_eth(struct rte_mbuf *m){
	struct rte_ether_hdr *eth_hdr;
	eth_hdr = rte_pktmbuf_mtod(m,
	struct rte_ether_hdr *);
	print_ether_addr("ETH src:",&eth_hdr->src_addr);
	print_ether_addr(" , dst:",&eth_hdr->dst_addr);
	printf("\n");
}

void get_and_print_ip4(struct rte_mbuf *m){
	/* Remove the Ethernet header and trailer from the input packet */
	rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ether_hdr));

	struct rte_ipv4_hdr *ip_hdr;
	/* Read the lookup key (i.e. ip_dst) from the input packet */
	ip_hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
	
	struct in_addr mask_dst, mask_src;
	mask_dst.s_addr = ip_hdr->dst_addr;
	mask_src.s_addr = ip_hdr->src_addr;

	printf("IPv4 src: %s, dst: %s\n", inet_ntoa(mask_src), inet_ntoa(mask_dst));

}

bool hit_flow(struct rte_mbuf *m){
	return false;
}

void process_flow(struct rte_mbuf *m){

}

/* Main_loop for flow filtering. 8< */
static int
main_loop(void)
{
	struct rte_mbuf *mbufs[32];
	struct rte_ether_hdr *eth_hdr;
	struct rte_flow_error error;
	uint16_t nb_rx;
	uint16_t i;
	uint16_t j;
	int ret;
	static struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
	struct rte_ether_addr *mac_addr;
	int count=0;

	for(int port_id=0;port_id<port_num;port_id++){
		rte_eth_macaddr_get(port_id, &ports_eth_addr[port_id]);
		printf("Port %u, MAC address: " RTE_ETHER_ADDR_PRT_FMT "\n", port_id, RTE_ETHER_ADDR_BYTES(&ports_eth_addr[port_id]));
	}

	int pkt_count[4]={0};
	clock_t last_time[4];
	for(int i=0;i<4;i++){
		last_time[i]=clock();
	} 
	int interval=100;

	while (!force_quit) {
		// pair port
		// receive from p2, if flow hit, sent from p3
		//				  , else sent to p0
		// receive from p3, if flow hit, sent from p32
		//				  , else sent to p1
		for(int port_id=0;port_id<4;port_id++){
			for(int i=0; i<nr_queues; i++){
				nb_rx=rte_eth_rx_burst(port_id, i, mbufs, 32);
				if(nb_rx){
					pkt_count[port_id]+=nb_rx;
					if(pkt_count[port_id] % interval == 0){
						clock_t now =clock();
						printf("port-%d queue-%d: %f s/%dpkts \n", port_id, i,((double)(now - last_time[port_id]))/CLOCKS_PER_SEC, interval);
						last_time[port_id]=now;
					}
					for(int j=0; j<nb_rx; j++){
						rte_pktmbuf_free(mbufs[j]);
					}
					/*
					for(int j=0;j<nb_rx;j++){
						struct rte_mbuf *m = mbufs[j];
						if(hit_flow(m)){
							process_flow(m);
						}else{
							// printf("redirect packet to %d\n", port_id-2);
							rte_eth_tx_burst(port_id-2, i, &m, 1);
						}
					}*/
				}
			}
		}
	}
	/* >8 End of reading the packets from all queues. */

	/* closing and releasing resources */
	for(int port_id=0; port_id++;port_id<port_num){
		rte_flow_flush(port_id, &error);
		ret = rte_eth_dev_stop(port_id);
		if (ret < 0)
			printf("Failed to stop port %u: %s",
				port_id, rte_strerror(-ret));
		rte_eth_dev_close(port_id);
	}

	return ret;
}
/* >8 End of main_loop for flow filtering. */

#define CHECK_INTERVAL 1000  /* 100ms */
#define MAX_REPEAT_TIMES 90  /* 9s (90 * 100ms) in total */

static void
assert_link_status(int port_id)
{
	struct rte_eth_link link;
	uint8_t rep_cnt = MAX_REPEAT_TIMES;
	int link_get_err = -EINVAL;

	memset(&link, 0, sizeof(link));
	do {
		link_get_err = rte_eth_link_get(port_id, &link);
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

/* Port initialization used in flow filtering. 8< */
static void
init_port(int port_id)
{
	int ret;
	uint16_t i;
	/* Ethernet port configured with default settings. 8< */
	struct rte_eth_conf port_conf = {
		.rxmode = {
			.split_hdr_size = 0,
		},
		.txmode = {
			.offloads =
				RTE_ETH_TX_OFFLOAD_VLAN_INSERT |
				RTE_ETH_TX_OFFLOAD_IPV4_CKSUM  |
				RTE_ETH_TX_OFFLOAD_UDP_CKSUM   |
				RTE_ETH_TX_OFFLOAD_TCP_CKSUM   |
				RTE_ETH_TX_OFFLOAD_SCTP_CKSUM  |
				RTE_ETH_TX_OFFLOAD_TCP_TSO,
		},
	};
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_dev_info dev_info;

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
			"Error during getting device (port %u) info: %s\n",
			port_id, strerror(-ret));

	port_conf.txmode.offloads &= dev_info.tx_offload_capa;
	printf(":: initializing port: %d\n", port_id);
	ret = rte_eth_dev_configure(port_id,
				nr_queues, nr_queues, &port_conf);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			":: cannot configure device: err=%d, port=%u\n",
			ret, port_id);
	}

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;
	/* >8 End of ethernet port configured with default settings. */

	/* Configuring number of RX and TX queues connected to single port. 8< */
	for (i = 0; i < nr_queues; i++) {
		ret = rte_eth_rx_queue_setup(port_id, i, 512,
				     rte_eth_dev_socket_id(port_id),
				     &rxq_conf,
				     mbuf_pool);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				":: Rx queue setup failed: err=%d, port=%u\n",
				ret, port_id);
		}
	}

	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.txmode.offloads;

	for (i = 0; i < nr_queues; i++) {
		ret = rte_eth_tx_queue_setup(port_id, i, 512,
				rte_eth_dev_socket_id(port_id),
				&txq_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				":: Tx queue setup failed: err=%d, port=%u\n",
				ret, port_id);
		}
	}
	/* >8 End of Configuring RX and TX queues connected to single port. */

	ret = rte_eth_promiscuous_disable(port_id);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
			":: promiscuous mode enable failed: err=%s, port=%u\n",
			rte_strerror(-ret), port_id);
	

	/* Starting the port. 8< */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			"rte_eth_dev_start:err=%d, port=%u\n",
			ret, port_id);
	}
	/* >8 End of starting the port. */

	assert_link_status(port_id);

	printf(":: initializing port: %d done\n", port_id);
}
/* >8 End of Port initialization used in flow filtering. */

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

int
main(int argc, char **argv)
{
	int ret;
	uint16_t nr_ports;
	struct rte_flow_error error;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, ":: invalid EAL arguments\n");

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	nr_ports = rte_eth_dev_count_avail();
	if (nr_ports == 0)
		rte_exit(EXIT_FAILURE, ":: no Ethernet ports found\n");
	if (nr_ports < port_num) {
		rte_exit(EXIT_FAILURE, ":: %d ports need, but only %d port detected\n", port_num, nr_ports);
	}
	
	enum rte_proc_type_t proc_type = rte_eal_process_type();
	proc_type = rte_eal_process_type();
	mbuf_pool= (proc_type==RTE_PROC_SECONDARY) ? 
				rte_mempool_lookup(MBUF_POOL) :
				rte_pktmbuf_pool_create("mbuf_pool", 4096, 128, 0,
					    RTE_MBUF_DEFAULT_BUF_SIZE,
					    rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");


	// assuming the primary process has initialized port 0-1
	// initialize port 2-3
	if(proc_type==RTE_PROC_SECONDARY){
		for(int i=2;i<port_num;i++)
			init_port(i);
	}else{
		for(int i=0;i<port_num;i++)
			init_port(i);
	}


	ret = main_loop();
	rte_eal_cleanup();

	return ret;
}
