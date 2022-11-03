/*
 * Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
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

#include <stdint.h>
#include <signal.h>

#include <rte_cycles.h>
#include <rte_launch.h>
#include <rte_ethdev.h>

#include <doca_argp.h>
#include <doca_log.h>

#include <dpdk_utils.h>
#include <utils.h>

#include "simple_fwd.h"
#include "simple_fwd_port.h"
#include "simple_fwd_vnf_core.h"

#include "SimpleFlow.grpc.pb.h"
#include "SimpleFlow.pb.h"
#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>
using namespace grpc;
using namespace simple_flow_offload;
using namespace std;

#include <condition_variable>
#include <doca_flow.h>
#include <iostream>
#include <string>
#include <cstdlib>
#include <iterator>
#include <regex>

DOCA_LOG_REGISTER(SIMPLE_FWD_VNF);

#define DEFAULT_NB_METERS (1 << 13)
#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

/* Boolean for ending the server */
static std::condition_variable server_lock;
static void server_teardown()
{
	server_lock.notify_one();
}


static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		DOCA_LOG_INFO("Signal %d received, preparing to exit...", signum);
		server_teardown();
		simple_fwd_process_pkts_stop();
	}
}

std::vector<std::string> s_split(const std::string& in, const std::string& delim) {
    std::regex re{ delim };
    // 调用 std::vector::vector (InputIterator first, InputIterator last,const allocator_type& alloc = allocator_type())
    // 构造函数,完成字符串分割
    return std::vector<std::string> {
        std::sregex_token_iterator(in.begin(), in.end(), re, -1),
            std::sregex_token_iterator()
    };
}

void str_mac(string str, uint8_t* mac){
	vector<string> t=s_split(str, ":");
	if(t.size() < 6)
		return;
	for(int i=0;i<6;i++){
		uint8_t sum=0;
		if(t[i][0]>='a') sum+=t[i][0]-'a'+10;
		else sum+=t[i][0]-'0';

		sum<<4;

		if(t[i][1]>='a') sum+=t[i][1]-'a'+10;
		else sum+=t[i][1]-'0';

		mac[i]=sum;
	}
}

uint32_t str_ip(string str){
	vector<string> t=s_split(str, ":");
	if(t.size() < 4)
		return 0;
	uint32_t re=0;
	for(int i=0; i<4; i++){
		re<<8;
		re+=atoi(t[i].c_str());
	}

	return re;
}

uint16_t str_port(string str){
	uint16_t re=atoi(str.c_str());
	return re;
}

class SimpleFlowOffloadImpl final : public SimpleFlowOffload::Service{
	public:
		explicit SimpleFlowOffloadImpl(struct simple_fwd_process_pkts_params* param){
			handler=param;
		}
	Status CreateFlow(ServerContext* context, const FlowRule* rule, Reply* rep) override {
		cout<<"creating flow rule: "<<rule->match()<<"; "<<rule->action()<<"; "<<rule->fwd()<<endl;
		struct doca_flow_match match={0};
		struct doca_flow_actions act={0};
		struct doca_flow_fwd fwd;
		struct doca_flow_error error;

		vector<string> match_entry=s_split(rule->match(), ",");
		for(int i=0;i<match_entry.size();i++){
			vector<string> m=s_split(match_entry[i], "=");
			if(m[0]=="dst_mac")
				str_mac(m[1], match.out_dst_mac);
			else if(m[0]=="src_mac")
				str_mac(m[1], match.out_src_mac);
			else if(m[0]=="dst_ip")
				match.out_dst_ip.ipv4_addr=str_ip(m[1]);
			else if(m[0]=="src_ip")
				match.out_src_ip.ipv4_addr=str_ip(m[1]);
			else if(m[0]=="l4_type"){
				if(m[1]=="tcp") match.out_l4_type=IPPROTO_TCP;
				else if(m[1]=="udp") match.out_l4_type=IPPROTO_UDP;
			}
			else if(m[0]=="dst_port")
				match.out_dst_port=str_port(m[1]);
			else if(m[0]=="src_port")
				match.out_src_port=str_port(m[1]);
		}

		vector<string> action_entry=s_split(rule->action(), ",");
		for(int i=0; i<action_entry.size(); i++){
			vector<string> m=s_split(action_entry[i], "=");
			if(m[0]=="mod_dst_mac")
				str_mac(m[1], act.mod_dst_mac);
			else if(m[0]=="mod_src_mac")
				str_mac(m[1], act.mod_src_mac);
			else if(m[0]=="mod_dst_ip")
				act.mod_dst_ip.ipv4_addr=str_ip(m[1]);
			else if(m[0]=="mod_src_mac")
				act.mod_src_ip.ipv4_addr=str_ip(m[1]);
			else if(m[0]=="mod_dst_port")
				act.mod_dst_port=str_port(m[1]);
			else if(m[0]=="mod_src_port")
				act.mod_src_port=str_port(m[1]);
		}

		vector<string> m=s_split(rule->fwd(), "=");
		if(m[0]=="fwd_port"){
			 fwd.type=DOCA_FLOW_FWD_PORT;
			 fwd.port_id=atoi(m[1].c_str());
		}
		else if(m[0]=="fwd_drop"){
			fwd.type=DOCA_FLOW_FWD_DROP;
		}
		if(manully_add_entry(&match, &act, &fwd, &error)){

			Status s(StatusCode::ABORTED, string(error.message));
			return s;
		}
		return Status::OK;
	}
	private:
		struct simple_fwd_process_pkts_params* handler;
};

int run_grpc_server(void *process_pkts_params){
	struct simple_fwd_config *app_config = ((struct simple_fwd_process_pkts_params *) process_pkts_params)->cfg;
	string server_address("0.0.0.0:"+to_string(app_config->grpc_port));
    SimpleFlowOffloadImpl service((struct simple_fwd_process_pkts_params *)process_pkts_params);

    EnableDefaultHealthCheckService(true);

    ServerBuilder builder;
    builder.AddListeningPort(server_address, InsecureServerCredentials());
    builder.RegisterService(&service);
	
    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "Server listening on " << server_address << std::endl;
	
	/* Wait for the Destroy command */
	std::mutex mutex;
	std::unique_lock<std::mutex> lock(mutex);
	server_lock.wait(lock);
	/* Officially shut down the server */
	server->Shutdown();

	return 0;
}

int
main(int argc, char **argv)
{
	uint16_t port_id;
	struct simple_fwd_port_cfg port_cfg = {0};
	struct application_dpdk_config dpdk_config;
	dpdk_config.port_config.nb_ports=2;
	dpdk_config.port_config.nb_queues = 1;
	dpdk_config.port_config.nb_hairpin_q = 0;
	dpdk_config.sft_config = {0};
	dpdk_config.reserve_main_thread = true;

	struct simple_fwd_config app_cfg = {
		.dpdk_cfg = &dpdk_config,
		.rx_only = 0,
		.hw_offload = 1,
		.stats_timer = 10000000000,
		.age_thread = false,
		.grpc_port=50051
	};
	struct app_vnf *vnf;
	struct simple_fwd_process_pkts_params process_pkts_params = {.cfg = &app_cfg};

	/* init and start parsing */
	struct doca_argp_program_general_config *doca_general_config;
	struct doca_argp_program_type_config type_config = {
		.is_dpdk = true,
		.is_grpc = false,
	};

	/* Parse cmdline/json arguments */
	doca_argp_init("simple_forward_vnf", &type_config, &app_cfg);
	register_simple_fwd_params();
	doca_argp_start(argc, argv, &doca_general_config);

	doca_log_create_syslog_backend("doca_core");
	
	/* update queues and ports */
	dpdk_init(&dpdk_config);

	printf("finish dpdk initialize\n");
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* convert to number of cycles */
	// app_cfg.stats_timer *= rte_get_timer_hz();

	vnf = simple_fwd_get_vnf();
	port_cfg.nb_queues = dpdk_config.port_config.nb_queues;
	port_cfg.is_hairpin = !!dpdk_config.port_config.nb_hairpin_q;
	port_cfg.nb_meters = DEFAULT_NB_METERS;
	port_cfg.nb_counters = (1 << 13);
	if (vnf->vnf_init(&port_cfg) != 0) {
		DOCA_LOG_ERR("vnf application init error");
		goto exit_app;
	}

	rte_eal_remote_launch(run_grpc_server, &process_pkts_params, 3);

	simple_fwd_map_queue(dpdk_config.port_config.nb_queues);
	process_pkts_params.vnf = vnf;
	rte_eal_mp_remote_launch(simple_fwd_process_pkts, &process_pkts_params, CALL_MAIN);

	// printf("--------------------remote launched\n");	
	rte_eal_mp_wait_lcore();
	RTE_ETH_FOREACH_DEV(port_id)
		doca_flow_destroy_port(port_id);

exit_app:
	/* cleanup app resources */
	simple_fwd_destroy(vnf);

	/* cleanup resources */
	dpdk_fini(&dpdk_config);

	/* ARGP cleanup */
	doca_argp_destroy();

	return 0;
}
