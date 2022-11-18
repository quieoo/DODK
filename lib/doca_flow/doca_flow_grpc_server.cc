#include "flow_grpc.grpc.pb.h"
#include "flow_grpc.pb.h"
#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include "doca_flow.h"
#include "offload_rules.h"

#include <stdint.h>
#include <signal.h>
#include <condition_variable>
#include <regex>
#include "doca_flow_grpc_client.h"

using namespace grpc;
using namespace flow_grpc;
using namespace std;


#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

static volatile bool force_quit;
static std::condition_variable server_lock;

DOCA_LOG_REGISTER(FIREWALL);
#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

struct doca_flow_pipe *pipe_list[1000];
static int pipe_index = 0;

typedef struct doca_flow_pipe
{
	// int port_id;
	struct doca_flow_pipe_cfg *cfg;
	uint32_t group_id;
	struct doca_flow_fwd *fwd;
	struct doca_flow_fwd *fwd_miss;
	uint64_t pipe_id;
};

std::vector<std::string> stringSplit(const std::string& str, char delim) {
    std::stringstream ss(str);
    std::string item;
    std::vector<std::string> elems;
    while (std::getline(ss, item, delim)) {
        if (!item.empty()) {
            elems.push_back(item);
        }
    }
    return elems;
}

int str_to_fwd(struct doca_flow_fwd *fwd, string str){
    //printf("    fwd_str: %s\n", str.c_str());
    vector<string> vec=stringSplit(str, ' ');
    if(vec[0]=="null")
        return 1;
    fwd->next_pipe->pipe_id=stoll(vec[0]);
    fwd->type=(enum struct doca_flow_fwd_type)stoll(vec[1]);
    fwd->port_id=stoll(vec[2]);
    return 0;
}

int str_to_match(struct doca_flow_match *match, string str){
    vector<string> vec=stringSplit(str, ' ');
    for(int i=0;i<6;i++)
        match->out_dst_mac[i]=stoll(vec[i]);
    for(int i=0; i<6; i++)
        match->out_src_mac[i]=stoll(vec[i+6]);
    match->out_dst_ip.ipv4_addr=stoll(vec[12]);
    match->out_src_ip.ipv4_addr=stoll(vec[13]);
    match->out_l4_type=stoll(vec[14]);
    match->out_dst_port=stoll(vec[15]);
    match->out_src_port=stoll(vec[16]);
}

int str_to_action(struct doca_flow_actions *action, string str){
    vector<string> vec=stringSplit(str, ' ');
    for(int i=0;i<6;i++)
        action->mod_dst_mac[i]=stoll(vec[i]);
    for(int i=0; i<6; i++)
        action->mod_src_mac[i]=stoll(vec[i+6]);
    action->mod_dst_ip.ipv4_addr=stoll(vec[12]);
    action->mod_src_ip.ipv4_addr=stoll(vec[13]);
    action->mod_dst_port=stoll(vec[14]);
    action->mod_src_port=stoll(vec[15]);
}


static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("Signal %d received, preparing to exit...", signum);
		force_quit=true;
        server_lock.notify_one();
        doca_flow_destroy();
        rte_eal_cleanup();
	}
}

struct lcore_config{
    uint16_t port;
    int num_queue;
};

int lcore_main(void *config){
    struct lcore_config *l_config=(struct lcore_config *)config;

    uint16_t nb_rx;
    struct rte_mbuf *mbufs[32];
    int core_id=rte_lcore_id();
    printf("Begin loop on core %d for port %d\n", core_id, l_config->port);
    while(!force_quit){
        for(int queue_id=0; queue_id<l_config->num_queue; queue_id++){
            nb_rx=rte_eth_rx_burst(l_config->port, queue_id, mbufs, 32);
            if(nb_rx==0)    continue;
            for(int i=0; i<nb_rx;i++){
                rte_pktmbuf_free(mbufs[i]);
            }
        }
    }
    return 0;
}

class FlowGRPCImpl final:public FlowGRPC::Service{
    public:
    explicit FlowGRPCImpl(int _argc, char **_argv){
        argc=_argc;
        argv=_argv;
    }
    Status EnvInitialize(ServerContext* context, const DPDKConfig *dpdk_config, Response *rep);
    Status GRPCInitialize(ServerContext* context, const GRPCConfig *grpc_config, Response *rep);
    Status PortStart(ServerContext *context, const FlowPortConfig *port_config, Response *rep);
    Status PortPair(ServerContext *context, const PortPairRequest *pair_config, Response *rep);
    Status EnvDestroy(ServerContext *context, const EnvDestroyRequest *destory, Response *rep);
    Status CreatePipe(ServerContext *context, const CreatePipeRequest *pipe_config, Response *rep);
    Status AddEntry(ServerContext *context, const AddEntryRequest *entry_config, Response *rep);
    private:
    struct application_dpdk_config app_dpdk_config;
    int argc;
    char **argv;
    struct rte_mempool *mbuf_pool;
    int pid=-1;
};

Status FlowGRPCImpl::EnvInitialize(ServerContext *context, const DPDKConfig *dpdk_config, Response *rep)
{
    printf("Initialize environment...\n");
    char str[100];
    
    int ret=rte_eal_init(argc, argv);
    if(ret<0){
        sprintf(str, "Failed initialize eal environment, invalid arguments\n");
        printf(str);
        return Status(StatusCode::ABORTED, string(str));
    }


    ret=rte_eth_dev_count_avail();
    int demand_ports=dpdk_config->app_port_config().nb_ports();
    if(demand_ports > 0 && demand_ports > ret){
        sprintf(str, "Error: Application only function with %u ports, num_of_ports=%d\n", demand_ports, ret);
        printf(str);
        return Status(StatusCode::ABORTED, string(str));
    }

    ret=rte_lcore_count();
    int demand_cores=dpdk_config->app_port_config().nb_queues()+1;
    if(demand_cores > 0 && demand_cores > ret){
        sprintf(str, "At least %d cores are needed for the application to run, available_cores=%d", demand_cores, ret);
        printf(str);
        return Status(StatusCode::ABORTED, string(str));
    }

    app_dpdk_config.port_config.nb_hairpin_q=dpdk_config->app_port_config().nb_hairpin_q();
    app_dpdk_config.port_config.nb_ports=dpdk_config->app_port_config().nb_ports();
    app_dpdk_config.port_config.nb_queues=dpdk_config->app_port_config().nb_queues();
    app_dpdk_config.reserve_main_thread=dpdk_config->reserve_main_thread();

    if(dpdk_config->reserve_main_thread()){
        app_dpdk_config.port_config.nb_queues -= 1;    
    }


    mbuf_pool=rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * app_dpdk_config.port_config.nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if(mbuf_pool == NULL){
        sprintf(str, "Failed to create mbuf pool\n");
        printf(str);
        return Status(StatusCode::ABORTED, string(str));
    }


    
    return Status::OK;
}

Status FlowGRPCImpl::GRPCInitialize(ServerContext *context, const GRPCConfig *grpc_config, Response *rep){
    printf("Initialize grpc...\n");
    return Status::OK;
}

Status FlowGRPCImpl::PortStart(ServerContext *context, const FlowPortConfig *port_config, Response *rep){
    uint16_t port = port_config->port_id();
    printf("starting port %d...\n", port);
    
    struct rte_eth_conf port_conf;
	const uint16_t rx_rings = app_dpdk_config.port_config.nb_queues, tx_rings = app_dpdk_config.port_config.nb_queues;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

    char str[100];
    if(!rte_eth_dev_is_valid_port(port)){
        sprintf(str, "Not a valid port: %d\n", port);
        printf(str);
        return Status(StatusCode::ABORTED, string(str));
    }

    memset(&port_conf, 0, sizeof(struct rte_eth_conf));
    retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		sprintf(str, "Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
        printf(str);
        return Status(StatusCode::ABORTED, string(str));
	}

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0){
        sprintf(str, "Failed to configure dev: %d, %s\n", port, strerror(-retval));
        printf(str);
        return Status(StatusCode::ABORTED, string(str));
    }

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0){
        sprintf(str, "Failed to adjust nb rx tx desc: %d, %s\n", port, strerror(-retval));
        printf(str);
        return Status(StatusCode::ABORTED, string(str));
    }

    for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0){
            sprintf(str, "Failed to setup rx queue: %d, %s\n", port, strerror(-retval));
            printf(str);
            return Status(StatusCode::ABORTED, string(str));
        }
	}

    txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;

    for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0){
            sprintf(str, "Failed to setup tx queue: %d, %s\n", port, strerror(-retval));
            printf(str);
            return Status(StatusCode::ABORTED, string(str));
        }
	}

    retval = rte_eth_dev_start(port);
    if (retval < 0){
        sprintf(str, "Failed to start port: %d, %s\n", port, strerror(-retval));
        printf(str);
        return Status(StatusCode::ABORTED, string(str));
    }

    struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0){
        sprintf(str, "Failed to get mac address: %d, %s\n", port, strerror(-retval));
        printf(str);
        return Status(StatusCode::ABORTED, string(str));
    }
	printf("ports[%u], MAC address: " RTE_ETHER_ADDR_PRT_FMT "\n", port, RTE_ETHER_ADDR_BYTES(&addr));

    return Status::OK;
}

Status FlowGRPCImpl::PortPair(ServerContext *context, const PortPairRequest *pair_config, Response *rep){
    if(is_soft_flow_enabled()){
        for(int port=0; port<app_dpdk_config.port_config.nb_ports; port++){        
            printf("soft flow enabled, start cpu loop on port...\n");
            struct lcore_config config;
            config.port=port;
            config.num_queue=app_dpdk_config.port_config.nb_queues;

            rte_eal_remote_launch(lcore_main, &config, port+1);   // launch processing of port i on core i+1, while grpc server runs on core 0}
        }
    }
}

Status FlowGRPCImpl::EnvDestroy(ServerContext *context, const EnvDestroyRequest *destory, Response *rep){
    printf("cleaning envirionment...\n");
    if(is_soft_flow_enabled()){
        force_quit=true;
    }
    for(int port=0; port<app_dpdk_config.port_config.nb_ports; port++)
        doca_flow_destroy_port(port);
    // doca_flow_destroy();

    // rte_eal_cleanup();
    return Status::OK;
}

Status FlowGRPCImpl::CreatePipe(ServerContext *context, const CreatePipeRequest *pipe_config, Response *rep){
    
    struct doca_flow_pipe_cfg pipe_cfg;
    struct doca_flow_fwd fwd;
    struct doca_flow_fwd fwd_miss;
    struct doca_flow_pipe fwd_next_pipe;
    struct doca_flow_pipe fwd_miss_next_pipe;
    fwd.next_pipe=&fwd_next_pipe;
    fwd_miss.next_pipe=&fwd_miss_next_pipe;

    struct doca_flow_fwd *fwd_p=NULL;
    struct doca_flow_fwd *fwd_miss_p=NULL;
    struct doca_flow_error err;
    struct doca_flow_match match;
    struct doca_flow_actions action;
    struct doca_flow_pipe *pipe;

    int j=0;
    str_to_match(&match, pipe_config->pipe_config().match().match_rule());
    str_to_action(&action, pipe_config->pipe_config().action().action_rule());
    pipe_cfg.match=&match;
    pipe_cfg.actions=&action;
    pipe_cfg.name=pipe_config->pipe_config().name().c_str();
    pipe_cfg.is_root=pipe_config->pipe_config().is_root();

    if(str_to_fwd(&fwd, pipe_config->fwd().fwd_rule())==0)
        fwd_p=&fwd;
    if(str_to_fwd(&fwd_miss, pipe_config->fwd_miss().fwd_rule())==0)
        fwd_miss_p=&fwd_miss;

    pipe=doca_flow_create_pipe(&pipe_cfg,fwd_p, fwd_miss_p, &err);
    pipe_list[pipe_index++]=pipe;
    if(pipe){
        rep->set_pipe_id(pipe->pipe_id);
        return Status::OK; 
    }else{
        return Status(StatusCode::ABORTED, "Create pipe failed");
    }
}

Status FlowGRPCImpl::AddEntry(ServerContext *context, const AddEntryRequest *entry_config, Response *rep){
    struct doca_flow_match match;
    struct doca_flow_actions action;
    struct doca_flow_fwd fwd;
    struct doca_flow_fwd *fwd_p=NULL;
    struct doca_flow_error err;
    struct doca_flow_pipe *pipe;
    uint64_t pipe_id=entry_config->pipe_id();
    if(pipe_id >= pipe_index){
        printf("error pipe_id: %d, max pipe_id: %d\n", pipe_index-1);
        return Status(StatusCode::ABORTED, "error pipe_id");
    }
    pipe=pipe_list[pipe_id];
    str_to_match(&match, entry_config->match().match_rule());
    str_to_action(&action, entry_config->action().action_rule());
    if(str_to_fwd(&fwd, entry_config->fwd().fwd_rule())==0)
        fwd_p=&fwd;
    struct doca_flow_pipe_entry *entry=doca_flow_pipe_add_entry(0, pipe,&match, &action,NULL, fwd_p, 0, NULL, &err);
    if(!entry){
        return Status(StatusCode::ABORTED, "failed to add entry: "+string(err.message));
    }
    return Status::OK;
}



int main(int argc, char **argv){
    doca_log_global_level_set(4);
    signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

    string server_address("0.0.0.0:50050");
    FlowGRPCImpl service(argc, argv);
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
}