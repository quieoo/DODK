#include "doca_flow.h"

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_flow.h>

#define MAX_PATTERN_NUM		10
#define MAX_ACTION_NUM		10

int
doca_flow_init(const struct doca_flow_cfg *cfg,
	       struct doca_flow_error *error)
{
	// printf("doca_flow_init\n"); // check
	return 0;
}

void
doca_flow_destroy(void){}

typedef struct _doca_flow_port_ 
{
  int port_id; 
}doca_flow_port;

doca_flow_port *ports[10];

struct doca_flow_port *
doca_flow_port_start(const struct doca_flow_port_cfg *cfg,
		     struct doca_flow_error *error)
{
	int id=atoi(cfg->devargs);

	doca_flow_port *port=malloc(sizeof(doca_flow_port));
	port->port_id=id;

	ports[id]=port;

	return port;
}

int
doca_flow_port_stop(struct doca_flow_port *port){}

int
doca_flow_port_pair(struct doca_flow_port *port, struct doca_flow_port *pair_port){}

uint8_t*
doca_flow_port_priv_data(struct doca_flow_port *port){}
int
doca_flow_shared_resource_cfg(enum doca_flow_shared_resource_type type, uint32_t id,
			      struct doca_flow_shared_resource_cfg *cfg,
			      struct doca_flow_error *error){}

int
doca_flow_shared_resources_bind(enum doca_flow_shared_resource_type type, uint32_t *res_array,
				uint32_t res_array_len, void *bindable_obj,
				struct doca_flow_error *error){}


typedef struct doca_flow_pipe{
	int port_id;
};

struct doca_flow_pipe *
doca_flow_create_pipe(const struct doca_flow_pipe_cfg *cfg,
		const struct doca_flow_fwd *fwd,
		const struct doca_flow_fwd *fwd_miss,
		struct doca_flow_error *error)
{
	struct doca_flow_pipe *pipe=malloc(sizeof(struct doca_flow_pipe));

	pipe->port_id=cfg->port;
	return pipe;
}

struct doca_flow_pipe_entry*
doca_flow_pipe_add_entry(uint16_t pipe_queue, 
struct doca_flow_pipe *pipe, 
const struct doca_flow_match *match, 
const struct doca_flow_actions *actions, 
const struct doca_flow_monitor *monitor, 
const struct doca_flow_fwd *fwd, 
uint32_t flags, 
void *usr_ctx, 
struct doca_flow_error *error){
	//dpdk need structures
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_ACTION_NUM];
	struct rte_flow *flow = NULL;
	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));
	memset(&attr, 0, sizeof(struct rte_flow_attr));

	attr.ingress=1;

	/*convert match->pattern*/
	//mac
	int p=0;
	pattern[p].type=RTE_FLOW_ITEM_TYPE_ETH;
	struct rte_flow_item_eth mac_spec;
	memset(&mac_spec,0,sizeof(struct rte_flow_item_eth));
	memcpy(mac_spec.hdr.dst_addr.addr_bytes, match->out_dst_mac,DOCA_ETHER_ADDR_LEN);
	memcpy(mac_spec.hdr.src_addr.addr_bytes, match->out_src_mac,DOCA_ETHER_ADDR_LEN);
	pattern[p++].spec=&mac_spec;
	
	//ip
	pattern[p].type=RTE_FLOW_ITEM_TYPE_IPV4;
	struct rte_flow_item_ipv4 ip_spec;
	memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
	ip_spec.hdr.src_addr=match->out_dst_ip.ipv4_addr;
	ip_spec.hdr.dst_addr=match->out_src_ip.ipv4_addr;
	pattern[p++].spec=&ip_spec;
	
	//TCP/UDP
	switch (match->out_l4_type)
	{
	case IPPROTO_UDP:
		pattern[p].type=RTE_FLOW_ITEM_TYPE_UDP;
		struct rte_flow_item_udp udp_spec;
		memset(&udp_spec,0,sizeof(struct rte_flow_item_udp));
		udp_spec.hdr.src_port=match->out_src_port;
		udp_spec.hdr.dst_port=match->out_dst_port;
		pattern[p++].spec=&udp_spec;
		break;
	
	default:
		printf("FLOW with L4 type: %d\n",match->out_l4_type);
		break;
	}
	pattern[p].type=RTE_FLOW_ITEM_TYPE_END;

	/*convert actions -> action*/
	// modify packets
	p=0;
	action[p].type=RTE_FLOW_ACTION_TYPE_SET_MAC_DST;
	struct rte_flow_action_set_mac dst_mac;
	for(int i=0;i<6;i++){
		dst_mac.mac_addr[i]=actions->mod_dst_mac[i];
	}
	action[p++].conf=&dst_mac;

	action[p].type=RTE_FLOW_ACTION_TYPE_SET_IPV4_DST;
	struct rte_flow_action_set_ipv4 set_ipv4;
	set_ipv4.ipv4_addr=actions->mod_dst_ip.ipv4_addr;
	action[p++].conf=&set_ipv4;

	action[p].type=RTE_FLOW_ACTION_TYPE_SET_TP_DST;
	struct rte_flow_action_set_tp set_tp;
	set_tp.port=actions->mod_dst_port;
	action[p++].conf=&set_tp;

	// forward actions
	switch (fwd->type)
	{
	case 1:
		//DOCA_FLOW_FWD_RSS
		action[p].type=RTE_FLOW_ACTION_TYPE_RSS;
		struct rte_flow_action_rss _rss;
		_rss.queue_num=fwd->num_of_queues;
		_rss.queue=fwd->rss_queues;
		action[p++].conf=&_rss;
		break;
	case 2:
		//DOCA_FLOW_FWD_PORT
		action[p].type=RTE_FLOW_ACTION_TYPE_PORT_ID;
		struct rte_flow_action_port_id _pid;
		_pid.id=fwd->port_id;
		action[p++].conf=&_pid;
		break;
	case 3:
		//DOCA_FLOW_FWD_PIPE
		printf("DOCA FWD PIPE\n");
		break;
	case 4:
		//DOCA_FLOW_FWD_DROP
		action[p++].type=RTE_FLOW_ACTION_TYPE_DROP;
		break;
	default:
		printf("DOCA FWD OTHER TYPE: %d\n",fwd->type);
		break;
	}

	struct rte_flow_action_queue queue = { .index = pipe_queue };
	action[p].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[p++].conf = &queue;


	action[p].type=RTE_FLOW_ACTION_TYPE_END;

	

	//get port id
	int port_id=pipe->port_id;
	
	//validate and create entry
	struct rte_flow_error rte_error;
	int res=rte_flow_validate(port_id, &attr,pattern,action,&rte_error);
	if(!res){
		flow = rte_flow_create(port_id, &attr, pattern, action, &rte_error);
		if (!flow) {
			printf("Flow can't be created %d message: %s\n",
				rte_error.type,
				rte_error.message ? rte_error.message : "(no stated reason)");
			rte_exit(EXIT_FAILURE, "error in creating flow");
		}
		//output_flow(port_id, &attr, pattern, action, &error);
	}else{
		printf("ERROR while validate flow: %d\n",res);
		printf("%s\n",rte_error.message);
	}

}

struct doca_flow_pipe_entry*
doca_flow_control_pipe_add_entry(uint16_t pipe_queue,
			uint8_t priority,
			struct doca_flow_pipe *pipe,
			const struct doca_flow_match *match,
			const struct doca_flow_match *match_mask,
			const struct doca_flow_fwd *fwd,
			struct doca_flow_error *error){}

int
doca_flow_pipe_rm_entry(uint16_t pipe_queue, void *usr_ctx,
			struct doca_flow_pipe_entry *entry){}

void
doca_flow_destroy_pipe(uint16_t port_id,
		       struct doca_flow_pipe *pipe){}


void
doca_flow_port_pipes_flush(uint16_t port_id){}

void
doca_flow_destroy_port(uint16_t port_id)
{
	printf("doca_flow_destroy_port\n");
	int ports_num=sizeof(ports)/sizeof(doca_flow_port*);
	for(int i=0;i<ports_num;i++){
		printf("%d\n",i);
		printf("free %d\n",ports[i]->port_id);
		free(ports[i]);
	}
}

void
doca_flow_port_pipes_dump(uint16_t port_id, FILE *f){}

int
doca_flow_query(struct doca_flow_pipe_entry *entry,
		struct doca_flow_query *query_stats){}

int
doca_flow_handle_aging(struct doca_flow_port *port, uint16_t queue,
			uint64_t quota, struct doca_flow_aged_query *entries, int len){}

int
doca_flow_entries_process(struct doca_flow_port *port,
		uint16_t pipe_queue, uint64_t timeout,
		uint32_t max_processed_entries){}

enum doca_flow_entry_status
doca_flow_entry_get_status(struct doca_flow_pipe_entry *entry){}
