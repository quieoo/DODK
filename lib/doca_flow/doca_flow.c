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
#include <soft_flow.h>

#define MAX_PATTERN_NUM 10
#define MAX_ACTION_NUM 10
DOCA_LOG_REGISTER(DOCA_FLOW);

const uint8_t mac0[6] = {0};
const uint32_t ip0 = 0;
const uint16_t port0 = 0;
int doca_flow_init(const struct doca_flow_cfg *cfg,
				   struct doca_flow_error *error)
{
	// printf("doca_flow_init\n"); // check
	return 0;
}

#define MAX_PIPE_NUM 1000
typedef struct doca_flow_port
{
	uint16_t port_id;
};
typedef struct doca_flow_pipe
{
	// int port_id;
	struct doca_flow_pipe_cfg *cfg;
	uint32_t group_id;
	struct doca_flow_fwd *fwd;
	struct doca_flow_fwd *fwd_miss;
};
struct doca_flow_pipe *pipes[MAX_PIPE_NUM];
static int p_pipe = 0;
static int GROUP = 0;
struct doca_flow_port ports[10];

struct doca_flow_port *
doca_flow_port_start(const struct doca_flow_port_cfg *cfg,
					 struct doca_flow_error *error)
{
	int id = atoi(cfg->devargs);

	struct doca_flow_port *port = malloc(sizeof(struct doca_flow_port));
	port->port_id = id;

	ports[id] = *port;
	return port;
}
void doca_flow_destroy(void)
{
	DOCA_LOG_INFO("DESTROY PIPES: ");
	for (int i = 0; i < p_pipe; i++)
	{
		struct doca_flow_pipe *p = pipes[i];
		DOCA_LOG_INFO("	%s", p->cfg->name);
		free(p->cfg->port);
		free(p->cfg->match);
		free(p->cfg->actions);
		free(p->fwd);
		free(p->fwd_miss);
		free(p->cfg);
		free(p);
	}
}

print_ether_addr(const char *what, uint8_t eth_addr[])
{
	printf("%s %x-%x-%x-%x-%x-%x\n", what, eth_addr[0], eth_addr[1], eth_addr[2], eth_addr[3], eth_addr[4], eth_addr[5]);
}
int doca_flow_port_stop(struct doca_flow_port *port) {}

int doca_flow_port_pair(struct doca_flow_port *port, struct doca_flow_port *pair_port)
{
	DOCA_LOG_INFO("Pair-Port: %d-%d\n", port->port_id, pair_port->port_id);
	return 0;
}

uint8_t *
doca_flow_port_priv_data(struct doca_flow_port *port) {}
int doca_flow_shared_resource_cfg(enum doca_flow_shared_resource_type type, uint32_t id,
								  struct doca_flow_shared_resource_cfg *cfg,
								  struct doca_flow_error *error) {}

int doca_flow_shared_resources_bind(enum doca_flow_shared_resource_type type, uint32_t *res_array,
									uint32_t res_array_len, void *bindable_obj,
									struct doca_flow_error *error) {}

void get_fwd_type(int typeID, char* txt){
	if (typeID==0) strcpy(txt, "DOCA_FLOW_FWD_NONE");
	else if (typeID==1) strcpy(txt, "DOCA_FLOW_FWD_RSS");
	else if (typeID==2) strcpy(txt, "DOCA_FLOW_FWD_PORT");
	else if (typeID==3) strcpy(txt, "DOCA_FLOW_FWD_PIPE");
	else if (typeID==4) strcpy(txt, "DOCA_FLOW_FWD_DROP");
	else strcpy(txt, "UNKNOWN");
}




void set_all_match(struct doca_flow_match *match){
	match->out_dst_ip.ipv4_addr=0xffffffff;
	match->out_src_ip.ipv4_addr=0xffffffff;
	match->in_dst_ip.ipv4_addr=0xffffffff;
	match->in_src_ip.ipv4_addr=0xffffffff;
	
	match->out_dst_port=0xffff;
	match->out_src_port=0xffff;
	match->in_dst_port=0xffff;
	match->in_src_port=0xffff;
	
	memset(match->out_dst_mac,0xff,6);
	memset(match->out_src_mac,0xff,6);
	memset(match->in_dst_mac,0xff,6);
	memset(match->in_src_mac,0xff,6);
}

struct doca_flow_pipe *
doca_flow_create_pipe(const struct doca_flow_pipe_cfg *cfg,
					  const struct doca_flow_fwd *fwd,
					  const struct doca_flow_fwd *fwd_miss,
					  struct doca_flow_error *error)
{
	char create_pipe_str[100];
	sprintf(create_pipe_str, "Create pipe %s", cfg->name);
	char fwd_str[30];
	char fwd_miss_str[20];
	char fwd_type_str[20];


	if (!fwd)
		sprintf(fwd_str, "%s","	fwd: NULL");
	else{
		get_fwd_type(fwd->type, fwd_type_str);
		sprintf(fwd_str, " fwd: %s", fwd_type_str);
	}
	if (!fwd_miss)
		sprintf(fwd_miss_str, "%s", "	fwd_miss: NULL");
	else
		sprintf(fwd_miss_str, "	fwd_miss: %s", fwd_miss->next_pipe->cfg->name);
	strcpy(create_pipe_str+strlen(create_pipe_str), fwd_str);
	strcpy(create_pipe_str+strlen(create_pipe_str), fwd_miss_str);
	DOCA_LOG_INFO("%s", create_pipe_str);

	struct doca_flow_pipe *pipe = calloc(1,sizeof(struct doca_flow_pipe));
	pipe->cfg = calloc(1,sizeof(struct doca_flow_pipe_cfg));
	pipe->cfg->port = calloc(1,sizeof(struct doca_flow_port));
	pipe->cfg->match = calloc(1,sizeof(struct doca_flow_match));
	pipe->cfg->actions = calloc(1,sizeof(struct doca_flow_actions));
	pipe->fwd = calloc(1,sizeof(struct doca_flow_fwd));
	pipe->fwd_miss = calloc(1,sizeof(struct doca_flow_fwd));

	pipe->cfg->name = cfg->name;
	pipe->cfg->type = cfg->type;
	if (cfg->port)
		memcpy(pipe->cfg->port, cfg->port, sizeof(struct doca_flow_port));
	pipe->cfg->is_root = cfg->is_root;
	if (cfg->match)
		memcpy(pipe->cfg->match, cfg->match, sizeof(struct doca_flow_match));
	if (cfg->actions)
		memcpy(pipe->cfg->actions, cfg->actions, sizeof(struct doca_flow_actions));
	pipe->cfg->nb_flows = cfg->nb_flows;
	if (fwd)
		memcpy(pipe->fwd, fwd, sizeof(struct doca_flow_fwd));
	if (fwd_miss)
		memcpy(pipe->fwd_miss, fwd_miss, sizeof(struct doca_flow_fwd));
	if (!(cfg->is_root))
		pipe->group_id = ++GROUP;
	else
		pipe->group_id = 0;

	if (fwd_miss)
	{

		struct rte_flow_attr attr;
		struct rte_flow_item pattern[MAX_PATTERN_NUM];
		struct rte_flow_action action[MAX_ACTION_NUM];
		// struct rte_flow *flow = NULL;

		memset(&attr, 0, sizeof(struct rte_flow_attr));
		memset(pattern, 0, sizeof(pattern));
		memset(action, 0, sizeof(action));
		// attr.priority = 1;
		attr.group = pipe->group_id;
		attr.ingress = 1;

		// pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
		pattern[0].type = RTE_FLOW_ITEM_TYPE_END;

		if (fwd_miss->type == DOCA_FLOW_FWD_DROP)
		{
			action[0].type = RTE_FLOW_ACTION_TYPE_DROP;
		}
		else if (fwd_miss->type == DOCA_FLOW_FWD_PIPE)
		{
			action[0].type = RTE_FLOW_ACTION_TYPE_JUMP;
			struct rte_flow_action_jump _jump;
			_jump.group = fwd_miss->next_pipe->group_id;
			action[0].conf = &_jump;
		}
		action[1].type = RTE_FLOW_ACTION_TYPE_END;

		struct rte_flow_error rte_error;
		struct rte_flow *flow;
		int res = rte_flow_validate(cfg->port->port_id, &attr, pattern, action, &rte_error);
		if (!res)
		{
			flow = rte_flow_create(cfg->port->port_id, &attr, pattern, action, &rte_error);
			if (!flow)
			{
				DOCA_LOG_ERR("Flow can't be created %d message: %s\n",
							 rte_error.type,
							 rte_error.message ? rte_error.message : "(no stated reason)");
				rte_exit(EXIT_FAILURE, "error in creating flow");
				return NULL;
			}
			// output_flow(cfg->port->port_id, &attr, pattern, action, &error);
		}
		else
		{
			DOCA_LOG_ERR("ERROR while validate flow: %d\n", res);
			DOCA_LOG_ERR("%s\n", rte_error.message);
		}
	}
	pipes[p_pipe++] = pipe;
	DOCA_LOG_INFO("Successfully create and offload a flow\n");

	return pipe;
}

void output_flow(uint16_t port_id, const struct rte_flow_attr *attr, const struct rte_flow_item *pattern, const struct rte_flow_action *actions, struct rte_flow_error *error)
{
	printf("{\n");

	printf("	port_id: %d\n", port_id);

	printf("	attr: \n");
	printf("		egress: %d\n", attr->egress);
	printf("		group: %d\n", attr->group);
	printf("		ingress: %d\n", attr->ingress);
	printf("		priority: %d\n", attr->priority);
	printf("		transfer: %d\n", attr->transfer);
	int i = 0;

	for (; pattern->type != RTE_FLOW_ITEM_TYPE_END; pattern++)
	{
		printf("	pattern-%d:\n", i++);
		printf("		type: ");
		switch (pattern->type)
		{
		case RTE_FLOW_ITEM_TYPE_VOID:
			printf("RTE_FLOW_ITEM_TYPE_VOID\n");
			break;
		case RTE_FLOW_ITEM_TYPE_ETH:
			printf("RTE_FLOW_ITEM_TYPE_ETH\n");
			if (pattern->spec)
			{
				const struct rte_flow_item_eth *spec = pattern->spec;
				print_ether_addr("			src_mac:", spec->hdr.src_addr.addr_bytes);
				print_ether_addr("			dst_mac:", spec->hdr.dst_addr.addr_bytes);
			}
			break;
		case RTE_FLOW_ITEM_TYPE_IPV4:
		{
			printf("RTE_FLOW_ITEM_TYPE_IPV4\n");
			if (pattern->mask)
			{
				const struct rte_flow_item_ipv4 *mask = pattern->mask;
				struct in_addr mask_dst, mask_src;
				mask_dst.s_addr = mask->hdr.dst_addr;
				mask_src.s_addr = mask->hdr.src_addr;
				printf("		mask.hdr:\n");
				printf("			dst_addr: %s\n", inet_ntoa(mask_dst));
			}
			if (pattern->spec)
			{
				const struct rte_flow_item_ipv4 *spec = pattern->spec;
				struct in_addr dst, src;
				dst.s_addr = spec->hdr.dst_addr;
				src.s_addr = spec->hdr.src_addr;
				printf("		spec.hdr:\n");
				printf("			src_addr: %s\n", inet_ntoa(src));
				printf("			dst_addr: %s\n", inet_ntoa(dst));
			}
			break;
		}
		case RTE_FLOW_ITEM_TYPE_UDP:
		{
			printf("RTE_FLOW_ITEM_TYPE_UDP\n");
			if (pattern->spec)
			{
				const struct rte_flow_item_udp *udpspec = pattern->spec;
				printf("		spec.hdr:\n");
				printf("			src_addr: %d\n", udpspec->hdr.src_port);
				printf("			dst_addr: %d\n", udpspec->hdr.dst_port);
			}

			break;
		}
		default:
			printf("other type: %d\n", pattern->type);
		}
	}
	i = 0;
	for (; actions->type != RTE_FLOW_ACTION_TYPE_END; actions++)
	{
		printf("	action-%d:\n", i++);
		printf("		type: ");

		switch (actions->type)
		{
		case RTE_FLOW_ACTION_TYPE_VOID:
			printf("RTE_FLOW_ACTION_TYPE_VOID\n");
			break;
		case RTE_FLOW_ACTION_TYPE_DROP:
			printf("RTE_FLOW_ACTION_TYPE_DROP\n");
			break;
		case RTE_FLOW_ACTION_TYPE_QUEUE:
		{
			printf("RTE_FLOW_ACTION_TYPE_QUEUE\n");
			if (actions->conf)
			{
				const struct rte_flow_action_queue *queue = actions->conf;
				printf("		index: %d\n", queue->index);
			}
			break;
		}
		case RTE_FLOW_ACTION_TYPE_SET_MAC_DST:
		{
			printf("RTE_FLOW_ACTION_TYPE_SET_MAC_DST\n");
			if (actions->conf)
			{
				const struct rte_flow_action_set_mac *dst_mac = actions->conf;
				print_ether_addr("		mac_addr: ", dst_mac->mac_addr);
			}
			break;
		}
		case RTE_FLOW_ACTION_TYPE_SET_IPV4_DST:
		{
			printf("RTE_FLOW_ACTION_TYPE_SET_IPV4_DST\n");
			if (actions->conf)
			{
				const struct rte_flow_action_set_ipv4 *dst_ip = actions->conf;
				struct in_addr addr;
				addr.s_addr = dst_ip->ipv4_addr;
				printf("		dst_addr: %s\n", inet_ntoa(addr));
			}
			break;
		}
		case RTE_FLOW_ACTION_TYPE_SET_TP_DST:
		{
			printf("RTE_FLOW_ACTION_TYPE_SET_TP_DST\n");
			if (actions->conf)
			{
				const struct rte_flow_action_set_tp *dst_tp = actions->conf;
				printf("		port: %d\n", dst_tp->port);
			}
			break;
		}
		case RTE_FLOW_ACTION_TYPE_PORT_ID:
		{
			printf("RTE_FLOW_ACTION_TYPE_PORT_ID\n");
			if (actions->conf)
			{
				const struct rte_flow_action_port_id *pid = actions->conf;
				printf("		port_id: %d\n", pid->id);
			}
			break;
		}

		default:
			printf("other type: %d\n", actions->type);
		}
	}

	printf("}\n");
}

/*
	append pipe_match to entry_match
*/
void merge_match(struct doca_flow_match *entry_match, struct doca_flow_match *pipe_match)
{
	// struct doca_flow_match *result = malloc(sizeof(struct doca_flow_match));
	if (!pipe_match)
	{
		return;
	}
	if (entry_match->flags == 0)
		entry_match->flags = pipe_match->flags;
	if(entry_match->meta.pkt_meta ==0)
		entry_match->meta.pkt_meta=pipe_match->meta.pkt_meta;
	if (memcmp(entry_match->out_src_mac, mac0, sizeof(mac0)) == 0)
		memcpy(entry_match->out_src_mac, pipe_match->out_src_mac, DOCA_ETHER_ADDR_LEN);
	if (memcmp(entry_match->out_dst_mac, mac0, sizeof(mac0)) == 0)
		memcpy(entry_match->out_dst_mac, pipe_match->out_dst_mac, DOCA_ETHER_ADDR_LEN);
	//	doca_be16_t out_eth_type;
	// 	doca_be16_t out_vlan_id;
	if(entry_match->out_eth_type==0)	entry_match->out_eth_type=pipe_match->out_eth_type;
	if(entry_match->out_vlan_id==0)	entry_match->out_vlan_id=pipe_match->out_vlan_id;
	if(entry_match->out_src_ip.ipv4_addr==ip0)	entry_match->out_src_ip.ipv4_addr=pipe_match->out_src_ip.ipv4_addr;
	if(entry_match->out_dst_ip.ipv4_addr==ip0)	entry_match->out_dst_ip.ipv4_addr=pipe_match->out_dst_ip.ipv4_addr;
	if(entry_match->out_l4_type==0)	entry_match->out_l4_type=pipe_match->out_l4_type;
	if(entry_match->out_tcp_flags==0)	entry_match->out_tcp_flags=pipe_match->out_tcp_flags;
	if(entry_match->out_src_port==0)	entry_match->out_src_port=pipe_match->out_src_port;
	if(entry_match->out_dst_port==0)	entry_match->out_dst_port=pipe_match->out_dst_port;
	if(entry_match->tun.type==0)	entry_match->tun.type=pipe_match->tun.type;

	if (memcmp(entry_match->in_src_mac, mac0, sizeof(mac0)) == 0)
		memcpy(entry_match->in_src_mac, pipe_match->in_src_mac, DOCA_ETHER_ADDR_LEN);
	if (memcmp(entry_match->in_dst_mac, mac0, sizeof(mac0)) == 0)
		memcpy(entry_match->in_dst_mac, pipe_match->in_dst_mac, DOCA_ETHER_ADDR_LEN);

	if(entry_match->in_eth_type==0)	entry_match->in_eth_type=pipe_match->in_eth_type;
	if(entry_match->in_vlan_id==0)	entry_match->in_vlan_id=pipe_match->in_vlan_id;
	if(entry_match->in_src_ip.ipv4_addr==0)	entry_match->in_src_ip.ipv4_addr=pipe_match->in_src_ip.ipv4_addr;
	if(entry_match->in_dst_ip.ipv4_addr==0)	entry_match->in_dst_ip.ipv4_addr=pipe_match->in_dst_ip.ipv4_addr;
	if(entry_match->in_l4_type==0)	entry_match->in_l4_type=pipe_match->in_l4_type;
	if(entry_match->in_tcp_flags==0)	entry_match->in_tcp_flags=pipe_match->in_tcp_flags;
	if(entry_match->in_src_port==0)	entry_match->in_src_port=pipe_match->in_src_port;
	if(entry_match->in_dst_port==0)	entry_match->in_dst_port=pipe_match->in_dst_port;
}

void merge_action(struct doca_flow_actions *first, struct doca_flow_actions *second)
{
	if(!second){
		DOCA_LOG_INFO("pipe action is empty");
		return;
	}
	if(first->flags==0)	first->flags=second->flags;
	if(!(first->decap) && second->decap) first->decap=second->decap;
	if (memcmp(first->mod_src_mac, mac0, sizeof(mac0)) == 0)
		memcpy(first->mod_src_mac, second->mod_src_mac, DOCA_ETHER_ADDR_LEN);
	if (memcmp(first->mod_dst_mac, mac0, sizeof(mac0)) == 0)
		memcpy(first->mod_dst_mac, second->mod_dst_mac, DOCA_ETHER_ADDR_LEN);
	if(first->mod_src_ip.ipv4_addr==0)	first->mod_src_ip.ipv4_addr=second->mod_src_ip.ipv4_addr;
	if(first->mod_dst_ip.ipv4_addr==0)	first->mod_dst_ip.ipv4_addr=second->mod_dst_ip.ipv4_addr;
	if(first->mod_src_port==0)	first->mod_src_port=second->mod_src_port;
	if(first->mod_dst_port==0)	first->mod_dst_port=second->mod_dst_port;
	if(!(first->dec_ttl) && second->dec_ttl)	first->dec_ttl=second->dec_ttl;
	if(!(first->has_encap) && second->has_encap)	first->has_encap=second->has_encap;
	if (memcmp(first->encap.src_mac, mac0, sizeof(mac0)) == 0)
		memcpy(first->encap.src_mac, second->encap.src_mac, DOCA_ETHER_ADDR_LEN);
	
	if (memcmp(first->encap.dst_mac, mac0, sizeof(mac0)) == 0)
		memcpy(first->encap.dst_mac, second->encap.dst_mac, DOCA_ETHER_ADDR_LEN);
	if(first->encap.src_ip.ipv4_addr==0)	first->encap.src_ip.ipv4_addr=second->encap.src_ip.ipv4_addr;
	if(first->encap.dst_ip.ipv4_addr==0)	first->encap.dst_ip.ipv4_addr=second->encap.dst_ip.ipv4_addr;
	
	if(first->encap.tun.type == 0){
		first->encap.tun.type=second->encap.tun.type;
		switch (first->encap.tun.type)
		{
		case DOCA_FLOW_TUN_VXLAN:
			first->encap.tun.vxlan_tun_id=second->encap.tun.vxlan_tun_id;
			break;
		case DOCA_FLOW_TUN_GRE:
			first->encap.tun.gre_key=second->encap.tun.gre_key;
			first->encap.tun.protocol=second->encap.tun.protocol;
			break;
		case DOCA_FLOW_TUN_GTPU:
			first->encap.tun.gtp_teid=second->encap.tun.gtp_teid;
			break;
		default:
			break;
		}
	}
	if(first->meta.pkt_meta==0)	first->meta.pkt_meta=second->meta.pkt_meta;
}

void merge_fwd(struct doca_flow_fwd *first, struct doca_flow_fwd *second)
{
	if (first->type == DOCA_FLOW_FWD_NONE && second->type != DOCA_FLOW_FWD_NONE)
	{
		memcpy(first, second, sizeof(struct doca_flow_fwd));
		return;
	}
}

static void
add_vxlan_encap(struct rte_flow_action *action,
	uint8_t actions_counter, struct doca_flow_actions *actions)
{
	static struct rte_flow_action_vxlan_encap vxlan_encap;
	static struct rte_flow_item items[5];
	static struct rte_flow_item_eth item_eth;
	static struct rte_flow_item_ipv4 item_ipv4;
	static struct rte_flow_item_udp item_udp;
	static struct rte_flow_item_vxlan item_vxlan;
	uint32_t ip_dst = 10000;

	memcpy(item_eth.hdr.dst_addr.addr_bytes, actions->encap.dst_mac, DOCA_ETHER_ADDR_LEN);
	memcpy(item_eth.hdr.src_addr.addr_bytes, actions->encap.src_mac, DOCA_ETHER_ADDR_LEN);	
	items[0].spec = &item_eth;
	items[0].mask = &item_eth;
	items[0].type = RTE_FLOW_ITEM_TYPE_ETH;

	item_ipv4.hdr.src_addr = actions->encap.src_ip.ipv4_addr;
	item_ipv4.hdr.dst_addr = actions->encap.dst_ip.ipv4_addr;
	item_ipv4.hdr.version_ihl = RTE_IPV4_VHL_DEF;
	items[1].spec = &item_ipv4;
	items[1].mask = &item_ipv4;
	items[1].type = RTE_FLOW_ITEM_TYPE_IPV4;


	item_udp.hdr.dst_port = RTE_BE16(RTE_VXLAN_DEFAULT_PORT);
	items[2].spec = &item_udp;
	items[2].mask = &item_udp;
	items[2].type = RTE_FLOW_ITEM_TYPE_UDP;


	items[3].type = RTE_FLOW_ITEM_TYPE_VXLAN;
	uint8_t *pt = (uint8_t *)&(actions->encap.tun.vxlan_tun_id);
	for (int i = 0; i < 3; i++)
	{
		item_vxlan.vni[i] = pt[3 - i];
	}
	items[3].spec = &item_vxlan;
	items[3].mask = &item_vxlan;

	items[4].type = RTE_FLOW_ITEM_TYPE_END;

	vxlan_encap.definition = items;

	action[actions_counter].type = RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP;
	action[actions_counter].conf = &vxlan_encap;
}


void get_pattern_str(int id, char *txt){
	if(id==9) strcpy(txt, "ETH");
	else if(id ==11) strcpy(txt, "IPV4");
	else if(id ==14) strcpy(txt, "UDP");
	else if(id== RTE_FLOW_ITEM_TYPE_TCP) strcpy(txt, "TCP");
	else if(id ==RTE_FLOW_ITEM_TYPE_END ) strcpy(txt, "END");
	else if(id==RTE_FLOW_ITEM_TYPE_VXLAN) strcpy(txt, "VXLAN");
	else if(id == RTE_FLOW_ITEM_TYPE_GRE) strcpy(txt, "GRE");
	else if(id==RTE_FLOW_ITEM_TYPE_GTPU) strcpy(txt, "GTPU");
	else strcpy(txt, "UNKNOWN");
}

void get_action_str(int id, char *txt){
	if(id==0) strcpy(txt, "END");
	else if(id ==28) strcpy(txt, "VXLAN_ENCAP");
	else if(id ==29) strcpy(txt, "VXLAN_DECAP");
	else if(id ==35) strcpy(txt, "SET_IPV4_DST");
	else if(id ==39) strcpy(txt, "SET_TP_DST");
	else if(id ==44) strcpy(txt, "SET_MAC_DST");
	else if(id == RTE_FLOW_ACTION_TYPE_RSS) strcpy(txt, "RSS");
	else if(id == RTE_FLOW_ACTION_TYPE_PORT_ID) strcpy(txt, "PORT");
	else if(id == RTE_FLOW_ACTION_TYPE_JUMP) strcpy(txt, "JUMP");
	else if(id == RTE_FLOW_ACTION_TYPE_DROP) strcpy(txt, "DROP");
	else strcpy(txt, "UNKNOWN");
}

struct doca_flow_pipe_entry *
doca_flow_pipe_add_entry(uint16_t pipe_queue,
						 struct doca_flow_pipe *pipe,
						 const struct doca_flow_match *match,
						 const struct doca_flow_actions *actions,
						 const struct doca_flow_monitor *monitor,
						 const struct doca_flow_fwd *fwd,
						 uint32_t flags,
						 void *usr_ctx,
						 struct doca_flow_error *error)
{
	DOCA_LOG_INFO("Add Entry to pipe: %s", pipe->cfg->name);
	// dpdk need structures
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_ACTION_NUM];
	struct rte_flow *flow = NULL;

	memset(&attr, 0, sizeof(struct rte_flow_attr));
	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));

	attr.ingress = 1;
	// merge match, actions, fwd
	merge_match(match, pipe->cfg->match);
	merge_action(actions, pipe->cfg->actions);
	merge_fwd(fwd, pipe->fwd);

	/*
		match -> pattern
	*/
	struct rte_flow_item_eth out_mac_spec;
	struct rte_flow_item_ipv4 out_ip_spec;
	struct rte_flow_item_udp out_udp_spec;
	struct rte_flow_item_tcp out_tcp_spec;

	int p = 0;
	if ((memcmp(match->out_dst_mac, mac0, sizeof(mac0))) != 0 || (memcmp(match->out_src_mac, mac0, sizeof(mac0))) != 0)
	{
		pattern[p].type=RTE_FLOW_ITEM_TYPE_ETH;	
		memset(&out_mac_spec, 0, sizeof(struct rte_flow_item_eth));
		memcpy(out_mac_spec.hdr.dst_addr.addr_bytes, match->out_dst_mac, DOCA_ETHER_ADDR_LEN);
		memcpy(out_mac_spec.hdr.src_addr.addr_bytes, match->out_src_mac, DOCA_ETHER_ADDR_LEN);
		pattern[p].spec = &out_mac_spec;
		p++;
	}

	if (match->out_dst_ip.ipv4_addr != ip0 || match->out_src_ip.ipv4_addr != ip0)
	{
		pattern[p].type = RTE_FLOW_ITEM_TYPE_IPV4;
		memset(&out_ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
		out_ip_spec.hdr.dst_addr = match->out_dst_ip.ipv4_addr;
		out_ip_spec.hdr.src_addr = match->out_src_ip.ipv4_addr;
		pattern[p].spec = &out_ip_spec;
		p++;
		// printf("DOCA_FLOW out_dst_ip %x out_src_ip %x\n", match->out_dst_ip.ipv4_addr, match->out_src_ip.ipv4_addr);
	}else if(match->out_dst_ip.type == DOCA_FLOW_IP4_ADDR || match->out_src_ip.type == DOCA_FLOW_IP4_ADDR){
		pattern[p++].type=RTE_FLOW_ITEM_TYPE_IPV4;
	}

	if (match->out_l4_type == IPPROTO_UDP)
	{
		out_ip_spec.hdr.next_proto_id=IPPROTO_UDP;
		pattern[p].type = RTE_FLOW_ITEM_TYPE_UDP;
		if (match->out_dst_port != port0 || match->out_src_port != port0)
		{
			memset(&out_udp_spec, 0, sizeof(struct rte_flow_item_udp));
			out_udp_spec.hdr.dst_port = match->out_dst_port;
			out_udp_spec.hdr.src_port = match->out_src_port;
			pattern[p].spec = &out_udp_spec;
		}
		p++;
		
	}
	else if (match->out_l4_type == IPPROTO_TCP)
	{
		out_ip_spec.hdr.next_proto_id=IPPROTO_TCP;
		pattern[p].type = RTE_FLOW_ITEM_TYPE_TCP;
		if (match->out_dst_port != port0 || match->out_src_port != port0)
		{
			memset(&out_tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
			out_tcp_spec.hdr.dst_port = match->out_dst_port;
			out_tcp_spec.hdr.src_port = match->out_src_port;
			pattern[p].spec = &out_tcp_spec;
		}
		p++;
	}
	// tunnel
	if (match->tun.type)
	{

		switch (match->tun.type)
		{
		case DOCA_FLOW_TUN_VXLAN:
		{
			pattern[p].type = RTE_FLOW_ITEM_TYPE_VXLAN;
			if(match->tun.vxlan_tun_id==0) break;
			struct rte_flow_item_vxlan vxlan_item;
			// rte_vxlan_gpe_hdr.vx_vni -> rte_flow_item_vxlan.vni
			// take higher 24 bits
			uint8_t *pt = (uint8_t *)&(match->tun.vxlan_tun_id);
			for (int i = 0; i < 3; i++)
			{
				vxlan_item.vni[i] = pt[3 - i];
			}
			pattern[p].spec = &vxlan_item;
			break;
		}
		case DOCA_FLOW_TUN_GRE:
		{ // gre_key (32bit) -> rte_flow_item_gre.c_rsvd0_ver + rte_flow_item_gre.protocol
			pattern[p].type = RTE_FLOW_ITEM_TYPE_GRE;
			if(match->tun.gre_key==0) break;
			struct rte_flow_item_gre gre_item;
			uint16_t *pt = (uint16_t) & (match->tun.gre_key);
			gre_item.c_rsvd0_ver = pt[0];
			gre_item.protocol = pt[1];
			pattern[p++].spec = &gre_item;
			break;
		}
		case DOCA_FLOW_TUN_GTPU:
		{
			if(match->tun.gtp_teid ==0) break;
			pattern[p].type = RTE_FLOW_ITEM_TYPE_GTPU;
			struct rte_flow_item_gtp gtp_item;
			gtp_item.teid = match->tun.gtp_teid;
			pattern[p++].spec = &gtp_item;
			break;
		}
		default:
			DOCA_LOG_WARN("TUNNEL OTHER TYPE: %d", match->tun.type);
			p--;
			break;
		}
		p++;

		// inner match
		if ((memcmp(match->in_dst_mac, mac0, sizeof(mac0))) != 0 || (memcmp(match->in_src_mac, mac0, sizeof(mac0))) != 0)
		{
			struct rte_flow_item_eth in_mac_spec;
			memcpy(in_mac_spec.hdr.dst_addr.addr_bytes, match->in_dst_mac, DOCA_ETHER_ADDR_LEN);
			memcpy(in_mac_spec.hdr.src_addr.addr_bytes, match->in_src_mac, DOCA_ETHER_ADDR_LEN);
			pattern[p].type = RTE_FLOW_ITEM_TYPE_ETH;
			pattern[p++].spec = &in_mac_spec;
		}
		if (match->in_dst_ip.ipv4_addr != ip0 || match->out_src_ip.ipv4_addr != ip0)
		{
			pattern[p].type = RTE_FLOW_ITEM_TYPE_IPV4;
			struct rte_flow_item_ipv4 in_ip_spec;
			memset(&in_ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
			in_ip_spec.hdr.dst_addr = match->in_dst_ip.ipv4_addr;
			in_ip_spec.hdr.src_addr = match->in_src_ip.ipv4_addr;
			pattern[p++].spec = &in_ip_spec;
		}else if(match->in_dst_ip.type==DOCA_FLOW_IP4_ADDR || match->in_src_ip.type==DOCA_FLOW_IP4_ADDR){
			pattern[p++].type=RTE_FLOW_ITEM_TYPE_IPV4;
		}

		if (match->in_l4_type == IPPROTO_UDP)
		{
			pattern[p].type = RTE_FLOW_ITEM_TYPE_UDP;
			if (match->in_dst_port != port0 || match->in_src_port != port0)
			{
				struct rte_flow_item_udp in_udp_spec;
				memset(&in_udp_spec, 0, sizeof(struct rte_flow_item_udp));
				in_udp_spec.hdr.dst_port = match->in_dst_port;
				in_udp_spec.hdr.src_port = match->in_src_port;
				pattern[p].spec = &in_udp_spec;
			}
			p++;
		}
		else if (match->in_l4_type == IPPROTO_TCP)
		{
			pattern[p].type = RTE_FLOW_ITEM_TYPE_TCP;
			if (match->in_dst_port != port0 || match->in_src_port != port0)
			{
				struct rte_flow_item_tcp in_tcp_spec;
				memset(&in_tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
				in_tcp_spec.hdr.dst_port = match->in_dst_port;
				in_tcp_spec.hdr.src_port = match->in_src_port;
				pattern[p].spec = &in_tcp_spec;
			}
			p++;
		}
	}

	pattern[p++].type = RTE_FLOW_ITEM_TYPE_END;

	char pattern_str[300]="	pattern:\n";
	for (int i = 0; i < p; i++)
	{
		char pattern_type_str[30];
		char pattern_enroll_str[50];
		get_pattern_str(pattern[i].type, pattern_type_str);
		sprintf(pattern_enroll_str, "			%s\n",pattern_type_str);
		//sprintf(_t, " %d",pattern[i].type);
		strcpy(pattern_str+strlen(pattern_str), pattern_enroll_str);	
	}
	DOCA_LOG_INFO("%s", pattern_str);
	/*convert actions -> action*/
	// modify packets
	p = 0;
	if (memcmp(actions->mod_dst_mac, mac0, sizeof(mac0)) != 0)
	{
		action[p].type = RTE_FLOW_ACTION_TYPE_SET_MAC_DST;
		struct rte_flow_action_set_mac dst_mac;
		memcpy(dst_mac.mac_addr, actions->mod_dst_mac, DOCA_ETHER_ADDR_LEN);
		action[p++].conf = &dst_mac;
	}
	if (memcmp(actions->mod_src_mac, mac0, sizeof(mac0)) != 0)
	{
		action[p].type = RTE_FLOW_ACTION_TYPE_SET_MAC_SRC;
		struct rte_flow_action_set_mac src_mac;
		memcpy(src_mac.mac_addr, actions->mod_src_mac, DOCA_ETHER_ADDR_LEN);
		action[p++].conf = &src_mac;
	}
	if (actions->mod_dst_ip.ipv4_addr != ip0)
	{
		action[p].type = RTE_FLOW_ACTION_TYPE_SET_IPV4_DST;
		struct rte_flow_action_set_ipv4 dst_ipv4;
		dst_ipv4.ipv4_addr = actions->mod_dst_ip.ipv4_addr;
		action[p++].conf = &dst_ipv4;
	}
	if (actions->mod_src_ip.ipv4_addr != ip0)
	{
		action[p].type = RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC;
		struct rte_flow_action_set_ipv4 src_ipv4;
		src_ipv4.ipv4_addr = actions->mod_src_ip.ipv4_addr;
		action[p++].conf = &src_ipv4;
	}
	if (actions->mod_dst_port != port0)
	{
		action[p].type = RTE_FLOW_ACTION_TYPE_SET_TP_DST;
		struct rte_flow_action_set_tp dst_tp;
		dst_tp.port = actions->mod_dst_port;
		action[p++].conf = &dst_tp;
	}
	if (actions->mod_src_port != port0)
	{
		action[p].type = RTE_FLOW_ACTION_TYPE_SET_TP_SRC;
		struct rte_flow_action_set_tp src_tp;
		src_tp.port = actions->mod_src_port;
		action[p++].conf = &src_tp;
	}

	// do vxlan encap/decap
	if (actions->decap)
	{
		action[p++].type = RTE_FLOW_ACTION_TYPE_VXLAN_DECAP;
	}
	if (actions->has_encap)
	{
		attr.egress = 1;
		attr.ingress = 0;
		add_vxlan_encap(action, p++, actions);
	}

	// forward actions
	switch (fwd->type)
	{
	case DOCA_FLOW_FWD_RSS:
		// DOCA_FLOW_FWD_RSS
		{
			action[p].type = RTE_FLOW_ACTION_TYPE_RSS;
			struct rte_flow_action_rss _rss;
			memset(&(_rss), 0, sizeof(struct rte_flow_action_rss));
			_rss.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
			_rss.level = 0;
			uint32_t _type = fwd->rss_flags;
			if (_type % 2 == 1)
			{
				// DOCA_FLOW_RSS_IP
				_rss.types |= RTE_ETH_RSS_IP;
			}
			_type = _type >> 1;
			if (_type % 2 == 1)
			{
				// DOCA_FLOW_RSS_UDP
				_rss.types |= RTE_ETH_RSS_UDP;
			}
			_type = _type >> 1;
			if (_type % 2 == 1)
			{
				// DOCA_FLOW_RSS_TCP
				_rss.types |= RTE_ETH_RSS_TCP;
			}
			_rss.queue_num = fwd->num_of_queues;
			_rss.queue = fwd->rss_queues;
			action[p++].conf = &(_rss);
		}
		break;
	case DOCA_FLOW_FWD_PORT:
		// DOCA_FLOW_FWD_PORT
		{
			action[p].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
			struct rte_flow_action_port_id _pid;
			_pid.id = fwd->port_id;
			action[p++].conf = &_pid;
		}
		break;
	case DOCA_FLOW_FWD_PIPE:
		// DOCA_FLOW_FWD_PIPE
		// printf("DOCA FWD PIPE\n");
		{
			action[p].type = RTE_FLOW_ACTION_TYPE_JUMP;
			struct rte_flow_action_jump _jump;
			_jump.group = fwd->next_pipe->group_id;
			action[p++].conf = &_jump;
		}
		break;
	case DOCA_FLOW_FWD_DROP:
		// DOCA_FLOW_FWD_DROP
		action[p++].type = RTE_FLOW_ACTION_TYPE_DROP;
		break;
	default:
		//DOCA_LOG_INFO("DOCA FWD OTHER TYPE: %d", fwd->type);
		break;
	}

	action[p++].type = RTE_FLOW_ACTION_TYPE_END;

	char action_str[200];
	sprintf(action_str, "%s", "	action:\n");
	for (int i = 0; i < p; i++)
	{
		char action_type_str[20];
		char action_enroll_str[30];
		get_action_str(action[i].type, action_type_str);
		sprintf(action_enroll_str, "			%s\n",action_type_str);
		strcpy(action_str+strlen(action_str), action_enroll_str);	
	}
	DOCA_LOG_INFO("%s", action_str);


	// action: 44 35 39 28
	//   set_mac_dst, set_ipv4_dst, set_tp_dst, encap, queue

	// get port id
	int port_id = pipe->cfg->port->port_id;

	// validate and create entry
	struct rte_flow_error rte_error;
	int res = rte_flow_validate(port_id, &attr, pattern, action, &rte_error);
	if (!res)
	{
		flow = rte_flow_create(port_id, &attr, pattern, action, &rte_error);
		if (!flow)
		{
			DOCA_LOG_ERR("Flow can't be created %d message: %s",
				   rte_error.type,
				   rte_error.message ? rte_error.message : "(no stated reason)");
			error->type = rte_error.type;
			error->message = rte_error.message;
			// rte_exit(EXIT_FAILURE, "error in creating flow");
			return NULL;
		}else{
			DOCA_LOG_INFO("Successfully create and offload a flow\n");
			// output_flow(port_id, &attr, pattern, action, &error);
			return (struct doca_flow_pipe_entry *)flow;
		}
		
	}
	else
	{
		DOCA_LOG_ERR("ERROR while validate flow: %d", res);
		DOCA_LOG_ERR("%s\n", rte_error.message);
	}
}

struct doca_flow_pipe_entry *
doca_flow_control_pipe_add_entry(uint16_t pipe_queue,
								 uint8_t priority,
								 struct doca_flow_pipe *pipe,
								 const struct doca_flow_match *match,
								 const struct doca_flow_match *match_mask,
								 const struct doca_flow_fwd *fwd,
								 struct doca_flow_error *error) 
{
	struct doca_flow_actions action={0};
	struct doca_flow_monitor monitor={0};
	return doca_flow_pipe_add_entry(pipe_queue, pipe, match, &action, &monitor, fwd, 0, NULL, error);
}

int doca_flow_pipe_rm_entry(uint16_t pipe_queue, void *usr_ctx,
							struct doca_flow_pipe_entry *entry) {}

void doca_flow_destroy_pipe(uint16_t port_id,
							struct doca_flow_pipe *pipe) {}

void doca_flow_port_pipes_flush(uint16_t port_id) {}

void doca_flow_destroy_port(uint16_t port_id)
{
	DOCA_LOG_INFO("DESTROY PORT: %d", port_id);
}

void doca_flow_port_pipes_dump(uint16_t port_id, FILE *f) {}

int doca_flow_query(struct doca_flow_pipe_entry *entry,
					struct doca_flow_query *query_stats) {}

int doca_flow_handle_aging(struct doca_flow_port *port, uint16_t queue,
						   uint64_t quota, struct doca_flow_aged_query *entries, int len)
{
	// process no aging
	return 0;
}
int doca_flow_entries_process(struct doca_flow_port *port,
							  uint16_t pipe_queue, uint64_t timeout,
							  uint32_t max_processed_entries) {}

enum doca_flow_entry_status
doca_flow_entry_get_status(struct doca_flow_pipe_entry *entry) {}
