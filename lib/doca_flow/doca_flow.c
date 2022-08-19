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

#define MAX_PATTERN_NUM 10
#define MAX_ACTION_NUM 10

const uint8_t mac0[6] = {0};
const uint32_t ip0 = 0;
const uint16_t port0 = 0;
#define CHOOSE(first, second, result, zero) \
	if (first == zero)                      \
		result = second;                    \
	else                                    \
		result = first;
#define CHOOSE21(para, zero)         \
	if (first->para == zero)         \
		result->para = second->para; \
	else                             \
		result->para = first->para;
int doca_flow_init(const struct doca_flow_cfg *cfg,
				   struct doca_flow_error *error)
{
	// printf("doca_flow_init\n"); // check
	return 0;
}

void doca_flow_destroy(void) {}
typedef struct doca_flow_port
{
	int port_id;
};

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
print_ether_addr(const char *what, uint8_t eth_addr[])
{
	printf("%s %02x-%02x-%02x-%02x-%02x-%02x\n", what, eth_addr[0], eth_addr[1], eth_addr[2], eth_addr[3], eth_addr[4], eth_addr[5]);
}
int doca_flow_port_stop(struct doca_flow_port *port) {}

int doca_flow_port_pair(struct doca_flow_port *port, struct doca_flow_port *pair_port) {}

uint8_t *
doca_flow_port_priv_data(struct doca_flow_port *port) {}
int doca_flow_shared_resource_cfg(enum doca_flow_shared_resource_type type, uint32_t id,
								  struct doca_flow_shared_resource_cfg *cfg,
								  struct doca_flow_error *error) {}

int doca_flow_shared_resources_bind(enum doca_flow_shared_resource_type type, uint32_t *res_array,
									uint32_t res_array_len, void *bindable_obj,
									struct doca_flow_error *error) {}

typedef struct doca_flow_pipe
{
	// int port_id;
	struct doca_flow_pipe_cfg *cfg;
	uint32_t group_id;
	struct doca_flow_fwd *fwd;
	struct doca_flow_fwd *fwd_miss;
};
static int GROUP = 0;

struct doca_flow_pipe *
doca_flow_create_pipe(const struct doca_flow_pipe_cfg *cfg,
					  const struct doca_flow_fwd *fwd,
					  const struct doca_flow_fwd *fwd_miss,
					  struct doca_flow_error *error)
{
	printf("create pipe: %s\n",cfg->name);
	struct doca_flow_pipe *pipe = malloc(sizeof(struct doca_flow_pipe));

	pipe->cfg->name = cfg->name;
	pipe->cfg->type=cfg->type;
	if(cfg->port!=NULL)
		memcpy(pipe->cfg->port, cfg->port, sizeof(struct doca_flow_port));
	pipe->cfg->is_root=cfg->is_root;
	if(cfg->match !=NULL)
		memcpy(pipe->cfg->match, cfg->match,sizeof(struct doca_flow_match));
	if(cfg->actions!=NULL)
		memcpy(pipe->cfg->actions, cfg->actions, sizeof(struct doca_flow_actions));
	pipe->cfg->nb_flows=cfg->nb_flows;
	if(fwd!=NULL)
		memcpy(pipe->fwd, fwd, sizeof(struct doca_flow_fwd));
	if(fwd_miss!=NULL)
		memcpy(pipe->fwd_miss, fwd_miss, sizeof(struct doca_flow_fwd));
	if (!cfg->is_root)
	{
		pipe->group_id = ++GROUP;
	}
	else
	{
		pipe->group_id = 0;
	}

	if (fwd_miss != NULL)
	{
		struct rte_flow_attr attr;
		struct rte_flow_item pattern[MAX_PATTERN_NUM];
		struct rte_flow_action action[MAX_ACTION_NUM];
		struct rte_flow *flow = NULL;

		memset(&attr, 0, sizeof(struct rte_flow_attr));
		memset(pattern, 0, sizeof(pattern));
		memset(action, 0, sizeof(action));
		// attr.priority = 1;
		attr.group = pipe->group_id;
		attr.ingress = 1;

		pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
		pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

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

		int res = rte_flow_validate(cfg->port->port_id, &attr, pattern, action, &rte_error);
		if (!res)
		{
			flow = rte_flow_create(cfg->port->port_id, &attr, pattern, action, &rte_error);
			if (!flow)
			{
				printf("Flow can't be created %d message: %s\n",
					   rte_error.type,
					   rte_error.message ? rte_error.message : "(no stated reason)");
				rte_exit(EXIT_FAILURE, "error in creating flow");
			}
			output_flow(cfg->port->port_id, &attr, pattern, action, &error);
		}
		else
		{
			printf("ERROR while validate flow: %d\n", res);
			printf("%s\n", rte_error.message);
		}
	}
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
			if (pattern->spec != NULL)
			{
				const struct rte_flow_item_eth *spec = pattern->spec;
				print_ether_addr("			src_mac:", spec->hdr.src_addr.addr_bytes);
				print_ether_addr("			dst_mac:", spec->hdr.dst_addr.addr_bytes);
			}
			break;
		case RTE_FLOW_ITEM_TYPE_IPV4:
		{
			printf("RTE_FLOW_ITEM_TYPE_IPV4\n");
			if (pattern->mask != NULL)
			{
				const struct rte_flow_item_ipv4 *mask = pattern->mask;
				struct in_addr mask_dst, mask_src;
				mask_dst.s_addr = mask->hdr.dst_addr;
				mask_src.s_addr = mask->hdr.src_addr;
				printf("		mask.hdr:\n");
				printf("			dst_addr: %s\n", inet_ntoa(mask_dst));
			}
			if (pattern->spec != NULL)
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
			if (pattern->spec != NULL)
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
			if (actions->conf != NULL)
			{
				const struct rte_flow_action_queue *queue = actions->conf;
				printf("		index: %d\n", queue->index);
			}
			break;
		}
		case RTE_FLOW_ACTION_TYPE_SET_MAC_DST:
		{
			printf("RTE_FLOW_ACTION_TYPE_SET_MAC_DST\n");
			if (actions->conf != NULL)
			{
				const struct rte_flow_action_set_mac *dst_mac = actions->conf;
				print_ether_addr("		mac_addr: ", dst_mac->mac_addr);
			}
			break;
		}
		case RTE_FLOW_ACTION_TYPE_SET_IPV4_DST:
		{
			printf("RTE_FLOW_ACTION_TYPE_SET_IPV4_DST\n");
			if (actions->conf != NULL)
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
			if (actions->conf != NULL)
			{
				const struct rte_flow_action_set_tp *dst_tp = actions->conf;
				printf("		port: %d\n", dst_tp->port);
			}
			break;
		}
		case RTE_FLOW_ACTION_TYPE_PORT_ID:
		{
			printf("RTE_FLOW_ACTION_TYPE_PORT_ID\n");
			if (actions->conf != NULL)
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
	merge_match:
		for all fields in doca_flow_match:
			if first defines, use first's definition, else use second's definition
*/
struct doca_flow_match *
merge_match(struct doca_flow_match *first, struct doca_flow_match *second)
{
	struct doca_flow_match *result = malloc(sizeof(struct doca_flow_match));
	if(second==NULL){
		printf("zero\n");
		return;
	}
	printf("c\n");
	if (first->flags == 0)
		result->flags = second->flags;
	else
		result->flags = first->flags;
	printf("c\n");
	CHOOSE21(flags, 0);
	printf("c\n");
	CHOOSE21(meta.pkt_meta, 0);
	printf("c\n");
	if (memcmp(first->out_src_mac, mac0, sizeof(mac0)) == 0)
	{
		memcpy(result->out_src_mac, second->out_src_mac, DOCA_ETHER_ADDR_LEN);
	}
	else
	{
		memcpy(result->out_src_mac, first->out_src_mac, DOCA_ETHER_ADDR_LEN);
	}
	printf("c\n");
	if (memcmp(first->out_dst_mac, mac0, sizeof(mac0)) == 0)
	{
		memcpy(result->out_dst_mac, second->out_dst_mac, DOCA_ETHER_ADDR_LEN);
	}
	else
	{
		memcpy(result->out_src_mac, first->out_src_mac, DOCA_ETHER_ADDR_LEN);
	}
	printf("c\n");
	//	doca_be16_t out_eth_type;
	// 	doca_be16_t out_vlan_id;
	CHOOSE21(out_eth_type, 0);
	printf("c\n");
	CHOOSE21(out_vlan_id, 0);
	printf("c\n");
	CHOOSE21(out_src_ip.ipv4_addr, ip0);
	printf("c\n");
	CHOOSE21(out_dst_ip.ipv4_addr, ip0);
	printf("c\n");
	CHOOSE21(out_l4_type, 0)
	printf("c\n");
	CHOOSE21(out_tcp_flags, 0);
	printf("c\n");
	CHOOSE21(out_src_port, 0);
	printf("c\n");
	CHOOSE21(out_dst_port, 0);
	printf("c\n");
	CHOOSE21(tun.type, 0);
	printf("c\n");
	if (memcmp(first->in_src_mac, mac0, sizeof(mac0)) == 0)
	{
		memcpy(result->in_src_mac, second->in_src_mac, DOCA_ETHER_ADDR_LEN);
	}
	else
	{
		memcpy(result->in_src_mac, first->in_src_mac, DOCA_ETHER_ADDR_LEN);
	}
	printf("c\n");
	if (memcmp(first->in_dst_mac, mac0, sizeof(mac0)) == 0)
	{
		memcpy(result->in_dst_mac, second->in_dst_mac, DOCA_ETHER_ADDR_LEN);
	}
	else
	{
		memcpy(result->in_src_mac, first->in_src_mac, DOCA_ETHER_ADDR_LEN);
	}
	printf("c\n");
	CHOOSE21(in_eth_type, 0);
	printf("c\n");
	CHOOSE21(in_vlan_id, 0);
	printf("c\n");
	CHOOSE21(in_src_ip.ipv4_addr, 0);
	printf("c\n");
	CHOOSE21(in_dst_ip.ipv4_addr, 0);
	printf("c\n");
	CHOOSE21(in_l4_type, 0);
	printf("c\n");
	CHOOSE21(in_tcp_flags, 0);
	printf("c\n");
	CHOOSE21(in_src_port, 0);
	printf("c\n");
	CHOOSE21(in_dst_port, 0);
	printf("c\n");
	return result;
}

struct doca_flow_actions *
merge_action(struct doca_flow_actions *first, struct doca_flow_actions *second)
{
	struct doca_flow_actions *result = malloc(sizeof(struct doca_flow_actions));
	CHOOSE21(flags, 0);
	CHOOSE21(decap, false);
	if (memcmp(first->mod_src_mac, mac0, sizeof(mac0)) == 0)
	{
		memcpy(result->mod_src_mac, second->mod_src_mac, DOCA_ETHER_ADDR_LEN);
	}
	else
	{
		memcpy(result->mod_src_mac, first->mod_src_mac, DOCA_ETHER_ADDR_LEN);
	}
	if (memcmp(first->mod_dst_mac, mac0, sizeof(mac0)) == 0)
	{
		memcpy(result->mod_dst_mac, second->mod_dst_mac, DOCA_ETHER_ADDR_LEN);
	}
	else
	{
		memcpy(result->mod_src_mac, first->mod_src_mac, DOCA_ETHER_ADDR_LEN);
	}
	CHOOSE21(mod_src_ip.ipv4_addr, 0);
	CHOOSE21(mod_dst_ip.ipv4_addr, 0);
	CHOOSE21(mod_src_port, 0);
	CHOOSE21(mod_dst_port, 0);
	CHOOSE21(dec_ttl, false);
	CHOOSE21(has_encap, false);
	CHOOSE21(encap.tun.type, 0);
	CHOOSE21(meta.pkt_meta, 0);

	return result;
}

struct doca_flow_fwd *
merge_fwd(struct doca_flow_fwd *first, struct doca_flow_fwd *second)
{
	struct doca_flow_fwd *result = malloc(sizeof(struct doca_flow_fwd));
	if (first->type == DOCA_FLOW_FWD_NONE && second->type != DOCA_FLOW_FWD_NONE)
	{
		memcpy(result, second, sizeof(struct doca_flow_fwd));
		return result;
	}
	memcpy(result, first, sizeof(struct doca_flow_fwd));
	return result;
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

	// dpdk need structures
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_ACTION_NUM];
	struct rte_flow *flow = NULL;

	memset(&attr, 0, sizeof(struct rte_flow_attr));
	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));

	attr.ingress = 1;
	printf("before\n");
	printf("%s\n",pipe->cfg);
	printf("before merge, pipe: %s\n",pipe->cfg->name);
	// merge match, actions, fwd
	struct doca_flow_match *mmatch = merge_match(match, pipe->cfg->match);
	printf("after merge match\n");

	struct doca_flow_actions *mactions = merge_action(actions, pipe->cfg->actions);
	printf("after merge action\n");
	struct doca_flow_fwd *mfwd = merge_fwd(fwd, pipe->fwd);
	printf("after merge\n");

	/*
		match -> pattern
	*/
	int p = 0;
	pattern[p].type = RTE_FLOW_ITEM_TYPE_ETH;

	if ((memcmp(mmatch->out_dst_mac, mac0, sizeof(mac0))) != 0 || (memcmp(mmatch->out_src_mac, mac0, sizeof(mac0))) != 0)
	{
		struct rte_flow_item_eth out_mac_spec;
		memset(&out_mac_spec, 0, sizeof(struct rte_flow_item_eth));
		memcpy(out_mac_spec.hdr.dst_addr.addr_bytes, mmatch->out_dst_mac, DOCA_ETHER_ADDR_LEN);
		memcpy(out_mac_spec.hdr.src_addr.addr_bytes, mmatch->out_src_mac, DOCA_ETHER_ADDR_LEN);
		pattern[p].spec = &out_mac_spec;
	}
	p++;

	pattern[p].type = RTE_FLOW_ITEM_TYPE_IPV4;
	if (mmatch->out_dst_ip.ipv4_addr != ip0 || mmatch->out_src_ip.ipv4_addr != ip0)
	{
		struct rte_flow_item_ipv4 out_ip_spec;
		memset(&out_ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
		out_ip_spec.hdr.dst_addr = mmatch->out_dst_ip.ipv4_addr;
		out_ip_spec.hdr.src_addr = mmatch->out_src_ip.ipv4_addr;
		pattern[p].spec = &out_ip_spec;
	}
	p++;

	if (mmatch->out_l4_type == IPPROTO_UDP)
	{
		pattern[p].type = RTE_FLOW_ITEM_TYPE_UDP;
		if (mmatch->out_dst_port != port0 || mmatch->out_src_port != port0)
		{
			struct rte_flow_item_udp out_udp_spec;
			memset(&out_udp_spec, 0, sizeof(struct rte_flow_item_udp));
			out_udp_spec.hdr.dst_port = mmatch->out_dst_port;
			out_udp_spec.hdr.src_port = mmatch->out_src_port;
			pattern[p].spec = &out_udp_spec;
		}
		p++;
	}
	else if (mmatch->out_l4_type == IPPROTO_TCP)
	{
		pattern[p].type = RTE_FLOW_ITEM_TYPE_TCP;
		if (mmatch->out_dst_port != port0 || mmatch->out_src_port != port0)
		{
			struct rte_flow_item_tcp out_tcp_spec;
			memset(&out_tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
			out_tcp_spec.hdr.dst_port = mmatch->out_dst_port;
			out_tcp_spec.hdr.src_port = mmatch->out_src_port;
			pattern[p].spec = &out_tcp_spec;
		}
		p++;
	}
	// tunnel
	if (mmatch->tun.type)
	{

		switch (mmatch->tun.type)
		{
		case DOCA_FLOW_TUN_VXLAN:
		{
			pattern[p].type = RTE_FLOW_ITEM_TYPE_VXLAN;
			struct rte_flow_item_vxlan vxlan_item;
			// rte_vxlan_gpe_hdr.vx_vni -> rte_flow_item_vxlan.vni
			// take higher 24 bits
			uint8_t *pt = (uint8_t *)&(mmatch->tun.vxlan_tun_id);
			for (int i = 0; i < 3; i++)
			{
				vxlan_item.vni[i] = pt[3 - i];
			}
			pattern[p++].spec = &vxlan_item;
			break;
		}
		case DOCA_FLOW_TUN_GRE:
		{ // gre_key (32bit) -> rte_flow_item_gre.c_rsvd0_ver + rte_flow_item_gre.protocol
			pattern[p].type = RTE_FLOW_ITEM_TYPE_GRE;
			struct rte_flow_item_gre gre_item;
			uint16_t *pt = (uint16_t) & (mmatch->tun.gre_key);
			gre_item.c_rsvd0_ver = pt[0];
			gre_item.protocol = pt[1];
			pattern[p++].spec = &gre_item;
			break;
		}
		case DOCA_FLOW_TUN_GTPU:
		{
			pattern[p].type = RTE_FLOW_ITEM_TYPE_GTPU;
			struct rte_flow_item_gtp gtp_item;
			gtp_item.teid = mmatch->tun.gtp_teid;
			pattern[p++].spec = &gtp_item;
			break;
		}
		default:
			printf("TUNNEL OTHER TYPE: %d\n", mmatch->tun.type);
			break;
		}

		// inner mmatch
		if ((memcmp(mmatch->in_dst_mac, mac0, sizeof(mac0))) != 0 || (memcmp(mmatch->in_src_mac, mac0, sizeof(mac0))) != 0)
		{
			struct rte_flow_item_eth in_mac_spec;
			memcpy(in_mac_spec.hdr.dst_addr.addr_bytes, mmatch->in_dst_mac, DOCA_ETHER_ADDR_LEN);
			memcpy(in_mac_spec.hdr.src_addr.addr_bytes, mmatch->in_src_mac, DOCA_ETHER_ADDR_LEN);
			pattern[p].type = RTE_FLOW_ITEM_TYPE_ETH;
			pattern[p++].spec = &in_mac_spec;
		}
		if (mmatch->in_dst_ip.ipv4_addr != ip0 || mmatch->out_src_ip.ipv4_addr != ip0)
		{
			pattern[p].type = RTE_FLOW_ITEM_TYPE_IPV4;
			struct rte_flow_item_ipv4 in_ip_spec;
			memset(&in_ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
			in_ip_spec.hdr.dst_addr = mmatch->in_dst_ip.ipv4_addr;
			in_ip_spec.hdr.src_addr = mmatch->in_src_ip.ipv4_addr;
			pattern[p++].spec = &in_ip_spec;
		}
		if (mmatch->in_l4_type == IPPROTO_UDP)
		{
			if (mmatch->in_dst_port != port0 || mmatch->in_src_port != port0)
			{
				pattern[p].type = RTE_FLOW_ITEM_TYPE_UDP;
				struct rte_flow_item_udp in_udp_spec;
				memset(&in_udp_spec, 0, sizeof(struct rte_flow_item_udp));
				in_udp_spec.hdr.dst_port = mmatch->in_dst_port;
				in_udp_spec.hdr.src_port = mmatch->in_src_port;
				pattern[p++].spec = &in_udp_spec;
			}
		}
		else if (mmatch->in_l4_type == IPPROTO_TCP)
		{
			if (mmatch->in_dst_port != port0 || mmatch->in_src_port != port0)
			{
				pattern[p].type = RTE_FLOW_ITEM_TYPE_TCP;
				struct rte_flow_item_tcp in_tcp_spec;
				memset(&in_tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
				in_tcp_spec.hdr.dst_port = mmatch->in_dst_port;
				in_tcp_spec.hdr.src_port = mmatch->in_src_port;
				pattern[p++].spec = &in_tcp_spec;
			}
		}
	}

	pattern[p].type = RTE_FLOW_ITEM_TYPE_END;
	printf("patern:");
	for (int i = 0; i < p; i++)
	{
		printf(" %d", pattern[i].type);
	}
	printf("\n");
	/*convert actions -> action*/
	// modify packets
	p = 0;
	if (memcmp(mactions->mod_dst_mac, mac0, sizeof(mac0)) != 0)
	{
		action[p].type = RTE_FLOW_ACTION_TYPE_SET_MAC_DST;
		struct rte_flow_action_set_mac dst_mac;
		memcpy(dst_mac.mac_addr, mactions->mod_dst_mac, DOCA_ETHER_ADDR_LEN);
		action[p++].conf = &dst_mac;
	}
	if (memcmp(mactions->mod_src_mac, mac0, sizeof(mac0)) != 0)
	{
		action[p].type = RTE_FLOW_ACTION_TYPE_SET_MAC_SRC;
		struct rte_flow_action_set_mac src_mac;
		memcpy(src_mac.mac_addr, mactions->mod_src_mac, DOCA_ETHER_ADDR_LEN);
		action[p++].conf = &src_mac;
	}
	if (mactions->mod_dst_ip.ipv4_addr != ip0)
	{
		action[p].type = RTE_FLOW_ACTION_TYPE_SET_IPV4_DST;
		struct rte_flow_action_set_ipv4 dst_ipv4;
		dst_ipv4.ipv4_addr = mactions->mod_dst_ip.ipv4_addr;
		action[p++].conf = &dst_ipv4;
	}
	if (mactions->mod_src_ip.ipv4_addr != ip0)
	{
		action[p].type = RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC;
		struct rte_flow_action_set_ipv4 src_ipv4;
		src_ipv4.ipv4_addr = mactions->mod_src_ip.ipv4_addr;
		action[p++].conf = &src_ipv4;
	}
	if (mactions->mod_dst_port != port0)
	{
		action[p].type = RTE_FLOW_ACTION_TYPE_SET_TP_DST;
		struct rte_flow_action_set_tp dst_tp;
		dst_tp.port = mactions->mod_dst_port;
		action[p++].conf = &dst_tp;
	}
	if (mactions->mod_src_port != port0)
	{
		action[p].type = RTE_FLOW_ACTION_TYPE_SET_TP_SRC;
		struct rte_flow_action_set_tp src_tp;
		src_tp.port = mactions->mod_src_port;
		action[p++].conf = &src_tp;
	}

	// do vxlan encap/decap
	if (mactions->decap)
	{
		action[p++].type = RTE_FLOW_ACTION_TYPE_VXLAN_DECAP;
	}
	if (mactions->has_encap)
	{
		action[p].type = RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP;
		struct rte_flow_action_vxlan_encap _vlencp;
		struct rte_flow_item items[5];

		items[0].type = RTE_FLOW_ITEM_TYPE_ETH;
		struct rte_flow_item_eth encap_eth_item;
		memcpy(encap_eth_item.hdr.dst_addr.addr_bytes, mactions->encap.dst_mac, DOCA_ETHER_ADDR_LEN);
		memcpy(encap_eth_item.hdr.src_addr.addr_bytes, mactions->encap.src_mac, DOCA_ETHER_ADDR_LEN);
		items[0].spec = &encap_eth_item;

		items[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
		struct rte_flow_item_ipv4 encap_ip_item;
		encap_ip_item.hdr.dst_addr = mactions->encap.dst_ip.ipv4_addr;
		encap_ip_item.hdr.src_addr = mactions->encap.src_ip.ipv4_addr;
		items[1].spec = &encap_ip_item;

		items[2].type = RTE_FLOW_ITEM_TYPE_UDP;
		struct rte_flow_item_udp encap_udp_item;
		encap_udp_item.hdr.dst_port = RTE_BE16(RTE_VXLAN_DEFAULT_PORT);
		items[2].spec = &encap_udp_item;

		items[3].type = RTE_FLOW_ITEM_TYPE_VXLAN;
		struct rte_flow_item_vxlan encap_vxlan_item;
		uint8_t *pt = (uint8_t *)&(mactions->encap.tun.vxlan_tun_id);
		for (int i = 0; i < 3; i++)
		{
			encap_vxlan_item.vni[i] = pt[3 - i];
		}
		items[3].spec = &encap_vxlan_item;

		items[4].type = RTE_FLOW_ITEM_TYPE_END;

		_vlencp.definition = items;
		action[p++].conf = &_vlencp;
	}

	// forward actions
	switch (fwd->type)
	{
	case 1:
		// DOCA_FLOW_FWD_RSS
		/*
		action[p].type=RTE_FLOW_ACTION_TYPE_RSS;
		struct rte_flow_action_rss _rss;
		_rss.queue_num=fwd->num_of_queues;
		_rss.queue=fwd->rss_queues;
		action[p++].conf=&_rss;
		*/
		break;
	case 2:
		// DOCA_FLOW_FWD_PORT
		action[p].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
		struct rte_flow_action_port_id _pid;
		_pid.id = fwd->port_id;
		action[p++].conf = &_pid;
		break;
	case 3:
		// DOCA_FLOW_FWD_PIPE
		// printf("DOCA FWD PIPE\n");
		action[p].type = RTE_FLOW_ACTION_TYPE_JUMP;
		struct rte_flow_action_jump _jump;
		_jump.group = fwd->next_pipe->group_id;
		action[p++].conf = &_jump;
		break;
	case 4:
		// DOCA_FLOW_FWD_DROP
		action[p++].type = RTE_FLOW_ACTION_TYPE_DROP;
		break;
	default:
		printf("DOCA FWD OTHER TYPE: %d\n", fwd->type);
		break;
	}

	struct rte_flow_action_queue queue = {.index = pipe_queue};
	action[p].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[p++].conf = &queue;

	action[p].type = RTE_FLOW_ACTION_TYPE_END;

	printf("action:");
	for (int i = 0; i < p; i++)
	{
		printf(" %d", action[i].type);
	}
	printf("\n");

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
			printf("Flow can't be created %d message: %s\n",
				   rte_error.type,
				   rte_error.message ? rte_error.message : "(no stated reason)");
			rte_exit(EXIT_FAILURE, "error in creating flow");
		}
		output_flow(port_id, &attr, pattern, action, &error);
	}
	else
	{
		printf("ERROR while validate flow: %d\n", res);
		printf("%s\n", rte_error.message);
	}
}

struct doca_flow_pipe_entry *
doca_flow_control_pipe_add_entry(uint16_t pipe_queue,
								 uint8_t priority,
								 struct doca_flow_pipe *pipe,
								 const struct doca_flow_match *match,
								 const struct doca_flow_match *match_mask,
								 const struct doca_flow_fwd *fwd,
								 struct doca_flow_error *error) {}

int doca_flow_pipe_rm_entry(uint16_t pipe_queue, void *usr_ctx,
							struct doca_flow_pipe_entry *entry) {}

void doca_flow_destroy_pipe(uint16_t port_id,
							struct doca_flow_pipe *pipe) {}

void doca_flow_port_pipes_flush(uint16_t port_id) {}

void doca_flow_destroy_port(uint16_t port_id)
{
	rte_eal_cleanup();
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
