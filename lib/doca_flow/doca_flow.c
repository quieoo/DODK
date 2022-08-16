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
	int port_id;
};

struct doca_flow_pipe *
doca_flow_create_pipe(const struct doca_flow_pipe_cfg *cfg,
					  const struct doca_flow_fwd *fwd,
					  const struct doca_flow_fwd *fwd_miss,
					  struct doca_flow_error *error)
{
	struct doca_flow_pipe *pipe = malloc(sizeof(struct doca_flow_pipe));

	pipe->port_id = cfg->port->port_id;
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
	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));
	memset(&attr, 0, sizeof(struct rte_flow_attr));

	attr.ingress = 1;

	/*
		convert match->pattern
		doca match items are initialized with 0. A 0-item means match all values in this field,
		which represents with a empry type(no spec) in dpdk.
		doca assumes a packet will contain a vxlan-tp-ip-mac tunple, so we add all of those dpdk pattern type
		and the spec is set according to match values
	*/
	int p = 0;
	pattern[p].type = RTE_FLOW_ITEM_TYPE_ETH;

	uint8_t mac0[6] = {0};
	if ((memcmp(match->out_dst_mac, mac0, sizeof(mac0))) != 0 || (memcmp(match->out_src_mac, mac0, sizeof(mac0))) != 0)
	{
		printf("set mac pattern\n");
		struct rte_flow_item_eth mac_spec;
		memset(&mac_spec, 0, sizeof(struct rte_flow_item_eth));
		memcpy(mac_spec.hdr.dst_addr.addr_bytes, match->out_dst_mac, DOCA_ETHER_ADDR_LEN);
		memcpy(mac_spec.hdr.src_addr.addr_bytes, match->out_src_mac, DOCA_ETHER_ADDR_LEN);
		pattern[p].spec = &mac_spec;
	}
	else
	{
		printf("skip pattern\n");
	}
	p++;

	pattern[p].type = RTE_FLOW_ITEM_TYPE_IPV4;
	uint32_t ip0 = 0;
	if (match->out_dst_ip.ipv4_addr != ip0 || match->out_src_ip.ipv4_addr != ip0)
	{
		struct rte_flow_item_ipv4 ip_spec;
		memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
		ip_spec.hdr.dst_addr = match->out_dst_ip.ipv4_addr;
		ip_spec.hdr.src_addr = match->out_src_ip.ipv4_addr;
		pattern[p].spec = &ip_spec;
	}
	p++;

	uint16_t port0 = 0;
	if (match->out_l4_type == IPPROTO_UDP)
	{
		pattern[p].type = RTE_FLOW_ITEM_TYPE_UDP;
		if (match->out_dst_port != port0 || match->out_src_port != port0)
		{
			struct rte_flow_item_udp udp_spec;
			memset(&udp_spec, 0, sizeof(struct rte_flow_item_udp));
			udp_spec.hdr.dst_port = match->out_dst_port;
			udp_spec.hdr.src_port = match->out_src_port;
			pattern[p].spec = &udp_spec;
		}
		p++;
	}
	else if (match->out_l4_type == IPPROTO_TCP)
	{
		pattern[p].type = RTE_FLOW_ITEM_TYPE_TCP;
		if (match->out_dst_port != port0 || match->out_src_port != port0)
		{
			struct rte_flow_item_tcp tcp_spec;
			memset(&tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
			tcp_spec.hdr.dst_port = match->out_dst_port;
			tcp_spec.hdr.src_port = match->out_src_port;
			pattern[p].spec = &tcp_spec;
		}
		p++;
	}
	pattern[p].type = RTE_FLOW_ITEM_TYPE_END;

	/*convert actions -> action*/
	// modify packets
	p = 0;
	action[p].type = RTE_FLOW_ACTION_TYPE_SET_MAC_DST;
	struct rte_flow_action_set_mac dst_mac;
	for (int i = 0; i < 6; i++)
	{
		dst_mac.mac_addr[i] = actions->mod_dst_mac[i];
	}
	action[p++].conf = &dst_mac;

	action[p].type = RTE_FLOW_ACTION_TYPE_SET_IPV4_DST;
	struct rte_flow_action_set_ipv4 set_ipv4;
	set_ipv4.ipv4_addr = actions->mod_dst_ip.ipv4_addr;
	action[p++].conf = &set_ipv4;

	action[p].type = RTE_FLOW_ACTION_TYPE_SET_TP_DST;
	struct rte_flow_action_set_tp set_tp;
	set_tp.port = actions->mod_dst_port;
	action[p++].conf = &set_tp;

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
		printf("DOCA FWD PIPE\n");
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

	// get port id
	int port_id = pipe->port_id;

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
