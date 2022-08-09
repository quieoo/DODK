

/**
 * @file doca_flow_net.h
 * @page doca flow net
 * @defgroup FLOW_NET flow net define
 * DOCA HW offload flow net structure define. For more details please refer to
 * the user guide on DOCA devzone.
 *
 * @{
 */

#ifndef DOCA_FLOW_NET_H_
#define DOCA_FLOW_NET_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint16_t doca_be16_t; /**< 16-bit big-endian value. */
typedef uint32_t doca_be32_t; /**< 32-bit big-endian value. */
typedef uint64_t doca_be64_t; /**< 64-bit big-endian value. */

#define DOCA_ETHER_ADDR_LEN (6) /**< length of ether add length. */
#define DOCA_PROTO_TCP (6) /**< Transmission Control Protocol. */
#define DOCA_PROTO_UDP (17) /**< User Datagram Protocol. */
#define DOCA_PROTO_GRE (47) /**< Cisco GRE tunnels (rfc 1701,1702). */
#define DOCA_GTPU_PORT (2152) /**< gtpu upd port id. */
#define DOCA_VXLAN_DEFAULT_PORT (4789) /**< default vxlan port id. */

/* Ethernet frame types */
#define DOCA_ETHER_TYPE_IPV4 (0x0800) /**< IPv4 Protocol. */
#define DOCA_ETHER_TYPE_IPV6 (0x86DD) /**< IPv6 Protocol. */
#define DOCA_ETHER_TYPE_TEB  (0x6558) /**< Transparent Ethernet Bridging. */

/**
 * @brief doca flow ip address type
 */
enum doca_flow_ip_type {
	DOCA_FLOW_ADDR_NONE = 0,
	/**< ip address is not set */
	DOCA_FLOW_IP4_ADDR = 4,
	/**< ip address is ipv4 */
	DOCA_FLOW_IP6_ADDR = 6,
	/**< ip address is ipv6 */
};

/**
 * @brief doca flow ip address
 */
struct doca_flow_ip_addr {
	uint8_t type;
	/**< ip address type */
	union {
		doca_be32_t ipv4_addr;
		/**< ipv4 address if type is ipv4 */
		doca_be32_t ipv6_addr[4];
		/**< ipv6 address if type is ipv6 */
	};
};

/**
 * @brief doca flow tunnel type
 */
enum doca_flow_tun_type {
	DOCA_FLOW_TUN_NONE = 0,
	/**< tunnel is not set */
	DOCA_FLOW_TUN_VXLAN,
	/**< tunnel is vxlan type */
	DOCA_FLOW_TUN_GTPU,
	/**< tunnel is gtpu type */
	DOCA_FLOW_TUN_GRE,
	/**< tunnel is gre type */
};

/**
 * @brief doca flow tunnel information
 */
struct doca_flow_tun {
	enum doca_flow_tun_type type;
	/**< tunnel type */
	union {
		struct {
			doca_be32_t vxlan_tun_id;
			/**< vxlan vni(24) + reserved (8). */
		};
		/**< vxlan information if tunnel is vxlan */
		struct {
			doca_be32_t gre_key;
			/**< gre key */
			doca_be16_t protocol;
			/**< next protocol */
		};
		/**< gre information if tunnel is gre */
		struct {
			doca_be32_t gtp_teid;
			/**< gtp teid */
		};
		/**< gtp information if tunnel is gtp */
	};
};

#ifdef __cplusplus
} /* extern "C" */
#endif

/** @} */

#endif /* DOCA_FLOW_NET_H_ */
