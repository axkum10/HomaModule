/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+ */

/* This file contains definitions related to the UDP tunnel that carries
 * all Homa packets.
 */

#ifndef _HOMA_UDP_TUNNEL_H
#define _HOMA_UDP_TUNNEL_H

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include "homa_peer.h"

int      homa_udp_encap_rcv(struct sock *sk, struct sk_buff *skb);
void     homa_udp_encap_err_rcv(struct sock *sk, struct sk_buff *skb, int err,
				__be16 port, u32 info, u8 *payload);
void     homa_udp_destroy(struct homa_net *hnet);
int      homa_udp_init(struct homa_net *hnet, struct net *net);
void     homa_udp_xmit(struct sk_buff *skb, struct homa_sock *hsk,
		       struct homa_route *route, u8 tos);
#ifndef __STRIP__ /* See strip.py */
int      homa_udp_gro_complete(struct sock *sk, struct sk_buff *skb,
			       int nhoff);
struct sk_buff *homa_udp_gro_receive(struct sock *sk,
				     struct list_head *held_list,
				     struct sk_buff *skb);
#endif /* See strip.py */

/**
 * homa_header() - Return the Homa header of a packet.
 * @skb:     Packet whose transport header refers to its UDP header.
 * Return:   The Homa header, which immediately follows the UDP header.
 */
static inline struct homa_common_hdr *homa_header(struct sk_buff *skb)
{
	return (struct homa_common_hdr *)(skb_transport_header(skb) +
					  sizeof(struct udphdr));
}

/**
 * homa_make_header_avl() - Invokes pskb_may_pull to make sure that all the
 * Homa header information for an incoming packet is in the linear part of
 * the skb, along with any headers that precede it.
 * @skb:     Packet for which header is needed.
 * Return:   The result of pskb_may_pull (true for success)
 */
static inline bool homa_make_header_avl(struct sk_buff *skb)
{
	int pull_length;

	pull_length = (u8 *)homa_header(skb) - skb->data + HOMA_MAX_HEADER;
	if (pull_length > skb->len)
		pull_length = skb->len;
	return pskb_may_pull(skb, pull_length);
}

/**
 * homa_ip_udp_hdr_len() - Return the number of bytes of IP and UDP headers
 * that precede the Homa header in packets sent on a route.
 * @route:   Route on which the packets will be sent.
 * Return:   See above.
 */
static inline int homa_ip_udp_hdr_len(const struct homa_route *route)
{
	return (ipv6_addr_v4mapped(&route->key.daddr) ? sizeof(struct iphdr) :
		sizeof(struct ipv6hdr)) + sizeof(struct udphdr);
}

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_udp_held_is_homa() - Return true if a packet held for GRO is a
 * Homa packet.
 * @skb:     Packet on a GRO list; its network and transport headers must
 *           be set.
 * Return:   See above.
 */
static inline bool homa_udp_held_is_homa(struct sk_buff *skb)
{
	int protocol;

	protocol = skb_is_ipv6(skb) ? ipv6_hdr(skb)->nexthdr :
				      ip_hdr(skb)->protocol;
	return protocol == IPPROTO_UDP &&
	       skb_headlen(skb) >= skb_transport_offset(skb) +
				   sizeof(struct udphdr) &&
	       udp_hdr(skb)->dest == htons(HOMA_UDP_PORT);
}
#endif /* See strip.py */

#endif /* _HOMA_UDP_TUNNEL_H */
