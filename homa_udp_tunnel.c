// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

/* This file implements the UDP tunnel that carries all Homa packets. Each
 * Homa packet travels in a UDP datagram whose source and destination ports
 * are both HOMA_UDP_PORT. The functions here add the UDP header to outgoing
 * packets and remove it from incoming ones, so the rest of Homa deals only
 * with Homa headers.
 */

#include "homa_impl.h"
#include <net/udp_tunnel.h>
#include "homa_peer.h"
#include "homa_rpc.h"
#include "homa_udp_tunnel.h"

#ifndef __STRIP__ /* See strip.py */
#include "homa_offload.h"
#endif /* See strip.py */

/**
 * homa_udp_init() - Initialize UDP tunneling for a network namespace.
 * @hnet:    Homa's information about the namespace.
 * @net:     The network namespace.
 * Return:   Zero for success, otherwise a negative errno.
 */
int homa_udp_init(struct homa_net *hnet, struct net *net)
{
	struct udp_tunnel_sock_cfg tunnel = {
		/* Any nonzero value enables the encap callbacks. */
		.encap_type = 1,
		.encap_rcv = homa_udp_encap_rcv,
		.encap_err_rcv = homa_udp_encap_err_rcv,
#ifndef __STRIP__ /* See strip.py */
		.gro_receive = homa_udp_gro_receive,
		.gro_complete = homa_udp_gro_complete,
#endif /* See strip.py */
	};
	struct udp_port_cfg port = {
		.family = AF_INET,
		.local_udp_port = htons(HOMA_UDP_PORT),
		.use_udp_checksums = true,
	};
	struct socket *udp4, *udp6;
	int err;

	err = udp_sock_create4(net, &port, &udp4);
	if (err)
		return err;
	port.family = AF_INET6;
	port.ipv6_v6only = true;
	port.use_udp6_tx_checksums = true;
	port.use_udp6_rx_checksums = true;
	err = udp_sock_create6(net, &port, &udp6);
	if (err) {
		udp_tunnel_sock_release(udp4);
		return err;
	}
	setup_udp_tunnel_sock(net, udp4, &tunnel);
	setup_udp_tunnel_sock(net, udp6, &tunnel);
	rcu_assign_pointer(hnet->udp4, udp4);
	rcu_assign_pointer(hnet->udp6, udp6);

	/* The callbacks discard packets until sk_user_data is set, so set
	 * it only after both sockets are ready.
	 */
	rcu_assign_sk_user_data(udp4->sk, hnet);
	rcu_assign_sk_user_data(udp6->sk, hnet);
	return 0;
}

/**
 * homa_udp_destroy() - This function is invoked during namespace
 * destruction to clean up information related to UDP tunneling. It must
 * not be invoked until all Homa sockets in the namespace have been shut
 * down.
 * @hnet:    Homa's information about the namespace.
 */
void homa_udp_destroy(struct homa_net *hnet)
{
	struct socket *udp4 = rcu_access_pointer(hnet->udp4);
	struct socket *udp6 = rcu_access_pointer(hnet->udp6);

	RCU_INIT_POINTER(hnet->udp4, NULL);
	RCU_INIT_POINTER(hnet->udp6, NULL);

	/* udp_tunnel_sock_release clears sk_user_data and waits for
	 * callbacks in progress to finish.
	 */
	if (udp4)
		udp_tunnel_sock_release(udp4);
	if (udp6)
		udp_tunnel_sock_release(udp6);
}

/**
 * homa_udp_xmit() - Encapsulate a Homa packet in a UDP datagram and
 * transmit it.
 * @skb:     Packet to transmit, with skb->data at the Homa header. The
 *           packet is consumed.
 * @hsk:     Socket on whose behalf the packet is sent.
 * @route:   Route to use to transmit the packet.
 * @tos:     Value for the TOS field of the IP header (traffic class for
 *           IPv6).
 */
void homa_udp_xmit(struct sk_buff *skb, struct homa_sock *hsk,
		   struct homa_route *route, u8 tos)
{
	bool ipv6 = !ipv6_addr_v4mapped(&route->peer->addr);
	struct socket *udp_sock;
	struct dst_entry *dst;

	skb->protocol = htons(ipv6 ? ETH_P_IPV6 : ETH_P_IP);
	skb->mark = route->key.mark;
	skb->priority = READ_ONCE(hsk->sock.sk_priority);
	skb->encapsulation = 0;

	/* Arrange for the UDP checksum to be computed (by the NIC, if
	 * possible). The UDP header will be added just before skb->data.
	 * CHECKSUM_NONE causes GSO packets to be segmented in software.
	 */
	skb->csum_start = skb_headroom(skb) - sizeof(struct udphdr);
	skb->csum_offset = offsetof(struct udphdr, check);
#ifndef __STRIP__ /* See strip.py */
	skb->ip_summed = skb_is_gso(skb) && !hsk->homa->gso_force_software ?
			 CHECKSUM_PARTIAL : CHECKSUM_NONE;
#else /* See strip.py */
	skb->ip_summed = skb_is_gso(skb) ? CHECKSUM_PARTIAL : CHECKSUM_NONE;
#endif /* See strip.py */

	/* udp_tunnel_xmit_skb and udp_tunnel6_xmit_skb must be invoked with
	 * bottom halves disabled.
	 */
	rcu_read_lock_bh();
	udp_sock = ipv6 ? rcu_dereference_bh(hsk->hnet->udp6) :
			  rcu_dereference_bh(hsk->hnet->udp4);
	dst = rcu_dereference_bh(route->dst);

	/* udp_tunnel_xmit_skb and udp_tunnel6_xmit_skb consume this
	 * reference.
	 */
	dst_hold(dst);
	if (ipv6) {
		struct flowi6 *flow = &route->flow.u.ip6;

		udp_tunnel6_xmit_skb(dst, udp_sock->sk, skb, NULL, &flow->saddr,
				     &flow->daddr, tos, ip6_dst_hoplimit(dst),
				     flow->flowlabel, htons(HOMA_UDP_PORT),
				     htons(HOMA_UDP_PORT), false, 0);
	} else {
		struct flowi4 *flow = &route->flow.u.ip4;

		udp_tunnel_xmit_skb((struct rtable *)dst, udp_sock->sk, skb,
				    flow->saddr, flow->daddr, tos,
				    ip4_dst_hoplimit(dst), htons(IP_DF),
				    htons(HOMA_UDP_PORT), htons(HOMA_UDP_PORT),
				    false, false, 0);
	}
	rcu_read_unlock_bh();
}

/**
 * homa_udp_encap_rcv() - This function is a wrapper around homa_softirq
 * that removes the IP and UDP headers from incoming packets, so that
 * homa_softirq sees only the Homa headers.
 * @sk:      Homa's UDP tunnel socket for the namespace.
 * @skb:     Incoming packet, whose UDP checksum has been verified (or which
 *           has no checksum). Its transport header refers to the UDP
 *           header. The packet is consumed.
 * Return:   Always 0.
 */
int homa_udp_encap_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct sk_buff **link, *child;

	if (!rcu_dereference_sk_user_data(sk)) {
		kfree_skb_reason(skb, SKB_DROP_REASON_NO_SOCKET);
		return 0;
	}
	if (!homa_make_header_avl(skb)) {
		kfree_skb_reason(skb, SKB_DROP_REASON_HDR_TRUNC);
		return 0;
	}
	__skb_pull(skb, (u8 *)homa_header(skb) - skb->data);

	link = &skb_shinfo(skb)->frag_list;
	child = *link;
	while (child) {
		if (!homa_make_header_avl(child)) {
			*link = child->next;
			child->next = NULL;
			kfree_skb_reason(child, SKB_DROP_REASON_HDR_TRUNC);
		} else {
			__skb_pull(child, (u8 *)homa_header(child) -
				   child->data);
			link = &child->next;
		}
		child = *link;
	}
	homa_softirq(skb);
	return 0;
}

/**
 * homa_udp_encap_err_rcv() - Invoked by the UDP stack when an ICMP error
 * message arrives for a Homa packet; aborts the RPCs affected by the error.
 * @sk:      Homa's UDP tunnel socket for the namespace.
 * @skb:     The ICMP message; skb->data refers to the IP header of the
 *           original packet. Not consumed.
 * @err:     Positive errno derived from the ICMP type and code.
 * @port:    UDP destination port of the original packet.
 * @info:    ICMP information field.
 * @payload: Homa header of the original packet (only the part included in
 *           the ICMP message is present).
 */
void homa_udp_encap_err_rcv(struct sock *sk, struct sk_buff *skb, int err,
			    __be16 port, u32 info, u8 *payload)
{
	struct homa_net *hnet = rcu_dereference_sk_user_data(sk);
	__be16 *dport, dport_buf;
	struct in6_addr daddr;
	int homa_port = 0;
	int error = 0;
	int type, code;

	/* Homa doesn't use path MTU discovery. */
	if (!hnet || !err || err == EMSGSIZE)
		return;
	if (sk->sk_family == AF_INET) {
		type = icmp_hdr(skb)->type;
		code = icmp_hdr(skb)->code;
		ipv6_addr_set_v4mapped(((struct iphdr *)skb->data)->daddr,
				       &daddr);
		if (type == ICMP_DEST_UNREACH && code == ICMP_PORT_UNREACH)
			error = -ENOTCONN;
		else if (type == ICMP_DEST_UNREACH && code == ICMP_PROT_UNREACH)
			error = -EPROTONOSUPPORT;
		else if (type == ICMP_DEST_UNREACH)
			error = -EHOSTUNREACH;
		else
			pr_notice("%s invoked with info %x, ICMP type %d, ICMP code %d\n",
				  __func__, info, type, code);
	} else {
		type = icmp6_hdr(skb)->icmp6_type;
		code = icmp6_hdr(skb)->icmp6_code;
		daddr = ((struct ipv6hdr *)skb->data)->daddr;
		if (type == ICMPV6_DEST_UNREACH && code == ICMPV6_PORT_UNREACH)
			error = -ENOTCONN;
		else if (type == ICMPV6_DEST_UNREACH &&
			 code == ICMPV6_ADDR_UNREACH)
			error = -EHOSTUNREACH;
		else if (type == ICMPV6_PARAMPROB &&
			 code == ICMPV6_UNK_NEXTHDR)
			error = -EPROTONOSUPPORT;
	}
	if (error == 0)
		return;
	if (error == -ENOTCONN) {
		/* If the ICMP message doesn't include the Homa port, abort
		 * all RPCs for the peer.
		 */
		dport = skb_header_pointer(skb, payload - skb->data +
					   offsetof(struct homa_common_hdr,
						    dport),
					   sizeof(dport_buf), &dport_buf);
		if (dport)
			homa_port = ntohs(*dport);
	}
	homa_abort_rpcs(hnet->homa, &daddr, homa_port, error);
}

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_udp_gro_receive() - Invoked by the UDP stack's GRO code for each
 * incoming Homa packet; passes the packet to homa_gro_receive.
 * @sk:         Homa's UDP tunnel socket for the namespace.
 * @held_list:  Pointer to header for list of packets that are being
 *              held for possible GRO merging.
 * @skb:        The newly arrived packet.
 * Return:      See homa_gro_receive.
 */
struct sk_buff *homa_udp_gro_receive(struct sock *sk,
				     struct list_head *held_list,
				     struct sk_buff *skb)
{
	/* Packets with no UDP checksum are rejected here: the UDP stack
	 * accepts them for IPv4, and packets merged by homa_gro_receive
	 * don't pass through the UDP stack's receive checks.
	 */
	if (!rcu_dereference_sk_user_data(sk) || NAPI_GRO_CB(skb)->flush ||
	    !homa_make_header_avl(skb) || !udp_hdr(skb)->check) {
		NAPI_GRO_CB(skb)->flush = 1;
		return NULL;
	}
	return homa_gro_receive(sk, held_list, skb);
}

/**
 * homa_udp_gro_complete() - Invoked by the UDP stack's GRO code just
 * before a packet held for GRO is passed up the network stack.
 * @sk:      Homa's UDP tunnel socket for the namespace.
 * @skb:     The packet for which GRO processing is now finished.
 * @nhoff:   Offset of the Homa header within the packet (not used).
 * Return:   See homa_gro_complete.
 */
int homa_udp_gro_complete(struct sock *sk, struct sk_buff *skb, int nhoff)
{
	return homa_gro_complete(skb);
}
#endif /* See strip.py */
