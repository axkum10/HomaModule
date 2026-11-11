// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

#include "homa_impl.h"
#include "homa_peer.h"
#include "homa_rpc.h"
#include "homa_sock.h"
#include "homa_udp_tunnel.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#ifndef __STRIP__ /* See strip.py */
#include "homa_offload.h"

#define cur_offload_core (&per_cpu(homa_offload_core, smp_processor_id()))
#endif /* See strip.py */

FIXTURE(homa_udp_tunnel) {
	struct homa homa;
	struct homa_net *hnet;
	struct homa_sock hsk;
	struct in6_addr client;
	struct in6_addr server;
	struct homa_data_hdr data;
};

FIXTURE_SETUP(homa_udp_tunnel)
{
	homa_init(&self->homa);
	self->hnet = mock_hnet(0, &self->homa);
	mock_sock_init(&self->hsk, self->hnet, 99);
	self->client = unit_get_in_addr("1.2.3.4");
	self->server = unit_get_in_addr("5.6.7.8");
	memset(&self->data, 0, sizeof(self->data));
	self->data.common.sport = htons(40000);
	self->data.common.dport = htons(99);
	self->data.common.sender_id = cpu_to_be64(100);
	self->data.common.type = DATA;
	self->data.msg_length = htonl(64);
	unit_log_clear();
}

FIXTURE_TEARDOWN(homa_udp_tunnel)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

/**
 * tx_skb() - Create an outgoing Homa DATA packet with the headroom and
 * layout that the real packet builders produce (skb->data at the Homa
 * header).
 * @header:  Homa DATA header to copy.
 * @payload: Number of data bytes to add after the header.
 * Return:   The new packet.
 */
static struct sk_buff *tx_skb(struct homa_data_hdr *header, int payload)
{
	struct sk_buff *skb;

	skb = __homa_skb_alloc(sizeof(*header) + payload);
	memcpy(skb_put(skb, sizeof(*header)), header, sizeof(*header));
	memset(skb_put(skb, payload), 0, payload);
	memset(homa_get_skb_info(skb), 0, sizeof(struct homa_skb_info));
	homa_get_skb_info(skb)->data_bytes = payload;
	return skb;
}

TEST_F(homa_udp_tunnel, homa_udp_init__basics)
{
	struct socket *udp4 = rcu_access_pointer(self->hnet->udp4);
	struct socket *udp6 = rcu_access_pointer(self->hnet->udp6);

	ASSERT_NE(NULL, udp4);
	ASSERT_NE(NULL, udp6);
	EXPECT_EQ(AF_INET, udp4->sk->sk_family);
	EXPECT_EQ(AF_INET6, udp6->sk->sk_family);
	EXPECT_EQ(htons(HOMA_UDP_PORT), mock_udp_port_cfg[0].local_udp_port);
	EXPECT_EQ(htons(HOMA_UDP_PORT), mock_udp_port_cfg[1].local_udp_port);
	EXPECT_TRUE((bool)mock_udp_port_cfg[0].use_udp_checksums);
	EXPECT_TRUE((bool)mock_udp_port_cfg[1].ipv6_v6only);
	EXPECT_TRUE((bool)mock_udp_port_cfg[1].use_udp6_tx_checksums);
	EXPECT_TRUE((bool)mock_udp_port_cfg[1].use_udp6_rx_checksums);
	EXPECT_NE(0, udp_sk(udp4->sk)->encap_type);
	EXPECT_NE(0, udp_sk(udp6->sk)->encap_type);
	EXPECT_EQ(&homa_udp_encap_rcv, udp_sk(udp4->sk)->encap_rcv);
	EXPECT_EQ(&homa_udp_encap_err_rcv, udp_sk(udp6->sk)->encap_err_rcv);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(&homa_udp_gro_receive, udp_sk(udp6->sk)->gro_receive);
	EXPECT_EQ(&homa_udp_gro_complete, udp_sk(udp6->sk)->gro_complete);
#endif /* See strip.py */
	EXPECT_EQ(self->hnet, udp4->sk->sk_user_data);
	EXPECT_EQ(self->hnet, udp6->sk->sk_user_data);
}
TEST_F(homa_udp_tunnel, homa_udp_init__create_ipv4_socket_fails)
{
	struct homa_net fresh;
	int releases = mock_udp_release_calls;

	homa_net_init(&fresh, &self->homa);
	mock_udp_create_errors = 1;
	mock_udp_create_errno = -EAFNOSUPPORT;
	EXPECT_EQ(-EAFNOSUPPORT, homa_udp_init(&fresh, &mock_nets[0]));
	EXPECT_EQ(NULL, rcu_access_pointer(fresh.udp4));
	EXPECT_EQ(NULL, rcu_access_pointer(fresh.udp6));
	EXPECT_EQ(releases, mock_udp_release_calls);
}
TEST_F(homa_udp_tunnel, homa_udp_init__create_ipv6_socket_fails)
{
	struct homa_net fresh;
	int releases = mock_udp_release_calls;

	homa_net_init(&fresh, &self->homa);
	mock_udp_create_errors = 2;
	mock_udp_create_errno = -EADDRINUSE;
	EXPECT_EQ(-EADDRINUSE, homa_udp_init(&fresh, &mock_nets[0]));
	EXPECT_EQ(NULL, rcu_access_pointer(fresh.udp4));
	EXPECT_EQ(NULL, rcu_access_pointer(fresh.udp6));
	EXPECT_EQ(releases + 1, mock_udp_release_calls);
}

TEST_F(homa_udp_tunnel, homa_udp_destroy__basics)
{
	struct homa_net fresh;
	int releases = mock_udp_release_calls;

	homa_net_init(&fresh, &self->homa);
	ASSERT_EQ(0, homa_udp_init(&fresh, &mock_nets[0]));
	homa_udp_destroy(&fresh);
	EXPECT_EQ(releases + 2, mock_udp_release_calls);
	EXPECT_EQ(NULL, rcu_access_pointer(fresh.udp4));
	EXPECT_EQ(NULL, rcu_access_pointer(fresh.udp6));

	/* A second call finds nothing left to release. */
	homa_udp_destroy(&fresh);
	EXPECT_EQ(releases + 2, mock_udp_release_calls);
}

TEST_F(homa_udp_tunnel, homa_udp_xmit__basics)
{
	int i;

	for (i = 0; i < 2; i++) {
		struct homa_route *route;
		struct sk_buff *skb;
		int count = mock_skb_count(), refs;

		mock_ipv6 = i;
		if (i)
			self->client = unit_get_in_addr("2001:db8::1");
		self->hsk.sock.sk_family = i ? AF_INET6 : AF_INET;
		route = homa_route_get(&self->hsk, &self->client);
		ASSERT_FALSE(IS_ERR(route));
		refs = refcount_read(&route->refs);
		skb = tx_skb(&self->data, 64);
		homa_udp_xmit(skb, &self->hsk, route, 6 << 5);
		EXPECT_EQ(count, mock_skb_count());
		EXPECT_EQ(refs, refcount_read(&route->refs));
		EXPECT_EQ(i ? AF_INET6 : AF_INET, mock_udp_last_family);
		EXPECT_EQ(6 << 5, mock_udp_last_tos);
		EXPECT_EQ(htons(HOMA_UDP_PORT), mock_udp_last_header.source);
		EXPECT_EQ(htons(HOMA_UDP_PORT), mock_udp_last_header.dest);
		EXPECT_NE(0, mock_udp_last_header.check);
		EXPECT_EQ(CHECKSUM_NONE, mock_udp_last_ip_summed);
		EXPECT_EQ(offsetof(struct udphdr, check),
			  mock_udp_last_csum_offset);
		homa_route_release(route);
	}
	EXPECT_EQ(2, mock_udp_xmit_calls);
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_udp_tunnel, homa_udp_xmit__gso)
{
	struct homa_route *route = homa_route_get(&self->hsk, &self->client);
	struct sk_buff *skb;

	ASSERT_FALSE(IS_ERR(route));
	skb = tx_skb(&self->data, sizeof(self->data) + 64);
	skb_shinfo(skb)->gso_type = SKB_GSO_UDP_L4;
	skb_shinfo(skb)->gso_size = sizeof(self->data) + 32;
	skb_shinfo(skb)->gso_segs = 2;
	homa_udp_xmit(skb, &self->hsk, route, 0);
	EXPECT_EQ(CHECKSUM_PARTIAL, mock_udp_last_ip_summed);

	skb = tx_skb(&self->data, sizeof(self->data) + 64);
	skb_shinfo(skb)->gso_type = SKB_GSO_UDP_L4;
	skb_shinfo(skb)->gso_size = sizeof(self->data) + 32;
	skb_shinfo(skb)->gso_segs = 2;
	self->homa.gso_force_software = 1;
	homa_udp_xmit(skb, &self->hsk, route, 0);
	EXPECT_EQ(CHECKSUM_NONE, mock_udp_last_ip_summed);
	homa_route_release(route);
}
#endif /* See strip.py */

TEST_F(homa_udp_tunnel, homa_udp_encap_rcv__basics)
{
	struct sock *sk = rcu_access_pointer(self->hnet->udp4)->sk;
	struct sk_buff *skb;

	skb = unit_udp_skb(&self->client, &self->server, &self->data.common,
			   64);

	/* Keep a reference so the packet can be examined afterwards. */
	skb_get(skb);
	EXPECT_EQ(0, homa_udp_encap_rcv(sk, skb));
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ((void *)skb->data, (void *)homa_header(skb));
	EXPECT_EQ(sizeof(self->data) + 64, skb->len);
	EXPECT_EQ(0, memcmp(&self->data, skb->data, sizeof(self->data)));
	kfree_skb(skb);
}
TEST_F(homa_udp_tunnel, homa_udp_encap_rcv__no_namespace)
{
	struct sock *sk = rcu_access_pointer(self->hnet->udp4)->sk;
	struct sk_buff *skb;
	int count;

	skb = unit_udp_skb(&self->client, &self->server, &self->data.common,
			   64);
	count = mock_skb_count();
	rcu_assign_sk_user_data(sk, NULL);
	EXPECT_EQ(0, homa_udp_encap_rcv(sk, skb));
	EXPECT_EQ(count - 1, mock_skb_count());
	EXPECT_EQ(SKB_DROP_REASON_NO_SOCKET, mock_drop_reasons[0]);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_udp_tunnel, homa_udp_encap_rcv__nonlinear_header)
{
	struct sock *sk = rcu_access_pointer(self->hnet->udp4)->sk;
	struct sk_buff *skb = unit_udp_skb(&self->client, &self->server,
					  &self->data.common, 64);
	struct page *page = alloc_page(GFP_KERNEL);
	int nonlinear = skb->len - 4;

	memcpy(page_address(page), skb->data + 4, nonlinear);
	skb_fill_page_desc(skb, 0, page, 0, nonlinear);
	skb->data_len = nonlinear;
	skb->tail -= nonlinear;
	EXPECT_EQ(0, homa_udp_encap_rcv(sk, skb));
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
}
TEST_F(homa_udp_tunnel, homa_udp_encap_rcv__data_at_ip_header)
{
	struct sock *sk = rcu_access_pointer(self->hnet->udp4)->sk;
	struct sk_buff *skb;

	skb = unit_gro_skb(&self->client, &self->server, &self->data.common,
			   64);
	skb_get(skb);
	EXPECT_EQ(0, homa_udp_encap_rcv(sk, skb));
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ((void *)skb->data, (void *)homa_header(skb));
	EXPECT_EQ(sizeof(self->data) + 64, skb->len);
	kfree_skb(skb);
}
TEST_F(homa_udp_tunnel, homa_udp_encap_rcv__frag_list)
{
	struct sock *sk = rcu_access_pointer(self->hnet->udp4)->sk;
	struct sk_buff *head, *child1, *child2;

	self->data.msg_length = htonl(192);
	head = unit_udp_skb(&self->client, &self->server, &self->data.common,
			    64);
	self->data.offset = htonl(64);
	child1 = unit_gro_skb(&self->client, &self->server,
			      &self->data.common, 64);
	self->data.offset = htonl(128);
	child2 = unit_gro_skb(&self->client, &self->server,
			      &self->data.common, 64);
	skb_shinfo(head)->frag_list = child1;
	child1->next = child2;
	skb_get(child1);
	skb_get(child2);

	EXPECT_EQ(0, homa_udp_encap_rcv(sk, head));
	EXPECT_EQ(0, unit_count_drops());
	EXPECT_EQ((void *)child1->data, (void *)homa_header(child1));
	EXPECT_EQ((void *)child2->data, (void *)homa_header(child2));
	EXPECT_EQ(sizeof(self->data) + 64, child1->len);
	EXPECT_EQ(sizeof(self->data) + 64, child2->len);
	kfree_skb(child1);
	kfree_skb(child2);
}

/**
 * use_family() - Configure the fixture and mocks for IPv4 or IPv6.
 * @self:  Test fixture.
 * @ipv6:  Nonzero means IPv6.
 */
static void use_family(FIXTURE_DATA(homa_udp_tunnel) *self, int ipv6)
{
	mock_ipv6 = ipv6;
	self->hsk.sock.sk_family = ipv6 ? AF_INET6 : AF_INET;
	self->client = unit_get_in_addr(ipv6 ? "2001:db8::1" : "1.2.3.4");
	self->server = unit_get_in_addr(ipv6 ? "2001:db8::2" : "5.6.7.8");
}

/**
 * icmp_quote() - Create an ICMP error whose quote is a Homa packet that
 * was sent to self->server through the tunnel.
 * @self:       Test fixture.
 * @ipv6:       True means ICMPv6 quoting IPv6, false means ICMP quoting IPv4.
 * @type:       ICMP type.
 * @code:       ICMP code.
 * @udp:        True means the quote includes the UDP header.
 * @homa_bytes: Number of bytes of the Homa common header included in the
 *              quote after the UDP header.
 * @dport:      Application destination port in the quoted Homa header.
 * Return:      skb with data at the quoted IP header and the transport
 *              header at the ICMP header.
 */
static struct sk_buff *icmp_quote(FIXTURE_DATA(homa_udp_tunnel) *self,
				  bool ipv6, int type, int code, bool udp,
				  int homa_bytes, int dport)
{
	struct homa_common_hdr common = self->data.common;
	struct sk_buff *skb = mock_raw_skb(&self->server, &self->client,
					   ipv6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP,
					   200);

	common.dport = htons(dport);
	if (ipv6) {
		struct icmp6hdr *icmp = skb_put(skb, sizeof(*icmp));
		struct ipv6hdr *ip;

		memset(icmp, 0, sizeof(*icmp));
		icmp->icmp6_type = type;
		icmp->icmp6_code = code;
		__skb_pull(skb, sizeof(*icmp));
		ip = skb_put(skb, sizeof(*ip));
		memset(ip, 0, sizeof(*ip));
		ip->version = 6;
		ip->nexthdr = IPPROTO_UDP;
		ip->saddr = self->client;
		ip->daddr = self->server;
	} else {
		struct icmphdr *icmp = skb_put(skb, sizeof(*icmp));
		struct iphdr *ip;

		memset(icmp, 0, sizeof(*icmp));
		icmp->type = type;
		icmp->code = code;
		__skb_pull(skb, sizeof(*icmp));
		ip = skb_put(skb, sizeof(*ip));
		memset(ip, 0, sizeof(*ip));
		ip->version = 4;
		ip->ihl = 5;
		ip->protocol = IPPROTO_UDP;
		ip->saddr = ipv6_to_ipv4(self->client);
		ip->daddr = ipv6_to_ipv4(self->server);
	}
	if (udp) {
		struct udphdr *uh = skb_put(skb, sizeof(*uh));

		memset(uh, 0, sizeof(*uh));
		uh->source = htons(HOMA_UDP_PORT);
		uh->dest = htons(HOMA_UDP_PORT);
		uh->len = htons(sizeof(*uh) + sizeof(common));
		memcpy(skb_put(skb, homa_bytes), &common, homa_bytes);
	}
	return skb;
}

/**
 * deliver_err() - Invoke the tunnel's error callback the way the UDP
 * stack does for an ICMP error.
 * @sk:     Tunnel socket to use.
 * @quote:  Error packet created by icmp_quote.
 * @ipv6:   True means @quote is an ICMPv6 error.
 * @err:    Positive errno that UDP would have derived from the ICMP error.
 */
static void deliver_err(struct sock *sk, struct sk_buff *quote, bool ipv6,
			int err)
{
	u8 *payload = quote->data + sizeof(struct udphdr) +
		      (ipv6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr));

	udp_sk(sk)->encap_err_rcv(sk, quote, err, htons(HOMA_UDP_PORT), 0,
				  payload);
}

static struct sock *tunnel_sock(struct homa_net *hnet, bool ipv6)
{
	return (ipv6 ? rcu_access_pointer(hnet->udp6) :
		       rcu_access_pointer(hnet->udp4))->sk;
}

TEST_F(homa_udp_tunnel, homa_udp_encap_err_rcv__path_mtu_ignored)
{
	int i;

	for (i = 0; i < 2; i++) {
		struct homa_rpc *rpc;
		struct sk_buff *quote;

		use_family(self, i);
		rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->client,
				      &self->server, 99, 100 + 2 * i, 100,
				      200);
		ASSERT_NE(NULL, rpc);
		quote = icmp_quote(self, i, i ? ICMPV6_PKT_TOOBIG :
					      ICMP_DEST_UNREACH,
				   i ? 0 : ICMP_FRAG_NEEDED, true,
				   sizeof(struct homa_common_hdr), 99);
		mock_printk_output[0] = 0;
		deliver_err(tunnel_sock(self->hnet, i), quote, i, EMSGSIZE);
		EXPECT_EQ(0, rpc->error);
		EXPECT_STREQ("", mock_printk_output);
		kfree_skb(quote);
	}
}

TEST_F(homa_udp_tunnel, homa_udp_encap_err_rcv__zero_err_ignored)
{
	struct homa_rpc *rpc;
	struct sk_buff *quote;

	use_family(self, 0);
	rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->client,
			      &self->server, 99, 100, 100, 200);
	ASSERT_NE(NULL, rpc);
	quote = icmp_quote(self, false, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH,
			   true, sizeof(struct homa_common_hdr), 99);
	deliver_err(tunnel_sock(self->hnet, false), quote, false, 0);
	EXPECT_EQ(0, rpc->error);
	kfree_skb(quote);
}

TEST_F(homa_udp_tunnel, homa_udp_encap_err_rcv__host_unreachable)
{
	int i;

	for (i = 0; i < 2; i++) {
		struct homa_rpc *rpc;
		struct sk_buff *quote;

		use_family(self, i);
		rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->client,
				      &self->server, 99, 100 + 2 * i, 100,
				      200);
		ASSERT_NE(NULL, rpc);
		quote = icmp_quote(self, i, i ? ICMPV6_DEST_UNREACH :
					      ICMP_DEST_UNREACH,
				   i ? ICMPV6_ADDR_UNREACH : ICMP_HOST_UNREACH,
				   true, sizeof(struct homa_common_hdr), 99);
		deliver_err(tunnel_sock(self->hnet, i), quote, i, EHOSTUNREACH);
		EXPECT_EQ(-EHOSTUNREACH, rpc->error);
		kfree_skb(quote);
	}
}

TEST_F(homa_udp_tunnel, homa_udp_encap_err_rcv__protocol_not_supported)
{
	int i;

	for (i = 0; i < 2; i++) {
		struct homa_rpc *rpc;
		struct sk_buff *quote;

		use_family(self, i);
		rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->client,
				      &self->server, 99, 100 + 2 * i, 100,
				      200);
		ASSERT_NE(NULL, rpc);
		quote = icmp_quote(self, i, i ? ICMPV6_PARAMPROB :
					      ICMP_DEST_UNREACH,
				   i ? ICMPV6_UNK_NEXTHDR : ICMP_PROT_UNREACH,
				   true, sizeof(struct homa_common_hdr), 99);
		deliver_err(tunnel_sock(self->hnet, i), quote, i, EPROTO);
		EXPECT_EQ(-EPROTONOSUPPORT, rpc->error);
		kfree_skb(quote);
	}
}

TEST_F(homa_udp_tunnel, homa_udp_encap_err_rcv__port_unreachable)
{
	int i;

	for (i = 0; i < 2; i++) {
		struct homa_rpc *rpc, *other_port;
		struct sk_buff *quote;
		int unreach = i ? ICMPV6_DEST_UNREACH : ICMP_DEST_UNREACH;
		int port = i ? ICMPV6_PORT_UNREACH : ICMP_PORT_UNREACH;

		use_family(self, i);
		rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->client,
				      &self->server, 99, 100 + 4 * i, 100, 200);
		other_port = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
					     &self->client, &self->server, 100,
					     102 + 4 * i, 100, 200);
		ASSERT_NE(NULL, rpc);
		ASSERT_NE(NULL, other_port);

		/* The Homa destination port in the quote selects the RPCs. */
		quote = icmp_quote(self, i, unreach, port, true,
				   sizeof(struct homa_common_hdr), 99);
		deliver_err(tunnel_sock(self->hnet, i), quote, i, ECONNREFUSED);
		EXPECT_EQ(-ENOTCONN, rpc->error);
		EXPECT_EQ(0, other_port->error);
		kfree_skb(quote);

		/* A quote too short to hold the port affects the whole peer. */
		quote = icmp_quote(self, i, unreach, port, true,
				   offsetof(struct homa_common_hdr, dport) + 1,
				   99);
		deliver_err(tunnel_sock(self->hnet, i), quote, i, ECONNREFUSED);
		EXPECT_EQ(-ENOTCONN, other_port->error);
		kfree_skb(quote);
	}
}

TEST_F(homa_udp_tunnel, homa_udp_encap_err_rcv__other_icmp_type_ignored)
{
	int i;

	for (i = 0; i < 2; i++) {
		struct homa_rpc *rpc;
		struct sk_buff *quote;

		use_family(self, i);
		rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->client,
				      &self->server, 99, 100 + 2 * i, 100,
				      200);
		ASSERT_NE(NULL, rpc);
		quote = icmp_quote(self, i, i ? ICMPV6_TIME_EXCEED :
					      ICMP_TIME_EXCEEDED, 0, true,
				   sizeof(struct homa_common_hdr), 99);
		mock_printk_output[0] = 0;
		deliver_err(tunnel_sock(self->hnet, i), quote, i, EHOSTUNREACH);

		/* Logged (IPv4 handler only), but the RPC is not aborted. */
		EXPECT_EQ(0, rpc->error);
		if (!i)
			EXPECT_SUBSTR("ICMP type 11, ICMP code 0",
				      mock_printk_output);
		kfree_skb(quote);
	}
}

TEST_F(homa_udp_tunnel, homa_udp_encap_err_rcv__no_namespace)
{
	int i;

	for (i = 0; i < 2; i++) {
		struct socket *socket = i ? rcu_access_pointer(self->hnet->udp6) :
					    rcu_access_pointer(self->hnet->udp4);
		struct homa_rpc *rpc;
		struct sk_buff *quote;

		use_family(self, i);
		rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->client,
				      &self->server, 99, 100 + 2 * i, 100,
				      200);
		ASSERT_NE(NULL, rpc);

		/* The tunnel socket doesn't belong to a namespace. */
		quote = icmp_quote(self, i, i ? ICMPV6_DEST_UNREACH :
					      ICMP_DEST_UNREACH,
				   i ? ICMPV6_ADDR_UNREACH : ICMP_HOST_UNREACH,
				   true, sizeof(struct homa_common_hdr), 99);
		rcu_assign_sk_user_data(socket->sk, NULL);
		deliver_err(socket->sk, quote, i, EHOSTUNREACH);
		EXPECT_EQ(0, rpc->error);
		rcu_assign_sk_user_data(socket->sk, self->hnet);
		kfree_skb(quote);
	}
}

#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_udp_tunnel, homa_udp_gro_receive__basics)
{
	struct sock *sk = rcu_access_pointer(self->hnet->udp4)->sk;
	struct sk_buff *skb;
	LIST_HEAD(held_list);

	skb = unit_gro_skb(&self->client, &self->server, &self->data.common,
			   64);
	self->homa.gro_policy = 0;
	cur_offload_core->held_skb = NULL;
	EXPECT_EQ(NULL, homa_udp_gro_receive(sk, &held_list, skb));
	EXPECT_FALSE(NAPI_GRO_CB(skb)->flush);
	EXPECT_EQ(skb, cur_offload_core->held_skb);
	cur_offload_core->held_skb = NULL;
	kfree_skb(skb);
}
TEST_F(homa_udp_tunnel, homa_udp_gro_receive__no_namespace)
{
	struct sock *sk = rcu_access_pointer(self->hnet->udp4)->sk;
	struct sk_buff *skb;
	LIST_HEAD(held_list);

	skb = unit_gro_skb(&self->client, &self->server, &self->data.common,
			   64);
	cur_offload_core->held_skb = NULL;
	rcu_assign_sk_user_data(sk, NULL);
	EXPECT_EQ(NULL, homa_udp_gro_receive(sk, &held_list, skb));
	EXPECT_TRUE(NAPI_GRO_CB(skb)->flush);
	EXPECT_EQ(NULL, cur_offload_core->held_skb);
	rcu_assign_sk_user_data(sk, self->hnet);
	kfree_skb(skb);
}
TEST_F(homa_udp_tunnel, homa_udp_gro_receive__flush_already_set)
{
	struct sock *sk = rcu_access_pointer(self->hnet->udp4)->sk;
	struct sk_buff *skb;
	LIST_HEAD(held_list);

	skb = unit_gro_skb(&self->client, &self->server, &self->data.common,
			   64);
	NAPI_GRO_CB(skb)->flush = 1;
	cur_offload_core->held_skb = NULL;
	EXPECT_EQ(NULL, homa_udp_gro_receive(sk, &held_list, skb));
	EXPECT_EQ(NULL, cur_offload_core->held_skb);
	kfree_skb(skb);
}
TEST_F(homa_udp_tunnel, homa_udp_gro_receive__no_udp_checksum)
{
	struct sock *sk = rcu_access_pointer(self->hnet->udp4)->sk;
	struct sk_buff *skb;
	LIST_HEAD(held_list);

	skb = unit_gro_skb(&self->client, &self->server, &self->data.common,
			   64);
	udp_hdr(skb)->check = 0;
	cur_offload_core->held_skb = NULL;
	EXPECT_EQ(NULL, homa_udp_gro_receive(sk, &held_list, skb));
	EXPECT_TRUE(NAPI_GRO_CB(skb)->flush);
	EXPECT_EQ(NULL, cur_offload_core->held_skb);
	kfree_skb(skb);
}

TEST_F(homa_udp_tunnel, homa_udp_gro_complete__basics)
{
	struct sock *sk = rcu_access_pointer(self->hnet->udp4)->sk;
	struct sk_buff *skb;

	skb = unit_gro_skb(&self->client, &self->server, &self->data.common,
			   64);
	skb_shinfo(skb)->gso_type = SKB_GSO_UDP_TUNNEL_CSUM;
	EXPECT_EQ(0, homa_udp_gro_complete(sk, skb, 0));
	EXPECT_EQ(0, skb_shinfo(skb)->gso_type);
	kfree_skb(skb);
}
#endif /* See strip.py */
