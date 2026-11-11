// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

#include "homa_impl.h"
#include "homa_grant.h"
#include "homa_peer.h"
#include "homa_rpc.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#ifndef __STRIP__ /* See strip.py */
#include "homa_qdisc.h"
#endif /* See strip.py */


/* The following hook function ends an RPC when it is locked. */
static struct homa_rpc *hook_rpc;
static void lock_end_hook(char *id)
{
	if (strcmp(id, "spin_lock") != 0)
		return;
	if (hook_rpc) {
		homa_rpc_end(hook_rpc);
		hook_rpc = NULL;
	}
}

/* Log the data in an array of fragments, which holds a sequence of
 * segments, each consisting of a homa_data_hdr followed by up to
 * @data_per_seg bytes of message data, and return a pointer to the new
 * contents of the log. If @initial_hdr is false then the first segment
 * has no homa_data_hdr.
 */
static const char *log_frags(skb_frag_t *frags, int num_frags,
			     int data_per_seg, bool initial_hdr)
{
	int total = 0, pos, bytes, i;
	static u8 buf[100000];
	struct homa_data_hdr h;

	for (i = 0; i < num_frags; i++)
		total += skb_frag_size(&frags[i]);
	if (total > sizeof(buf))
		return "log_frags buffer too small";
	for (i = 0, pos = 0; i < num_frags; i++) {
		memcpy(buf + pos, unit_frag_first_byte(&frags[i]),
		       skb_frag_size(&frags[i]));
		pos += skb_frag_size(&frags[i]);
	}
	for (pos = 0; pos < total; pos += bytes) {
		if (initial_hdr || pos != 0) {
			memcpy(&h, buf + pos, sizeof(h));
			unit_log_printf("; ", "offset %d:", ntohl(h.offset));
			pos += sizeof(h);
		}
		bytes = min(data_per_seg, total - pos);
		unit_log_data(initial_hdr || pos != 0 ? " " : "; ", buf + pos,
			      bytes);
	}
	return unit_log_get();
}

static void enable_gso(struct homa_rpc *rpc, int segments)
{
	struct dst_entry *dst = rcu_dereference(rpc->route->dst);

	rpc->hsk->homa->max_gso_size = 100000;
	dst->dev->gso_max_size = 100000;
	dst->dev->gso_max_segs = 128;
	rpc->msgout.max_gso_segs = segments;
}

/* Examine every actual UDP payload, not just the first linear DATA header. */
static void check_gso_records(struct __test_metadata *_metadata,
			      struct homa_rpc *rpc, struct sk_buff *skb,
			      int first, int end, bool retransmit, u64 ack_id)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	int offset = first, wire_offset = 0, records = 0;
	u8 actual[8192], expected[8192];

	while (offset < end) {
		struct homa_data_hdr h;
		int bytes = min(rpc->msgout.max_seg_data, end - offset);
		int pool_offset = offset + (offset / rpc->msgout.max_seg_data + 1) *
				  sizeof(struct homa_data_hdr);
		int frag_index, copied = 0;

		ASSERT_LE(bytes, sizeof(actual));
		ASSERT_EQ(0, skb_copy_bits(skb, wire_offset, &h, sizeof(h)));
		EXPECT_EQ(DATA, h.common.type);
		EXPECT_EQ(rpc->hsk->port, ntohs(h.common.sport));
		EXPECT_EQ(rpc->dport, ntohs(h.common.dport));
		EXPECT_EQ(rpc->id, be64_to_cpu(h.common.sender_id));
		EXPECT_EQ(rpc->msgout.length, ntohl(h.msg_length));
		EXPECT_EQ(offset, ntohl(h.offset));
		EXPECT_EQ(records == 0 ? retransmit : 0, h.retransmit);
		if (records == 0)
			IF_NO_STRIP(EXPECT_EQ(rpc->route->peer->cutoff_version,
					      h.cutoff_version));
		EXPECT_EQ(records == 0 ? ack_id : 0, be64_to_cpu(h.ack.client_id));
		ASSERT_EQ(0, skb_copy_bits(skb, wire_offset + sizeof(h),
					   actual, bytes));
		for (frag_index = 0; frag_index < rpc->msgout.num_frags;
		     frag_index++) {
			skb_frag_t *frag = &rpc->msgout.frags[frag_index];
			int take;

			if (pool_offset >= skb_frag_size(frag)) {
				pool_offset -= skb_frag_size(frag);
				continue;
			}
			take = min_t(int, bytes - copied,
				     skb_frag_size(frag) - pool_offset);
			memcpy(expected + copied,
			       unit_frag_first_byte(frag) + pool_offset, take);
			copied += take;
			pool_offset = 0;
			if (copied == bytes)
				break;
		}
		ASSERT_EQ(bytes, copied);
		EXPECT_EQ(0, memcmp(actual, expected, bytes));
		wire_offset += sizeof(h) + bytes;
		offset += bytes;
		records++;
	}
	EXPECT_EQ(wire_offset, skb->len);
	EXPECT_EQ(end - first, homa_get_skb_info(skb)->data_bytes);
	EXPECT_LE(shinfo->nr_frags, MAX_SKB_FRAGS);
	EXPECT_EQ(records > 1 ? SKB_GSO_UDP_L4 : 0, shinfo->gso_type);
	EXPECT_EQ(records > 1 ? records : 0, shinfo->gso_segs);
	EXPECT_EQ(records > 1 ? sizeof(struct homa_data_hdr) +
		  rpc->msgout.max_seg_data : 0, shinfo->gso_size);
}

FIXTURE(homa_outgoing) {
	struct in6_addr client_ip[1];
	int client_port;
	struct in6_addr server_ip[1];
	int server_port;
	u64 client_id;
	u64 server_id;
	struct homa homa;
	struct homa_net *hnet;
	struct net_device *dev;
	struct homa_sock hsk;
	union sockaddr_in_union server_addr;
	struct homa_route *route;
};
FIXTURE_SETUP(homa_outgoing)
{
	self->client_ip[0] = unit_get_in_addr("196.168.0.1");
	self->client_port = 40000;
	self->server_ip[0] = unit_get_in_addr("1.2.3.4");
	self->server_port = 99;
	self->client_id = 1234;
	self->server_id = 1235;
	homa_init(&self->homa);
	self->hnet = mock_hnet(0, &self->homa);
	self->dev = mock_dev(0, &self->homa);
	mock_clock = 10000;
#ifndef __STRIP__ /* See strip.py */
	self->homa.max_gso_size = 10000;
	self->homa.unsched_bytes = 10000;
	self->homa.grant->window = 10000;
	self->homa.qshared->fifo_fraction = 0;
#endif /* See strip.py */
	mock_sock_init(&self->hsk, self->hnet, self->client_port);
	self->server_addr.in6.sin6_family = AF_INET;
	self->server_addr.in6.sin6_addr = self->server_ip[0];
	self->server_addr.in6.sin6_port = htons(self->server_port);
	self->route = homa_route_get(&self->hsk,
				     &self->server_addr.in6.sin6_addr);
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_outgoing)
{
	homa_route_release(self->route);
	homa_destroy(&self->homa);
	unit_teardown();
}

#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_outgoing, homa_message_out_init__basics)
{
	struct homa_rpc *srpc;

	srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
		self->server_ip, self->client_port, 1111, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	/* First call: message is scheduled. */
	self->homa.unsched_bytes = 10000;
	EXPECT_EQ(0, homa_message_out_init(srpc, 10001));
	EXPECT_EQ(0, srpc->msgout.granted);

	/* Second call: message is unscheduled. */
	EXPECT_EQ(0, homa_message_out_init(srpc, 10000));
	EXPECT_EQ(10000, srpc->msgout.granted);
	EXPECT_EQ(6, srpc->msgout.priority);
}
#endif /* See strip.py */
TEST_F(homa_outgoing, homa_message_out_init__mtu_too_small)
{
	struct homa_rpc *srpc;

	srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
		self->server_ip, self->client_port, 1111, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	mock_mtu = 50;
	EXPECT_EQ(EHOSTUNREACH, -homa_message_out_init(srpc, 10001));
	EXPECT_STREQ("route has MTU too small for Homa", srpc->hsk->error_msg);
}
TEST_F(homa_outgoing, homa_message_out_init__max_gso_segs)
{
	struct homa_rpc *crpc;

	crpc = homa_rpc_alloc_client(&self->hsk, &self->server_addr);

	/* First call: limited by dev->gso_max_segs. */
	mock_devices[0].gso_max_segs = 2;
	self->homa.max_gso_size = 100000;
	mock_devices[0].gso_max_size = 100000;
	EXPECT_EQ(0, homa_message_out_init(crpc, 10000));
	EXPECT_EQ(2, crpc->msgout.max_gso_segs);

	/* Second call: limited by homa->max_gso_size. */
	mock_devices[0].gso_max_segs = 10;
	self->homa.max_gso_size = 5000;
	mock_devices[0].gso_max_size = 100000;
	EXPECT_EQ(0, homa_message_out_init(crpc, 10000));
	EXPECT_EQ(3, crpc->msgout.max_gso_segs);

	/* Third call: limited by dev->gso_max_size. */
	mock_devices[0].gso_max_segs = 10;
	self->homa.max_gso_size = 100000;
	mock_devices[0].gso_max_size = 6900;
	EXPECT_EQ(0, homa_message_out_init(crpc, 10000));
	EXPECT_EQ(4, crpc->msgout.max_gso_segs);

	/* Fourth call: ensure at least one segment. */
	mock_devices[0].gso_max_segs = 10;
	self->homa.max_gso_size = 100000;
	mock_devices[0].gso_max_size = 1000;
	EXPECT_EQ(0, homa_message_out_init(crpc, 10000));
	EXPECT_EQ(1, crpc->msgout.max_gso_segs);

	homa_rpc_unlock(crpc);
}

TEST_F(homa_outgoing, homa_message_out_init__udp_mtu_geometry)
{
	union sockaddr_in_union addr = self->server_addr;
	int ip_length;

	mock_set_ipv6(&self->hsk);
	addr.in6.sin6_family = AF_INET6;
	/* A route MTU below the device MTU is usable in either family. */
	for (ip_length = sizeof(struct iphdr); ip_length <= sizeof(struct ipv6hdr);
	     ip_length += sizeof(struct ipv6hdr) - sizeof(struct iphdr)) {
		struct homa_rpc *crpc;

		addr.in6.sin6_addr = unit_get_in_addr(ip_length == sizeof(struct iphdr) ?
						     "1.2.3.4" : "2001:db8::1");
		crpc = homa_rpc_alloc_client(&self->hsk, &addr);
		ASSERT_FALSE(IS_ERR(crpc));
		mock_mtu = 1200;
		EXPECT_EQ(0, homa_message_out_init(crpc, 10000));
		EXPECT_EQ(1200 - ip_length - 8 - 34, crpc->msgout.max_seg_data);
		mock_mtu = ip_length + 8 + 34 + HOMA_MIN_SEG_DATA;
		EXPECT_EQ(0, homa_message_out_init(crpc, 10000));
		EXPECT_EQ(HOMA_MIN_SEG_DATA, crpc->msgout.max_seg_data);
		mock_mtu--;
		EXPECT_EQ(-EHOSTUNREACH, homa_message_out_init(crpc, 10000));
		EXPECT_STREQ("route has MTU too small for Homa", self->hsk.error_msg);
		homa_rpc_unlock(crpc);
	}
}

TEST_F(homa_outgoing, homa_message_out_init__gso_size_underflow_and_caps)
{
	struct homa_rpc *crpc = homa_rpc_alloc_client(&self->hsk,
						      &self->server_addr);

	ASSERT_FALSE(IS_ERR(crpc));
	self->homa.max_gso_size = 1;
	self->dev->gso_max_size = 1;
	EXPECT_EQ(0, homa_message_out_init(crpc, 10000));
	EXPECT_EQ(1, crpc->msgout.max_gso_segs);

	self->homa.max_gso_size = 1000000;
	self->dev->gso_max_size = 1000000;
	self->dev->gso_max_segs = 1000;
	EXPECT_EQ(0, homa_message_out_init(crpc, 1000000));
	EXPECT_LE(crpc->msgout.max_gso_segs *
		  (sizeof(struct homa_data_hdr) + crpc->msgout.max_seg_data) +
		  sizeof(struct iphdr) + sizeof(struct udphdr), U16_MAX);
	homa_rpc_unlock(crpc);
}

TEST_F(homa_outgoing, homa_tx_copy_from_user__basics)
{
	struct homa_rpc *crpc;
	struct iov_iter *iter;
	u8 data[9000];

	crpc = homa_rpc_alloc_client(&self->hsk, &self->server_addr);
	unit_fill_data(data, sizeof(data), 5000);
	iter = unit_iov_iter(data, sizeof(data));
	mock_no_high_order_pages = true;

	EXPECT_EQ(0, homa_message_out_init(crpc, iter->count));
	EXPECT_EQ(0, homa_tx_copy_from_user(crpc, iter, false));
	EXPECT_EQ(3, crpc->msgout.num_frags);
	EXPECT_EQ(0, skb_frag_off(&crpc->msgout.frags[0]));
	EXPECT_EQ(PAGE_SIZE, skb_frag_size(&crpc->msgout.frags[0]));
	unit_log_clear();
	EXPECT_STREQ("offset 0: 5000-6399; offset 1400: 6400-7799; "
		     "offset 2800: 7800-9199; offset 4200: 9200-10599; "
		     "offset 5600: 10600-11999; offset 7000: 12000-13399; "
		     "offset 8400: 13400-13999",
		     log_frags(crpc->msgout.frags, crpc->msgout.num_frags,
			       crpc->msgout.max_seg_data, true));
	EXPECT_EQ(9000 + 7 * sizeof(struct homa_data_hdr),
		  crpc->msgout.frag_bytes);
	EXPECT_EQ(9000 + 7 * sizeof(struct homa_data_hdr) + 1,
		  refcount_read(&self->hsk.sock.sk_wmem_alloc));
	IF_NO_STRIP(EXPECT_EQ(9000, homa_metrics_per_cpu()->sent_msg_bytes));
	homa_rpc_unlock(crpc);
}
TEST_F(homa_outgoing, homa_tx_copy_from_user__cant_allocate_frags)
{
	struct homa_rpc *crpc;
	struct iov_iter *iter;

	crpc = homa_rpc_alloc_client(&self->hsk, &self->server_addr);
	iter = unit_iov_iter(NULL, 1000);
	mock_alloc_page_errors = 0xff;

	EXPECT_EQ(0, homa_message_out_init(crpc, iter->count));
	EXPECT_EQ(-ENOMEM, homa_tx_copy_from_user(crpc, iter, false));
	EXPECT_EQ(0, crpc->msgout.num_frags);
	homa_rpc_unlock(crpc);
}
TEST_F(homa_outgoing, homa_tx_copy_from_user__homa_copy_to_frags_fails)
{
	struct homa_rpc *crpc;
	struct iov_iter *iter;

	crpc = homa_rpc_alloc_client(&self->hsk, &self->server_addr);
	iter = unit_iov_iter(NULL, 1000);
	mock_copy_to_frags_errors = 1;

	EXPECT_EQ(0, homa_message_out_init(crpc, iter->count));
	EXPECT_EQ(EINVAL, -homa_tx_copy_from_user(crpc, iter, false));
	homa_rpc_unlock(crpc);
}
TEST_F(homa_outgoing, homa_tx_copy_from_user__homa_copy_iter_to_frags_fails)
{
	struct homa_rpc *crpc;
	struct iov_iter *iter;

	crpc = homa_rpc_alloc_client(&self->hsk, &self->server_addr);
	iter = unit_iov_iter(NULL, 9000);
	mock_copy_data_errors = 1;

	EXPECT_EQ(0, homa_message_out_init(crpc, iter->count));
	EXPECT_EQ(EFAULT, -homa_tx_copy_from_user(crpc, iter, false));
	homa_rpc_unlock(crpc);
}
TEST_F(homa_outgoing, homa_tx_copy_from_user__call_homa_xmit_data_at_end)
{
	struct homa_rpc *crpc;
	struct iov_iter *iter;
	u8 data[500];

	crpc = homa_rpc_alloc_client(&self->hsk, &self->server_addr);
	iter = unit_iov_iter(data, sizeof(data));
	unit_log_clear();
	mock_copy_from_iter_no_log = true;

	EXPECT_EQ(0, homa_message_out_init(crpc, iter->count));
	EXPECT_EQ(0, homa_tx_copy_from_user(crpc, iter, true));
	EXPECT_STREQ("homa_tx_copy_to_user done; xmit DATA 500@0",
		     unit_log_get());
	homa_rpc_unlock(crpc);
}
TEST_F(homa_outgoing, homa_tx_copy_from_user__xmit_false)
{
	struct homa_rpc *crpc;
	struct iov_iter *iter;
	u8 data[1500];

	crpc = homa_rpc_alloc_client(&self->hsk, &self->server_addr);
	iter = unit_iov_iter(data, sizeof(data));
	unit_log_clear();
	mock_copy_from_iter_no_log = true;

	EXPECT_EQ(0, homa_message_out_init(crpc, iter->count));
	EXPECT_EQ(0, homa_tx_copy_from_user(crpc, iter, false));
	EXPECT_STREQ("homa_tx_copy_to_user done", unit_log_get());
	IF_NO_STRIP(EXPECT_EQ(1500, homa_metrics_per_cpu()->sent_msg_bytes));
	homa_rpc_unlock(crpc);
}

TEST_F(homa_outgoing, homa_tx_skb_alloc__basics)
{
	struct homa_data_hdr *h;
	struct homa_rpc *crpc;
	struct sk_buff *skb;
	char buffer[1000];
	u32 end;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 2500, 100);
	ASSERT_NE(NULL, crpc);

	end = 1550;
	skb = homa_tx_skb_alloc(crpc, 1520, &end);
	if (IS_ERR(skb))
		EXPECT_EQ(0, -PTR_ERR(skb));
	EXPECT_EQ(2500, end);
	EXPECT_STREQ("DATA from 0.0.0.0:40000, dport 99, id 1234, "
		     "msg_length 2500, offset 1400, data_length 1100",
		     homa_print_packet(skb, buffer, sizeof(buffer)));
	unit_log_clear();
	EXPECT_STREQ("1400-2499",
		     log_frags(skb_shinfo(skb)->frags,
		     	       skb_shinfo(skb)->nr_frags,
			       crpc->msgout.max_seg_data, false));
	h = (struct homa_data_hdr *)skb_transport_header(skb);
	EXPECT_EQ(1400, ntohl(h->offset));
	kfree_skb(skb);
}
TEST_F(homa_outgoing, homa_tx_skb_alloc__invalid_offset)
{
	struct homa_rpc *crpc;
	struct sk_buff *skb;
	u32 end;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 100, 100);
	ASSERT_NE(NULL, crpc);

	end = 10000;
	skb = homa_tx_skb_alloc(crpc, 100, &end);
	EXPECT_EQ(EINVAL, -PTR_ERR(skb));
}
TEST_F(homa_outgoing, homa_tx_skb_alloc__round_end_down_to_msg_length)
{
	struct homa_rpc *crpc;
	struct sk_buff *skb;
	char buffer[1000];
	u32 end;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 100, 100);
	ASSERT_NE(NULL, crpc);

	end = 1000;
	skb = homa_tx_skb_alloc(crpc, 20, &end);
	if (IS_ERR(skb))
		EXPECT_EQ(0, -PTR_ERR(skb));
	EXPECT_EQ(100, end);
	EXPECT_STREQ("DATA from 0.0.0.0:40000, dport 99, id 1234, "
		     "msg_length 100, offset 0, data_length 100",
		     homa_print_packet(skb, buffer, sizeof(buffer)));
	kfree_skb(skb);
}
TEST_F(homa_outgoing, homa_tx_skb_alloc__find_starting_point)
{
	struct skb_shared_info *shinfo;
	struct homa_rpc *crpc;
	struct sk_buff *skb;
	u32 end;

	mock_no_high_order_pages = true;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 20000, 100);
	ASSERT_NE(NULL, crpc);
	crpc->msgout.max_gso_segs = 1;

	end = 10001;
	skb = homa_tx_skb_alloc(crpc, 10000, &end);
	if (IS_ERR(skb))
		EXPECT_EQ(0, -PTR_ERR(skb));
	shinfo = skb_shinfo(skb);
	EXPECT_EQ(11200, end);
	EXPECT_EQ(1, shinfo->nr_frags);
	EXPECT_EQ(1880, skb_frag_off(&shinfo->frags[0]));
	EXPECT_EQ(1400, skb_frag_size(&shinfo->frags[0]));
	unit_log_clear();
	unit_log_data("; ", unit_frag_first_byte(&shinfo->frags[0]),
		       skb_frag_size(&shinfo->frags[0]));
	EXPECT_STREQ("9800-11199", unit_log_get());
	kfree_skb(skb);
}
TEST_F(homa_outgoing, homa_tx_skb_alloc__compute_num_segs)
{
	struct homa_rpc *crpc;
	struct sk_buff *skb;
	u32 end;

	mock_no_high_order_pages = true;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 6000, 100);
	ASSERT_NE(NULL, crpc);
	enable_gso(crpc, 10);

	/* First call fills 2 segments. */
	end = 4200;
	skb = homa_tx_skb_alloc(crpc, 1500, &end);
	if (IS_ERR(skb))
		ASSERT_EQ(0, -PTR_ERR(skb));
	EXPECT_EQ(4200, end);
	kfree_skb(skb);

	/* Second call overflows into a third segment*/
	end = 4201;
	skb = homa_tx_skb_alloc(crpc, 1500, &end);
	if (IS_ERR(skb))
		ASSERT_EQ(0, -PTR_ERR(skb));
	EXPECT_EQ(5600, end);
	kfree_skb(skb);
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_outgoing, homa_tx_skb_alloc__allocation_metrics)
{
	struct homa_rpc *crpc;
	struct sk_buff *skb;
	u32 end;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 6000, 100);
	ASSERT_NE(NULL, crpc);
	mock_clock_tick = 300;
	homa_metrics_per_cpu()->skb_allocs = 0;

	/* First call fills 2 segments. */
	end = 1001;
	skb = homa_tx_skb_alloc(crpc, 1000, &end);
	if (IS_ERR(skb))
		ASSERT_EQ(0, -PTR_ERR(skb));
	kfree_skb(skb);

	EXPECT_EQ(1, homa_metrics_per_cpu()->skb_allocs);
	EXPECT_EQ(300, homa_metrics_per_cpu()->skb_alloc_cycles);
}
#endif /* See strip.py */
TEST_F(homa_outgoing, homa_tx_skb_alloc__set_retransmit)
{
	struct homa_rpc *crpc;
	struct sk_buff *skb;
	char buffer[1000];
	u32 end;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 10000, 100);
	ASSERT_NE(NULL, crpc);

	/* First call is a retransmit. */
	crpc->msgout.next_xmit_offset = 5000;
	end = 3001;
	skb = homa_tx_skb_alloc(crpc, 3000, &end);
	if (IS_ERR(skb))
		ASSERT_EQ(0, -PTR_ERR(skb));
	EXPECT_STREQ("DATA from 0.0.0.0:40000, dport 99, id 1234, "
		     "msg_length 10000, offset 2800, data_length 1400, "
		     "RETRANSMIT",
		     homa_print_packet(skb, buffer, sizeof(buffer)));
	kfree_skb(skb);

	/* Second call is not a retransmit. */
	crpc->msgout.next_xmit_offset = 5000;
	end = 7001;
	skb = homa_tx_skb_alloc(crpc, 7000, &end);
	if (IS_ERR(skb))
		ASSERT_EQ(0, -PTR_ERR(skb));
	EXPECT_STREQ("DATA from 0.0.0.0:40000, dport 99, id 1234, "
		     "msg_length 10000, offset 7000, data_length 1400",
		     homa_print_packet(skb, buffer, sizeof(buffer)));
	kfree_skb(skb);
}
TEST_F(homa_outgoing, homa_tx_skb_alloc__fill_in_skb_frags)
{
	struct homa_rpc *crpc;
	struct sk_buff *skb;
	u32 end;

	mock_no_high_order_pages = true;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 20000, 100);
	ASSERT_NE(NULL, crpc);
	enable_gso(crpc, 10);

	end = 15000;
	skb = homa_tx_skb_alloc(crpc, 5000, &end);
	ASSERT_FALSE(IS_ERR(skb));
	EXPECT_EQ(15400, end);
	EXPECT_EQ(3, skb_shinfo(skb)->nr_frags);
	EXPECT_EQ(8, skb_shinfo(skb)->gso_segs);
	check_gso_records(_metadata, crpc, skb, 4200, end, false, 0);
	kfree_skb(skb);
}
TEST_F(homa_outgoing, homa_tx_skb_alloc__not_enough_frags_in_skb)
{
	struct homa_rpc *crpc;
	struct sk_buff *skb;
	u32 end;

	mock_no_high_order_pages = true;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 20000, 100);
	ASSERT_NE(NULL, crpc);
	enable_gso(crpc, 10);
	mock_max_skb_frags = 2;

	end = 18000;
	skb = homa_tx_skb_alloc(crpc, 4000, &end);
	if (IS_ERR(skb))
		EXPECT_EQ(0, -PTR_ERR(skb));
	EXPECT_EQ(7000, end);
	EXPECT_EQ(2, skb_shinfo(skb)->nr_frags);
	check_gso_records(_metadata, crpc, skb, 2800, end, false, 0);
	kfree_skb(skb);
}
TEST_F(homa_outgoing, homa_tx_skb_alloc__not_enough_frags_in_skb_must_drop_frag)
{
	struct homa_rpc *crpc;
	struct sk_buff *skb;
	u32 end;

	/* Allow 7000 bytes of data per segment. */
	mock_mtu += 7000 - 1400;
	mock_no_high_order_pages = true;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 20000, 100);
	ASSERT_NE(NULL, crpc);
	enable_gso(crpc, 10);
	mock_max_skb_frags = 3;

	end = 14000;
	skb = homa_tx_skb_alloc(crpc, 0, &end);
	if (IS_ERR(skb))
		EXPECT_EQ(0, -PTR_ERR(skb));
	unit_log_clear();
	EXPECT_STREQ("0-6999",
		     log_frags(skb_shinfo(skb)->frags,
		     	       skb_shinfo(skb)->nr_frags,
			       crpc->msgout.max_seg_data, false));
	EXPECT_EQ(7000, end);
	kfree_skb(skb);
}
TEST_F(homa_outgoing, homa_tx_skb_alloc__not_enough_space_for_one_segment)
{
	struct homa_rpc *crpc;
	struct sk_buff *skb;
	u32 end;

	/* Allow 7000 bytes of data per segment. */
	mock_mtu += 7000 - 1400;
	mock_no_high_order_pages = true;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 20000, 100);
	ASSERT_NE(NULL, crpc);
	enable_gso(crpc, 10);
	mock_max_skb_frags = 1;

	end = 14000;
	skb = homa_tx_skb_alloc(crpc, 0, &end);
	EXPECT_TRUE(IS_ERR(skb));
	EXPECT_EQ(EINVAL, -PTR_ERR(skb));
}
TEST_F(homa_outgoing, homa_tx_skb_alloc__message_ends_mid_fragment)
{
	struct homa_rpc *crpc;
	struct sk_buff *skb;
	u32 end;

	mock_no_high_order_pages = true;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 2000, 100);
	ASSERT_NE(NULL, crpc);
	crpc->msgout.max_gso_segs = 1;

	end = 3000;
	skb = homa_tx_skb_alloc(crpc, 1500, &end);
	if (IS_ERR(skb))
		EXPECT_EQ(0, -PTR_ERR(skb));
	unit_log_clear();
	EXPECT_STREQ("1400-1999",
		     log_frags(skb_shinfo(skb)->frags,
		     	       skb_shinfo(skb)->nr_frags,
			       crpc->msgout.max_seg_data, false));
	EXPECT_EQ(2000, end);
	kfree_skb(skb);
}
TEST_F(homa_outgoing, homa_tx_skb_alloc__shinfo_gso_fields)
{
	struct skb_shared_info *shinfo;
	struct homa_rpc *crpc;
	struct sk_buff *skb;
	u32 end;

	mock_no_high_order_pages = true;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 5000, 100);
	ASSERT_NE(NULL, crpc);
	enable_gso(crpc, 3);

	/* First packet has only one segment. */
	end = 1501;
	skb = homa_tx_skb_alloc(crpc, 1500, &end);
	if (IS_ERR(skb))
		EXPECT_EQ(0, -PTR_ERR(skb));
	unit_log_clear();
	EXPECT_STREQ("1400-2799",
		     log_frags(skb_shinfo(skb)->frags,
		     	       skb_shinfo(skb)->nr_frags,
			       crpc->msgout.max_seg_data, false));
	EXPECT_EQ(2800, end);
	shinfo = skb_shinfo(skb);
	EXPECT_EQ(0, shinfo->gso_segs);
	EXPECT_EQ(0, shinfo->gso_size);
	EXPECT_EQ(0, shinfo->gso_type);
	kfree_skb(skb);

	/* Second packet has multiple segments. */
	end = 3000;
	skb = homa_tx_skb_alloc(crpc, 0, &end);
	if (IS_ERR(skb))
		EXPECT_EQ(0, -PTR_ERR(skb));
	check_gso_records(_metadata, crpc, skb, 0, 4200, false, 0);
	EXPECT_EQ(4200, end);
	shinfo = skb_shinfo(skb);
	EXPECT_EQ(3, shinfo->gso_segs);
	EXPECT_EQ(1400 + sizeof(struct homa_data_hdr), shinfo->gso_size);
	EXPECT_EQ(SKB_GSO_UDP_L4, shinfo->gso_type);
	kfree_skb(skb);
}
TEST_F(homa_outgoing, homa_tx_skb_alloc__homa_info_fields)
{
	struct homa_skb_info *homa_info;
	struct homa_rpc *crpc;
	struct sk_buff *skb;
	u32 end;

	mock_no_high_order_pages = true;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 5000, 100);
	ASSERT_NE(NULL, crpc);
	enable_gso(crpc, 3);

	end = 5000;
	skb = homa_tx_skb_alloc(crpc, 1500, &end);
	if (IS_ERR(skb))
		EXPECT_EQ(0, -PTR_ERR(skb));
	EXPECT_EQ(5000, end);
	homa_info = homa_get_skb_info(skb);
	EXPECT_EQ(3600, homa_info->data_bytes);
	EXPECT_EQ(0, homa_info->dont_defer);
	kfree_skb(skb);
}

TEST_F(homa_outgoing, homa_tx_skb_alloc__all_headers_short_tail_and_private_retransmit)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			self->client_id, 5003, 100);
	struct homa_peer *peer = crpc->route->peer;
	struct sk_buff *original, *retrans;
	struct homa_data_hdr h;
	u8 pool_bytes[6000];
	u32 end = 5003;
	int i;

	ASSERT_EQ(1, crpc->msgout.num_frags);
	ASSERT_LE(skb_frag_size(crpc->msgout.frags), sizeof(pool_bytes));
	memcpy(pool_bytes, unit_frag_first_byte(crpc->msgout.frags),
	       skb_frag_size(crpc->msgout.frags));
	enable_gso(crpc, 10);
	IF_NO_STRIP(peer->cutoff_version = htons(7));
	peer->num_acks = 1;
	peer->acks[0].client_id = cpu_to_be64(90);
	peer->acks[0].server_port = htons(99);
	original = homa_tx_skb_alloc(crpc, 0, &end);
	ASSERT_FALSE(IS_ERR(original));
	EXPECT_EQ(5003, end);
	EXPECT_EQ(4, skb_shinfo(original)->gso_segs);
	EXPECT_EQ(5003 + 4 * 34, original->len);
	check_gso_records(_metadata, crpc, original, 0, end, false, 90);
	EXPECT_EQ(0, peer->num_acks);

	crpc->msgout.next_xmit_offset = crpc->msgout.length;
	IF_NO_STRIP(peer->cutoff_version = htons(8));
	peer->num_acks = 1;
	peer->acks[0].client_id = cpu_to_be64(92);
	end = 5003;
	retrans = homa_tx_skb_alloc(crpc, 1501, &end);
	ASSERT_FALSE(IS_ERR(retrans));
	EXPECT_EQ(5003, end);
	check_gso_records(_metadata, crpc, retrans, 1400, end, true, 92);
	EXPECT_EQ(0, peer->num_acks);

	/* Mutating a retransmission must leave all in-flight headers intact. */
	for (i = 0; i < 4; i++) {
		ASSERT_EQ(0, skb_copy_bits(original, i * (1400 + 34), &h, sizeof(h)));
		EXPECT_EQ(i * 1400, ntohl(h.offset));
		EXPECT_EQ(0, h.retransmit);
		IF_NO_STRIP(EXPECT_EQ(i == 0 ? htons(7) : 0, h.cutoff_version));
		EXPECT_EQ(i == 0 ? 90 : 0, be64_to_cpu(h.ack.client_id));
	}
	EXPECT_EQ(0, memcmp(pool_bytes, unit_frag_first_byte(crpc->msgout.frags),
			    skb_frag_size(crpc->msgout.frags)));
	kfree_skb(original);
	kfree_skb(retrans);
}

TEST_F(homa_outgoing, homa_tx_skb_alloc__pool_header_crosses_page)
{
	struct homa_rpc *crpc;
	struct sk_buff *skb;
	u32 end = 9000;

	mock_no_high_order_pages = true;
	mock_mtu = sizeof(struct iphdr) + 8 + 34 + PAGE_SIZE - 5;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			9000, 100);
	ASSERT_NE(NULL, crpc);
	enable_gso(crpc, 10);
	/* The second internal four-byte offset begins at PAGE_SIZE - 1. */
	EXPECT_EQ(PAGE_SIZE - 5, crpc->msgout.max_seg_data);
	skb = homa_tx_skb_alloc(crpc, 0, &end);
	ASSERT_FALSE(IS_ERR(skb));
	EXPECT_EQ(9000, end);
	check_gso_records(_metadata, crpc, skb, 0, end, false, 0);
	kfree_skb(skb);
}

TEST_F(homa_outgoing, homa_tx_skb_send__existing_geometry_mtu_change)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			self->client_id, 6000, 100);
	u32 end = 6000;
	int old_mtu = mock_mtu, calls = mock_udp_xmit_calls;

	enable_gso(crpc, 10);
	crpc->route->peer->num_acks = 1;
	homa_rpc_lock(crpc);
	mock_mtu--;
	EXPECT_EQ(-EMSGSIZE, homa_tx_skb_send(crpc, 0, &end));
	EXPECT_EQ(0, crpc->msgout.next_xmit_offset);
	EXPECT_EQ(1400, crpc->msgout.max_seg_data);
	EXPECT_EQ(1, crpc->route->peer->num_acks);
	EXPECT_EQ(calls, mock_udp_xmit_calls);
	IF_NO_STRIP(EXPECT_EQ(1, homa_metrics_per_cpu()->data_xmit_errors));
	EXPECT_EQ(-EHOSTUNREACH, crpc->error);
	EXPECT_STREQ("route has MTU too small for Homa", self->hsk.error_msg);

	mock_mtu = old_mtu + 1000;
	EXPECT_EQ(0, homa_tx_skb_send(crpc, 0, &end));
	IF_NO_STRIP(EXPECT_EQ(1, homa_metrics_per_cpu()->data_xmit_errors));
	EXPECT_EQ(1400, crpc->msgout.max_seg_data);
	EXPECT_EQ(6000, end);
	homa_rpc_unlock(crpc);
}
TEST_F(homa_outgoing, homa_tx_skb_send__mtu_change_aborts_server_rpc)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 6000);
	u32 end = 6000;

	ASSERT_NE(NULL, srpc);
	homa_rpc_lock(srpc);
	mock_mtu--;
	EXPECT_EQ(-EMSGSIZE, homa_tx_skb_send(srpc, 0, &end));
	EXPECT_EQ(RPC_DEAD, srpc->state);
	EXPECT_STREQ("route has MTU too small for Homa", self->hsk.error_msg);
	homa_rpc_unlock(srpc);
}

TEST_F(homa_outgoing, homa_tx_skb_send__basics)
{
	struct homa_rpc *crpc;
	u32 end;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 5000, 100);
	ASSERT_NE(NULL, crpc);
	crpc->msgout.max_gso_segs = 1;
	unit_log_clear();

	homa_rpc_lock(crpc);
	end = 2000;
	EXPECT_EQ(0, homa_tx_skb_send(crpc, 1500, &end));
	EXPECT_STREQ("xmit DATA 1400@1400", unit_log_get());
	homa_rpc_unlock(crpc);
}
TEST_F(homa_outgoing, homa_tx_skb_send__update_next_xmit_offset)
{
	struct homa_rpc *crpc;
	u32 end;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 10000, 100);
	ASSERT_NE(NULL, crpc);
	crpc->msgout.max_gso_segs = 1;
	unit_log_clear();
	homa_rpc_lock(crpc);

	/* First call updates next_xmit_offset. */
	end = 4100;
	EXPECT_EQ(0, homa_tx_skb_send(crpc, 4000, &end));
	EXPECT_STREQ("xmit DATA 1400@2800", unit_log_get());
	EXPECT_EQ(4200, crpc->msgout.next_xmit_offset);
	EXPECT_EQ(4200, end);

	/* Second call doesn't update next_xmit_offset. */
	unit_log_clear();
	end = 2100;
	EXPECT_EQ(0, homa_tx_skb_send(crpc, 2000, &end));
	EXPECT_STREQ("xmit DATA retrans 1400@1400", unit_log_get());
	EXPECT_EQ(4200, crpc->msgout.next_xmit_offset);
	EXPECT_EQ(2800, end);

	homa_rpc_unlock(crpc);
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_outgoing, homa_tx_skb_send__priorities)
{
	struct homa_rpc *crpc;
	u32 end;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 20000, 100);
	ASSERT_NE(NULL, crpc);
	crpc->msgout.max_gso_segs = 1;
	crpc->msgout.priority = 2;
	crpc->msgout.retrans_priority = 3;
	crpc->msgout.next_xmit_offset = 1500;
	mock_xmit_log_verbose = 1;
	/* A second accidental priority_map application would produce 7. */
	self->homa.priority_map[2] = 4;
	self->homa.priority_map[3] = 5;
	self->homa.priority_map[4] = 7;
	self->homa.priority_map[5] = 7;

	/* First packet uses retransmit priority.*/
	homa_rpc_lock(crpc);
	end = 100;
	EXPECT_EQ(0, homa_tx_skb_send(crpc, 0, &end));
	EXPECT_STREQ("5", mock_xmit_prios);

	/* Second packet uses msgout priority.*/
	mock_clear_xmit_prios();
	end = 2000;
	EXPECT_EQ(0, homa_tx_skb_send(crpc, 1500, &end));
	EXPECT_STREQ("4", mock_xmit_prios);
	homa_rpc_unlock(crpc);
}
TEST_F(homa_outgoing, homa_tx_skb_send__metrics)
{
	struct homa_rpc *crpc;
	u32 end;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 5000, 100);
	ASSERT_NE(NULL, crpc);
	crpc->msgout.max_gso_segs = 1;
	unit_log_clear();

	homa_rpc_lock(crpc);
	end = 2000;
	EXPECT_EQ(0, homa_tx_skb_send(crpc, 1500, &end));
	EXPECT_EQ(1, homa_metrics_per_cpu()->packets_sent[0]);
	EXPECT_EQ(1434, homa_metrics_per_cpu()->priority_bytes[6]);
	EXPECT_EQ(1, homa_metrics_per_cpu()->priority_packets[6]);
	homa_rpc_unlock(crpc);
}
#endif /* See strip.py */

TEST_F(homa_outgoing, homa_xmit_control__busy_from_server_request)
{
	struct homa_busy_hdr h;
	struct homa_rpc *srpc;

	homa_sock_bind(self->hnet, &self->hsk, self->server_port);
	srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
			self->server_ip, self->client_port, self->server_id,
			10000, 10000);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();

	mock_xmit_log_verbose = 1;
	homa_rpc_lock(srpc);
	mock_clear_xmit_prios();
	EXPECT_EQ(0, homa_xmit_control(BUSY, &h, sizeof(h), srpc));
	EXPECT_STREQ("padded control packet with 5 bytes; "
		     "xmit BUSY from 0.0.0.0:99, dport 40000, id 1235",
			unit_log_get());
#ifndef __STRIP__ /* See strip.py */
	EXPECT_STREQ("7", mock_xmit_prios);
#endif /* See strip.py */
	homa_rpc_unlock(srpc);
}
TEST_F(homa_outgoing, homa_xmit_control__busy_from_client_response)
{
	struct homa_busy_hdr h;
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			100, 10000);
	ASSERT_NE(NULL, crpc);
	unit_log_clear();

	mock_xmit_log_verbose = 1;
	homa_rpc_lock(crpc);
	mock_clear_xmit_prios();
	EXPECT_EQ(0, homa_xmit_control(BUSY, &h, sizeof(h), crpc));
	EXPECT_STREQ("padded control packet with 5 bytes; "
		     "xmit BUSY from 0.0.0.0:40000, dport 99, id 1234",
			unit_log_get());
#ifndef __STRIP__ /* See strip.py */
	EXPECT_STREQ("7", mock_xmit_prios);
#endif /* See strip.py */
	homa_rpc_unlock(crpc);
}

TEST_F(homa_outgoing, __homa_xmit_control__cant_alloc_skb)
{
	struct homa_busy_hdr h;
	struct homa_rpc *srpc;

	srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
		self->server_ip, self->client_port, 1111, 10000, 10000);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();

	h.common.type = BUSY;
	mock_xmit_log_verbose = 1;
	mock_alloc_skb_errors = 1;
	EXPECT_EQ(ENOBUFS, -__homa_xmit_control(&h, sizeof(h), srpc->route,
		  &self->hsk));
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_outgoing, __homa_xmit_control__pad_packet)
{
	struct homa_rpc *srpc;
	struct homa_busy_hdr h;

	srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
		self->server_ip, self->client_port, 1111, 10000, 10000);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();
	homa_rpc_lock(srpc);
	EXPECT_EQ(0, homa_xmit_control(BUSY, &h, sizeof(h), srpc));
	EXPECT_STREQ("padded control packet with 5 bytes; xmit BUSY",
		     unit_log_get());
	EXPECT_EQ(sizeof(struct udphdr) + HOMA_MIN_PKT_LENGTH,
		  ntohs(mock_udp_last_header.len));
	homa_rpc_unlock(srpc);
}
TEST_F(homa_outgoing, __homa_xmit_control__unsendable_padded_control)
{
	struct homa_busy_hdr busy = {.common.type = BUSY};
	struct homa_ack_hdr ack = {.common.type = ACK};
	int calls = mock_udp_xmit_calls;

	mock_mtu = sizeof(struct iphdr) + 8 + HOMA_MIN_PKT_LENGTH - 1;
	EXPECT_EQ(-EMSGSIZE, __homa_xmit_control(&busy, sizeof(busy),
						self->route, &self->hsk));
	EXPECT_EQ(calls, mock_udp_xmit_calls);
	IF_NO_STRIP(EXPECT_EQ(1, homa_metrics_per_cpu()->control_xmit_errors));
	mock_mtu++;
	EXPECT_EQ(0, __homa_xmit_control(&busy, sizeof(busy),
					self->route, &self->hsk));
	EXPECT_EQ(calls + 1, mock_udp_xmit_calls);
	IF_NO_STRIP(EXPECT_EQ(1, homa_metrics_per_cpu()->control_xmit_errors));

	mock_mtu = sizeof(struct iphdr) + 8 + sizeof(ack) - 1;
	EXPECT_EQ(-EMSGSIZE, __homa_xmit_control(&ack, sizeof(ack),
						self->route, &self->hsk));
	EXPECT_EQ(calls + 1, mock_udp_xmit_calls);
	IF_NO_STRIP(EXPECT_EQ(2, homa_metrics_per_cpu()->control_xmit_errors));
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_outgoing, homa_xmit_unknown__basics)
{
	struct homa_grant_hdr h = {{.sport = htons(self->client_port),
			.dport = htons(self->server_port),
			.sender_id = cpu_to_be64(99990),
			.type = GRANT},
			.offset = htonl(11200)};
	struct sk_buff *skb;

	mock_xmit_log_verbose = 1;
	skb = mock_skb_alloc(self->client_ip, self->server_ip, &h.common, 0, 0);
	homa_xmit_unknown(skb, &self->hsk);
	EXPECT_STREQ("padded control packet with 5 bytes; "
		     "xmit RPC_UNKNOWN from 0.0.0.0:99, dport 40000, id 99991",
			unit_log_get());
	kfree_skb(skb);
}
TEST_F(homa_outgoing, homa_xmit_unknown__cant_find_peer)
{
	struct homa_grant_hdr h = {{.sport = htons(self->client_port),
			.dport = htons(self->server_port),
			.sender_id = cpu_to_be64(99990),
			.type = GRANT},
			.offset = htonl(11200)};
	struct sk_buff *skb;

	mock_kmalloc_errors = 1;
	skb = mock_skb_alloc(self->client_ip, self->server_ip, &h.common, 0, 0);
	homa_xmit_unknown(skb, &self->hsk);
	EXPECT_STREQ("", unit_log_get());
	kfree_skb(skb);
}

TEST_F(homa_outgoing, homa_xmit_start_msg)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 6000, 1000);

	mock_xmit_log_verbose = 1;
	unit_log_clear();
	homa_rpc_lock(crpc);
	homa_xmit_start_msg(crpc, 2500);
	EXPECT_STREQ("padded control packet with 1 bytes; "
		     "xmit START_MSG from 0.0.0.0:40000, dport 99, id 1234, msg_length 2500",
		     unit_log_get());
	homa_rpc_unlock(crpc);
}
#endif /* See strip.py */

TEST_F(homa_outgoing, homa_xmit_data__basics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 4000, 1000);

	unit_log_clear();
	homa_rpc_lock(crpc);
	homa_xmit_data(crpc);
	homa_rpc_unlock(crpc);
	EXPECT_STREQ("xmit DATA 1400@0; "
		     "xmit DATA 1400@1400; "
		     "xmit DATA 1200@2800", unit_log_get());
	EXPECT_EQ(4000, crpc->msgout.next_xmit_offset);
}
TEST_F(homa_outgoing, homa_xmit_data__rpc_ended)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 6000, 1000);

	unit_log_clear();
	homa_rpc_lock(crpc);
	unit_hook_register(lock_end_hook);
	hook_rpc = crpc;
	homa_xmit_data(crpc);
	homa_rpc_unlock(crpc);
	EXPECT_STREQ("xmit DATA 1400@0; homa_rpc_end invoked",
			unit_log_get());
	EXPECT_EQ(1400, crpc->msgout.next_xmit_offset);
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_outgoing, homa_xmit_data__stop_because_no_more_granted)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 6000, 1000);

	unit_log_clear();
	crpc->msgout.granted = 1000;
	homa_rpc_lock(crpc);
	homa_xmit_data(crpc);
	homa_rpc_unlock(crpc);
	EXPECT_STREQ("xmit DATA 1400@0", unit_log_get());
}
#endif /* See strip.py */
TEST_F(homa_outgoing, homa_xmit_data__stop_because_not_enough_data_copied_from_user_space)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 6000, 1000);
	crpc->msgout.copied_from_user = 2799;
	unit_log_clear();
	homa_rpc_lock(crpc);

	/* First call can't quite transmit the second packet. */
	homa_xmit_data(crpc);
	EXPECT_STREQ("xmit DATA 1400@0", unit_log_get());

	/* Second call transmits the second packet. */
	unit_log_clear();
	crpc->msgout.copied_from_user = 2800;
	homa_xmit_data(crpc);
	EXPECT_STREQ("xmit DATA 1400@1400", unit_log_get());

	homa_rpc_unlock(crpc);
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_outgoing, homa_xmit_data__metrics_for_client_rpc)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 6000, 1000);

	crpc->msgout.granted = 4000;
	homa_rpc_lock(crpc);
	homa_xmit_data(crpc);
	EXPECT_EQ(4200, homa_metrics_per_cpu()->client_request_bytes_done);
	EXPECT_EQ(0, homa_metrics_per_cpu()->client_requests_done);

	crpc->msgout.granted = 6000;
	homa_xmit_data(crpc);
	EXPECT_EQ(6000, homa_metrics_per_cpu()->client_request_bytes_done);
	EXPECT_EQ(1, homa_metrics_per_cpu()->client_requests_done);
	homa_rpc_unlock(crpc);
}
TEST_F(homa_outgoing, homa_xmit_data__metrics_for_server_rpc)
{
	struct homa_rpc *srpc;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->client_port,
			       self->server_id, 1000, 10000);

	srpc->msgout.granted = 4000;
	homa_rpc_lock(srpc);
	homa_xmit_data(srpc);
	EXPECT_EQ(4200, homa_metrics_per_cpu()->server_response_bytes_done);
	EXPECT_EQ(0, homa_metrics_per_cpu()->server_responses_done);

	srpc->msgout.granted = 9900;
	homa_xmit_data(srpc);
	EXPECT_EQ(10000, homa_metrics_per_cpu()->server_response_bytes_done);
	EXPECT_EQ(1, homa_metrics_per_cpu()->server_responses_done);
	homa_rpc_unlock(srpc);
}
#endif /* See strip.py */

TEST_F(homa_outgoing, homa_resend_data__basics)
{
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			16000, 1000);
	unit_log_clear();

	homa_rpc_lock(crpc);
	EXPECT_EQ(0, -homa_resend_data(crpc, 7100, 10000));
	EXPECT_STREQ("xmit DATA 1400@7000; "
		     "xmit DATA 1400@8400; "
		     "xmit DATA 1400@9800", unit_log_get());
	IF_NO_STRIP(EXPECT_EQ(3, homa_metrics_per_cpu()->resent_packets));
	homa_rpc_unlock(crpc);
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_outgoing, homa_resend_data__error)
{
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			16000, 1000);
	unit_log_clear();
	mock_alloc_skb_errors = 2;

	homa_rpc_lock(crpc);
	EXPECT_EQ(ENOMEM, -homa_resend_data(crpc, 7100, 10000));
	EXPECT_STREQ("xmit DATA 1400@7000", unit_log_get());
	IF_NO_STRIP(EXPECT_EQ(1, homa_metrics_per_cpu()->resent_packets));
	homa_rpc_unlock(crpc);
}

TEST_F(homa_outgoing, homa_rpc_tx_end)
{
	struct homa_qdisc_dev *qdev;
	struct homa_skb_info *info;
	struct homa_data_hdr h;
	struct homa_rpc *srpc;
	struct sk_buff *skb;
	int offset, length;

	qdev = homa_qdisc_qdev_get(self->dev);
	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->client_port, 1111,
			       10000, 10000);

	EXPECT_EQ(0, homa_rpc_tx_end(srpc));

	homa_rpc_lock(srpc);
	srpc->msgout.granted = 5000;
	homa_xmit_data(srpc);
	EXPECT_EQ(5600, homa_rpc_tx_end(srpc));
	homa_rpc_unlock(srpc);

	h.common = (struct homa_common_hdr){
		.sport = htons(srpc->hsk->port),
		.dport = htons(srpc->dport),
		.type = DATA,
		.sender_id = cpu_to_be64(srpc->id)
	};
	offset = 3000;
	length = 1000;
	h.msg_length = htonl(srpc->msgout.length);
	h.offset = htonl(offset);
	skb = unit_gro_skb(self->server_ip, self->client_ip, &h.common,
			   length + sizeof(struct homa_skb_info));
	info = homa_get_skb_info(skb);
	info->data_bytes = length;
	info->dont_defer = 0;
	qdisc_skb_cb(skb)->pkt_len = length + 100;

	homa_qdisc_defer_homa(qdev, skb);
	EXPECT_EQ(3000, homa_rpc_tx_end(srpc));

	homa_qdisc_xmit_deferred_homa(qdev);
	EXPECT_EQ(5600, homa_rpc_tx_end(srpc));

        homa_qdisc_qdev_put(qdev);
}
#endif /* See strip.py */
