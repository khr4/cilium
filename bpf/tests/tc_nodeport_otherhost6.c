// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

static int
BPF_FUNC(skb_vlan_push, struct __sk_buff *skb, __be16 proto, __u16 tci);

/* Enable code paths under test */
#define ENABLE_IPV6
#define ENABLE_NODEPORT

#define CLIENT_IP	     { .addr = v6_ext_node_one_addr }
#define CLIENT_PORT	     __bpf_htons(111)
#define CLIENT_IP_2	     { .addr = v6_ext_node_two_addr }

#define FRONTEND_IP_LOCAL    { .addr = v6_svc_one_addr }
#define FRONTEND_IP_REMOTE   { .addr = v6_svc_two_addr }
#define FRONTEND_IP_REMOTE_2 { .addr = v6_svc_three_addr }
#define FRONTEND_PORT	     tcp_svc_one

#define LB_IP		     { .addr = v6_node_one_addr }
#define IPV6_DIRECT_ROUTING  LB_IP

#define BACKEND_IP_LOCAL     { .addr = v6_pod_one_addr }
#define BACKEND_IP_REMOTE    { .addr = v6_pod_two_addr }
#define BACKEND_PORT	     __bpf_htons(8080)

#define DEFAULT_IFACE	     24
#define BACKEND_IFACE	     25
#define SVC_EGRESS_IFACE     26

#define BACKEND_EP_ID	     127

#define fib_lookup	     mock_fib_lookup

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *lb_mac = mac_host;
static volatile const __u8 *node_mac = mac_three;
static volatile const __u8 *local_backend_mac = mac_four;
static volatile const __u8 *remote_backend_mac = mac_five;

__section_entry int mock_handle_policy(struct __ctx_buff *ctx __maybe_unused)
{
	return TC_ACT_REDIRECT;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 256);
	__array(values, int());
} mock_policy_call_map __section(".maps") = {
	.values = {
		[BACKEND_EP_ID] = &mock_handle_policy,
	},
};

#define tail_call_dynamic mock_tail_call_dynamic
static __always_inline __maybe_unused void mock_tail_call_dynamic(
	struct __ctx_buff *ctx __maybe_unused, const void *map __maybe_unused,
	__u32 slot __maybe_unused)
{
	tail_call(ctx, &mock_policy_call_map, slot);
}

struct mock_settings {
	__be16 nat_source_port;
	bool fail_fib;
	bool deny_early_hook;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct mock_settings));
	__uint(max_entries, 1);
} settings_map __section_maps_btf;

#define fib_lookup mock_fib_lookup

long mock_fib_lookup(
	__maybe_unused struct __ctx_buff *volatile ctx,
	struct bpf_fib_lookup *params, __maybe_unused int plen,
	__maybe_unused __u32 flags)
{
	const union v6addr backend_ip_remote = BACKEND_IP_REMOTE;
	const union v6addr frontend_ip_local = FRONTEND_IP_LOCAL;
	const union v6addr client_ip_2 = CLIENT_IP_2;
	__u32 key = 0;
	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	/* Verifier doesn't know that params is not NULL when verifying this
	 * function separately (see btf_prepare_func_args in kernel/bpf/btf.c).
	 * There is no appropriate EINVAL-like error code in this helper, so
	 * return some arbitrary error.
	 */
	if (!params)
		return BPF_FIB_LKUP_RET_BLACKHOLE;

	params->ifindex = DEFAULT_IFACE;

	if (memcmp(params->ipv6_dst, &backend_ip_remote,
		   sizeof(backend_ip_remote)) == 0) {
		__bpf_memcpy_builtin(params->smac, (__u8 *)lb_mac, ETH_ALEN);
		__bpf_memcpy_builtin(
			params->dmac, (__u8 *)remote_backend_mac, ETH_ALEN);
	} else if (
		memcmp(params->ipv6_src, &frontend_ip_local,
		       sizeof(frontend_ip_local)) == 0 &&
		memcmp(params->ipv6_dst, &client_ip_2, sizeof(client_ip_2)) == 0) {
		__bpf_memcpy_builtin(params->smac, (__u8 *)lb_mac, ETH_ALEN);
		__bpf_memcpy_builtin(params->dmac, (__u8 *)client_mac, ETH_ALEN);
		params->ifindex = SVC_EGRESS_IFACE;
	} else {
		__bpf_memcpy_builtin(params->smac, (__u8 *)lb_mac, ETH_ALEN);
		__bpf_memcpy_builtin(params->dmac, (__u8 *)client_mac, ETH_ALEN);
	}

	if (settings && settings->fail_fib)
		return BPF_FIB_LKUP_RET_NO_NEIGH;

	return 0;
}

#define ctx_redirect mock_ctx_redirect

static __always_inline __maybe_unused int mock_ctx_redirect(
	const struct __sk_buff *ctx __maybe_unused, int ifindex __maybe_unused,
	__u32 flags __maybe_unused)
{
	const union v6addr client_ip = CLIENT_IP;
	const union v6addr client_ip_2 = CLIENT_IP_2;
	const union v6addr lb_ip = LB_IP;
	const union v6addr frontend_ip_remote = FRONTEND_IP_REMOTE;
	const union v6addr frontend_ip_remote_2 = FRONTEND_IP_REMOTE_2;
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;
	struct ipv6hdr *ip6;

	ip6 = data + sizeof(struct ethhdr);
	if ((void *)ip6 + sizeof(*ip6) > data_end)
		return CTX_ACT_DROP;

	/* Forward to backend: */
	if (memcmp(&ip6->saddr, &client_ip, sizeof(client_ip)) == 0 &&
	    ifindex == BACKEND_IFACE)
		return CTX_ACT_REDIRECT;
	if (memcmp(&ip6->saddr, &client_ip_2, sizeof(client_ip_2)) == 0 &&
	    ifindex == BACKEND_IFACE)
		return CTX_ACT_REDIRECT;
	if (memcmp(&ip6->saddr, &lb_ip, sizeof(lb_ip)) == 0 &&
	    ifindex == DEFAULT_IFACE)
		return CTX_ACT_REDIRECT;

	/* Redirected reply: */
	if (memcmp(&ip6->daddr, &client_ip_2, sizeof(client_ip_2)) == 0 &&
	    ifindex == SVC_EGRESS_IFACE)
		return CTX_ACT_REDIRECT;
	if (memcmp(&ip6->saddr, &frontend_ip_remote,
		   sizeof(frontend_ip_remote)) == 0 &&
	    ifindex == DEFAULT_IFACE)
		return CTX_ACT_REDIRECT;
	if (memcmp(&ip6->saddr, &frontend_ip_remote_2,
		   sizeof(frontend_ip_remote_2)) == 0 &&
	    ifindex == DEFAULT_IFACE)
		return CTX_ACT_REDIRECT;

	return CTX_ACT_DROP;
}

static __always_inline int
mock_early_hook(struct __ctx_buff *ctx __maybe_unused, __be16 proto __maybe_unused)
{
	__u32 key = 0;
	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	return settings && settings->deny_early_hook ? CTX_ACT_DROP : CTX_ACT_OK;
}

#define tcx_early_hook mock_early_hook

#include "lib/bpf_host.h"

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"

ASSIGN_CONFIG(bool, enable_bpf_host_routing, true)
ASSIGN_CONFIG(__u32, interface_ifindex, DEFAULT_IFACE)

/* Set port ranges to have deterministic source port selection */
#include "nodeport_defaults.h"

struct original_packet {
	__u8 frame[74];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct original_packet);
	__uint(max_entries, 1);
} original_packets __section_maps_btf;

static __always_inline int make_syn(struct __ctx_buff *ctx, __u32 type)
{
	union v6addr client = CLIENT_IP;
	union v6addr frontend = FRONTEND_IP_LOCAL;
	struct pktgen builder;
	struct tcphdr *tcp;

	__u32 key = 0;
	struct mock_settings settings = {};

	if (map_update_elem(&settings_map, &key, &settings, BPF_ANY))
		return TEST_ERROR;
	pktgen__init(&builder, ctx);
	tcp = pktgen__push_ipv6_tcp_packet(
		&builder, (__u8 *)client_mac,
		type == PACKET_OTHERHOST ? (__u8 *)node_mac : (__u8 *)lb_mac,
		(__u8 *)&client, (__u8 *)&frontend,
		__bpf_htons((__u16)(111 + type)), FRONTEND_PORT);
	if (!tcp)
		return TEST_ERROR;
	tcp->syn = 1;
	pktgen__finish(&builder);
	return 0;
}

static __always_inline int setup_syn(struct __ctx_buff *ctx, __u32 type)
{
	union v6addr frontend = FRONTEND_IP_LOCAL;
	union v6addr backend = BACKEND_IP_LOCAL;
	lb_v6_add_service(&frontend, FRONTEND_PORT, IPPROTO_TCP, 1, 1);
	lb_v6_add_backend(
		&frontend, FRONTEND_PORT, 1, 124, &backend, BACKEND_PORT,
		IPPROTO_TCP, 0);
	endpoint_v6_add_entry(
		&backend, BACKEND_IFACE, BACKEND_EP_ID, 0, 0,
		(__u8 *)local_backend_mac, (__u8 *)node_mac);
	ipcache_v6_add_entry(&backend, 0, 112233, 0, 0);
	__u32 key = 0;
	struct original_packet original = {};

	if (ctx_load_bytes(ctx, 0, &original, sizeof(original)))
		return TEST_ERROR;
	if (map_update_elem(&original_packets, &key, &original, BPF_ANY))
		return TEST_ERROR;
	return netdev_receive_packet_type(ctx, type);
}

static __always_inline int
check_syn(const struct __ctx_buff *ctx, bool otherhost)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *end = (void *)(long)ctx->data_end;
	__u32 *status = data;
	union v6addr frontend = FRONTEND_IP_LOCAL;
	union v6addr backend = BACKEND_IP_LOCAL;
	union v6addr client = CLIENT_IP;
	struct ipv6hdr *ip = data + sizeof(*status) + sizeof(struct ethhdr);

	test_init();
	if ((void *)(ip + 1) > end)
		test_fatal("packet truncated");
	if (otherhost) {
		__u32 key = 0;
		struct original_packet *original =
			map_lookup_elem(&original_packets, &key);
		struct ipv6_ct_tuple tuple = {
			.saddr = CLIENT_IP,
			.daddr = FRONTEND_IP_LOCAL,
			.sport = FRONTEND_PORT,
			.dport = __bpf_htons(111 + PACKET_OTHERHOST),
			.nexthdr = IPPROTO_TCP
		};

		assert(original);
		assert(ctx_full_len(ctx) ==
		       sizeof(__u32) + sizeof(original->frame));
		if (data + sizeof(__u32) + sizeof(original->frame) > end)
			test_fatal("original frame truncated");
		assert(!memcmp(data + sizeof(__u32), original->frame,
			       sizeof(original->frame)));
		/* CT stores ports reversed; NAT uses wire-order ports. Check both
		 * tuple directions and both service and backend addresses.
		 */
		for (__u8 flags = 0; flags < 8; flags++) {
			tuple.flags = flags;
			struct ipv6_ct_tuple nat_tuple = tuple;

			assert(!map_lookup_elem(&cilium_ct6_global, &tuple));
			ipv6_ct_tuple_swap_ports(&nat_tuple);
			assert(!map_lookup_elem(
				&cilium_snat_v6_external, &nat_tuple));
		}
		ipv6_ct_tuple_swap_addrs(&tuple);
		ipv6_ct_tuple_swap_ports(&tuple);
		for (__u8 flags = 0; flags < 8; flags++) {
			tuple.flags = flags;
			struct ipv6_ct_tuple nat_tuple = tuple;

			assert(!map_lookup_elem(&cilium_ct6_global, &tuple));
			ipv6_ct_tuple_swap_ports(&nat_tuple);
			assert(!map_lookup_elem(
				&cilium_snat_v6_external, &nat_tuple));
		}
		ipv6_ct_tuple_swap_addrs(&tuple);
		ipv6_ct_tuple_swap_ports(&tuple);
		tuple.daddr = (union v6addr)BACKEND_IP_LOCAL;
		tuple.sport = BACKEND_PORT;
		for (__u8 flags = 0; flags < 8; flags++) {
			tuple.flags = flags;
			struct ipv6_ct_tuple nat_tuple = tuple;

			assert(!map_lookup_elem(&cilium_ct6_global, &tuple));
			ipv6_ct_tuple_swap_ports(&nat_tuple);
			assert(!map_lookup_elem(
				&cilium_snat_v6_external, &nat_tuple));
		}
		ipv6_ct_tuple_swap_addrs(&tuple);
		ipv6_ct_tuple_swap_ports(&tuple);
		for (__u8 flags = 0; flags < 8; flags++) {
			tuple.flags = flags;
			struct ipv6_ct_tuple nat_tuple = tuple;

			assert(!map_lookup_elem(&cilium_ct6_global, &tuple));
			ipv6_ct_tuple_swap_ports(&nat_tuple);
			assert(!map_lookup_elem(
				&cilium_snat_v6_external, &nat_tuple));
		}
		assert(*status == CTX_ACT_OK);
		assert(!memcmp(&ip->daddr, &frontend, sizeof(frontend)));
		assert(!memcmp(&ip->saddr, &client, sizeof(client)));
	} else {
		assert(*status == CTX_ACT_REDIRECT);
		assert(!memcmp(&ip->daddr, &backend, sizeof(backend)));
	}
	test_finish();
}

PKTGEN(PROG_TYPE, "otherhost_syn")
int otherhost_pktgen(struct __ctx_buff *ctx)
{
	return make_syn(ctx, PACKET_OTHERHOST);
}
SETUP(PROG_TYPE, "otherhost_syn")
int otherhost_setup(struct __ctx_buff *ctx)
{
	return setup_syn(ctx, PACKET_OTHERHOST);
}
CHECK(PROG_TYPE, "otherhost_syn")
int otherhost_check(const struct __ctx_buff *ctx)
{
	return check_syn(ctx, true);
}

PKTGEN(PROG_TYPE, "host_syn")
int host_pktgen(struct __ctx_buff *ctx)
{
	return make_syn(ctx, PACKET_HOST);
}
SETUP(PROG_TYPE, "host_syn")
int host_setup(struct __ctx_buff *ctx)
{
	return setup_syn(ctx, PACKET_HOST);
}
CHECK(PROG_TYPE, "host_syn")
int host_check(const struct __ctx_buff *ctx)
{
	return check_syn(ctx, false);
}

PKTGEN(PROG_TYPE, "broadcast_syn")
int broadcast_pktgen(struct __ctx_buff *ctx)
{
	return make_syn(ctx, PACKET_BROADCAST);
}
SETUP(PROG_TYPE, "broadcast_syn")
int broadcast_setup(struct __ctx_buff *ctx)
{
	return setup_syn(ctx, PACKET_BROADCAST);
}
CHECK(PROG_TYPE, "broadcast_syn")
int broadcast_check(const struct __ctx_buff *ctx)
{
	return check_syn(ctx, false);
}

PKTGEN(PROG_TYPE, "multicast_syn")
int multicast_pktgen(struct __ctx_buff *ctx)
{
	return make_syn(ctx, PACKET_MULTICAST);
}
SETUP(PROG_TYPE, "multicast_syn")
int multicast_setup(struct __ctx_buff *ctx)
{
	return setup_syn(ctx, PACKET_MULTICAST);
}
CHECK(PROG_TYPE, "multicast_syn")
int multicast_check(const struct __ctx_buff *ctx)
{
	return check_syn(ctx, false);
}

/* Foreign destination MACs must not bypass mandatory ingress guards. */
PKTGEN(PROG_TYPE, "otherhost_hook_deny")
int otherhost_hook_pktgen(struct __ctx_buff *ctx)
{
	return make_syn(ctx, PACKET_OTHERHOST);
}
SETUP(PROG_TYPE, "otherhost_hook_deny")
int otherhost_hook_setup(struct __ctx_buff *ctx)
{
	__u32 key = 0;
	struct mock_settings settings = { .deny_early_hook = true };

	if (map_update_elem(&settings_map, &key, &settings, BPF_ANY))
		return TEST_ERROR;
	return setup_syn(ctx, PACKET_OTHERHOST);
}
CHECK(PROG_TYPE, "otherhost_hook_deny")
int otherhost_hook_check(const struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *end = (void *)(long)ctx->data_end;
	__u32 *status = data;

	test_init();
	if ((void *)(status + 1) > end)
		test_fatal("status truncated");
	assert(*status == CTX_ACT_DROP);
	test_finish();
}

PKTGEN(PROG_TYPE, "otherhost_vlan_deny")
int otherhost_vlan_pktgen(struct __ctx_buff *ctx)
{
	return make_syn(ctx, PACKET_OTHERHOST);
}
SETUP(PROG_TYPE, "otherhost_vlan_deny")
int otherhost_vlan_setup(struct __ctx_buff *ctx)
{
	if (skb_vlan_push(ctx, __bpf_htons(ETH_P_8021Q), 4094))
		return TEST_ERROR;
	return setup_syn(ctx, PACKET_OTHERHOST);
}
CHECK(PROG_TYPE, "otherhost_vlan_deny")
int otherhost_vlan_check(const struct __ctx_buff *ctx)
{
	return otherhost_hook_check(ctx);
}
