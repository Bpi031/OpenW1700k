// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright: Joel Wirāmu Pauling <aenertia@aenertia.net>
//
// Artifact Name: airoha_hybrid_offload.c
// Purpose: TC ingress datapath for selective NPU flow offloading on Airoha AN7581.
//
// Architecture (Soft Hook):
//   TC ingress evaluates each packet on all physical interfaces (wired + WiFi).
//   For L3 routed flows: sets skb->mark = 0xAF00 (intercepted by NF_INET_FORWARD
//   hook in airoha_ppe.c). For L2 bridged flows: sets skb->mark = 0xAF01
//   (intercepted by NF_BR_FORWARD hook). The hooks program the NPU TCAM.
//
//   Three offload paths: HWNAT (wired, 0% CPU), WED (2.4/5GHz WiFi, 0% CPU),
//   NPU Loopback (6GHz WiFi with broken WED, ~10% CPU for bridge forwarding).
//
//   Latency-sensitive traffic (small packets, DNS, VoIP) is explicitly bypassed
//   so that SQM/CAKE can shape it on the CPU path.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

/* Constants not provided by vmlinux.h */
#define TC_ACT_OK          0
#define AF_INET            2
#define AF_INET6           10
#define ETH_P_IP           0x0800
#define ETH_P_IPV6         0x86DD
#define ETH_P_8021Q        0x8100
#define ETH_P_8021AD       0x88A8
#define IPPROTO_TCP        6
#define IPPROTO_UDP        17
#define IPPROTO_FRAGMENT   44
#define IPS_ESTABLISHED_BIT 1
#define IPS_ESTABLISHED    (1 << IPS_ESTABLISHED_BIT)
#define BPF_FIB_LKUP_RET_SUCCESS 0

#define AIROHA_FLOW_OFFLOAD_MARK   0xAF00 /* L3 routed flows */
#define AIROHA_BRIDGE_OFFLOAD_MARK 0xAF01 /* L2 bridged flows */
#define AIROHA_OFFLOAD_HWNAT       0x01
#define AIROHA_OFFLOAD_WED         0x02
#define AIROHA_OFFLOAD_LOOPBACK    0x03   /* 6GHz NPU loopback (broken WED) */
#define BPF_F_CURRENT_NETNS        (-1)

/* Minimum packet size to consider for offloading.
 * Packets smaller than this (ACKs, DNS, VoIP) stay on the CPU
 * for SQM/CAKE processing. */
#define OFFLOAD_MIN_PKT_LEN      128

/* vlan_hdr is already defined in vmlinux.h */

/* ----------------------------------------------------------------
 * Flow tracking structures (shared with airoha-sync-daemon)
 * ---------------------------------------------------------------- */
struct flow_key {
	__u32 src_ip[4];
	__u32 dst_ip[4];
	__be16 src_port;
	__be16 dst_port;
	__be16 l3_proto;
	__u8 l4_proto;
	__u8 padding;
};

struct flow_value {
	__u8 offload_flags;
	__u8 _pad[3];
	__u32 idle_time;
	__u64 last_hw_bytes;
	__u64 last_hw_pkts;
};

struct fdb_key {
	__u8 mac[6];
	__u16 padding;
	__u32 bridge_ifindex;
};

/* ----------------------------------------------------------------
 * BPF Maps
 * ---------------------------------------------------------------- */

/* Interface offload capability: ifindex -> offload type
 * 0=none, 1=WED (2.4/5GHz), 2=HWNAT (wired), 3=NPU loopback (6GHz) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} iface_offload_map SEC(".maps");

/* L2 FDB overlay: (MAC, bridge_ifindex) -> physical port ifindex */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct fdb_key);
	__type(value, __u32);
} mac_fdb_map SEC(".maps");

/* Port-to-bridge mapping: port ifindex -> bridge ifindex */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u32);
} port_to_bridge_map SEC(".maps");

/* Network namespace tracking: ifindex -> netns_id */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u32);
} netns_map SEC(".maps");

/* Active offloaded flows: flow_key -> flow_value (used by daemon for telemetry/eviction) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct flow_key);
	__type(value, struct flow_value);
} active_flow_map SEC(".maps");

/* Ring buffer for NPU hardware stats events (kprobe -> daemon) */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} hw_stats_rb SEC(".maps");

/* ----------------------------------------------------------------
 * bpf_ct_opts: kfunc parameter struct for conntrack lookups.
 * Not in vmlinux.h; defined in net/netfilter/nf_conntrack_bpf.c.
 * Must match the kernel's layout for CO-RE.
 * ---------------------------------------------------------------- */
struct bpf_ct_opts {
	__s32 netns_id;
	__s32 error;
	__u8 l4proto;
	__u8 dir;
	__u8 reserved[2];
};

/* Conntrack kfunc declarations (TC variant) */
extern struct nf_conn *bpf_skb_ct_lookup(struct __sk_buff *,
					 struct bpf_sock_tuple *, __u32,
					 struct bpf_ct_opts *, __u32) __ksym;
extern void bpf_ct_release(struct nf_conn *) __ksym;

/* ----------------------------------------------------------------
 * TC Ingress Program: Selective NPU Offload Decision Engine
 *
 * For each packet on ingress:
 *   1. Parse L2/L3/L4 headers (with VLAN/QinQ support)
 *   2. Skip small packets (let SQM/CAKE handle them)
 *   3. Determine egress via L2 FDB or L3 FIB lookup
 *   4. Verify egress interface supports hardware offload
 *   5. Check conntrack: only offload ESTABLISHED flows
 *   6. Set skb->mark = 0xAF00 and track the flow
 *
 * The mark survives IP forwarding. The airoha_eth driver checks
 * for it at TX time and programs the NPU TCAM.
 * ---------------------------------------------------------------- */
SEC("tc")
int airoha_tc_offload(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;

	if (data + sizeof(*eth) > data_end)
		return TC_ACT_OK;

	__be16 h_proto = eth->h_proto;
	int hdr_offset = sizeof(*eth);

	/* Handle single and double VLAN tags (802.1Q / 802.1AD) */
	if (h_proto == bpf_htons(ETH_P_8021Q) ||
	    h_proto == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr = data + hdr_offset;
		if ((void *)(vhdr + 1) > data_end)
			return TC_ACT_OK;
		h_proto = vhdr->h_vlan_encapsulated_proto;
		hdr_offset += sizeof(struct vlan_hdr);

		if (h_proto == bpf_htons(ETH_P_8021Q)) {
			vhdr = data + hdr_offset;
			if ((void *)(vhdr + 1) > data_end)
				return TC_ACT_OK;
			h_proto = vhdr->h_vlan_encapsulated_proto;
			hdr_offset += sizeof(struct vlan_hdr);
		}
	}

	/* Only handle IPv4 and IPv6 */
	if (h_proto != bpf_htons(ETH_P_IP) &&
	    h_proto != bpf_htons(ETH_P_IPV6))
		return TC_ACT_OK;

	/* Parse L3 and L4 headers */
	__be16 src_port = 0, dst_port = 0;
	__u8 l4_proto = 0;
	__u32 src_ip[4] = {0}, dst_ip[4] = {0};
	void *l4_hdr;
	int pkt_len = 0;

	struct bpf_sock_tuple tuple = {};
	__u32 tuple_len = 0;

	if (h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = data + hdr_offset;
		if ((void *)(ip + 1) > data_end)
			return TC_ACT_OK;

		/* Skip IP fragments - can't reliably extract L4 */
		if ((ip->frag_off & bpf_htons(0x3FFF)) != 0)
			return TC_ACT_OK;

		l4_proto = ip->protocol;
		l4_hdr = (void *)ip + (ip->ihl * 4);
		pkt_len = bpf_ntohs(ip->tot_len);
		src_ip[0] = ip->saddr;
		dst_ip[0] = ip->daddr;

		tuple.ipv4.saddr = ip->saddr;
		tuple.ipv4.daddr = ip->daddr;
		tuple_len = sizeof(tuple.ipv4);
	} else {
		struct ipv6hdr *ipv6 = data + hdr_offset;
		if ((void *)(ipv6 + 1) > data_end)
			return TC_ACT_OK;

		/* Skip IPv6 extension headers — only handle direct TCP/UDP
		 * nexthdr. Packets with Hop-by-Hop, Routing, Fragment, or
		 * Destination options headers stay on the CPU path.
		 * This matches the kernel PPE driver behavior (ROUTE_5T). */
		if (ipv6->nexthdr != IPPROTO_TCP && ipv6->nexthdr != IPPROTO_UDP)
			return TC_ACT_OK;

		l4_proto = ipv6->nexthdr;
		l4_hdr = (void *)(ipv6 + 1);
		pkt_len = bpf_ntohs(ipv6->payload_len) + sizeof(*ipv6);

		__builtin_memcpy(src_ip, &ipv6->saddr, sizeof(src_ip));
		__builtin_memcpy(dst_ip, &ipv6->daddr, sizeof(dst_ip));
		__builtin_memcpy(&tuple.ipv6.saddr, &ipv6->saddr,
				 sizeof(tuple.ipv6.saddr));
		__builtin_memcpy(&tuple.ipv6.daddr, &ipv6->daddr,
				 sizeof(tuple.ipv6.daddr));
		tuple_len = sizeof(tuple.ipv6);
	}

	/* Only offload TCP and UDP flows */
	if (l4_proto == IPPROTO_TCP) {
		struct tcphdr *tcp = l4_hdr;
		if ((void *)(tcp + 1) > data_end)
			return TC_ACT_OK;
		src_port = tcp->source;
		dst_port = tcp->dest;
	} else if (l4_proto == IPPROTO_UDP) {
		struct udphdr *udp = l4_hdr;
		if ((void *)(udp + 1) > data_end)
			return TC_ACT_OK;
		src_port = udp->source;
		dst_port = udp->dest;
	} else {
		return TC_ACT_OK;
	}

	/* Fill in L4 ports for the CT lookup tuple */
	if (h_proto == bpf_htons(ETH_P_IP)) {
		tuple.ipv4.sport = src_port;
		tuple.ipv4.dport = dst_port;
	} else {
		tuple.ipv6.sport = src_port;
		tuple.ipv6.dport = dst_port;
	}

	/* SQM bypass: skip small packets so CAKE/fq_codel can shape them.
	 * This keeps ACKs, DNS, VoIP, and gaming traffic on the CPU. */
	if (pkt_len < OFFLOAD_MIN_PKT_LEN)
		return TC_ACT_OK;

	/* Determine egress interface.
	 * First try L2 FDB (bridged traffic), then fall back to L3 FIB. */
	__u32 ingress_ifindex = skb->ingress_ifindex;
	__u32 egress_ifindex = 0;

	__u32 *bridge_ifindex = bpf_map_lookup_elem(&port_to_bridge_map,
						    &ingress_ifindex);
	if (bridge_ifindex) {
		struct fdb_key fkey = {};
		__builtin_memcpy(fkey.mac, eth->h_dest, 6);
		fkey.bridge_ifindex = *bridge_ifindex;

		__u32 *fdb_ifindex = bpf_map_lookup_elem(&mac_fdb_map, &fkey);
		if (fdb_ifindex && *fdb_ifindex != 0) {
			/*
			 * L2 bridge flow: mark for NPU offloading via
			 * the NF_BR_FORWARD hook. No CT lookup needed
			 * (bridged traffic has no conntrack without
			 * br_netfilter). No size filter (SQM is for
			 * WAN bottleneck, not local bridge traffic).
			 *
			 * Mark 0xAF01 distinguishes L2 bridge flows
			 * from L3 routed flows (0xAF00). The kernel
			 * bridge NF hook creates PPE_PKT_TYPE_BRIDGE
			 * entries in ppe->l2_flows.
			 */
			__u8 *ot = bpf_map_lookup_elem(&iface_offload_map,
						       fdb_ifindex);
			if (!ot || *ot == 0)
				return TC_ACT_OK;

			skb->mark = AIROHA_BRIDGE_OFFLOAD_MARK;

			struct flow_key fkey_l2 = {};
			__builtin_memcpy(fkey_l2.src_ip, src_ip,
					 sizeof(fkey_l2.src_ip));
			__builtin_memcpy(fkey_l2.dst_ip, dst_ip,
					 sizeof(fkey_l2.dst_ip));
			fkey_l2.src_port = src_port;
			fkey_l2.dst_port = dst_port;
			fkey_l2.l3_proto = h_proto;
			fkey_l2.l4_proto = l4_proto;

			struct flow_value fval_l2 = {};
			fval_l2.offload_flags = *ot;
			bpf_map_update_elem(&active_flow_map, &fkey_l2,
					    &fval_l2, BPF_NOEXIST);
			return TC_ACT_OK;
		}
	}

	/* L3 routed flow: resolved via FIB lookup */
	{
		struct bpf_fib_lookup fib_params = {};
		if (h_proto == bpf_htons(ETH_P_IP)) {
			fib_params.family = AF_INET;
			fib_params.ipv4_src = src_ip[0];
			fib_params.ipv4_dst = dst_ip[0];
		} else {
			fib_params.family = AF_INET6;
			__builtin_memcpy(fib_params.ipv6_src, src_ip,
					 sizeof(fib_params.ipv6_src));
			__builtin_memcpy(fib_params.ipv6_dst, dst_ip,
					 sizeof(fib_params.ipv6_dst));
		}
		fib_params.ifindex = ingress_ifindex;

		int fib_rc = bpf_fib_lookup(skb, &fib_params,
					    sizeof(fib_params), 0);
		if (fib_rc != BPF_FIB_LKUP_RET_SUCCESS)
			return TC_ACT_OK;

		egress_ifindex = fib_params.ifindex;
	}

	/* Verify the egress interface supports hardware offloading */
	__u8 *offload_type = bpf_map_lookup_elem(&iface_offload_map,
						 &egress_ifindex);
	if (!offload_type || *offload_type == 0)
		return TC_ACT_OK;

	/* Resolve the network namespace for the CT lookup */
	__u32 *netns_id_ptr = bpf_map_lookup_elem(&netns_map,
						  &ingress_ifindex);
	__s32 netns_id = (netns_id_ptr && *netns_id_ptr != 0xFFFFFFFF)
			 ? (__s32)*netns_id_ptr : BPF_F_CURRENT_NETNS;

	/* Conntrack lookup: only offload ESTABLISHED flows.
	 * This prevents SYN flood / UDP flood from exhausting the TCAM. */
	struct bpf_ct_opts ct_opts = {
		.netns_id = netns_id,
		.l4proto = l4_proto,
	};
	struct nf_conn *ct = bpf_skb_ct_lookup(skb, &tuple, tuple_len,
					       &ct_opts, sizeof(ct_opts));
	if (!ct)
		return TC_ACT_OK;

	__u32 ct_status = BPF_CORE_READ(ct, status);
	if (ct_status & IPS_ESTABLISHED) {
		/*
		 * Set the offload mark. This survives through IP forwarding
		 * to a Netfilter FORWARD hook in airoha_ppe.c, which
		 * extracts the flow tuple and NAT info from conntrack
		 * (via nf_ct_get) and programs the NPU TCAM.
		 *
		 * Works for both wired (HWNAT) and WiFi (WED) egress —
		 * airoha_ppe_foe_entry_prepare() auto-detects WiFi via
		 * dev_fill_forward_path() -> FE_PSE_PORT_CDM4.
		 */
		skb->mark = AIROHA_FLOW_OFFLOAD_MARK;

		/* Track the flow for daemon telemetry and eviction.
		 * BPF_NOEXIST ensures only the first packet inserts. */
		struct flow_key fkey = {};
		__builtin_memcpy(fkey.src_ip, src_ip, sizeof(fkey.src_ip));
		__builtin_memcpy(fkey.dst_ip, dst_ip, sizeof(fkey.dst_ip));
		fkey.src_port = src_port;
		fkey.dst_port = dst_port;
		fkey.l3_proto = h_proto;
		fkey.l4_proto = l4_proto;

		struct flow_value fval = {};
		fval.offload_flags = *offload_type;
		bpf_map_update_elem(&active_flow_map, &fkey, &fval,
				    BPF_NOEXIST);
	}

	bpf_ct_release(ct);
	return TC_ACT_OK;
}

/* ----------------------------------------------------------------
 * Kprobe: NPU Hardware Telemetry Collector
 *
 * Attaches to the noinline anchor bpf_airoha_npu_telemetry_event()
 * in the airoha_npu.c polling loop. Reads hw_stats_event from the
 * NPU driver's stack and forwards it to userspace via ring buffer.
 * ---------------------------------------------------------------- */
/*
 * hw_stats_event layout must EXACTLY match struct airoha_hw_stats_event
 * in the kernel (998 patch). Fields are inline (not embedded flow_key)
 * because the kernel places teardown_flag at the padding byte position,
 * giving a 56-byte struct vs 64 if flow_key were embedded separately.
 */
struct hw_stats_event {
	__u32 src_ip[4];
	__u32 dst_ip[4];
	__u16 src_port;
	__u16 dst_port;
	__u16 l3_proto;
	__u8 l4_proto;
	__u8 teardown_flag;
	__u64 bytes;
	__u64 packets;
};

SEC("kprobe/bpf_airoha_npu_telemetry_event")
int BPF_KPROBE(airoha_npu_telemetry_kprobe, void *drv_event_ptr)
{
	struct hw_stats_event *ring_event;

	ring_event = bpf_ringbuf_reserve(&hw_stats_rb,
					 sizeof(*ring_event), 0);
	if (!ring_event)
		return 0;

	bpf_probe_read_kernel(ring_event, sizeof(*ring_event),
			      drv_event_ptr);
	bpf_ringbuf_submit(ring_event, 0);

	return 0;
}

char _license[] SEC("license") = "GPL";
