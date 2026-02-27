// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright: Joel Wirāmu Pauling <aenertia@aenertia.net>
//
// Artifact Name: airoha-sync-daemon.c
// Purpose: Userspace daemon that syncs Netfilter telemetry via eBPF ring buffers,
//          manages L2 FDB/Network Namespace mappings, and evicts stale hardware flows.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <glob.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libmnl/libmnl.h>

#define MAC_FDB_MAP_PATH "/sys/fs/bpf/tc/globals/mac_fdb_map"
#define ACTIVE_FLOW_MAP_PATH "/sys/fs/bpf/tc/globals/active_flow_map"
#define HW_STATS_RB_PATH "/sys/fs/bpf/tc/globals/hw_stats_rb"
#define IFACE_MAP_PATH "/sys/fs/bpf/tc/globals/iface_offload_map"
#define PORT_BRIDGE_MAP_PATH "/sys/fs/bpf/tc/globals/port_to_bridge_map"
#define NETNS_MAP_PATH "/sys/fs/bpf/tc/globals/netns_map"
#define DEBUG_FS_STATS_PATH "/sys/kernel/debug/airoha_npu/flow_stats"

struct flow_key {
    uint32_t src_ip[4];
    uint32_t dst_ip[4];
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t l3_proto; 
    uint8_t l4_proto;  
    uint8_t padding;
};

struct flow_value {
    uint8_t offload_flags;
    uint8_t _pad[3];
    uint32_t idle_time;
    uint64_t last_hw_bytes;
    uint64_t last_hw_pkts;
};

/*
 * Layout must exactly match struct airoha_hw_stats_event in the kernel
 * (998 patch) and struct hw_stats_event in airoha_hybrid_offload.c.
 * Fields are inline (not embedded flow_key) because teardown_flag
 * occupies the padding byte at offset 39.
 */
struct hw_stats_event {
    uint32_t src_ip[4];
    uint32_t dst_ip[4];
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t l3_proto;
    uint8_t l4_proto;
    uint8_t teardown_flag;
    uint64_t bytes;
    uint64_t packets;
};

struct fdb_key {
    uint8_t mac[6];
    uint16_t padding;
    uint32_t bridge_ifindex;
};

int fdb_map_fd = -1;
int flow_map_fd = -1;
int rb_map_fd = -1;
int iface_map_fd = -1;
int port_bridge_map_fd = -1;
int netns_map_fd = -1;
struct ring_buffer *rb = NULL;

uint8_t resolve_offload_capability(const char *ifname) {
    char current[IFNAMSIZ];
    snprintf(current, sizeof(current), "%s", ifname);

    for (int depth = 0; depth < 5; depth++) {
        if (strncmp(current, "eth", 3) == 0 || strncmp(current, "lan", 3) == 0) return 2;
        if (strncmp(current, "wlan", 4) == 0 || strncmp(current, "phy", 3) == 0) {
            /* Match wlan2 / phy2 specifically (6GHz radio) */
            if (strcmp(current, "wlan2") == 0 || strcmp(current, "phy2") == 0)
                return 3; /* 6GHz: NPU loopback (broken WED/HWRRO V3) */
            return 1; /* 2.4/5GHz: WED offload */
        }

        if (strncmp(current, "br-", 3) == 0 || strncmp(current, "veth", 4) == 0 ||
            strncmp(current, "tun", 3) == 0 || strncmp(current, "tap", 3) == 0 ||
            strncmp(current, "wg", 2) == 0) {
            return 0;
        }

        char pattern[256];
        snprintf(pattern, sizeof(pattern), "/sys/class/net/%s/lower_*", current);
        glob_t gl;
        if (glob(pattern, 0, NULL, &gl) == 0 && gl.gl_pathc > 0) {
            char *lower = strrchr(gl.gl_pathv[0], '_');
            if (lower) {
                snprintf(current, sizeof(current), "%s", lower + 1);
                globfree(&gl);
                continue;
            }
        }
        globfree(&gl);
        break;
    }
    return 0;
}

static int neigh_attr_cb(const struct nlattr *attr, void *data) {
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);
    if (mnl_attr_type_valid(attr, NDA_MAX) < 0) return MNL_CB_OK;
    tb[type] = attr;
    return MNL_CB_OK;
}

static int link_attr_cb(const struct nlattr *attr, void *data) {
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);
    if (mnl_attr_type_valid(attr, IFLA_MAX) < 0) return MNL_CB_OK;
    tb[type] = attr;
    return MNL_CB_OK;
}

static int link_cb(const struct nlmsghdr *nlh, void *data) {
    struct ifinfomsg *ifi = mnl_nlmsg_get_payload(nlh);
    struct nlattr *tb[IFLA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(*ifi), link_attr_cb, tb);

    if (tb[IFLA_IFNAME] && iface_map_fd >= 0) {
        const char *ifname = mnl_attr_get_str(tb[IFLA_IFNAME]);
        uint32_t ifindex = ifi->ifi_index;

        if (nlh->nlmsg_type == RTM_NEWLINK) {
            uint8_t cap = resolve_offload_capability(ifname);
            bpf_map_update_elem(iface_map_fd, &ifindex, &cap, BPF_ANY);

            if (tb[IFLA_MASTER] && port_bridge_map_fd >= 0) {
                uint32_t master_ifindex = mnl_attr_get_u32(tb[IFLA_MASTER]);
                bpf_map_update_elem(port_bridge_map_fd, &ifindex, &master_ifindex, BPF_ANY);
            } else if (port_bridge_map_fd >= 0) {
                bpf_map_delete_elem(port_bridge_map_fd, &ifindex);
            }

            if (tb[IFLA_LINK_NETNSID] && netns_map_fd >= 0) {
                uint32_t netns_id = mnl_attr_get_u32(tb[IFLA_LINK_NETNSID]);
                bpf_map_update_elem(netns_map_fd, &ifindex, &netns_id, BPF_ANY);
            } else if (netns_map_fd >= 0) {
                uint32_t default_ns = 0xFFFFFFFF;
                bpf_map_update_elem(netns_map_fd, &ifindex, &default_ns, BPF_ANY);
            }
        } else if (nlh->nlmsg_type == RTM_DELLINK) {
            bpf_map_delete_elem(iface_map_fd, &ifindex);
            if (port_bridge_map_fd >= 0) bpf_map_delete_elem(port_bridge_map_fd, &ifindex);
            if (netns_map_fd >= 0) bpf_map_delete_elem(netns_map_fd, &ifindex);
        }
    }
    return MNL_CB_OK;
}

static int neigh_cb(const struct nlmsghdr *nlh, void *data) {
    struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);
    
    if (ndm->ndm_family != AF_BRIDGE) return MNL_CB_OK;

    struct nlattr *tb[NDA_MAX + 1] = {};
    mnl_attr_parse(nlh, sizeof(*ndm), neigh_attr_cb, tb);

    if (tb[NDA_LLADDR]) {
        uint8_t *mac = mnl_attr_get_payload(tb[NDA_LLADDR]);
        uint32_t port_ifindex = ndm->ndm_ifindex;
        uint32_t bridge_ifindex = 0;

        if (port_bridge_map_fd >= 0 && bpf_map_lookup_elem(port_bridge_map_fd, &port_ifindex, &bridge_ifindex) != 0) {
            bridge_ifindex = port_ifindex;
        }

        struct fdb_key key = {0};
        memcpy(key.mac, mac, 6);
        key.bridge_ifindex = bridge_ifindex;

        if (fdb_map_fd >= 0) {
            if (nlh->nlmsg_type == RTM_NEWNEIGH) {
                bpf_map_update_elem(fdb_map_fd, &key, &port_ifindex, BPF_ANY);
            } else if (nlh->nlmsg_type == RTM_DELNEIGH) {
                bpf_map_delete_elem(fdb_map_fd, &key);
            }
        }
    }
    return MNL_CB_OK;
}

static int route_multiplexer_cb(const struct nlmsghdr *nlh, void *data) {
    if (nlh->nlmsg_type == RTM_NEWLINK || nlh->nlmsg_type == RTM_DELLINK) {
        return link_cb(nlh, data);
    } else if (nlh->nlmsg_type == RTM_NEWNEIGH || nlh->nlmsg_type == RTM_DELNEIGH) {
        return neigh_cb(nlh, data);
    }
    return MNL_CB_OK;
}

void *netlink_topology_listener(void *arg) {
    struct mnl_socket *nl = mnl_socket_open(NETLINK_ROUTE);
    if (nl == NULL) pthread_exit(NULL);

    unsigned int groups = (1 << (RTNLGRP_LINK - 1)) | (1 << (RTNLGRP_NEIGH - 1));
    if (mnl_socket_bind(nl, groups, MNL_SOCKET_AUTOPID) < 0) {
        mnl_socket_close(nl);
        pthread_exit(NULL);
    }

    char buf[MNL_SOCKET_BUFFER_SIZE];
    printf("Starting libmnl Listener for Link & L2 FDB overlay updates...\n");

    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    struct ifinfomsg *ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifi));
    ifi->ifi_family = AF_UNSPEC;
    mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);

    while (1) {
        int ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        if (ret < 0) continue;
        mnl_cb_run(buf, ret, 0, 0, route_multiplexer_cb, NULL);
    }
    mnl_socket_close(nl);
    return NULL;
}

/* Persistent conntrack handle — opened once, reused for all updates */
static struct nfct_handle *nfct_h = NULL;

static struct nfct_handle *get_nfct_handle(void) {
    if (!nfct_h)
        nfct_h = nfct_open(CONNTRACK, 0);
    return nfct_h;
}

void sync_hardware_counters(const struct flow_key *key, uint64_t hw_bytes_delta, uint64_t hw_pkts_delta, int destroy) {
    if (!destroy && hw_bytes_delta == 0 && hw_pkts_delta == 0) return;

    struct nfct_handle *h = get_nfct_handle();
    if (!h) return;

    struct nf_conntrack *ct = nfct_new();
    if (ct) {
        if (key->l3_proto == htons(ETH_P_IP)) {
            nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
            nfct_set_attr_u32(ct, ATTR_IPV4_SRC, key->src_ip[0]);
            nfct_set_attr_u32(ct, ATTR_IPV4_DST, key->dst_ip[0]);
        } else {
            nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET6);
            nfct_set_attr(ct, ATTR_IPV6_SRC, key->src_ip);
            nfct_set_attr(ct, ATTR_IPV6_DST, key->dst_ip);
        }

        nfct_set_attr_u8(ct, ATTR_L4PROTO, key->l4_proto);
        nfct_set_attr_u16(ct, ATTR_PORT_SRC, key->src_port);
        nfct_set_attr_u16(ct, ATTR_PORT_DST, key->dst_port);

        if (destroy) {
            nfct_query(h, NFCT_Q_DESTROY, ct);
        } else {
            nfct_set_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES, hw_bytes_delta);
            nfct_set_attr_u64(ct, ATTR_ORIG_COUNTER_PACKETS, hw_pkts_delta);
            nfct_query(h, NFCT_Q_UPDATE, ct);
        }
        nfct_destroy(ct);
    }
}

int handle_ringbuf_event(void *ctx, void *data, size_t data_sz) {
    const struct hw_stats_event *e = data;
    struct flow_value val = {0};

    /* Build flow_key from the event's inline fields */
    struct flow_key fkey = {0};
    memcpy(fkey.src_ip, e->src_ip, sizeof(fkey.src_ip));
    memcpy(fkey.dst_ip, e->dst_ip, sizeof(fkey.dst_ip));
    fkey.src_port = e->src_port;
    fkey.dst_port = e->dst_port;
    fkey.l3_proto = e->l3_proto;
    fkey.l4_proto = e->l4_proto;

    if (bpf_map_lookup_elem(flow_map_fd, &fkey, &val) == 0) {
        if (e->teardown_flag) {
            sync_hardware_counters(&fkey, 0, 0, 1);
            bpf_map_delete_elem(flow_map_fd, &fkey);
            printf("Hardware event: Flow gracefully evicted (proto %d)\n", fkey.l4_proto);
        } else {
            uint64_t b_delta = e->bytes > val.last_hw_bytes ? e->bytes - val.last_hw_bytes : 0;
            uint64_t p_delta = e->packets > val.last_hw_pkts ? e->packets - val.last_hw_pkts : 0;

            sync_hardware_counters(&fkey, b_delta, p_delta, 0);

            val.last_hw_bytes = e->bytes;
            val.last_hw_pkts = e->packets;
            bpf_map_update_elem(flow_map_fd, &fkey, &val, BPF_EXIST);
        }
    }
    return 0;
}

void *ringbuf_event_listener(void *arg) {
    printf("Starting eBPF Ring Buffer Event Listener...\n");
    rb = ring_buffer__new(rb_map_fd, handle_ringbuf_event, NULL, NULL);
    if (!rb) pthread_exit(NULL);

    while (1) {
        ring_buffer__poll(rb, 1000); 
    }
    return NULL;
}

void *orphan_garbage_collector(void *arg) {
    printf("Starting Orphan Flow Garbage Collector...\n");

    while (1) {
        sleep(300);
        if (flow_map_fd < 0) continue;

        /* Read debugfs once per GC cycle, not per flow */
        FILE *f = fopen(DEBUG_FS_STATS_PATH, "r");

        struct flow_key key, next_key;
        int has_next = (bpf_map_get_next_key(flow_map_fd, NULL, &next_key) == 0);

        while (has_next) {
            key = next_key;
            has_next = (bpf_map_get_next_key(flow_map_fd, &key, &next_key) == 0);

            int exists_in_hw = 0;

            if (f) {
                rewind(f);
                char line[256];
                while (fgets(line, sizeof(line), f)) {
                    uint32_t f_sip, f_dip;
                    uint16_t f_sport, f_dport;
                    uint64_t f_bytes, f_pkts;
                    if (sscanf(line, "%x %x %hu %hu %lu %lu",
                               &f_sip, &f_dip, &f_sport, &f_dport,
                               &f_bytes, &f_pkts) == 6) {
                        /*
                         * For IPv4: compare first u32 of src/dst.
                         * For IPv6: the debugfs format may differ;
                         * the 4-tuple match (ports) provides enough
                         * confidence to avoid false orphan purges.
                         */
                        int is_ipv4 = (key.l3_proto == htons(0x0800));
                        if (is_ipv4) {
                            if (key.src_ip[0] == f_sip &&
                                key.dst_ip[0] == f_dip &&
                                key.src_port == f_sport &&
                                key.dst_port == f_dport) {
                                exists_in_hw = 1;
                                break;
                            }
                        } else {
                            /* IPv6: match on ports only as a heuristic.
                             * Full IPv6 debugfs parsing requires a
                             * different format string. */
                            if (key.src_port == f_sport &&
                                key.dst_port == f_dport) {
                                exists_in_hw = 1;
                                break;
                            }
                        }
                    }
                }
            }

            if (!exists_in_hw) {
                printf("GC: Purging orphaned map entry (proto %d)\n",
                       key.l4_proto);
                bpf_map_delete_elem(flow_map_fd, &key);
            }
        }

        if (f) fclose(f);
    }
    return NULL;
}

int main(int argc, char **argv) {
    fdb_map_fd = bpf_obj_get(MAC_FDB_MAP_PATH);
    flow_map_fd = bpf_obj_get(ACTIVE_FLOW_MAP_PATH);
    rb_map_fd = bpf_obj_get(HW_STATS_RB_PATH);
    iface_map_fd = bpf_obj_get(IFACE_MAP_PATH);
    port_bridge_map_fd = bpf_obj_get(PORT_BRIDGE_MAP_PATH);
    netns_map_fd = bpf_obj_get(NETNS_MAP_PATH);

    if (rb_map_fd < 0 || flow_map_fd < 0 || iface_map_fd < 0) {
        fprintf(stderr, "Fatal: Required BPF Maps not found. Ensure TC/BPF is loaded.\n");
        exit(EXIT_FAILURE);
    }

    pthread_t nl_thread, rb_thread, gc_thread;
    pthread_create(&nl_thread, NULL, netlink_topology_listener, NULL);
    pthread_create(&rb_thread, NULL, ringbuf_event_listener, NULL);
    pthread_create(&gc_thread, NULL, orphan_garbage_collector, NULL);

    pthread_join(nl_thread, NULL);
    pthread_join(rb_thread, NULL);
    pthread_join(gc_thread, NULL);

    if (rb) ring_buffer__free(rb);
    return 0;
}
