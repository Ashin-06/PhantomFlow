// capture/xdp_capture.c
// Runs in kernel space — zero-copy, line-rate packet metadata extraction
// Compiles to eBPF bytecode, loaded by xdp_loader.py

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_FLOWS 1048576  // 1M concurrent flows

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
};

struct flow_meta {
    __u64 first_seen;
    __u64 last_seen;
    __u64 pkt_count;
    __u64 byte_count;
    __u64 last_pkt_size;
    __u64 iat_sum;           // inter-arrival time sum (ns)
    __u32 tcp_flags_or;      // OR of all TCP flag bytes
};

// BPF map: flow key → metadata
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_meta);
} flow_table SEC(".maps");

// Perf event map for userspace notification
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct pkt_event {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 pkt_len;
    __u8  protocol;
    __u8  tcp_flags;
    __u64 iat_ns;            // inter-arrival time from last packet
};

SEC("xdp")
int xdp_flow_tracker(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    
    __u16 eth_type = bpf_ntohs(eth->h_proto);
    
    struct flow_key key = {};
    __u16 pkt_len = 0;
    __u8 tcp_flags = 0;
    
    if (eth_type == ETH_P_IP) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) return XDP_PASS;
        
        key.src_ip = iph->saddr;
        key.dst_ip = iph->daddr;
        key.protocol = iph->protocol;
        pkt_len = bpf_ntohs(iph->tot_len);
        
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)(iph + 1);
            if ((void *)(tcph + 1) > data_end) return XDP_PASS;
            key.src_port = bpf_ntohs(tcph->source);
            key.dst_port = bpf_ntohs(tcph->dest);
            tcp_flags = ((__u8*)tcph)[13];
        } else if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udph = (void *)(iph + 1);
            if ((void *)(udph + 1) > data_end) return XDP_PASS;
            key.src_port = bpf_ntohs(udph->source);
            key.dst_port = bpf_ntohs(udph->dest);
        }
    }
    
    // Skip non-TCP/UDP
    if (key.src_ip == 0) return XDP_PASS;
    
    __u64 now = bpf_ktime_get_ns();
    struct flow_meta *meta = bpf_map_lookup_elem(&flow_table, &key);
    __u64 iat = 0;
    
    if (meta) {
        iat = now - meta->last_seen;
        meta->last_seen = now;
        meta->pkt_count++;
        meta->byte_count += pkt_len;
        meta->iat_sum += iat;
        meta->last_pkt_size = pkt_len;
        meta->tcp_flags_or |= tcp_flags;
    } else {
        struct flow_meta new_meta = {
            .first_seen = now,
            .last_seen = now,
            .pkt_count = 1,
            .byte_count = pkt_len,
            .last_pkt_size = pkt_len,
            .tcp_flags_or = tcp_flags,
        };
        bpf_map_update_elem(&flow_table, &key, &new_meta, BPF_ANY);
    }
    
    // Emit perf event for userspace
    struct pkt_event evt = {
        .timestamp_ns = now,
        .src_ip = key.src_ip,
        .dst_ip = key.dst_ip,
        .src_port = key.src_port,
        .dst_port = key.dst_port,
        .pkt_len = pkt_len,
        .protocol = key.protocol,
        .tcp_flags = tcp_flags,
        .iat_ns = iat,
    };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    
    return XDP_PASS;  // Passive — never drop
}

char _license[] SEC("license") = "GPL";
