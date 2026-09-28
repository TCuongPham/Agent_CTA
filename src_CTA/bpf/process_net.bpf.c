// Chương trình eBPF chạy trong Kernel đo lưu lượng mạng theo PID

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Cấu trúc lưu trữ tổng số byte nhận (RX) và gửi (TX)
struct net_stats {
    __u64 rx_bytes;
    __u64 tx_bytes;
};

// BPF Map dạng Hash: Key là PID (u32), Value là net_stats
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240); // Theo dõi tối đa 10,240 tiến trình
    __type(key, __u32);
    __type(value, struct net_stats);
} proc_net_map SEC(".maps");

// 1. Hook kprobe bắt lưu lượng TCP GỬI ĐI (TX): tcp_sendmsg
// int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(trace_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    // Lấy PID hiện tại (32-bit trên của tgid)
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct net_stats *stats = bpf_map_lookup_elem(&proc_net_map, &pid);

    if (stats) {
        __sync_fetch_and_add(&stats->tx_bytes, size);
    } else {
        struct net_stats init_stats = { .rx_bytes = 0, .tx_bytes = size };
        bpf_map_update_elem(&proc_net_map, &pid, &init_stats, BPF_ANY);
    }
    return 0;
}

// 2. Hook kprobe bắt lưu lượng TCP NHẬN VỀ (RX): tcp_cleanup_rbuf
// int tcp_cleanup_rbuf(struct sock *sk, int copied)
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(trace_tcp_cleanup_rbuf, struct sock *sk, int copied) {
    if (copied <= 0) {
        return 0;
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct net_stats *stats = bpf_map_lookup_elem(&proc_net_map, &pid);

    if (stats) {
        __sync_fetch_and_add(&stats->rx_bytes, (__u64)copied);
    } else {
        struct net_stats init_stats = { .rx_bytes = (__u64)copied, .tx_bytes = 0 };
        bpf_map_update_elem(&proc_net_map, &pid, &init_stats, BPF_ANY);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
