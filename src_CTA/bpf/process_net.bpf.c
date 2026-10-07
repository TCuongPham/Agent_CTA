// Chương trình eBPF chạy trong Kernel đo lưu lượng mạng theo PID (TCP & UDP)

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

// Hàm giúp cộng dồn lưu lượng theo PID 
static __always_inline void add_net_stats(__u32 pid, __u64 rx, __u64 tx) {
    struct net_stats *stats = bpf_map_lookup_elem(&proc_net_map, &pid);
    if (stats) {
        if (rx > 0) {
            __sync_fetch_and_add(&stats->rx_bytes, rx);
        }
        if (tx > 0) {
            __sync_fetch_and_add(&stats->tx_bytes, tx);
        }
    } else {
        struct net_stats init_stats = { .rx_bytes = rx, .tx_bytes = tx };
        bpf_map_update_elem(&proc_net_map, &pid, &init_stats, BPF_ANY);
    }
}

// -------------------------------------------------------------
// TCP TRACKING (IPv4 & IPv6)
// -------------------------------------------------------------

// 1. Hook kprobe bắt lưu lượng TCP GỬI ĐI (TX): tcp_sendmsg
// int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(trace_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    if ((long)size <= 0) {
        return 0;
    }
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    add_net_stats(pid, 0, (__u64)size);
    return 0;
}

// 2. Hook kprobe bắt lưu lượng TCP NHẬN VỀ (RX): tcp_cleanup_rbuf
// int tcp_cleanup_rbuf(struct sock *sk, int copied)
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(trace_tcp_cleanup_rbuf, struct sock *sk, int copied) {
    int bytes = (int)copied;
    if (bytes <= 0) {
        return 0;
    }
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    add_net_stats(pid, (__u64)bytes, 0);
    return 0;
}

// -------------------------------------------------------------
// UDP TRACKING (IPv4 & IPv6)
// -------------------------------------------------------------

// 3. Hook kprobe bắt lưu lượng UDP IPv4 GỬI ĐI (TX): udp_sendmsg
// int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    if ((long)len <= 0) {
        return 0;
    }
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    add_net_stats(pid, 0, (__u64)len);
    return 0;
}

// 4. Hook kretprobe bắt lưu lượng UDP IPv4 NHẬN VỀ (RX): udp_recvmsg
// int udp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, ...)
SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(trace_udp_recvmsg, int ret) {
    int bytes = (int)ret;
    if (bytes <= 0) {
        return 0;
    }
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    add_net_stats(pid, (__u64)bytes, 0);
    return 0;
}

// 5. Hook kprobe bắt lưu lượng UDP IPv6 GỬI ĐI (TX): udpv6_sendmsg
// int udpv6_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(trace_udpv6_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    if ((long)len <= 0) {
        return 0;
    }
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    add_net_stats(pid, 0, (__u64)len);
    return 0;
}

// 6. Hook kretprobe bắt lưu lượng UDP IPv6 NHẬN VỀ (RX): udpv6_recvmsg
// int udpv6_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, ...)
SEC("kretprobe/udpv6_recvmsg")
int BPF_KRETPROBE(trace_udpv6_recvmsg, int ret) {
    int bytes = (int)ret;
    if (bytes <= 0) {
        return 0;
    }
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    add_net_stats(pid, (__u64)bytes, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
