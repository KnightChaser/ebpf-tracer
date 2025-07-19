// src/controller.c

#include "controller.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

// Store PID of the child process the user want to trace.
// User-space program (main.c) will write the PID into this map.
// Kernel-space program (here) will read from it to filter events.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, pid_t);
} target_pid_map SEC(".maps");

// Ring buffer for syscall events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} events SEC(".maps");

// syscall metadata array
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SYSCALL_NR);
    __type(key, u32);
    __type(value, struct tracer_syscall_info);
} syscalls_map SEC(".maps");

// Program that triggers every time a process enters a syscall.
SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__sys_enter(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 zero = 0;
    pid_t *target_pid = bpf_map_lookup_elem(&target_pid_map, &zero);
    if (!target_pid || *target_pid != pid) {
        // If the target PID is not set or does not match, ignore this event.
        return -1;
    }

    u32 id = ctx->id;
    if (id >= MAX_SYSCALL_NR) {
        // If the syscall number is out of bounds, ignore this event.
        return -1;
    }

    const struct tracer_syscall_info *info =
        bpf_map_lookup_elem(&syscalls_map, &id);
    if (!info) {
        // If the syscall metadata is not found, ignore this event.
        return -1;
    }

    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        // If we cannot reserve space in the ring buffer, ignore this event.
        return -1;
    }

    e->mode = EVENT_SYS_ENTER;
    e->enter.syscall_nr = id;

    // Fetch metadata from the static lookup table.
    bpf_probe_read_kernel_str(e->enter.name, sizeof(e->enter.name), info->name);
    e->enter.num_args = info->num_args;

    e->enter.args[0] = BPF_CORE_READ(ctx, args[0]);
    e->enter.args[1] = BPF_CORE_READ(ctx, args[1]);
    e->enter.args[2] = BPF_CORE_READ(ctx, args[2]);
    e->enter.args[3] = BPF_CORE_READ(ctx, args[3]);
    e->enter.args[4] = BPF_CORE_READ(ctx, args[4]);
    e->enter.args[5] = BPF_CORE_READ(ctx, args[5]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Program that triggers every time a process exits a syscall.
SEC("tracepoint/raw_syscalls/sys_exit")
int tracepoint__sys_exit(struct trace_event_raw_sys_exit *ctx) {
    // Check if this PID is the one we want to trace
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    u32 key = 0;
    pid_t *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    if (!target_pid || *target_pid != pid) {
        // ignore
        return 0;
    }

    // Get the syscall number
    long syscall_nr = ctx->id;

    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        // If we cannot reserve space in the ring buffer, ignore this event.
        return -1;
    }

    // Populate the event structure for a SYS_EXIT event and prepare
    // information to be sent to user-space.
    e->mode = EVENT_SYS_EXIT;
    e->exit.retval = ctx->ret;

    // Submit the event to the ring buffer
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
