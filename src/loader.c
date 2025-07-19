// src/loader.c

#include "loader.h"
#include "controller.h"
#include "controller.skel.h"
#include <bpf/libbpf.h>
#include <stdio.h>

// This path will be defined by Meson during compilation,
// pointing to the compiled BPF object file.
#ifndef EBPF_OBJ_PATH
#define EBPF_OBJ_PATH "ebpftracer.bpf.o"
#endif

// Global pointers to our BPF objects so they can be accessed
// by the cleanup function.
static struct controller_bpf *g_skel = NULL;
static struct ring_buffer *g_ring_buf = NULL;

// Array of syscall metadata, indexed by syscall number.
// This is used to map syscall numbers to their names and argument counts.
static const struct tracer_syscall_info syscalls[MAX_SYSCALL_NR] = {
    [SYS_read] = {"read", 3},
    [SYS_write] = {"write", 3},
    [SYS_open] = {"open", 2},
    [SYS_close] = {"close", 1},
    [SYS_stat] = {"stat", 2},
    [SYS_fstat] = {"fstat", 2},
    [SYS_lstat] = {"lstat", 2},
    [SYS_poll] = {"poll", 3},
    [SYS_lseek] = {"lseek", 3},
    [SYS_mmap] = {"mmap", 6},
    [SYS_mprotect] = {"mprotect", 3},
    [SYS_munmap] = {"munmap", 2},
    [SYS_brk] = {"brk", 1},
    [SYS_rt_sigaction] = {"rt_sigaction", 4},
    [SYS_rt_sigprocmask] = {"rt_sigprocmask", 4},
    [SYS_ioctl] = {"ioctl", 3},
    [SYS_pread64] = {"pread64", 4},
    [SYS_pwrite64] = {"pwrite64", 4},
    [SYS_readv] = {"readv", 3},
    [SYS_writev] = {"writev", 3},
    [SYS_access] = {"access", 2},
    [SYS_pipe] = {"pipe", 1},
    [SYS_select] = {"select", 5},
    [SYS_sched_yield] = {"sched_yield", 0},
    [SYS_exit_group] = {"exit_group", 1},
    [SYS_openat] = {"openat", 3},
};

// Callback function that is called every time an event is read from the ring
// buffer. (syscall events)
static int event_handler(void *ctx __attribute__((unused)), void *data,
                         size_t len __attribute__((unused))) {
    const struct syscall_event *e = data;

    if (e->mode == EVENT_SYS_ENTER) {
        // If the syscall name is known, print it; otherwise, print
        // "UNKNOWNSYSCALL" because we just don't know! >_<
        if (e->enter.name[0] != '\0') {
            printf("%-6ld %-16s(", e->enter.syscall_nr, e->enter.name);
        } else {

            printf("%-6ld UNKNOWNSYSCALL  (", e->enter.syscall_nr);
        }

        for (int i = 0; i < e->enter.num_args; ++i) {
            printf("0x%lx%s", e->enter.args[i],
                   (i == e->enter.num_args - 1) ? "" : ", ");
        }
        printf(")");

        // We use fflush to ensure the first part of the line is printed
        // immediately, without waiting for a newline.
        fflush(stdout);
    } else if (e->mode == EVENT_SYS_EXIT) {
        printf(" = 0x%lx\n", e->exit.retval);
    }

    return 0;
}

// Function to load the BPF object file and set up the ring buffer.
int bpf_loader_init(void) {
    g_skel = controller_bpf__open();
    if (!g_skel) {
        perror("bpf_object__open");
        return -1;
    }

    return 0;
}

// Function to load the BPF object and attach it to the target PID.
int bpf_loader_load_and_attach(pid_t pid) {
    if (!g_skel) {
        fprintf(stderr, "BPF object not initialized.\n");
        return -1;
    }

    // Load the eBPF object into the kernel
    if (controller_bpf__load(g_skel)) {
        perror("controller_bpf__load");
        return -1;
    }

    // Seed the syscall-info ARRAY map
    for (u_int32_t i = 0; i < MAX_SYSCALL_NR; i++) {
        bpf_map__update_elem(g_skel->maps.syscalls_map, &i, sizeof(i),
                             &syscalls[i], sizeof(syscalls[i]), BPF_ANY);
    }

    // Update the PID map with the child's PID
    u_int32_t key = 0;
    if (bpf_map__update_elem(g_skel->maps.target_pid_map, &key, sizeof(key),
                             &pid, sizeof(pid), BPF_ANY) != 0) {
        perror("bpf_map_update_elem");
        return -1;
    }

    // Attach all BPF programs defined in the skeleton
    if (controller_bpf__attach(g_skel)) {
        perror("controller_bpf__attach");
        return -1;
    }

    // Set up the ring buffer using the map file descriptor from the skeleton
    int ring_buf_fd = bpf_map__fd(g_skel->maps.events);
    if (ring_buf_fd < 0) {
        perror("bpf_map__fd");
        return -1;
    }

    g_ring_buf = ring_buffer__new(ring_buf_fd, event_handler, NULL, NULL);
    if (g_ring_buf == NULL) {
        perror("ring_buffer__new");
        return -1;
    }

    return 0;
}

// Function to clean up resources allocated by the BPF loader.
int bpf_loader_poll_events(void) {
    if (!g_ring_buf) {
        return -1;
    }
    return ring_buffer__poll(g_ring_buf,
                             100); // Poll for events with a timeout of 100 ms
}

// Function to clean up resources allocated by the BPF loader.
void bpf_loader_cleanup(void) {
    if (g_ring_buf) {
        ring_buffer__free(g_ring_buf);
        g_ring_buf = NULL;
    }

    if (g_skel) {
        controller_bpf__destroy(g_skel);
        g_skel = NULL;
    }

    printf("BPF resources cleaned up.\n");
}
