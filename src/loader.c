// src/loader.c

#define _GNU_SOURCE
#include "loader.h"
#include "controller.h"
#include "controller.skel.h"
#include "syscall_table.h"
#include "syscalls/fd_cache.h"
#include "syscalls/syscalls.h"
#include <bpf/libbpf.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

// This path will be defined by Meson during compilation,
// pointing to the compiled BPF object file.
#ifndef EBPF_OBJ_PATH
#define EBPF_OBJ_PATH "ebpftracer.bpf.o"
#endif

// Global pointers to our BPF objects so they can be accessed
// by the cleanup function.
static struct controller_bpf *g_skel = NULL;
static struct ring_buffer *g_ring_buf = NULL;
static pid_t g_target_pid = -1; // Store the child PID

// Array of syscall metadata, indexed by syscall number.
// This is used to map syscall numbers to their names and argument counts.
static const struct tracer_syscall_info syscalls[MAX_SYSCALL_NR] = {
    [SYS_read] = {"read", 3},
    [SYS_write] = {"write", 3},
    [SYS_open] = {"open", 2},
    [SYS_close] = {"close", 1},
    [SYS_dup] = {"dup", 1},
    [SYS_dup2] = {"dup2", 2},
#ifdef SYS_dup3
    [SYS_dup3] = {"dup3", 3},
#endif
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
    [SYS_fcntl] = {"fcntl", 3},
    [SYS_openat] = {"openat", 3},
};

/**
 * Reads a null-terminated string from the memory of a process.
 * @param pid The PID of the process to read from.
 * @param addr The address in the process's memory to read from.
 * @param buffer The buffer to store the read string.
 * @param size The maximum size of the buffer.
 * @return The number of bytes read, or -1 on error.
 */
long read_string_from_process(pid_t pid, unsigned long addr, char *buffer,
                              size_t size) {
    struct iovec local_iov = {.iov_base = buffer, .iov_len = size};
    struct iovec remote_iov = {.iov_base = (void *)addr, .iov_len = size};
    ssize_t bytes_read =
        process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);

    if (bytes_read < 0) {
        return -1;
    }
    if ((size_t)bytes_read < size) {
        // Ensure null-termination even if the string is shorter than the buffer
        buffer[bytes_read] = '\0';
    } else {
        // If the buffer is full, ensure it is null-terminated
        buffer[size - 1] = '\0';
    }

    return bytes_read;
}

/**
 * Event handler for syscall entry events.
 * This function is called when a syscall entry event is detected.
 * It looks up the syscall metadata and calls the appropriate handler.
 * @param ctx The BPF context (unused).
 * @param data Pointer to the syscall event data.
 * @param len The length of the data (unused).
 * @return 0 on success, or a negative error code on failure.
 */
static int event_handler(void *ctx __attribute__((unused)), void *data,
                         size_t len __attribute__((unused))) {
    const struct syscall_event *e = data;

    if (e->mode == EVENT_SYS_ENTER) {
        // If the syscall name is known, print it; otherwise, print
        // "UNKNOWNSYSCALL" because we just don't know! >_<
        if (e->enter.name[0] != '\0') {
            if (e->syscall_nr < MAX_SYSCALL_NR &&
                enter_handlers[e->syscall_nr]) {
                enter_handlers[e->syscall_nr](g_target_pid, e);
            } else {
                handle_sys_enter_default(g_target_pid, e);
            }
        }
    } else if (e->mode == EVENT_SYS_EXIT) {
        // The same with exit events
        if (e->syscall_nr < MAX_SYSCALL_NR && exit_handlers[e->syscall_nr]) {
            exit_handlers[e->syscall_nr](g_target_pid, e);
        } else {
            handle_sys_exit_default(g_target_pid, e);
        }
    }
    return 0;
}

/**
 * Initializes the BPF loader by opening the BPF skeleton.
 * This function prepares the BPF object for loading and attaching.
 * @return 0 on success, or -1 on failure.
 */
int bpf_loader_init(void) {
    g_skel = controller_bpf__open();
    if (!g_skel) {
        perror("bpf_object__open");
        return -1;
    }

    // Initialize syscall handlers (function pointers)
    syscall_table_init();

    // Initialize the file descriptor cache
    fd_cache_init();

    return 0;
}

/**
 * Loads the BPF object and attaches it to the target PID.
 * This function sets up the BPF maps, attaches the programs,
 * and initializes the ring buffer for event handling.
 * @param pid The PID of the process to trace.
 * @return 0 on success, or -1 on failure.
 */
int bpf_loader_load_and_attach(pid_t pid) {
    g_target_pid = pid;

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

/**
 * Polls the ring buffer for events.
 * @return 0 on success, or -1 on failure.
 */
int bpf_loader_poll_events(void) {
    if (!g_ring_buf) {
        return -1;
    }
    return ring_buffer__poll(g_ring_buf,
                             100); // Poll for events with a timeout of 100 ms
}

/**
 * Cleans up the BPF resources.
 * This function frees the ring buffer and destroys the BPF skeleton.
 */
void bpf_loader_cleanup(void) {
    if (g_ring_buf) {
        ring_buffer__free(g_ring_buf);
        g_ring_buf = NULL;
    }

    if (g_skel) {
        controller_bpf__destroy(g_skel);
        g_skel = NULL;
    }

    // Clean up syscall handlers
    fd_cache_cleanup();

    printf("BPF resources cleaned up.\n");
}
