// src/syscalls/read_common.c
#define _GNU_SOURCE
#include "read_common.h"
#include "../syscalls/syscalls.h"
// #include "handlers/handle_pread.h"
#include "../utils/logger.h"
#include "handlers/handle_read.h"
// #include "handlers/handle_readv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

// NOTE: Show only up to 64 bytes of data for buffer in read() syscall
static const size_t DUMP_MAX = 256;

/**
 * Structure to hold pending (file) read requests.
 * This is used to track reads that are in progress but not yet resolved.
 */

struct pending_read {
    struct read_args args;
    struct pending_read *next;
};

static struct pending_read *read_pending_list_head = NULL;
static struct pending_read *read_pending_list_tail = NULL;

/**
 * Adds a pending read request to the list.
 * This is used to track reads that are in progress but not yet resolved.
 *
 * @param r The read_args structure containing the arguments for the read
 * syscall.
 */
static void read_pending_push(const struct read_args *r) {
    struct pending_read *n = calloc(1, sizeof(struct pending_read));
    if (!n) {
        // Memory allocation failed
        perror("Failed to allocate memory for pending read");
        return;
    }

    n->args = *r;
    n->next = NULL;

    // If this is the first pending read, set it as the head.
    // If there is already a tail, link it to the new node.
    if (!read_pending_list_tail) {
        read_pending_list_head = n;
    } else {
        read_pending_list_tail->next = n;
    }
    read_pending_list_tail = n;
}

/**
 * Pops the next pending read request from the list.
 * This is used to resolve reads that are in progress but not yet resolved.
 *
 * @return The read_args structure containing the arguments for the read
 * syscall, or an empty read_args structure if no pending reads.
 */
static struct read_args read_pending_pop(void) {
    struct read_args empty = {0};
    if (!read_pending_list_head) {
        // No pending reads
        return empty;
    }

    struct pending_read *n = read_pending_list_head;
    struct read_args ret = n->args;
    read_pending_list_head = n->next;
    if (!read_pending_list_head) {
        // If we popped the last element, reset the tail as well.
        read_pending_list_tail = NULL;
    }
    free(n);

    return ret;
}

/**
 * Fetches the arguments for read-like syscalls.
 * It currently encompasses: read(), pread64(), and readv().
 *
 * @param pid The process ID of the target process.
 * @param e The syscall event containing the arguments.
 * @param out Pointer to a read_args structure to fill with the arguments.
 * @return 0 on success, -1 on failure.
 */
int fetch_read_args(pid_t pid, const struct syscall_event *e,
                    struct read_args *out) {
    memset(out, 0, sizeof(*out));
    out->fd = (int)e->enter.args[0];
    out->count = e->enter.args[2 < e->enter.num_args ? 2 : 1];

    switch (e->syscall_nr) {
    case SYS_read:
        out->buf = e->enter.args[1];
        return 0;
    case SYS_pread64:
        out->buf = e->enter.args[1];
        out->offset = (off_t)e->enter.args[3];
        return 0;
    case SYS_readv:
        out->iovcnt = (int)e->enter.args[2];
        out->iov = calloc(out->iovcnt, sizeof(struct iovec));
        if (!out->iov) {
            return -1;
        }
        // Pull the array of iovec structures from the process memory
        {
            struct iovec local = {
                .iov_base = (void *)out->iov,
                .iov_len = sizeof(*out->iov) * out->iovcnt,
            };
            struct iovec remote = {
                .iov_base = (void *)e->enter.args[1],
                .iov_len = sizeof(*out->iov) * out->iovcnt,
            };
            if (process_vm_readv(pid, &local, 1, &remote, 1, 0) < 0) {
                free(out->iov);
                return -1;
            }
        }
        return 0;
    default:
        return -1;
    }
}

/**
 * Dispatches the syscall enter event for read-like syscalls.
 * It calls the appropriate handler based on the syscall number.
 *
 * @param pid The process ID of the target process.
 * @param e The syscall event containing the arguments.
 */
void read_enter_dispatch(pid_t pid, const struct syscall_event *e) {
    switch (e->syscall_nr) {
    case SYS_read:
        handle_read_enter(pid, e);
        break;
    // case SYS_pread64:
    //     handle_pread_enter(pid, e);
    //     break;
    // case SYS_readv:
    //     handle_readv_enter(pid, e);
    //     break;
    default:
        handle_sys_enter_default(pid, e);
    }

    // NOTE: resolve & stash the read arguments for the read_exit
    {
        struct read_args ra;
        if (fetch_read_args(pid, e, &ra) == 0) {
            read_pending_push(&ra);
        } else {
            // If fetching the arguments failed, push an empty read_args
            struct read_args empty = {0};
            read_pending_push(&empty);
        }
    }
}

/**
 * Dispatches the syscall exit event for read-like syscalls.
 * It calls the appropriate handler based on the syscall number.
 *
 * @param pid The process ID of the target process.
 * @param e The syscall event containing the arguments.
 */
void read_exit_dispatch(pid_t pid, const struct syscall_event *e) {
    // NOTE: yank the args that was stashed at enter-time
    struct read_args ra = read_pending_pop();
    long bytes_read = 0;

    switch (e->syscall_nr) {
    case SYS_read:
        bytes_read = e->exit.retval;
        // First print the usual retval line
        handle_read_exit(pid, e);

        // If it actually read something, use your saved ra.buf &
        // ra.count
        if (bytes_read > 0 && ra.buf) {
            size_t to_read = MIN((size_t)bytes_read, DUMP_MAX);
            char *buf = calloc(to_read + 1, sizeof(char));
            if (buf) {
                struct iovec local = {.iov_base = buf, .iov_len = to_read};
                struct iovec remote = {.iov_base = (void *)ra.buf,
                                       .iov_len = to_read};

                if (process_vm_readv(pid, &local, 1, &remote, 1, 0) ==
                    (ssize_t)to_read) {
                    buf[to_read] = '\0';
                    log_kv("data", "first (up to) %zu byte%s%s", /* headline */
                           to_read, to_read == 1 ? "" : "s",
                           (size_t)bytes_read > to_read ? " (truncated)" : "");
                    log_hexdump(8, buf, to_read);
                }
                free(buf);
            }
        }
        break;
    // case SYS_pread64:
    //     handle_pread_exit(pid, e);
    //     break;
    // case SYS_readv:
    //     handle_readv_exit(pid, e);
    //     break;
    default:
        handle_sys_exit_default(pid, e);
    }
}
