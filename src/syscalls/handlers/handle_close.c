// src/syscalls/handlers/handle_close.c
#define _GNU_SOURCE
#include "../../controller.h"
#include "../../utils/logger.h"
#include "../fd_cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct close_req {
    int fd;
    struct close_req *next;
};

static struct close_req *close_pending_list_head = NULL;
static struct close_req *close_pending_list_tail = NULL;

/**
 * Adds a close request to the pending list.
 * This is used to track file descriptors that are closed but not yet processed.
 *
 * @param fd The file descriptor to be closed.
 */
static void close_push(int fd) {
    struct close_req *n = calloc(1, sizeof(struct close_req));
    if (!n) {
        // Memory allocation failed
        perror("Failed to allocate memory for close request");
        return;
    }

    n->fd = fd;
    n->next = NULL;
    if (!close_pending_list_tail) {
        close_pending_list_head = n;
    } else {
        close_pending_list_tail->next = n;
    }
    close_pending_list_tail = n;
}

/**
 * Pops the next pending close request from the list.
 * This is used to resolve file descriptors that were closed but not yet
 * processed.
 *
 * @return The file descriptor to be closed, or -1 if no pending closes.
 */
static int close_pop(void) {
    if (!close_pending_list_head) {
        // No pending closes
        return -1;
    }

    struct close_req *n = close_pending_list_head;
    int fd = n->fd;
    close_pending_list_head = n->next;

    if (!close_pending_list_head) {
        // If we popped the last element, reset the tail as well.
        close_pending_list_tail = NULL;
    }
    free(n);

    return fd;
}

/**
 * Handles the enter event of the close syscall.
 *
 * @param pid The process ID of the syscall event.
 * @param e The syscall event structure containing syscall information.
 */
void handle_close_enter(pid_t pid __attribute__((unused)),
                        const struct syscall_event *e) {
    int fd = (int)e->enter.args[0];

    char argbuf[16];
    snprintf(argbuf, sizeof(argbuf), "%d", fd);
    log_syscall(e->syscall_nr, e->enter.name, argbuf, /*retval*/ 0);

    const char *path = fd_cache_get(fd);
    if (path) {
        printf("\n => path: %s\n", path);
    }

    // stash the fd so that on exit we can evict it if the current close system
    // call succeeds
    close_push(fd);
}

/**
 * Handles the exit event of the close syscall.
 *
 * @param pid The process ID of the syscall event.
 * @param e The syscall event structure containing syscall information.
 */
void handle_close_exit(pid_t pid __attribute__((unused)),
                       const struct syscall_event *e) {
    long ret = e->exit.retval;

    // pop the fd that was stashed at handle_close_enter()
    int fd = close_pop();
    if (ret >= 0 && fd >= 0) {
        // NOTE: only remove from cache on a successful close() syscall
        fd_cache_remove(fd);
    }
}
