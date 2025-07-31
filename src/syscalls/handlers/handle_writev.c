// src/syscalls/handlers/handle_writev.c
#define _GNU_SOURCE
#include "handle_writev.h"
#include "../../utils/logger.h"
#include "../fd_cache.h"
#include <stdio.h>

/**
 * Handles the syscall enter event for writev.
 * It logs the syscall number, name, and arguments.
 * It also logs the file path associated with the file descriptor.
 *
 * @param pid The process ID of the target process.
 * @param e The syscall event containing the arguments.
 * @param args The arguments for the writev syscall.
 */
void handle_writev_enter(pid_t pid __attribute__((unused)),
                         const struct syscall_event *e,
                         const struct write_args *args) {
    char argbuf[128] = {0};
    snprintf(argbuf, sizeof(argbuf), "%d, %p, %d",
             args->fd,          // file descriptor
             (void *)args->iov, // pointer to the iovec array
             (int)args->count); // number of iovecs
    log_syscall(e->syscall_nr, e->enter.name, argbuf, /* retval */ 0);

    const char *path = fd_cache_get(args->fd);
    if (path) {
        log_kv("path", "%s", path);
    } else {
        log_kv("path", "<unknown>");
    }
}

/**
 * Handles the syscall exit event for writev.
 * It logs the return value of the syscall.
 *
 * @param pid The process ID of the target process.
 * @param e The syscall event containing the exit information.
 */
void handle_writev_exit(pid_t pid __attribute__((unused)),
                        const struct syscall_event *e) {
    log_ret(e->exit.retval, "writev");
}
