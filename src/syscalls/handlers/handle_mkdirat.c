// src/syscalls/handlers/handle_mkdirat.c
#define _GNU_SOURCE
#include "handle_mkdirat.h"
#include "../../syscalls/syscalls.h"
#include "../../utils/logger.h"
#include <fcntl.h> // For AT_FDCWD
#include <linux/limits.h>
#include <stdio.h>
#include <sys/stat.h>

/**
 * Handle the entry of the mkdirat syscall.
 * This function reads the directory file descriptor, path, and mode from the
 * syscall arguments, and logs the syscall with its arguments in a
 *human-readable format.
 *
 * @param pid The process ID.
 * @param e The syscall event containing the arguments.
 */
void handle_mkdirat_enter(pid_t pid, const struct syscall_event *e) {
    int dirfd = (int)e->enter.args[0];

    char path[PATH_MAX] = {0};
    if (read_string_from_process(pid, e->enter.args[1], path, sizeof(path)) <=
        0) {
        snprintf(path, sizeof(path), "0x%lx (invalid)", e->enter.args[1]);
    }

    mode_t mode = (mode_t)e->enter.args[2];

    char argbuf[PATH_MAX + 32];
    if (dirfd == AT_FDCWD) {
        snprintf(argbuf, sizeof(argbuf), "AT_FDCWD, \"%s\", 0%o", path, mode);
    } else {
        snprintf(argbuf, sizeof(argbuf), "%d, \"%s\", 0%o", dirfd, path, mode);
    }

    log_syscall(e->syscall_nr, e->enter.name, argbuf, /*retval=*/0);

    // NOTE: Optional) Try to resolve the path for `dirfd` from our fd_cache
    // for more context, but this is a great start.
}

/**
 * Handle the exit of the mkdirat syscall.
 * This function logs the return value of the syscall.
 *
 * @param pid The process ID.
 * @param e The syscall event containing the exit information.
 */
void handle_mkdirat_exit(pid_t pid __attribute__((unused)),
                         const struct syscall_event *e) {
    log_ret(e->exit.retval, "mkdirat");
}
