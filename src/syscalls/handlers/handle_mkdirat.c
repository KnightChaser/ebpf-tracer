// src/syscalls/handlers/handle_mkdirat.c
#define _GNU_SOURCE
#include "handle_mkdirat.h"
#include "../../syscalls/syscalls.h"
#include "../../utils/logger.h"
#include "../../utils/path_utils.h"
#include <fcntl.h>
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

    char rel_path[PATH_MAX] = {0};
    if (read_string_from_process(pid, e->enter.args[1], rel_path,
                                 sizeof(rel_path)) <= 0) {
        snprintf(rel_path, sizeof(rel_path), "0x%lx (invalid)",
                 e->enter.args[1]);
    }

    mode_t mode = (mode_t)e->enter.args[2];

    char argbuf[PATH_MAX + 32];
    if (dirfd == AT_FDCWD) {
        snprintf(argbuf, sizeof(argbuf), "AT_FDCWD, \"%s\", 0%o", rel_path,
                 mode);
    } else {
        snprintf(argbuf, sizeof(argbuf), "%d, \"%s\", 0%o", dirfd, rel_path,
                 mode);
    }

    log_syscall(e->syscall_nr, e->enter.name, argbuf, /*retval=*/0);

    char abs_path[PATH_MAX] = {0};
    if (resolve_abs_path(pid, dirfd, rel_path, abs_path, sizeof(abs_path)) ==
        0) {
        log_kv("path", "%s", abs_path);
    } else {
        log_kv("path", "<could not resolve>");
    }
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
