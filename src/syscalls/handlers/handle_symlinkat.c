// src/syscalls/handlers/handle_symlinkat.c
#define _GNU_SOURCE
#include "handle_symlinkat.h"
#include "../../syscalls/syscalls.h"
#include "../../utils/logger.h"
#include "../../utils/path_utils.h"
#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>

/**
 * Handles the enter event of the symlinkat syscall.
 * It reads the target path and link path from the process memory,
 * resolves the absolute path of the link, and logs the syscall arguments.
 *
 * @param pid The process ID of the syscall.
 * @param e The syscall event containing the syscall number and arguments.
 */
void handle_symlinkat_enter(pid_t pid, const struct syscall_event *e) {
    int newdirfd = (int)e->enter.args[1];

    char target_path[PATH_MAX] = {0};
    if (read_string_from_process(pid, e->enter.args[0], target_path,
                                 sizeof(target_path)) <= 0) {
        snprintf(target_path, sizeof(target_path), "0x%lx (invalid)",
                 e->enter.args[0]);
    }

    char linkpath_rel[PATH_MAX] = {0};
    if (read_string_from_process(pid, e->enter.args[2], linkpath_rel,
                                 sizeof(linkpath_rel)) <= 0) {
        snprintf(linkpath_rel, sizeof(linkpath_rel), "0x%lx (invalid)",
                 e->enter.args[2]);
    }

    // Format arguments for logging
    char argbuf[PATH_MAX * 2 + 32];
    if (newdirfd == AT_FDCWD) {
        snprintf(argbuf, sizeof(argbuf), "\"%s\", AT_FDCWD, \"%s\"",
                 target_path, linkpath_rel);
    } else {
        snprintf(argbuf, sizeof(argbuf), "\"%s\", %d, \"%s\"", target_path,
                 newdirfd, linkpath_rel);
    }
    log_syscall(e->syscall_nr, e->enter.name, argbuf, /*retval=*/0);

    // WARNING: Only resolve the linkpath_abs, not the target
    // Refer to annotations written in handle_symlink.c for details.
    log_kv("target", "%s", target_path);

    char linkpath_abs[PATH_MAX] = {0};
    if (resolve_abs_path(pid, newdirfd, linkpath_rel, linkpath_abs,
                         sizeof(linkpath_abs)) == 0) {
        log_kv("linkpath_abs", "%s", linkpath_abs);
    } else {
        log_kv("linkpath_abs", "<could not resolve>");
    }
}

/**
 * Handles the exit event of the symlinkat syscall.
 * It logs the return value of the syscall.
 *
 * @param pid The process ID of the syscall.
 * @param e The syscall event containing the syscall number and exit status.
 */
void handle_symlinkat_exit(pid_t pid __attribute__((unused)),
                           const struct syscall_event *e) {
    log_ret(e->exit.retval, "symlinkat");
}
