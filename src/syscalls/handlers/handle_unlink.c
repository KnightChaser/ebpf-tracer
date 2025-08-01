// src/syscalls/handlers/handle_unlink.c
#define _GNU_SOURCE
#include "handle_unlink.h"
#include "../../syscalls/syscalls.h"
#include "../../utils/logger.h"
#include "../../utils/path_utils.h"
#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>

/**
 * Handles the enter event for the unlink syscall.
 * It reads the relative path from the process memory,
 * resolves it to an absolute path, and logs the syscall details.
 *
 * @param pid The process ID of the syscall.
 * @param e The syscall event containing the syscall number and arguments.
 */
void handle_unlink_enter(pid_t pid, const struct syscall_event *e) {
    char rel_path[PATH_MAX] = {0};
    if (read_string_from_process(pid, e->enter.args[0], rel_path,
                                 sizeof(rel_path)) <= 0) {
        snprintf(rel_path, sizeof(rel_path), "0x%lx (invalid)",
                 e->enter.args[0]);
    }

    char argbuf[PATH_MAX + 8] = {0};
    snprintf(argbuf, sizeof(argbuf), "\"%s\"", rel_path);

    log_syscall(e->syscall_nr, e->enter.name, argbuf, /*retval=*/0);

    // Resolve and log the absolute path
    char abs_path[PATH_MAX] = {0};
    if (resolve_abs_path(pid, AT_FDCWD, rel_path, abs_path, sizeof(abs_path)) ==
        0) {
        log_kv("abs_path", "%s", abs_path);
    } else {
        log_kv("abs_path", "<could not resolve>");
    }
}

/**
 * Handles the exit event for the unlink syscall.
 * It logs the return value of the syscall.
 *
 * @param pid The process ID of the syscall (unused).
 * @param e The syscall event containing the exit details.
 */
void handle_unlink_exit(pid_t pid __attribute__((unused)),
                        const struct syscall_event *e) {
    log_ret(e->exit.retval, "unlink");
}
