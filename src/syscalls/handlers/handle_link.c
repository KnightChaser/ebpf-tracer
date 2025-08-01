#define _GNU_SOURCE
#include "handle_link.h"
#include "../../syscalls/syscalls.h"
#include "../../utils/logger.h"
#include "../../utils/path_utils.h"
#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>

/**
 * Handles the enter event for the link syscall.
 * It reads the old and new relative paths from the process memory,
 * resolves them to absolute paths, and logs the syscall details.
 *
 * @param pid The process ID of the syscall.
 * @param e The syscall event containing the syscall number and arguments.
 */
void handle_link_enter(pid_t pid, const struct syscall_event *e) {
    char old_rel_path[PATH_MAX] = {0};
    if (read_string_from_process(pid, e->enter.args[0], old_rel_path,
                                 sizeof(old_rel_path)) <= 0) {
        snprintf(old_rel_path, sizeof(old_rel_path), "0x%lx (invalid)",
                 e->enter.args[0]);
    }

    char new_rel_path[PATH_MAX] = {0};
    if (read_string_from_process(pid, e->enter.args[1], new_rel_path,
                                 sizeof(new_rel_path)) <= 0) {
        snprintf(new_rel_path, sizeof(new_rel_path), "0x%lx (invalid)",
                 e->enter.args[1]);
    }

    char argbuf[PATH_MAX * 2 + 16] = {0};
    snprintf(argbuf, sizeof(argbuf), "\"%s\", \"%s\"", old_rel_path,
             new_rel_path);
    log_syscall(e->syscall_nr, e->enter.name, argbuf, /*retval=*/0);

    // Resolve and log absolute paths for both arguments
    char abs_path[PATH_MAX] = {0};
    if (resolve_abs_path(pid, AT_FDCWD, old_rel_path, abs_path,
                         sizeof(abs_path)) == 0) {
        log_kv("old_abs_path", "%s", abs_path);
    } else {
        log_kv("old_abs_path", "<could not resolve>");
    }

    if (resolve_abs_path(pid, AT_FDCWD, new_rel_path, abs_path,
                         sizeof(abs_path)) == 0) {
        log_kv("new_abs_path", "%s", abs_path);
    } else {
        log_kv("new_abs_path", "<could not resolve>");
    }
}

/**
 * Handles the exit event for the link syscall.
 * It logs the return value of the syscall.
 *
 * @param pid The process ID of the syscall (unused).
 * @param e The syscall event containing the exit details.
 */
void handle_link_exit(pid_t pid __attribute__((unused)),
                      const struct syscall_event *e) {
    log_ret(e->exit.retval, "link");
}
