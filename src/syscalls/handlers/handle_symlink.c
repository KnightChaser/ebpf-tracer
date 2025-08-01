// src/syscalls/handlers/handle_symlink.c
#define _GNU_SOURCE
#include "handle_symlink.h"
#include "../../syscalls/syscalls.h"
#include "../../utils/logger.h"
#include "../../utils/path_utils.h"
#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>

/**
 * Handles the enter event of the symlink syscall.
 * It reads the target path and link path from the process memory,
 * resolves the absolute path of the link, and logs the syscall arguments.
 *
 * @param pid The process ID of the syscall.
 * @param e The syscall event containing the syscall number and arguments.
 */
void handle_symlink_enter(pid_t pid, const struct syscall_event *e) {
    char target_path[PATH_MAX] = {0};
    if (read_string_from_process(pid, e->enter.args[0], target_path,
                                 sizeof(target_path)) <= 0) {
        snprintf(target_path, sizeof(target_path), "0x%lx (invalid)",
                 e->enter.args[0]);
    }

    char linkpath_rel[PATH_MAX] = {0};
    if (read_string_from_process(pid, e->enter.args[1], linkpath_rel,
                                 sizeof(linkpath_rel)) <= 0) {
        snprintf(linkpath_rel, sizeof(linkpath_rel), "0x%lx (invalid)",
                 e->enter.args[1]);
    }

    char argbuf[PATH_MAX * 2 + 16];
    snprintf(argbuf, sizeof(argbuf), "\"%s\", \"%s\"", target_path,
             linkpath_rel);
    log_syscall(e->syscall_nr, e->enter.name, argbuf, /*retval=*/0);

    /**
     * WARNING: For symlink, the "target" path is treated as a "literal string"
     * that gets stored inside the link. We should not resolve it, because its
     * meaning depends on the context from where the symlink is eventually used.
     * Instead, we only should resolve "linkpath", which is the location where
     * the symlink file itself is being created.
     */

    /**
     * NOTE:
     * The difnition of symlink() is follows as:
     *   symlink() creates a symbolic link named "linkpath" which contains the
     *   string "target".
     */
    log_kv("target", "%s", target_path);

    char linkpath_abs[PATH_MAX] = {0};
    if (resolve_abs_path(pid, AT_FDCWD, linkpath_rel, linkpath_abs,
                         sizeof(linkpath_abs)) == 0) {
        log_kv("linkpath_abs", "%s", linkpath_abs);
    } else {
        log_kv("linkpath_abs", "<could not resolve>");
    }
}

/**
 * Handles the exit event of the symlink syscall.
 * It logs the return value of the syscall.
 *
 * @param pid The process ID of the syscall.
 * @param e The syscall event containing the syscall number and exit status.
 */
void handle_symlink_exit(pid_t pid __attribute__((unused)),
                         const struct syscall_event *e) {
    log_ret(e->exit.retval, "symlink");
}
