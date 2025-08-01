// src/syscalls/handlers/handle_unlinkat.c
#define _GNU_SOURCE
#include "handle_unlinkat.h"
#include "../../syscalls/syscalls.h"
#include "../../syscalls/utils.h"
#include "../../utils/logger.h"
#include "../../utils/path_utils.h"
#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>

static const struct flag_name unlinkat_flags[] = {
    /*
     * By default, unlinkat() performs the equivalent of unlink() on pathname.
     * If the AT_REMOVEDIR flag is specified, it performs the equivalent of
     * rmdir(2) on pathname.
     */
    {AT_REMOVEDIR, "AT_REMOVEDIR"},
};

/**
 * Handles the enter event for the unlinkat syscall.
 * It reads the directory file descriptor, relative path, and flags,
 * resolves the absolute path, and logs the syscall details.
 *
 * @param pid The process ID of the syscall.
 * @param e The syscall event containing the syscall number and arguments.
 */
void handle_unlinkat_enter(pid_t pid, const struct syscall_event *e) {
    int dirfd = (int)e->enter.args[0];
    int flags = (int)e->enter.args[2];

    char rel_path[PATH_MAX] = {0};
    if (read_string_from_process(pid, e->enter.args[1], rel_path,
                                 sizeof(rel_path)) <= 0) {
        snprintf(rel_path, sizeof(rel_path), "0x%lx (invalid)",
                 e->enter.args[1]);
    }

    // Format arguments
    char argbuf[PATH_MAX + 64] = {0};
    int off = 0;
    if (dirfd == AT_FDCWD) {
        off += snprintf(argbuf, sizeof(argbuf), "AT_FDCWD, \"%s\"", rel_path);
    } else {
        off += snprintf(argbuf, sizeof(argbuf), "%d, \"%s\"", dirfd, rel_path);
    }

    if (flags != 0) {
        char flag_str[128] = {0};
        flags_to_str(flags, unlinkat_flags,
                     sizeof(unlinkat_flags) / sizeof(unlinkat_flags[0]),
                     flag_str, sizeof(flag_str));
        snprintf(argbuf + off, sizeof(argbuf) - off, ", %s", flag_str);
    }

    log_syscall(e->syscall_nr, e->enter.name, argbuf, /*retval=*/0);

    // Resolve and log the absolute path
    char abs_path[PATH_MAX] = {0};
    if (resolve_abs_path(pid, dirfd, rel_path, abs_path, sizeof(abs_path)) ==
        0) {
        log_kv("abs_path", "%s", abs_path);
    } else {
        log_kv("abs_path", "<could not resolve>");
    }
}

/**
 * Handles the exit event for the unlinkat syscall.
 * It logs the return value of the syscall.
 *
 * @param pid The process ID of the syscall (unused).
 * @param e The syscall event containing the exit details.
 */
void handle_unlinkat_exit(pid_t pid __attribute__((unused)),
                          const struct syscall_event *e) {
    log_ret(e->exit.retval, "unlinkat");
}
