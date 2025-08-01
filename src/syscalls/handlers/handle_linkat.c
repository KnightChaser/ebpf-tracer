// src/syscalls/handlers/handle_linkat.c
#define _GNU_SOURCE
#include "handle_linkat.h"
#include "../../syscalls/syscalls.h"
#include "../../syscalls/utils.h" // For flags_to_str
#include "../../utils/logger.h"
#include "../../utils/path_utils.h"
#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>

static const struct flag_name linkat_flags[] = {
    /**
     * If oldpath is an empty string, create a link to the file referenced by
     * olddirfd (which may have been obtained using the open(2) O_PATH flag). In
     * this case, olddirfd can refer to any type of file except a directory.
     * This will generally not work if the file has a link count of zero (files
     * created with O_TMPFILE and without O_EXCL are an exception). The caller
     * must have the CAP_DAC_READ_SEARCH capability in order to use this flag.
     * This flag is Linux-specific; define _GNU_SOURCE to obtain its definition.
     */
    {AT_SYMLINK_FOLLOW, "AT_SYMLINK_FOLLOW"},
    /**
     * By default, linkat(), does not dereference oldpath if it is a symbolic
     * link (like link()). The flag AT_SYMLINK_FOLLOW can be specified in flags
     * to cause oldpath to be dereferenced if it is a symbolic link. If procfs
     * is mounted, this can be used as an alternative to AT_EMPTY_PATH, like
     * this:
     */
    {AT_EMPTY_PATH, "AT_EMPTY_PATH"},
};

/**
 * Handles the enter event for the linkat syscall.
 * It reads the old and new relative paths from the process memory,
 * resolves them to absolute paths, and logs the syscall details.
 *
 * @param pid The process ID of the syscall.
 * @param e The syscall event containing the syscall number and arguments.
 */
void handle_linkat_enter(pid_t pid, const struct syscall_event *e) {
    int olddirfd = (int)e->enter.args[0];
    int newdirfd = (int)e->enter.args[2];
    int flags = (int)e->enter.args[4];

    char old_rel_path[PATH_MAX] = {0};
    if (read_string_from_process(pid, e->enter.args[1], old_rel_path,
                                 sizeof(old_rel_path)) <= 0) {
        snprintf(old_rel_path, sizeof(old_rel_path), "0x%lx (invalid)",
                 e->enter.args[1]);
    }

    char new_rel_path[PATH_MAX] = {0};
    if (read_string_from_process(pid, e->enter.args[3], new_rel_path,
                                 sizeof(new_rel_path)) <= 0) {
        snprintf(new_rel_path, sizeof(new_rel_path), "0x%lx (invalid)",
                 e->enter.args[3]);
    }

    // Format arguments for logging
    char argbuf[PATH_MAX * 2 + 64] = {0};
    int off = 0;
    off += snprintf(argbuf, sizeof(argbuf), "%s, \"%s\", %s, \"%s\"",
                    (olddirfd == AT_FDCWD) ? "AT_FDCWD" : "%d", old_rel_path,
                    (newdirfd == AT_FDCWD) ? "AT_FDCWD" : "%d", new_rel_path);

    char flag_str[128] = {0};
    flags_to_str(flags, linkat_flags,
                 sizeof(linkat_flags) / sizeof(linkat_flags[0]), flag_str,
                 sizeof(flag_str));
    snprintf(argbuf + off, sizeof(argbuf) - off, ", %s", flag_str);

    log_syscall(e->syscall_nr, e->enter.name, argbuf, /*retval=*/0);

    // Resolve and log absolute paths for both arguments
    char abs_path[PATH_MAX] = {0};
    if (resolve_abs_path(pid, olddirfd, old_rel_path, abs_path,
                         sizeof(abs_path)) == 0) {
        log_kv("old_abs_path", "%s", abs_path);
    } else {
        log_kv("old_abs_path", "<could not resolve>");
    }

    if (resolve_abs_path(pid, newdirfd, new_rel_path, abs_path,
                         sizeof(abs_path)) == 0) {
        log_kv("new_abs_path", "%s", abs_path);
    } else {
        log_kv("new_abs_path", "<could not resolve>");
    }
}

/**
 * Handles the exit event for the linkat syscall.
 * It logs the return value of the syscall.
 *
 * @param pid The process ID of the syscall (unused).
 * @param e The syscall event containing the exit details.
 */
void handle_linkat_exit(pid_t pid __attribute__((unused)),
                        const struct syscall_event *e) {
    log_ret(e->exit.retval, "linkat");
}
