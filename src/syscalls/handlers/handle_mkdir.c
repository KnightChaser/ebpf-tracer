// src/syscalls/handlers/handle_mkdir.c
#define _GNU_SOURCE
#include "handle_mkdir.h"
#include "../../syscalls/syscalls.h"
#include "../../utils/logger.h"
#include "../../utils/path_utils.h"
#include <linux/limits.h>
#include <stdio.h>
#include <sys/stat.h>

/**
 * Handle the entry of the mkdir syscall.
 * This function reads the path and mode from the syscall arguments,
 * and logs the syscall with its arguments in a human-readable format.
 *
 * @param pid The process ID.
 * @param e The syscall event containing the arguments.
 */
void handle_mkdir_enter(pid_t pid, const struct syscall_event *e) {
    char rel_path[PATH_MAX] = {0};
    if (read_string_from_process(pid, e->enter.args[0], rel_path,
                                 sizeof(rel_path)) <= 0) {
        snprintf(rel_path, sizeof(rel_path), "0x%lx (invalid)",
                 e->enter.args[0]);
    }

    mode_t mode = (mode_t)e->enter.args[1];
    char argbuf[PATH_MAX + 16] = {0};
    snprintf(argbuf, sizeof(argbuf), "\"%s\", 0%o", rel_path, mode);

    log_syscall(e->syscall_nr, e->enter.name, argbuf, /* retval */ 0);

    char abs_path[PATH_MAX] = {0};
    if (resolve_abs_path(pid, AT_FDCWD, rel_path, abs_path, sizeof(abs_path)) ==
        0) {
        log_kv("path", "%s", abs_path);
    } else {
        log_kv("path", "<could not resolve>");
    }
}

/**
 * Handle the exit of the mkdir syscall.
 * This function logs the return value of the syscall.
 *
 * @param pid The process ID.
 * @param e The syscall event containing the exit information.
 */
void handle_mkdir_exit(pid_t pid __attribute__((unused)),
                       const struct syscall_event *e) {
    log_ret(e->exit.retval, "mkdir");
}
