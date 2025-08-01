// src/syscalls/handlers/handle_mkdir.c
#define _GNU_SOURCE
#include "handle_mkdir.h"
#include "../../syscalls/syscalls.h"
#include "../../utils/logger.h"
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
    char path[PATH_MAX] = {0};
    if (read_string_from_process(pid, e->enter.args[0], path, sizeof(path)) <=
        0) {
        snprintf(path, sizeof(path), "0x%lx (invalid)", e->enter.args[0]);
    }

    mode_t mode = (mode_t)e->enter.args[1];
    char argbuf[PATH_MAX + 16] = {0};
    snprintf(argbuf, sizeof(argbuf), "\"%s\", 0%o", path, mode);

    log_syscall(e->syscall_nr, e->enter.name, argbuf, /* retval */ 0);
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
