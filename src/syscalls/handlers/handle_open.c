// src/syscalls/handlers/handle_open.c
#define _GNU_SOURCE
#include "../../utils/logger.h"
#include "../open_common.h"
#include "consts.h"
#include <fcntl.h>

/**
 * Handles the entry of the open syscall.
 * This function prints the syscall arguments in a human-readable format.
 *
 * @param pid The process ID.
 * @param e The syscall event containing the arguments.
 */
void handle_open_enter(pid_t pid, const struct syscall_event *e) {
    char path[PATH_MAX] = {0};
    if (read_string_from_process(pid, e->enter.args[0], path, sizeof(path)) <=
        0) {
        snprintf(path, sizeof(path), "0x%lx", e->enter.args[0]);
    }

    long flags = e->enter.args[1];

    const char *acc;
    switch (flags & O_ACCMODE) {
    case O_WRONLY:
        acc = "O_WRONLY";
        break;
    case O_RDWR:
        acc = "O_RDWR";
        break;
    case O_RDONLY:
    default:
        acc = "O_RDONLY";
        break;
    }
    long rest = flags & ~O_ACCMODE;

    char rest_buf[256] = "0";
    if (rest) {
        flags_to_str(rest, open_flags,
                     sizeof(open_flags) / sizeof(open_flags[0]), rest_buf,
                     sizeof(rest_buf));
    }

    // Compose the full argument list
    char argbuf[512];
    int off = snprintf(argbuf, sizeof(argbuf), "\"%s\", %s%s%s", path, acc,
                       rest ? "|" : "", rest ? rest_buf : "");

    // Optional mode (only valid with O_CREAT/O_TMPFILE)
    if (flags & (O_CREAT | O_TMPFILE)) {
        mode_t m = (mode_t)e->enter.args[2];
        snprintf(argbuf + off, sizeof(argbuf) - off, ", 0%o", m);
    }

    log_syscall(e->syscall_nr, e->enter.name, argbuf, /*retval*/ 0);
}

/**
 * Handles the exit of the open syscall.
 * This function prints the return value of the syscall.
 *
 * @param pid The process ID.
 * @param e The syscall event containing the return value.
 */
void handle_open_exit(pid_t pid, const struct syscall_event *e) {
    log_ret(e->exit.retval, "open");
    print_open_exit(pid, e);
}
