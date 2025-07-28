// src/syscalls/handlers/handle_openat.c
#define _GNU_SOURCE
#include "../../utils/logger.h"
#include "../open_common.h"
#include "consts.h"
#include <fcntl.h>
#include <linux/limits.h>

/**
 * Handles the entry of the openat syscall.
 * This function prints the syscall arguments in a human-readable format.
 *
 * @param pid The process ID.
 * @param e The syscall event containing the arguments.
 */
void handle_openat_enter(pid_t pid, const struct syscall_event *e) {
    int dirfd = (int)e->enter.args[0];
    long flags = e->enter.args[2];

    char path[PATH_MAX] = {0};
    if (read_string_from_process(pid, e->enter.args[1], path, sizeof(path)) <=
        0) {
        snprintf(path, sizeof(path), "0x%lx", e->enter.args[1]);
    }

    // Compose printable argument list
    char argbuf[512] = {0};

    // 1. dirfd
    int offset = snprintf(argbuf, sizeof(argbuf),
                          (dirfd == AT_FDCWD ? "AT_FDCWD, " : "%d, "), dirfd);

    // 2.pathname
    offset +=
        snprintf(argbuf + offset, sizeof(argbuf) - offset, "\"%s\", ", path);

    // 3. flags
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

    char flbuf[256] = {0};
    if (rest) {
        flags_to_str(rest, open_flags,
                     sizeof(open_flags) / sizeof(open_flags[0]), flbuf,
                     sizeof(flbuf));
    }

    offset += snprintf(argbuf + offset, sizeof(argbuf) - offset, "%s%s%s", acc,
                       (rest ? "|" : ""), (rest ? flbuf : ""));

    // 4. optional mode (only valid with O_CREAT/O_TMPFILE)
    if (flags & (O_CREAT | O_TMPFILE)) {
        mode_t mode = (mode_t)e->enter.args[3];
        snprintf(argbuf + offset, sizeof(argbuf) - offset, ", 0%o", mode);
    }

    log_syscall(e->syscall_nr, e->enter.name, argbuf, /*retval=*/0);
}

/**
 * Handles the entry of the openat syscall.
 *
 * @param id The process ID.
 * @param e The syscall event containing the arguments.
 */
void handle_openat_exit(pid_t id, const struct syscall_event *e) {
    print_open_exit(id, e);
}
