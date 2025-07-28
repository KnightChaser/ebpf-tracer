// src/syscalls/handlers/handle_fcntl.c
#define _GNU_SOURCE
#include "../../controller.h"
#include "../../utils/logger.h"
#include "../fd_cache.h"
#include <fcntl.h>
#include <stdio.h>

// Common fcntl() commands
static struct {
    int cmd;
    const char *name;
} _cmds[] = {
    {F_DUPFD, "F_DUPFD"}, {F_DUPFD_CLOEXEC, "F_DUPFD_CLOEXEC"},
    {F_GETFD, "F_GETFD"}, {F_SETFD, "F_SETFD"},
    {F_GETFL, "F_GETFL"}, {F_SETFL, "F_SETFL"},
    // Add more if I gonna like this more ... >_<
};

/**
 * Converts a fcntl command to its string representation.
 * This is used for printing the command name in the syscall enter handler.
 *
 * @param cmd The fcntl command to convert.
 * @return The string representation of the command, or "UNKNOWN_FCNTL_CMD"
 *         if the command is not recognized.
 */
static const char *cmd_to_str(int cmd) {
    for (size_t i = 0; i < sizeof(_cmds) / sizeof(_cmds[0]); i++) {
        if (_cmds[i].cmd == cmd) {
            return _cmds[i].name;
        }
    }
    return "UNKNOWN_FCNTL_CMD";
}

/**
 * Handles the enter event for the fcntl syscall.
 * This function prints the syscall number, name, and arguments.
 *
 * @param pid The process ID of the traced process.
 * @param e The syscall_event structure containing syscall information.
 */
void handle_fcntl_enter(pid_t pid __attribute__((unused)),
                        const struct syscall_event *e) {
    const int fd = (int)e->enter.args[0];
    const int cmd = (int)e->enter.args[1];
    const long arg = e->enter.args[2];

    // If the command is frequently used, we can print additional arguments
    char argbuf[128];
    switch (cmd) {
    case F_DUPFD:         // fallthrough
    case F_DUPFD_CLOEXEC: // fallthrough
    case F_SETFL:         // fallthrough
    case F_SETFD:
        snprintf(argbuf, sizeof argbuf, "%d, %s, 0x%lx", fd, cmd_to_str(cmd),
                 arg);
        break;
    default:
        snprintf(argbuf, sizeof argbuf, "%d, %s", fd, cmd_to_str(cmd));
        break;
    }

    log_syscall(e->syscall_nr, e->enter.name, argbuf, /*retval*/ 0);

    // NOTE: If the syscall is for a file descriptor, we can try to resolve its
    // path. In normal case, the file descriptor should be valid, because the
    // user must probe the file after opening (acquiring the file descriptor)
    // the file successfully.
    const char *path = fd_cache_get(fd);
    if (path) {
        log_kv("fd_path", "%s", path);
    } else {
        log_kv("fd_path", "<unknown>");
    }
}

void handle_fcntl_exit(pid_t pid __attribute__((unused)),
                       const struct syscall_event *e) {
    long ret = e->exit.retval;
    log_ret(ret, "fcntl");

    // If the syscall was successful and the command is F_DUPFD or
    // F_DUPFD_CLOEXEC (meaning it duplicated a file descriptor),
    //  we need to update the fd cache with the new file descriptor.
    int cmd = (int)e->enter.args[1];
    if (ret >= 0 && (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC)) {
        int oldfd = (int)e->enter.args[0];
        const char *path = fd_cache_get(oldfd);
        if (path) {
            fd_cache_set((int)ret, path);
        }
    }
}
