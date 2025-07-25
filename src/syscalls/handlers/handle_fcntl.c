// src/syscalls/handlers/handle_fcntl.c
#define _GNU_SOURCE
#include "../../controller.h"
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
    int fd = (int)e->enter.args[0];
    int cmd = (int)e->enter.args[1];
    printf("%-6ld %-16s(%d, %s", e->syscall_nr, e->enter.name, fd,
           cmd_to_str(cmd));

    // If the command is frequently used, we can print additional arguments
    switch (cmd) {
    case F_DUPFD:
    case F_DUPFD_CLOEXEC:
    case F_SETFL:
    case F_SETFD:
        printf(", %ld", e->enter.args[2]);
        break;
    default:
        break;
    }
    printf(")");
    fflush(stdout);

    // NOTE: If the syscall is for a file descriptor, we can try to resolve its
    // path. In normal case, the file descriptor should be valid, because the
    // user must probe the file after opening (acquiring the file descriptor)
    // the file successfully.
    if (fd >= 0) {
        const char *path = fd_cache_get(fd);
        if (path) {
            printf("\n => path: %s\n", path);
        } else {
            printf("\n");
        }
    } else {
        printf("\n");
    }
}

void handle_fcntl_exit(pid_t pid __attribute__((unused)),
                       const struct syscall_event *e) {
    long ret = e->exit.retval;
    printf(" = 0x%lx\n", ret);

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
