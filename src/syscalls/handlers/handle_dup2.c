// src/syscalls/handlers/handle_dup2.c
#include "../dup_common.h"
#include <stdio.h>
#include <unistd.h>

/**
 * Handles the enter event for the dup2 syscall.
 *
 * @param pid The process ID of the syscall event.
 * @param e The syscall event containing the arguments.
 */
void handle_dup2_enter(pid_t pid, const struct syscall_event *e) {
    int oldfd = (int)e->enter.args[0];
    int newfd = (int)e->enter.args[1];
    printf("%-6ld %-16s(%d, %d)", e->syscall_nr, e->enter.name, oldfd, newfd);
    fflush(stdout);
}

/**
 * Handles the exit event for the dup2 syscall.
 *
 * @param pid The process ID of the syscall event.
 * @param e The syscall event containing the arguments.
 */
void handle_dup2_exit(pid_t pid, const struct syscall_event *e) {
    print_dup_exit(pid, e);
}
