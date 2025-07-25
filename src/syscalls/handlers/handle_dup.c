// src/syscalls/handlers/handle_dup.c
#include "../dup_common.h"
#include <stdio.h>
#include <unistd.h>

/**
 * Handles the enter event for the dup syscall.
 *
 * @param pid The process ID of the syscall event.
 * @param e The syscall event containing the arguments.
 */
void handle_dup_enter(pid_t pid, const struct syscall_event *e) {
    int oldfd = (int)e->enter.args[0];
    printf("%-6ld %-16s(%d)", e->syscall_nr, e->enter.name, oldfd);
    fflush(stdout);
}

/**
 * Handles the exit event for the dup syscall.
 *
 * @param pid The process ID of the syscall event.
 * @param e The syscall event containing the arguments.
 */
void handle_dup_exit(pid_t pid, const struct syscall_event *e) {
    print_dup_exit(pid, e);
}
