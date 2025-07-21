// src/syscalls/default.c
#include "syscalls.h"
#include <stdio.h>

/**
 * Default handler for syscall entry events.
 * This function prints the syscall number, name, and arguments.
 * @param pid The PID of the process making the syscall.
 * @param e The syscall event containing the syscall information.
 */
void handle_sys_enter_default(pid_t pid __attribute__((unused)), const struct syscall_event *e) {
    if (e->enter.name[0] != '\0') {
        printf("%-6ld %-16s(", e->enter.syscall_nr, e->enter.name);
    } else {
        printf("%-6ld UNKNOWNSYSCALL  (", e->enter.syscall_nr);
    }

    for (int i = 0; i < e->enter.num_args; ++i) {
        printf("0x%lx%s", e->enter.args[i],
               (i == e->enter.num_args - 1) ? "" : ", ");
    }
    printf(")");
    fflush(stdout);
}

/**
 * Default handler for syscall exit events.
 * This function prints the return value of the syscall.
 * @param pid The PID of the process making the syscall.
 * @param e The syscall event containing the syscall information.
 */
void handle_sys_exit_default(pid_t pid __attribute__((unused)), const struct syscall_event *e) {
    printf(" = 0x%lx\n", e->exit.retval);
}