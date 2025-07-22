// src/syscalls/openat.c
#define _GNU_SOURCE
#include "syscalls.h"
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>

/**
 * Handle the entry of the openat syscall.
 * It prints the syscall number, name, and arguments in a human-readable format.
 * @param pid The PID of the process making the syscall.
 * @param e The syscall event containing the syscall information.
 */
void handle_sys_enter_openat(pid_t pid, const struct syscall_event *e) {
    printf("%-6ld %-16s(", e->enter.syscall_nr, e->enter.name);

    // Arg 0: dirfd
    int dirfd = e->enter.args[0];
    if (dirfd == AT_FDCWD) {
        printf("AT_FDCWD, ");
    } else {
        printf("%d, ", dirfd);
    }

    // Arg 1: pathname (a pointer)
    char pathname[256];
    if (read_string_from_process(pid, e->enter.args[1], pathname,
                                 sizeof(pathname)) > 0) {
        printf("\"%s\", ", pathname);
    } else {
        printf("0x%lx, ", e->enter.args[1]); // Fallback to raw pointer
    }

    // Arg 2: flags
    printf("0x%lx", e->enter.args[2]);

    // TODO: A more advanced version would decode the flags (O_RDONLY, etc.)

    printf(")");
    fflush(stdout);
}
