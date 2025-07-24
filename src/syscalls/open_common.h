// src/syscalls/open_common.h

#ifndef OPEN_COMMON_H
#define OPEN_COMMON_H

#include "../controller.h"
#include "syscalls.h"
#include "utils.h"

// Public entry points registered in syscall table
void open_enter_dispatch(pid_t pid, const struct syscall_event *e);
void open_exit_dispatch(pid_t pid, const struct syscall_event *e);

// Internal helpers shared by handlers
struct open_args {
    int dirfd;
    char path[256];
    long flags;
    long mode;    // -1 if N/A
    long resolve; // -1 if N/A (for openat2() system call only)
};

int fetch_open_args(pid_t pid, const struct syscall_event *e,
                    struct open_args *out);
void print_open_exit(pid_t pid, const struct syscall_event *e);

#endif // OPEN_COMMON_H
