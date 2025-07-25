// src/syscalls/dup_common.h
#pragma once
#include "../controller.h"
#include <sys/types.h>

// Public entry points
void dup_enter_dispatch(pid_t pid, const struct syscall_event *e);
void dup_exit_dispatch(pid_t pid, const struct syscall_event *e);

// Internal helpers
struct dup_args {
    int oldfd;
    int newfd; // NOTE: dup2/dup3 only, otherwise -1
    int flags; // NOTE: dup3 only, otherwise 0
};

int fetch_dup_args(pid_t pid, const struct syscall_event *e,
                   struct dup_args *out);
void print_dup_exit(pid_t pid, const struct syscall_event *e);
