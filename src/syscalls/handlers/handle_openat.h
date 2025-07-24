// src/syscalls/handlers/handle_openat.h
#ifndef HANDLE_OPENAT_H
#define HANDLE_OPENAT_H

#include <sys/types.h>

void handle_openat_enter(pid_t pid, const struct syscall_event *e);
void handle_openat_exit(pid_t pid, const struct syscall_event *e);

#endif // HANDLE_OPENAT_H
