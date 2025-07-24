// src/syscalls/handlers/handle_openat2.h
#ifndef HANDLE_OPENAT2_H
#define HANDLE_OPENAT2_H

#include <sys/types.h>

void handle_openat2_enter(pid_t pid, const struct syscall_event *e);
void handle_openat2_exit(pid_t pid, const struct syscall_event *e);

#endif // HANDLE_OPENAT2_H
