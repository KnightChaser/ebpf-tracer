// src/syscalls/handlers/handle_open.h
#ifndef HANDLE_OPEN_H
#define HANDLE_OPEN_H

#include <sys/types.h>

void handle_open_enter(pid_t pid, const struct syscall_event *e);
void handle_open_exit(pid_t pid, const struct syscall_event *e);

#endif // HANDLE_OPEN_H
