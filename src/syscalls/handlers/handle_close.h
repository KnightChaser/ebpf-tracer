// src/syscalls/handlers/handle_close.h
#ifndef HANDLE_CLOSE_H
#define HANDLE_CLOSE_H

#include <sys/types.h>

void handle_close_enter(pid_t pid, const struct syscall_event *e);
void handle_close_exit(pid_t pid, const struct syscall_event *e);

#endif // HANDLE_CLOSE_H
