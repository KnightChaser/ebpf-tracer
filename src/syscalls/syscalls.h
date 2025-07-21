// src/syscalls/syscalls.h
#ifndef SYSCALLS_H
#define SYSCALLS_H

#include "../controller.h"
#include <sys/types.h>

// Helper function to read a string from a traced process's memory
long read_string_from_process(pid_t pid, unsigned long addr, char *buffer, size_t size);

// Default Handlers 
void handle_sys_enter_default(pid_t pid, const struct syscall_event *e);
void handle_sys_exit_default(pid_t pid, const struct syscall_event *e);

// Specific Syscall Handlers 
void handle_sys_enter_openat(pid_t pid, const struct syscall_event *e);

#endif // SYSCALLS_H