// src/syscalls/handlers/handle_openat2.h
#pragma once

#include <sys/types.h>

void handle_openat2_enter(pid_t pid, const struct syscall_event *e);
void handle_openat2_exit(pid_t pid, const struct syscall_event *e);
