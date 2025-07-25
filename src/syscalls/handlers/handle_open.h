// src/syscalls/handlers/handle_open.h
#pragma once

#include <sys/types.h>

void handle_open_enter(pid_t pid, const struct syscall_event *e);
void handle_open_exit(pid_t pid, const struct syscall_event *e);
