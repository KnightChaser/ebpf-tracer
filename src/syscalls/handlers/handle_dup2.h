// src/syscalls/handlers/handle_dup2.h
#pragma once
#include <sys/types.h>

void handle_dup2_enter(pid_t pid, const struct syscall_event *e);
void handle_dup2_exit(pid_t pid, const struct syscall_event *e);
