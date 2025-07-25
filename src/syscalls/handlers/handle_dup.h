// src/syscalls/handlers/handle_dup.h
#pragma once
#include <sys/types.h>

void handle_dup_enter(pid_t pid, const struct syscall_event *e);
void handle_dup_exit(pid_t pid, const struct syscall_event *e);
