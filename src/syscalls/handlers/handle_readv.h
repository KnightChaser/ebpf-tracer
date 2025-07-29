// src/syscalls/handlers/handle_readv.h
#pragma once
#include <sys/types.h>

void handle_readv_enter(pid_t pid, const struct syscall_event *e);
void handle_readv_exit(pid_t pid, const struct syscall_event *e);
