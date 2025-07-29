// src/syscalls/handlers/handle_preadv.h
#pragma once
#include <sys/types.h>

void handle_preadv_enter(pid_t pid, const struct syscall_event *e);
void handle_preadv_exit(pid_t pid, const struct syscall_event *e);
