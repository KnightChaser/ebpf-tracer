// src/handlers/handle_fcntl.h
#pragma once

#include <sys/types.h>

void handle_fcntl_enter(pid_t pid, const struct syscall_event *e);
void handle_fcntl_exit(pid_t pid, const struct syscall_event *e);
