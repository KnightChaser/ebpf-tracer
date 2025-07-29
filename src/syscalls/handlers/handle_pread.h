// src/syscalls/handlers/handle_pread.h
#pragma once
#include "../../controller.h"
#include <sys/types.h>

void handle_pread_enter(pid_t pid, const struct syscall_event *e);
void handle_pread_exit(pid_t pid, const struct syscall_event *e);
