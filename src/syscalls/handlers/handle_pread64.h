// src/syscalls/handlers/handle_pread64.h
#pragma once
#include "../../controller.h"
#include <sys/types.h>

void handle_pread64_enter(pid_t pid, const struct syscall_event *e);
void handle_pread64_exit(pid_t pid, const struct syscall_event *e);
