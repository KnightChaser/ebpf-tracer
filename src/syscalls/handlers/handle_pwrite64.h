// src/syscalls/handlers/handle_pwrite64.h
#pragma once
#include "../../controller.h"
#include "../write_common.h"
#include <sys/types.h>

void handle_pwrite64_enter(pid_t pid, const struct syscall_event *e,
                           const struct write_args *args);
void handle_pwrite64_exit(pid_t pid, const struct syscall_event *e);
