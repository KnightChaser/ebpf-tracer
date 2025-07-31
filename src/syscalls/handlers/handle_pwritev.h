// src/syscalls/handlers/handle_pwritev.h
#pragma once
#include "../../controller.h"
#include "../write_common.h"
#include <sys/types.h>

void handle_pwritev_enter(pid_t pid, const struct syscall_event *e,
                          const struct write_args *args);
void handle_pwritev_exit(pid_t pid, const struct syscall_event *e);
