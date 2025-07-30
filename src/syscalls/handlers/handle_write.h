// src/syscalls/handlers/handle_write.h
#pragma once
#include "../../controller.h"
#include "../write_common.h"
#include <sys/types.h>

void handle_write_enter(pid_t pid, const struct syscall_event *e,
                        const struct write_args *args);
void handle_write_exit(pid_t pid, const struct syscall_event *e);
