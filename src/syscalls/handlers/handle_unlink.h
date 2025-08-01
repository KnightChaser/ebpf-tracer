// src/syscalls/handlers/handle_unlink.h
#pragma once
#include "../../controller.h"
#include <sys/types.h>

void handle_unlink_enter(pid_t pid, const struct syscall_event *e);
void handle_unlink_exit(pid_t pid, const struct syscall_event *e);
