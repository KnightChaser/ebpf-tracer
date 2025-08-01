// src/syscalls/handlers/handle_rmdir.h
#pragma once
#include "../../controller.h"
#include <sys/types.h>

void handle_rmdir_enter(pid_t pid, const struct syscall_event *e);
void handle_rmdir_exit(pid_t pid, const struct syscall_event *e);
