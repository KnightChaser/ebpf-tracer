// src/syscalls/handlers/handle_symlink.h
#pragma once
#include "../../controller.h"
#include <sys/types.h>

void handle_symlink_enter(pid_t pid, const struct syscall_event *e);
void handle_symlink_exit(pid_t pid, const struct syscall_event *e);
