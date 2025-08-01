// src/syscalls/handlers/handle_mkdir.h
#pragma once
#include "../../controller.h"
#include <sys/types.h>

void handle_mkdir_enter(pid_t pid, const struct syscall_event *e);
void handle_mkdir_exit(pid_t pid, const struct syscall_event *e);
