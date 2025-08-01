// src/syscalls/handlers/handle_symlinkat.h
#pragma once
#include "../../controller.h"
#include <sys/types.h>

void handle_symlinkat_enter(pid_t pid, const struct syscall_event *e);
void handle_symlinkat_exit(pid_t pid, const struct syscall_event *e);
