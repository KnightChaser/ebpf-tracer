// src/syscalls/handlers/handle_unlinkat.h
#pragma once
#include "../../controller.h"
#include <sys/types.h>

void handle_unlinkat_enter(pid_t pid, const struct syscall_event *e);
void handle_unlinkat_exit(pid_t pid, const struct syscall_event *e);
