// src/syscalls/handlers/handle_linkat.h
#pragma once
#include "../../controller.h"
#include <sys/types.h>

void handle_linkat_enter(pid_t pid, const struct syscall_event *e);
void handle_linkat_exit(pid_t pid, const struct syscall_event *e);
