// src/syscalls/handlers/handle_mkdirat.h
#pragma once
#include "../../controller.h"
#include <sys/types.h>

void handle_mkdirat_enter(pid_t pid, const struct syscall_event *e);
void handle_mkdirat_exit(pid_t pid, const struct syscall_event *e);
