// src/syscalls/handlers/handle_link.h
#pragma once
#include "../../controller.h"
#include <sys/types.h>

void handle_link_enter(pid_t pid, const struct syscall_event *e);
void handle_link_exit(pid_t pid, const struct syscall_event *e);
