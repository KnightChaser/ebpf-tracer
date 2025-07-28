// src/syscalls/syscalls.h
#pragma once

#include "../controller.h"
#include <sys/types.h>

// Helper function to read a string from a traced process's memory
long read_string_from_process(pid_t pid, unsigned long addr, char *buffer,
                              size_t size);

// Default Handlers
void handle_sys_enter_default(pid_t pid, const struct syscall_event *e);
void handle_sys_exit_default(pid_t pid, const struct syscall_event *e);

// Specific Syscall Handlers
#include "handlers/handle_open.h"
#include "handlers/handle_openat.h"
#include "handlers/handle_openat2.h"
#include "open_common.h"

#include "handlers/handle_close.h"

#include "handlers/handle_dup.h"
#include "handlers/handle_dup2.h"
#ifdef SYS_dup3
#include "handlers/handle_dup3.h"
#endif

#include "handlers/handle_fcntl.h"

#include "handlers/handle_read.h"
#include "read_common.h"
