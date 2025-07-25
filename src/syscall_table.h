// src/syscall_table.h
#pragma once

#include "controller.h"
#include <sys/types.h>

typedef void (*syscall_handler_t)(pid_t, const struct syscall_event *);

extern syscall_handler_t enter_handlers[];
extern syscall_handler_t exit_handlers[];

void syscall_table_init(void);

// one-liner macro for syscall handler registration
#define REGISTER_SYSCALL_HANDLER(sysno, enter_handler, exit_handler)           \
    do {                                                                       \
        enter_handlers[sysno] = enter_handler;                                 \
        exit_handlers[sysno] = exit_handler;                                   \
    } while (0)

// Check if a specific syscall is registered
#define IS_SYSCALL_REGISTERED(sysno)                                           \
    (enter_handlers[sysno] != NULL && exit_handlers[sysno] != NULL)

// Check if a specific syscall is supported on the machine
#define IS_SYSCALL_SUPPORTED(sysno) (sysno < MAX_SYSCALL_NR)
