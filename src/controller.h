// src/controller.h

#ifndef CONTROLLER_H
#define CONTROLLER_H
// The highest number on x86_64 syscall number... around 334
#define MAX_SYSCALL_NR 335

// Syscalls on x86_64 have at most 6 arguments
#define MAX_SYSCALL_ARGS 6

#include <sys/syscall.h>

// An enum to distinguish between enter and exit events.
typedef enum { EVENT_SYS_ENTER, EVENT_SYS_EXIT } event_mode;

// This is the main data structure sent from kernel to user-space.
// We use a union to save space, as an event is either an ENTER
// (with args) or an EXIT (with a return value), but never both.
struct syscall_event {
    // The 'mode' tells us which part of the union is valid.
    event_mode mode;
    long syscall_nr;

    union {

        // Data for the ENTER event
        struct {
            char name[32];
            int num_args;
            // Store arguments as raw pointers/values
            unsigned long args[MAX_SYSCALL_ARGS];
        } enter;

        // Data for the EXIT event
        struct {
            long retval;
        } exit;
    };
};

// A simple struct for our lookup table.
struct tracer_syscall_info {
    char name[32];
    int num_args;
};

#endif // CONTROLLER_H
