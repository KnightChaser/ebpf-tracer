// src/syscalls/dup_common.c
#define _GNU_SOURCE
#include "dup_common.h"
#include "fd_cache.h"
#include "handlers/handle_dup.h"
#include "handlers/handle_dup2.h"
#include "handlers/handle_dup3.h"
#include "syscalls.h"
#include "utils.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

/**
 * Fetches the arguments for dup/dup2/dup3 syscalls.
 *
 * @param pid The process ID of the syscall event.
 * @param e The syscall event containing the arguments.
 * @param o Output structure to fill with the syscall arguments.
 * @return 0 on success, -1 if the syscall is unsupported.
 */
int fetch_dup_args(pid_t pid __attribute__((unused)), // [in]
                   const struct syscall_event *e,     // [in]
                   struct dup_args *o                 // [out]
) {
    memset(o, 0, sizeof(*o));
    o->newfd = -1;
    o->flags = 0;

    switch (e->syscall_nr) {
    case SYS_dup:
        o->oldfd = (int)e->enter.args[0];
        break;
    case SYS_dup2:
        o->oldfd = e->enter.args[0];
        o->newfd = e->enter.args[1];
        break;
#ifdef SYS_dup3
    case SYS_dup3:
        o->oldfd = e->enter.args[0];
        o->newfd = e->enter.args[1];
        o->flags = e->enter.args[2];
        break;
#endif
    default:
        return -1; // Unsupported syscall
    }

    // NOTE: actually, there is no possibility to reach this point...
    return -1;
}

/**
 * Dispatches the enter event for dup/dup2/dup3 syscalls.
 * Since dup system call copies the file descriptor,
 * their paths are the same. It updates the file descriptor cache
 * and prints the new file descriptor path, too.
 *
 * @param pid The process ID of the syscall event.
 * @param e The syscall event containing the arguments.
 */
void print_dup_exit(pid_t pid, const struct syscall_event *e) {
    long ret = e->exit.retval;
    printf(" = 0x%lx\n", ret);

    if (ret >= 0) {
        // 1) grab the oldfd so we know what path to duplicate
        struct dup_args args;
        if (fetch_dup_args(pid, e, &args) == 0) {
            const char *oldpath = fd_cache_get(args.oldfd);
            if (oldpath) {
                // 2) cache the newfd => same path
                fd_cache_set((int)ret, oldpath);
            }
        }
        // 3) finally, print it just like any other fd
        print_fd_path(pid, (int)ret, 4);
    }
}

/**
 * Handles the enter event for dup/dup2/dup3 syscalls.
 *
 * @param pid The process ID of the syscall event.
 * @param e The syscall event containing the arguments.
 */
void dup_enter_dispatch(pid_t pid, const struct syscall_event *e) {
    switch (e->syscall_nr) {
    case SYS_dup:
        handle_dup_enter(pid, e);
        break;
    case SYS_dup2:
        handle_dup2_enter(pid, e);
        break;
#ifdef SYS_dup3
    case SYS_dup3:
        handle_dup3_enter(pid, e);
        break;
#endif
    default:
        handle_sys_enter_default(pid, e);
    }
}

/**
 * Handles the exit event for dup/dup2/dup3 syscalls.
 *
 * @param pid The process ID of the syscall event.
 * @param e The syscall event containing the arguments.
 */
void dup_exit_dispatch(pid_t pid, const struct syscall_event *e) {
    switch (e->syscall_nr) {
    case SYS_dup:
        handle_dup_exit(pid, e);
        break;
    case SYS_dup2:
        handle_dup2_exit(pid, e);
        break;
#ifdef SYS_dup3
    case SYS_dup3:
        handle_dup3_exit(pid, e);
        break;
#endif
    default:
        handle_sys_exit_default(pid, e);
    }
}
