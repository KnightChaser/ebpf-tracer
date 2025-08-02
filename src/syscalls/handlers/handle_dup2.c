// src/syscalls/handlers/handle_dup2.c
#include "../../utils/logger.h"
#include "../dup_common.h"
#include "../fd_cache.h"
#include <stdio.h>
#include <unistd.h>

/**
 * Handles the enter event for the dup2 syscall.
 *
 * @param pid The process ID of the syscall event.
 * @param e The syscall event containing the arguments.
 */
void handle_dup2_enter(pid_t pid __attribute__((unused)),
                       const struct syscall_event *e) {
    int oldfd = (int)e->enter.args[0];
    int newfd = (int)e->enter.args[1];

    char argbuf[32] = {0};
    snprintf(argbuf, sizeof(argbuf), "%d, %d", oldfd, newfd);
    log_syscall(e->syscall_nr, e->enter.name, argbuf, /*retval*/ 0);

    const char *p = fd_cache_get(oldfd);
    if (p) {
        log_kv("oldfd (path resolved)", "%s", p);
    } else {
        log_kv("oldfd (path unresolved)", "%d", oldfd);
    }

    // Stash the dup syscall arguments for the exit handler
    stash_dup_enter(pid, e);
}

/**
 * Handles the exit event for the dup2 syscall.
 *
 * @param pid The process ID of the syscall event.
 * @param e The syscall event containing the arguments.
 */
void handle_dup2_exit(pid_t pid, const struct syscall_event *e) {
    print_dup_exit(pid, e);
}
