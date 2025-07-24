// src/syscalls/open_common.c

#define _GNU_SOURCE
#include "open_common.h"
#include "fd_cache.h"
#include "handlers/handle_open.h"
#include "handlers/handle_openat.h"
#include "handlers/handle_openat2.h"
#include <fcntl.h>
#include <linux/openat2.h>
#include <string.h>
#include <sys/uio.h>

/**
 * Fetches the arguments for open/openat/openat2 syscalls from the
 * syscall_event structure.
 *
 * @param pid The process ID of the traced process.
 * @param e The syscall_event structure containing syscall information.
 * @param o Pointer to the open_args structure to fill with the arguments.
 * @return 0 on success, -1 on failure.
 */
int fetch_open_args(pid_t pid,                     // [in]
                    const struct syscall_event *e, // [in]
                    struct open_args *o            // [out]
) {
    memset(o, 0, sizeof(*o));
    o->mode = -1;
    o->resolve = -1;

    switch (e->syscall_nr) {
    case SYS_open:
        // int open(const char *pathname, int flags, ... /* mode_t mode */ );
        o->dirfd = AT_FDCWD;
        if (read_string_from_process(pid, e->enter.args[0], o->path,
                                     sizeof(o->path)) <= 0) {
            snprintf(o->path, sizeof(o->path), "0x%lx", e->enter.args[0]);
        }
        o->flags = e->enter.args[1];
        if (o->flags & (O_CREAT | O_TMPFILE)) {
            // If O_CREAT or O_TMPFILE is set, we also have a mode
            o->mode = e->enter.args[2];
        }
        return 0;

    case SYS_openat:
        // int openat(int dirfd, const char *pathname, int flags, ... /* mode_t
        // mode */ );
        o->dirfd = e->enter.args[0];
        if (read_string_from_process(pid, e->enter.args[1], o->path,
                                     sizeof(o->path)) <= 0) {
            snprintf(o->path, sizeof(o->path), "0x%lx", e->enter.args[1]);
        }
        o->flags = e->enter.args[2];
        if (o->flags & (O_CREAT | O_TMPFILE)) {
            // If O_CREAT or O_TMPFILE is set, we also have a mode
            o->mode = e->enter.args[3];
        }
        return 0;

    case SYS_openat2:
        // int openat2(int dirfd, const struct open_how *how, size_t how_size);
        o->dirfd = e->enter.args[0];
        if (read_string_from_process(pid, e->enter.args[1], o->path,
                                     sizeof(o->path)) <= 0) {
            snprintf(o->path, sizeof(o->path), "0x%lx", e->enter.args[1]);
        }

        // Read the open_how structure from the process memory
        struct open_how how;
        struct iovec liov = {
            .iov_base = &how,
            .iov_len = sizeof(how),
        };
        struct iovec riov = {
            .iov_base = (void *)e->enter.args[2],
            .iov_len = sizeof(how),
        };
        if (process_vm_readv(pid, &liov, 1, &riov, 1, 0) < 0) {
            return -1;
        }
        o->flags = how.flags;
        o->mode = how.mode;
        o->resolve = how.resolve;
        return 0;

    default:
        // Unsupported syscall, return an error
        return -1;
    }
}

/**
 * Prints the exit information for open/openat/openat2 syscalls.
 * Simply, it prints the return value and the file descriptor path if
 * the syscall was successful.
 *
 * @param pid The process ID of the traced process.
 * @param e The syscall_event structure containing syscall information.
 */
void print_open_exit(pid_t pid, const struct syscall_event *e) {
    printf("\n = 0x%lx (open[at[2]])\n", e->exit.retval);
    if (e->exit.retval >= 0) {
        char absolutePath[PATH_MAX] = {0};
        int fd = (int)e->exit.retval;
        if (fd_realpath(pid, fd, absolutePath, sizeof(absolutePath)) >= 0) {
            printf(" => path: %s\n", absolutePath);

            // cache it
            absolutePath[sizeof(absolutePath) - 1] = '\0';
            fd_cache_set(fd, absolutePath);
        } else {
            printf(" = <error resolving path>\n");
        }
    } else {
        printf(" = -1 (errno: %ld)\n", -e->exit.retval);
    }
}

/**
 * Dispatches the syscall enter events for open/openat/openat2 syscalls.
 *
 * @param pid The process ID of the traced process.
 * @param e The syscall_event structure containing syscall information.
 */
void open_enter_dispatch(pid_t pid, const struct syscall_event *e) {
    switch (e->syscall_nr) {
    case SYS_open:
        handle_open_enter(pid, e);
        break;
    case SYS_openat:
        handle_openat_enter(pid, e);
        break;
    case SYS_openat2:
        handle_openat2_enter(pid, e);
        break;
    default:
        printf("Unhandled syscall: %ld, expected either open, openat, or "
               "openat2\n",
               e->syscall_nr);
        handle_sys_enter_default(pid, e);
    }
}

/**
 * Dispatches the syscall exit events for open/openat/openat2 syscalls.
 *
 * @param pid The process ID of the traced process.
 * @param e The syscall_event structure containing syscall information.
 */
void open_exit_dispatch(pid_t pid, const struct syscall_event *e) {
    switch (e->syscall_nr) {
    case SYS_open:
        handle_open_exit(pid, e);
        break;
    case SYS_openat:
        handle_openat_exit(pid, e);
        break;
    case SYS_openat2:
        handle_openat2_exit(pid, e);
        break;
    default:
        printf("Unhandled syscall: %ld, expected either open, openat, or "
               "openat2\n",
               e->syscall_nr);
        handle_sys_exit_default(pid, e);
    }
}
