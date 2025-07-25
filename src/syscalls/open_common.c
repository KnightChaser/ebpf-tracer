// src/syscalls/open_common.c

#define _GNU_SOURCE
#include "open_common.h"
#include "fd_cache.h"
#include "handlers/handle_open.h"
#include "handlers/handle_openat.h"
#include "handlers/handle_openat2.h"
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

/**
 * Structure to hold pending (file) open requests.
 * This is used to track files that are opened but not yet resolved.
 */
struct pending_open {
    char *abs_path;
    struct pending_open *next;
};

static struct pending_open *open_pending_list_head = NULL;
static struct pending_open *open_pending_list_tail = NULL;

/**
 * Adds a pending open request to the list.
 * This is used to track files that are opened but not yet resolved.
 *
 * @param abspath The absolute path of the file being opened.
 */
static void pending_push(const char *abspath) {
    struct pending_open *n = calloc(1, sizeof(struct pending_open));
    if (!n) {
        // Memory allocation failed
        perror("Failed to allocate memory for pending open");
        return;
    }

    n->abs_path = strdup(abspath ? abspath : "");
    if (!n->abs_path) {
        // Memory allocation failed
        free(n);
        return;
    }
    n->next = NULL;

    // If this is the first pending open, set it as the head.
    // If there is already a tail, link it to the new node.
    if (!open_pending_list_tail) {
        open_pending_list_head = n;
    } else {
        open_pending_list_tail->next = n;
    }
    open_pending_list_tail = n;
}

/**
 * Pops the next pending open request from the list.
 * This is used to resolve files that were opened but not yet resolved.
 *
 * @return The absolute path of the file being opened, or NULL if no pending
 * opens.
 */
static char *pending_pop(void) {
    if (!open_pending_list_head) {
        // No pending opens
        return NULL;
    }

    struct pending_open *n = open_pending_list_head;
    char *ret = n->abs_path;
    open_pending_list_head = n->next;

    if (!open_pending_list_head) {
        // If we popped the last element, reset the tail as well.
        open_pending_list_tail = NULL;
    }
    free(n);

    return ret;
}

/**
 * Builds an absolute path from a relative path and the current working
 * directory of the specified process.
 *
 * @param pid The process ID of the traced process.
 * @param raw The raw relative path to convert.
 * @param out The buffer to store the resulting absolute path.
 * @param outsz The size of the output buffer.
 * @return 0 on success, -1 on error.
 */
static int build_abs_path(pid_t pid,       // [IN]
                          const char *raw, // [IN]
                          char *out,       // [OUT]
                          size_t outsz     // [IN]
) {
    if (raw[0] == '/') {
        // already an absolute path
        snprintf(out, outsz, "%s", raw);
        return 0;
    }

    // read /proc/<pid>/cwd to get the current working directory
    char cwd_link[64];
    char cwd[PATH_MAX];
    int n = snprintf(cwd_link, sizeof(cwd_link), "/proc/%d/cwd", pid);
    if (n < 0 || (size_t)n >= sizeof(cwd_link)) {
        return -1;
    }
    ssize_t m = readlink(cwd_link, cwd, sizeof(cwd) - 1);
    if (m < 0 || m >= (ssize_t)(sizeof(cwd) - 1)) {
        return -1;
    }
    cwd[m] = '\0';

    // combine them to build the full path
    if ((size_t)snprintf(out, outsz, "%s/%s", cwd, raw) >= outsz) {
        return -1;
    }
    return 0;
}

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
 * This function is called when the syscall exits and prints the return value.
 *
 * @param pid The process ID of the traced process.
 * @param e The syscall_event structure containing syscall information.
 */
void print_open_exit(pid_t pid __attribute__((unused)),
                     const struct syscall_event *e) {
    long ret = e->exit.retval;
    printf("\n = 0x%lx (open[at[2]])\n", ret);
    if (ret >= 0) {
        // If the syscall succeeded, we can try to resolve the file descriptor
        const char *path = fd_cache_get((int)ret);
        if (path) {
            printf(" => path: %s", path);
        } else {
            printf(" => path: <unknown>\n");
        }
    }
    printf("\n");
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

    // NOTE: resolve & stash the absolute path for the open*_exit
    {
        struct open_args oa;
        char abs[PATH_MAX];
        if (fetch_open_args(pid, e, &oa) == 0 &&
            build_abs_path(pid, oa.path, abs, sizeof(abs)) == 0) {
            // If we successfully fetched the arguments, and built the absolute
            // path, we can stash it for later use.
            pending_push(abs);
        } else {
            pending_push(NULL);
        }
    }
}

/**
 * Dispatches the syscall exit events for open/openat/openat2 syscalls.
 *
 * @param pid The process ID of the traced process.
 * @param e The syscall_event structure containing syscall information.
 */
void open_exit_dispatch(pid_t pid, const struct syscall_event *e) {

    // NOTE: pop the path we stashed, and if the syscall succeeded, cache it
    // to the fd_cache too. Maybe other syscalls such as dup() or close() use.
    {
        long ret = e->exit.retval;
        char *abs = pending_pop();
        if (ret >= 0 && abs && *abs) {
            fd_cache_set((int)ret, abs);
        }
        free(abs);
    }

    // After setting the fd_cache(), we can handle the exit event.
    // It will eventually call print_open_exit() to print the exit information.
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
