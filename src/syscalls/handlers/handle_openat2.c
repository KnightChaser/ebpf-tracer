// src/syscalls/handlers/handle_openat2.c
#define _GNU_SOURCE
#include "../../utils/logger.h"
#include "../open_common.h"
#include "consts.h"
#include <fcntl.h>
#include <linux/openat2.h>

/**
 * Converts flags to a string representation.
 * This function takes a set of flags and converts them into a human-readable
 * string format, using a predefined array of flag names.
 */
static const struct flag_name resolve_flags[] = {
    {RESOLVE_BENEATH, "RESOLVE_BENEATH"},
    {RESOLVE_IN_ROOT, "RESOLVE_IN_ROOT"},
    {RESOLVE_NO_MAGICLINKS, "RESOLVE_NO_MAGICLINKS"},
    {RESOLVE_NO_SYMLINKS, "RESOLVE_NO_SYMLINKS"},
    {RESOLVE_NO_XDEV, "RESOLVE_NO_XDEV"},
    {RESOLVE_CACHED, "RESOLVE_CACHED"},
};

/**
 * Handles the entry of the openat2 syscall.
 * This function prints the syscall arguments in a human-readable format.
 *
 * @param pid The process ID.
 * @param e The syscall event containing the arguments.
 */
void handle_openat2_enter(pid_t pid, const struct syscall_event *e) {
    struct open_args oa;
    if (fetch_open_args(pid, e, &oa) < 0) {
        handle_sys_enter_default(pid, e);
        return;
    }

    // 1. dirfd
    char argbuf[512] = {0};
    int off =
        snprintf(argbuf, sizeof(argbuf),
                 (oa.dirfd == AT_FDCWD ? "AT_FDCWD, " : "%d, "), oa.dirfd);

    // 2. path
    off += snprintf(argbuf + off, sizeof(argbuf) - off, "\"%s\", ", oa.path);

    // 3. flags (for openat2())
    long fl = oa.flags;
    const char *acc = (fl & O_ACCMODE) == O_WRONLY ? "O_WRONLY"
                      : (fl & O_ACCMODE) == O_RDWR ? "O_RDWR"
                                                   : "O_RDONLY";
    fl &= ~O_ACCMODE;

    char flbuf[256] = {0};
    if (fl) {
        flags_to_str(fl, open_flags, sizeof(open_flags) / sizeof(open_flags[0]),
                     flbuf, sizeof(flbuf));
    }
    off += snprintf(argbuf + off, sizeof(argbuf) - off, "%s%s%s",
                    acc,                // access mode
                    (fl ? "|" : ""),    // separator if flags are present
                    (fl ? flbuf : "")); // flags

    // 4. optional mode (for openat2())
    if (oa.mode != -1) {
        off += snprintf(argbuf + off, sizeof(argbuf) - off, ", 0%lo", oa.mode);
    }

    // 5. optional resolve
    if (oa.resolve != -1) {
        char resbuf[256] = {0};
        flags_to_str(oa.resolve, resolve_flags,
                     sizeof(resolve_flags) / sizeof(resolve_flags[0]), resbuf,
                     sizeof(resbuf));
        snprintf(argbuf + off, sizeof(argbuf) - off, ", resolve=%s", resbuf);
    }

    log_syscall(e->syscall_nr, e->enter.name, argbuf, /*retval=*/0);
}

/**
 * Handles the exit of the openat2 syscall.
 * This function prints the return value of the syscall.
 *
 * @param pid The process ID.
 * @param e The syscall event containing the return value.
 */
void handle_openat2_exit(pid_t pid, const struct syscall_event *e) {
    log_ret(e->exit.retval, "openat2");
    print_open_exit(pid, e);
}
