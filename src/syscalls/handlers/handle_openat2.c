// src/syscalls/handlers/handle_openat2.c
#define _GNU_SOURCE
#include "../open_common.h"
#include <fcntl.h>
#include <linux/openat2.h>

static const struct flag_name open_flags[] = {
    {O_CREAT, "O_CREAT"},   {O_EXCL, "O_EXCL"},
    {O_NOCTTY, "O_NOCTTY"}, {O_TRUNC, "O_TRUNC"},
    {O_APPEND, "O_APPEND"}, {O_NONBLOCK, "O_NONBLOCK"},
    {O_DSYNC, "O_DSYNC"},   {O_SYNC, "O_SYNC"},
    {O_RSYNC, "O_RSYNC"},   {O_CLOEXEC, "O_CLOEXEC"},
};

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

    printf("%-6ld %-16s(", e->syscall_nr, e->enter.name);

    // dirfd
    if (oa.dirfd == AT_FDCWD)
        printf("AT_FDCWD, ");
    else
        printf("%d, ", oa.dirfd);

    // path
    printf("\"%s\", ", oa.path);

    // flags
    long f = oa.flags;
    const char *acc = (f & O_ACCMODE) == O_WRONLY ? "O_WRONLY"
                      : (f & O_ACCMODE) == O_RDWR ? "O_RDWR"
                                                  : "O_RDONLY";
    f &= ~O_ACCMODE;
    printf("%s", acc);
    if (f) {
        char buf[256];
        flags_to_str(f, open_flags, sizeof(open_flags) / sizeof(open_flags[0]),
                     buf, sizeof(buf));
        printf("|%s", buf);
    }

    // mode
    if (oa.mode != -1) {
        printf(", 0%lo", oa.mode);
    }

    // resolve
    if (oa.resolve != -1) {
        char buf[256];
        flags_to_str(oa.resolve, resolve_flags,
                     sizeof(resolve_flags) / sizeof(resolve_flags[0]), buf,
                     sizeof(buf));
        printf(", resolve=%s", buf);
    }

    printf(")");
    fflush(stdout);
}

/**
 * Handles the exit of the openat2 syscall.
 * This function prints the return value of the syscall.
 *
 * @param pid The process ID.
 * @param e The syscall event containing the return value.
 */
void handle_openat2_exit(pid_t pid, const struct syscall_event *e) {
    print_open_exit(pid, e);
}
