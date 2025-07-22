// src/syscalls/openat.c
#define _GNU_SOURCE
#include "syscalls.h"
#include "utils.h"
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>

// Define the flag names for openat syscall
static const struct flag_name open_flags[] = {
    {O_CREAT, "O_CREAT"},       {O_EXCL, "O_EXCL"},
    {O_NOCTTY, "O_NOCTTY"},     {O_TRUNC, "O_TRUNC"},
    {O_APPEND, "O_APPEND"},     {O_NONBLOCK, "O_NONBLOCK"},
    {O_DSYNC, "O_DSYNC"},       {O_SYNC, "O_SYNC"},
    {O_RSYNC, "O_RSYNC"},       {O_DIRECTORY, "O_DIRECTORY"},
    {O_NOFOLLOW, "O_NOFOLLOW"}, {O_CLOEXEC, "O_CLOEXEC"},
    {O_PATH, "O_PATH"},         {O_TMPFILE, "O_TMPFILE"},
    // NOTE: may be added if needed >_<
};

/**
 * Handle the entry of the openat syscall.
 * It prints the syscall number, name, and arguments in a human-readable format.
 * @param pid The PID of the process making the syscall.
 * @param e The syscall event containing the syscall information.
 */
void handle_sys_enter_openat(pid_t pid, const struct syscall_event *e) {
    printf("%-6ld %-16s(", e->enter.syscall_nr, e->enter.name);

    // dirfd
    int dirfd = e->enter.args[0];
    if (dirfd == AT_FDCWD) {
        printf("AT_FDCWD, ");
    } else {
        printf("%d, ", dirfd);
    }

    // pathname
    char pathname[256];
    if (read_string_from_process(pid, e->enter.args[1], pathname,
                                 sizeof(pathname)) > 0) {
        printf("\"%s\", ", pathname);
    } else {
        printf("0x%lx, ", e->enter.args[1]); // Fallback to raw pointer
    }

    // flags
    long flags = e->enter.args[2];
    char flagBuf[256];
    const char *accmode;

    switch (flags & O_ACCMODE) {
    // Extract access mode
    case O_RDONLY:
        accmode = "O_RDONLY";
        break;
    case O_WRONLY:
        accmode = "O_WRONLY";
        break;
    case O_RDWR:
        accmode = "O_RDWR";
        break;
    default:
        accmode = "???";
        break;
    }
    flags &= ~O_ACCMODE; // Clear access mode from flags
    printf("%s", accmode);

    if (flags) {
        flags_to_str(flags, open_flags,
                     sizeof(open_flags) / sizeof(open_flags[0]), flagBuf,
                     sizeof(flagBuf));
        printf("|%s", flagBuf);
    }

    // NOTE: openat(dirfd, pathname, flags[, mode])
    // The mode param is only parsed by the kernel if flags has O_CREAT or
    // O_TMPFILE. Otherwise that slot is garbage/ignored.
    if ((e->enter.args[2] & (O_CREAT | O_TMPFILE)) != 0) {
        mode_t mode = e->enter.args[3];
        printf(", 0%o", mode);
    }

    printf(")");
    fflush(stdout);
}
