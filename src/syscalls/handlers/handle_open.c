// src/syscalls/handlers/handle_open.c
#define _GNU_SOURCE
#include "../open_common.h"
#include <fcntl.h>

/**
 * Converts flags to a string representation.
 * This function takes a set of flags and converts them into a human-readable
 * string format, using a predefined array of flag names.
 */
static const struct flag_name open_flags[] = {
    {O_CREAT, "O_CREAT"},       {O_EXCL, "O_EXCL"},
    {O_NOCTTY, "O_NOCTTY"},     {O_TRUNC, "O_TRUNC"},
    {O_APPEND, "O_APPEND"},     {O_NONBLOCK, "O_NONBLOCK"},
    {O_DSYNC, "O_DSYNC"},       {O_SYNC, "O_SYNC"},
    {O_RSYNC, "O_RSYNC"},       {O_DIRECTORY, "O_DIRECTORY"},
    {O_NOFOLLOW, "O_NOFOLLOW"}, {O_CLOEXEC, "O_CLOEXEC"},
    // NOTE: may be added if needed >_<
};

/**
 * Handles the entry of the open syscall.
 * This function prints the syscall arguments in a human-readable format.
 *
 * @param pid The process ID.
 * @param e The syscall event containing the arguments.
 */
void handle_open_enter(pid_t pid, const struct syscall_event *e) {
    printf("%-6ld %-16s(", e->syscall_nr, e->enter.name);

    // pathname
    char path[256];
    if (read_string_from_process(pid, e->enter.args[0], path, sizeof(path)) >
        0) {
        printf("\"%s\", ", path);
    } else {
        printf("0x%lx, ", e->enter.args[0]);
    }

    // flags
    long flags = e->enter.args[1];
    const char *acc = (flags & O_ACCMODE) == O_WRONLY ? "O_WRONLY"
                      : (flags & O_ACCMODE) == O_RDWR ? "O_RDWR"
                                                      : "O_RDONLY";
    flags &= ~O_ACCMODE;
    printf("%s", acc);

    if (flags) {
        char buf[256];
        flags_to_str(flags, open_flags,
                     sizeof(open_flags) / sizeof(open_flags[0]), buf,
                     sizeof(buf));
        printf("|%s", buf);
    }

    // mode?
    if (e->enter.args[1] & (O_CREAT | O_TMPFILE)) {
        mode_t m = (mode_t)e->enter.args[2];
        printf(", 0%o", m);
    }

    printf(")");
    fflush(stdout);
}

/**
 * Handles the exit of the open syscall.
 * This function prints the return value of the syscall.
 *
 * @param pid The process ID.
 * @param e The syscall event containing the return value.
 */
void handle_open_exit(pid_t pid, const struct syscall_event *e) {
    print_open_exit(pid, e);
}
