// src/syscalls/write_common.h
#pragma once
#include "../controller.h"
#include <sys/types.h>
#include <sys/uio.h>

struct write_args {
    int fd;
    off_t offset;      // for pwrite64(), pwritev()
    size_t count;      // for write(), pwrite64()
    unsigned long buf; // for write(), pwrite64()
    struct iovec *iov; // for writev(), pwritev()
    int iovcnt;        // for writev(), pwritev()
};

// Public entry points for the syscall table
void write_enter_dispatch(pid_t pid, const struct syscall_event *e);
void write_exit_dispatch(pid_t pid, const struct syscall_event *e);

// Public cleanup function
void write_common_cleanup(void);

// Helper to fetch args
int fetch_write_args(pid_t pid, const struct syscall_event *e,
                     struct write_args *out);
