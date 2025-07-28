// src/syscalls/read_common.h
#pragma once
#include "../controller.h"
#include <sys/types.h>
#include <sys/uio.h>

struct read_args {
    int fd;            // for read(), pread64(), readv()
    off_t offset;      // for pread64()
    size_t count;      // for read(), pread64()
    unsigned long buf; // for read(), pread64()
    struct iovec *iov; // for readv()
    int iovcnt;        // for readv()
};

int fetch_read_args(pid_t pid, const struct syscall_event *e,
                    struct read_args *out);
void read_enter_dispatch(pid_t pid, const struct syscall_event *e);
void read_exit_dispatch(pid_t pid, const struct syscall_event *e);
