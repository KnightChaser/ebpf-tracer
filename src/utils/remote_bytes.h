// src/utils/remote_bytes.h
#pragma once
#include <sys/types.h>

void dump_remote_bytes(pid_t pid, const void *remote_addr, size_t want,
                       size_t total);
void dump_remote_iov(pid_t pid, const struct iovec *iov, int iovcnt,
                     size_t max_total, size_t real_total);
