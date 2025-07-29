// src/utils/remote_bytes.h
#pragma once
#include <sys/types.h>

void dump_remote_bytes(pid_t pid, const void *remote_addr, size_t want,
                       size_t total);
