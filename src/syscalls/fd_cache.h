// src/syscalls/fd_cache.h
#pragma once

#include <stddef.h>

// Initialize and clean up the file descriptor cache.
// (FD => absolute path mappings)
void fd_cache_init(void);
void fd_cache_cleanup(void);

// Store or update path for fd
int fd_cache_set(int fd, const char *path);

// Lookup the path via fd
const char *fd_cache_get(int fd);

// Remove entry for fd, freeing its string
void fd_cache_remove(int fd);
