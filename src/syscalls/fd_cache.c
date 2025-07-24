// src/syscalls/fd_cache.c
#include "fd_cache.h"
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char **cache = NULL; // Pointer to the file descriptor cache
                            // which will be used throughout the program
static size_t capacity = 0; // Current capacity of the cache

/**
 * Initializes the file descriptor cache.
 * Allocates memory for the cache and sets the initial capacity.
 */
void fd_cache_init(void) {
    capacity = 64;
    cache = calloc(capacity, sizeof(*cache));
    if (!cache) {
        perror("Failed to initialize fd cache");
        exit(EXIT_FAILURE);
    }
}

/**
 * Free the memory used by the file descriptor cache.
 */
void fd_cache_cleanup(void) {
    if (!cache) {
        // Nothing to clean up
        return;
    }
    for (size_t i = 0; i < capacity; i++) {
        free(cache[i]);
    }
    free(cache);
    cache = NULL;
    capacity = 0;
}

/**
 * Store or update the path for a given file descriptor.
 *
 * @param fd The file descriptor to store the path for.
 * @param path The absolute path to associate with the file descriptor.
 * @return 0 on success, -1 on failure.
 */
static int ensure_capacity(int fd) {
    if ((size_t)fd < capacity) {
        // double the capacity and cache size until we fit
        return 0;
    }
    size_t newCapacity = capacity;
    while (newCapacity <= (size_t)fd) {
        // *2
        newCapacity <<= 1;
    }
    char **tmp = realloc(cache, newCapacity * sizeof(*cache));
    if (!tmp) {
        perror("Failed to expand fd cache");
        return -1;
    }

    // Zero the new slots
    memset(tmp + capacity, 0, (newCapacity - capacity) * sizeof(*tmp));
    cache = tmp;
    capacity = newCapacity;
    return 0;
}

/**
 * Store or update the path for a given file descriptor.
 *
 * @param fd The file descriptor to store the path for.
 * @param path The absolute path to associate with the file descriptor.
 * @return 0 on success, -1 on failure.
 */
int fd_cache_set(int fd, const char *path) {
    if (fd < 0) {
        return -1;
    }
    if (ensure_capacity(fd) < 0) {
        return -1;
    }

    free(cache[fd]);
    cache[fd] = strdup(path);
    return cache[fd] ? 0 : -1;
}

/**
 * Lookup the path associated with a given file descriptor.
 *
 * @param fd The file descriptor to look up.
 * @return The absolute path associated with the file descriptor, or NULL if not
 * found.
 */
const char *fd_cache_get(int fd) {
    if (fd < 0 || (size_t)fd >= capacity) {
        return NULL;
    } else {
        return cache[fd];
    }
}

/**
 * Remove the entry for a given file descriptor, freeing its associated string.
 *
 * @param fd The file descriptor to remove from the cache.
 */
void fd_cache_remove(int fd) {
    if (fd < 0 || (size_t)fd >= capacity) {
        return;
    }
    free(cache[fd]);
    cache[fd] = NULL;
}
