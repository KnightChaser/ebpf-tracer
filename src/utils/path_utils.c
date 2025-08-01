// src/utils/path_utils.c
#include "path_utils.h"
#include "../syscalls/fd_cache.h"
#include "logger.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/**
 * Builds an absolute path from a relative path and a directory file
 * descriptor (dirfd). If dirfd is AT_FDCWD, the current working
 * directory of the process with the given pid is used as the base.
 * Otherwise, the path associated with dirfd is used as the base.
 *
 * @param pid The process ID whose current working directory is used if dirfd
 *           is AT_FDCWD.
 * @param dirfd The directory file descriptor. If AT_FDCWD, the current
 *              working directory of the process is used.
 * @param rel_path The relative path to resolve.
 * @param out The buffer to store the resolved absolute path.
 * @param outsz The size of the output buffer.
 * @return 0 on success, -1 on failure.
 */
int resolve_abs_path(pid_t pid,            // [in]
                     int dirfd,            // [in]
                     const char *rel_path, // [in]
                     char *out,            // [out]
                     size_t outsz          // [in]
) {
    if (!rel_path || !out || outsz == 0) {
        log_error("Invalid arguments provided to resovle_abs_path: pid=%d, "
                  "dirfd=%d, rel_path=%s, out=%p, outsz=%zu",
                  pid, dirfd, rel_path, out, outsz);
        return -1; // Invalid arguments
    }

    if (rel_path[0] == '/') {
        // It's already an absolute path ,just copy it
        snprintf(out, outsz, "%s", rel_path);
        return 0;
    }

    char base_path[PATH_MAX] = {0};
    if (dirfd == AT_FDCWD) {
        // Relative to the current working directory
        char cwd_link[64] = {0};
        snprintf(cwd_link, sizeof(cwd_link), "/proc/%d/cwd", pid);
        ssize_t bytes_read =
            readlink(cwd_link, base_path, sizeof(base_path) - 1);
        if (bytes_read < 0) {
            log_error("Failed to read current working directory for pid %d: %s",
                      pid, strerror(errno));
            return -1; // Failed to read current working directory
        }
    } else {
        // Relative to the path of dirfd
        const char *cached_path = fd_cache_get(dirfd);
        if (!cached_path) {
            return -1;
        }
        snprintf(base_path, sizeof(base_path), "%s", cached_path);
    }

    // Combine the base path and the relative path
    int n = snprintf(out, outsz, "%s/%s", base_path, rel_path);
    if (n < 0 || (size_t)n >= outsz) {
        log_error("Failed to resolve absolute path: base_path=%s, rel_path=%s, "
                  "outsz=%zu, n=%d (Buffer too small?)",
                  base_path, rel_path, outsz, n);
        return -1;
    }

    return 0; // Success
}
