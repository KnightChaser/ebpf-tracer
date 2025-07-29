// src/utils/remote_bytes.c
#define _GNU_SOURCE
#include "remote_bytes.h"
#include "logger.h"
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

// NOTE: Show only up to 64 bytes of data for buffer in read() syscall
static const size_t DUMP_MAX = 256;

#define MIN(a, b) ((a) < (b) ? (a) : (b))

/**
 * Reads and dumps a specified number of bytes from a remote process's memory.
 *
 * @param pid The PID of the remote process.
 * @param remote_addr The address in the remote process's memory to read from.
 * @param want The number of bytes to read.
 * @param total The total number of bytes available to read (for logging).
 */
void dump_remote_bytes(pid_t pid, const void *remote_addr, size_t want,
                       size_t total) {
    // NOTE: for brevity, we limit to DUMP_MAX
    size_t to_read = MIN(want, DUMP_MAX);
    char *buf = calloc(to_read, sizeof(char));
    if (!buf) {
        log_error("Failed to allocate memory for remote read buffer");
        return;
    }

    struct iovec local = {
        .iov_base = buf,    // Local buffer to read into
        .iov_len = to_read, // Number of bytes to read
    };
    struct iovec remote = {
        .iov_base = (void *)remote_addr, // Remote address to read from
        .iov_len = to_read,              // Number of bytes to read from remote
    };

    if (process_vm_readv(pid, &local, 1, &remote, 1, 0) == (ssize_t)to_read) {
        buf[to_read] = '\0'; // Null-terminate the buffer for printing
        log_kv("data", "first (up to) %zu byte%s%s", /* headline */
               to_read, to_read == 1 ? "" : "s",
               total > to_read ? " (truncated)" : "");
        log_hexdump(8, buf, to_read);
    } else {
        log_error("Failed to read remote memory at %p", remote_addr);
    }

    free(buf);
}
