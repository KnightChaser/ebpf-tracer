// src/utils/remote_bytes.c
#define _GNU_SOURCE
#include "logger.h"
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

// NOTE: Show only up to 256 bytes of data for buffer in read() syscall
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
    if (to_read == 0) {
        log_error("nothing to read: (want=%zu, total=%zu)", want, total);
        return;
    }

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

/**
 * Reads and dumps data from a remote process's memory using an iovec.
 *
 * @param pid The PID of the remote process.
 * @param iov The iovec structure containing the remote memory addresses and
 * lengths.
 * @param iovcnt The number of elements in the iovec array.
 * @param max_total The maximum total bytes to read (for logging).
 * @param real_total The actual total bytes available to read (for logging).
 */
void dump_remote_iov(pid_t pid, const struct iovec *iov, int iovcnt,
                     size_t max_total, size_t real_total) {
    // NOTE: for brevity, we limit to DUMP_MAX
    size_t copied = 0;
    size_t want = MIN(max_total, DUMP_MAX);
    char *scratch = calloc(want, sizeof(char));
    if (!scratch) {
        log_error("Failed to allocate memory for remote iovec read buffer");
        return;
    }

    // Read data from the remote process's memory using the iovec.
    // However, we limit the total bytes read to DUMP_MAX.
    for (int i = 0; i < iovcnt && copied < want; i++) {
        size_t take = iov[i].iov_len;
        if (copied + take > want) {
            take = want - copied;
        }

        struct iovec loc = {
            .iov_base = scratch + copied,
            .iov_len = take,
        };
        struct iovec rem = {
            .iov_base = iov[i].iov_base,
            .iov_len = take,
        };

        ssize_t ret = process_vm_readv(pid, &loc, 1, &rem, 1, 0);
        if (ret < 0) {
            log_error("Failed to read remote memory at %p", rem.iov_base);
            break;
        }

        copied += ret;
    }

    if (!copied) {
        log_error("No data read from remote iovec");
        return;
    }

    log_kv("data", "first %zu byte%s%s", copied, copied == 1 ? "" : "s",
           real_total > copied ? " (truncated)" : "");
    log_hexdump(8, scratch, copied);

    free(scratch);
}
