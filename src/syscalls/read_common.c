// src/syscalls/read_common.c
#define _GNU_SOURCE
#include "read_common.h"
#include "../syscalls/syscalls.h"
#include "../utils/logger.h"
#include "../utils/remote_bytes.h"
#include "handlers/handle_pread64.h"
#include "handlers/handle_preadv.h"
#include "handlers/handle_read.h"
#include "handlers/handle_readv.h"
#include "hashmap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

/**
 * The item that will be stored int he hashmap.
 * It must contain the key (tid) and the value (args)
 */
struct pending_read_item {
    pid_t tid;
    struct read_args args;
};

/**
 * Compare function for the hashmap, required by hashmap.c
 * It compares items by their thread ID (tid).
 *
 * @param a Pointer to the first item.
 * @param b Pointer to the second item.
 * @param udata Unused user data pointer. (Required by hashmap API but unused
 * explicitly)
 */
static int pending_read_compare(const void *a, const void *b,
                                void *udata __attribute__((unused))) {
    const struct pending_read_item *item_a = a;
    const struct pending_read_item *item_b = b;

    return item_a->tid - item_b->tid;
}

/**
 * Hash function for the hashmap, required by hashmap.c
 * It hashes the thread ID (tid) of the pending read item.
 *
 * @param item Pointer to the item to hash.
 * @param seed0 First seed for hashing.
 * @param seed1 Second seed for hashing.
 * @return The computed hash value.
 */
static uint64_t pending_read_hash(const void *item, uint64_t seed0,
                                  uint64_t seed1) {
    const struct pending_read_item *p = item;
    return hashmap_sip(&p->tid, sizeof(p->tid), seed0, seed1);
}

// Global hashmap to store pending reads
static struct hashmap *pending_reads_map = NULL;

/**
 * Ensures that the pending reads hashmap is initialized.
 * If it is not initialized, it creates a new hashmap for pending reads.
 * (struct pending_read_item)
 */
static void ensure_map_initialized(void) {
    if (pending_reads_map == NULL) {
        pending_reads_map =
            hashmap_new(sizeof(struct pending_read_item), // size of the item
                        0,                                // initial capacity
                        0,                                // seed0
                        0,                                // seed1
                        pending_read_hash,                // hash function
                        pending_read_compare,             // compare function
                        NULL, NULL);
    }
}

/**
 * Cleans up the pending reads hashmap.
 * This will be called from the loader.c
 */
void read_common_cleanup(void) {
    if (pending_reads_map) {
        hashmap_free(pending_reads_map);
        pending_reads_map = NULL;
    }
}

/**
 * Fetches the arguments for read-like syscalls.
 * It currently encompasses: read(), pread64(), and readv().
 *
 * @param pid The process ID of the target process.
 * @param e The syscall event containing the arguments.
 * @param out Pointer to a read_args structure to fill with the arguments.
 * @return 0 on success, -1 on failure.
 */
int fetch_read_args(pid_t pid,                     // [in]
                    const struct syscall_event *e, // [in]
                    struct read_args *out          // [out]
) {
    memset(out, 0, sizeof(*out));
    out->fd = (int)e->enter.args[0];

    switch (e->syscall_nr) {

    case SYS_read: /* ssize_t read (fd, buf, count)   */
        out->buf = e->enter.args[1];
        out->count = e->enter.args[2];
        return 0;

    case SYS_pread64: /* ssize_t pread64(fd,buf,count,off) */
        out->buf = e->enter.args[1];
        out->count = e->enter.args[2];
        out->offset = (off_t)e->enter.args[3];
        return 0;

    case SYS_preadv: /* ssize_t preadv(fd,iov,iovcnt,off) */
        out->offset = (off_t)e->enter.args[3];
        // fallthrough

    case SYS_readv: /* ssize_t readv(fd,iov,iovcnt) */
        out->iovcnt = (int)e->enter.args[2];
        if (out->iovcnt <= 0) {
            log_error("readv/preadv with iovcnt=%d", out->iovcnt);
            return -1;
        }

        // WARNING: don't forget to free this later!
        out->iov = calloc(out->iovcnt, sizeof(struct iovec));
        if (!out->iov) {
            perror("calloc");
            return -1;
        }

        // copy the remote iovec array
        {
            struct iovec liov = {.iov_base = out->iov,
                                 .iov_len = sizeof(struct iovec) * out->iovcnt};
            struct iovec riov = {.iov_base = (void *)e->enter.args[1],
                                 .iov_len = liov.iov_len};

            if (process_vm_readv(pid, &liov, 1, &riov, 1, 0) < 0) {
                free(out->iov);
                out->iov = NULL;
                return -1;
            }
        }

        // optional: compute total bytes requested
        size_t total = 0;
        for (int i = 0; i < out->iovcnt; ++i) {
            total += out->iov[i].iov_len;
        }
        out->count = total;

        return 0;

    default:
        log_error("Unhandled read-like syscall %ld in fetch_read_args",
                  e->syscall_nr);
        return -1;
    }
}

/**
 * Dispatches the syscall enter event for read-like syscalls.
 * It calls the appropriate handler based on the syscall number.
 *
 * @param pid The process ID of the target process.
 * @param e The syscall event containing the arguments.
 */
void read_enter_dispatch(pid_t pid, const struct syscall_event *e) {
    // NOTE: Ensure the hashmap is well initialized before using it.
    ensure_map_initialized();

    struct read_args ra;
    if (fetch_read_args(pid, e, &ra) != 0) {
        // If fetching fails, we can't process this system call with our
        // handlers.
        handle_sys_enter_default(pid, e);
        return;
    }

    switch (e->syscall_nr) {
    case SYS_read:
        handle_read_enter(pid, e, &ra);
        break;
    case SYS_pread64:
        handle_pread64_enter(pid, e, &ra);
        break;
    case SYS_readv:
        handle_readv_enter(pid, e, &ra);
        break;
    case SYS_preadv:
        handle_preadv_enter(pid, e, &ra);
        break;
    default:
        log_error("Unhandled syscall: expected either 'read', 'pread64', "
                  "'readv', or 'preadv', got %ld (enter_dispatch)",
                  e->syscall_nr);
        handle_sys_enter_default(pid, e);
        free(ra.iov); // WARNING: clean up if fetch allocated memory
        return;
    }

    // Stash the successfully fetched args into the hashmap
    hashmap_set(pending_reads_map,
                &(struct pending_read_item){.tid = pid, .args = ra});
}

/**
 * Dispatches the syscall exit event for read-like syscalls.
 * It calls the appropriate handler based on the syscall number.
 *
 * @param pid The process ID of the target process.
 * @param e The syscall event containing the arguments.
 */
void read_exit_dispatch(pid_t pid, const struct syscall_event *e) {
    if (!pending_reads_map) {
        handle_sys_exit_default(pid, e);
        return;
    }

    long n = e->exit.retval;

    // first, print the normal return info
    switch (e->syscall_nr) {
    case SYS_read:
        handle_read_exit(pid, e);
        break;
    case SYS_pread64:
        handle_pread64_exit(pid, e);
        break;
    case SYS_readv:
        handle_readv_exit(pid, e);
        break;
    case SYS_preadv:
        handle_preadv_exit(pid, e);
        break;
    default:
        handle_sys_exit_default(pid, e);
        break;
    }

    // Retrieve the stashed arguments using the thread ID.
    struct pending_read_item *item = (struct pending_read_item *)hashmap_get(
        pending_reads_map, &(struct pending_read_item){.tid = pid});
    if (!item) {
        // No stashed argument. This can happen if the corresponding enter event
        // has failed or we started tracing mid-syscall.
        // We can't dump data anymore, we are done.
        return;
    }

    struct read_args ra = item->args;

    // NOTE: Delete the entry from the map now that we're done with it
    hashmap_delete(pending_reads_map, &(struct pending_read_item){.tid = pid});

    // now dump the data if anything was read
    if (n > 0) {
        bool vectored =
            (e->syscall_nr == SYS_readv || e->syscall_nr == SYS_preadv);
        if (vectored && ra.iov && ra.iovcnt > 0) {
            dump_remote_iov(pid, ra.iov, ra.iovcnt, (size_t)n, (size_t)n);
        } else if (!vectored && ra.buf) {
            dump_remote_bytes(pid, (void *)ra.buf, (size_t)n, (size_t)n);
        }
    }

    // free the iovec we malloc’d (safe even if NULL)
    free(ra.iov);
}
