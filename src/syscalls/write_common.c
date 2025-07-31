// src/syscalls/write_common.c
#define _GNU_SOURCE
#include "write_common.h"
#include "../syscalls/syscalls.h"
#include "../utils/logger.h"
#include "../utils/remote_bytes.h"
#include "handlers/handle_pwrite64.h"
#include "handlers/handle_pwritev.h"
#include "handlers/handle_write.h"
#include "handlers/handle_writev.h"
#include "hashmap.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

/**
 * NOTE: In this write_common file, we handle the common logic for
 * the following system calls:
 * - write()
 * - pwrite64()
 * - writev()
 * - pwritev()
 * However, for write() and pwrite64() system calls receive the buffer
 * itself as a parameter. So, its contents are valid and ready to be
 * read by the kernel at sys_enter. Therefore, we can and we should
 * read and dump the contents of the buffer at sys_enter.
 * We have all the information we need: the remote address(buffer) and
 * the length(count). At sys_exit, the only new piece of information
 * its the return value. We don't need any information from the enter event
 * to interpret the exit event. So, for write() and pwrite64()
 * we don't need to store any information in the hashmap.
 * However, for writev() and pwritev() system calls, the buffer is
 * passed as an array of iovecs. And the return value at the exit indicates
 * how many bytes were written. Such values may be differ(less) than requested
 * at the enter. So, we need to store the information at sys_enter and
 * retrieve it at sys_exit. For that, we will use a hashmap to store the
 * pending writes of writev() and pwritev() syscalls. (only)
 */

/**
 * The item that will be stored int he hashmap.
 * It must contain the key (tid) and the value (write_args)
 */
struct pending_write_item {
    pid_t tid;
    struct write_args args;
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
static int pending_write_compare(const void *a, const void *b,
                                 void *udata __attribute__((unused))) {
    const struct pending_write_item *item_a = a;
    const struct pending_write_item *item_b = b;

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
static uint64_t pending_write_hash(const void *item, uint64_t seed0,
                                   uint64_t seed1) {
    const struct pending_write_item *p = item;
    return hashmap_sip(&p->tid, sizeof(p->tid), seed0, seed1);
}

// Global hashmap to store pending reads
static struct hashmap *pending_writes_map = NULL;

/**
 * Ensures that the pending reads hashmap is initialized.
 * If it is not initialized, it creates a new hashmap for pending reads.
 * (struct pending_read_item)
 */
static void ensure_map_initialized(void) {
    if (pending_writes_map == NULL) {
        pending_writes_map =
            hashmap_new(sizeof(struct pending_write_item), // size of the item
                        0,                                 // initial capacity
                        0,                                 // seed0
                        0,                                 // seed1
                        pending_write_hash,                // hash function
                        pending_write_compare,             // compare function
                        NULL, NULL);
    }
}

/**
 * Cleans up the pending reads hashmap.
 * This will be called from the loader.c
 */
void write_common_cleanup(void) {
    if (pending_writes_map) {
        // args.iov allocates memory for the iovecs, so we must clean it up.
        size_t iter = 0;
        void *item;
        while (hashmap_iter(pending_writes_map, &iter, &item)) {
            struct pending_write_item *p_item = item;
            free(p_item->args.iov);
        }
        hashmap_free(pending_writes_map);
        pending_writes_map = NULL;
    }
}

/**
 * Fetches the arguments for read-like syscalls.
 * It calls the appropriate handler based on the syscall number.
 *
 * @param pid The process ID of the target process.
 * @param e The syscall event containing the arguments.
 * @return 0 on success, -1 on error.
 */
int fetch_write_args(pid_t pid __attribute__((unused)), // [in]
                     const struct syscall_event *e,     // [in]
                     struct write_args *out             // [out]
) {
    memset(out, 0, sizeof(*out));
    out->fd = (int)e->enter.args[0];

    switch (e->syscall_nr) {
    case SYS_write:
        // ssize_t write(int fd, const void *buf, size_t count);
        out->buf = (unsigned long)e->enter.args[1];
        out->count = (size_t)e->enter.args[2];
        return 0;

    case SYS_pwrite64:
        // ssize_t pwrite64(int fd, const void *buf, size_t count,
        //                  off64_t offset);
        out->buf = (unsigned long)e->enter.args[1];
        out->count = (size_t)e->enter.args[2];
        out->offset = (off_t)e->enter.args[3];
        return 0;

    case SYS_pwritev:
        // ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt
        //                 off_t offset);
        out->offset = (off_t)e->enter.args[3];
        // fallthrough

    case SYS_writev:
        // ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
        out->iovcnt = (int)e->enter.args[2];
        if (out->iovcnt <= 0) {
            // NOTE: Not necessarily an error, it can be technically valid to
            // have 0 iovecs. But we cannot proceed with 0 iovecs.
            return 0;
        }

        // Create the iovec array to hold the iovecs of the vectored write
        // syscalls. (later store data into the hashmap...)
        out->iov = calloc(out->iovcnt, sizeof(struct iovec));
        if (!out->iov) {
            log_error("Failed to allocate memory for iovecs in syscall %ld: %s",
                      e->syscall_nr, strerror(errno));
            return -1;
        }

        struct iovec liov = {
            .iov_base = out->iov,
            .iov_len = sizeof(struct iovec) * out->iovcnt,
        };

        struct iovec riov = {.iov_base = (void *)e->enter.args[1],
                             .iov_len = sizeof(struct iovec) * out->iovcnt};

        if (process_vm_readv(pid, &liov, 1, &riov, 1, 0) < 0) {
            log_error("Failed to read iovecs for syscall %ld: %s",
                      e->syscall_nr, strerror(errno));
            free(out->iov);
            out->iov = NULL;
            return -1;
        }

        size_t total = 0;
        for (int i = 0; i < out->iovcnt; i++) {
            total += out->iov[i].iov_len;
        }
        out->count = total;
        return 0;

    default:
        log_error("Unhandled write-like syscall %ld in fetch_write_args",
                  e->syscall_nr);
        return -1;
    }
}

/**
 * Dispatches the syscall enter event for write-like syscalls.
 * It calls the appropriate handler based on the syscall number.
 *
 * @param pid The process ID of the target process.
 * @param e The syscall event containing the arguments.
 */
void write_enter_dispatch(pid_t pid, const struct syscall_event *e) {
    // NOTE: Ensure the hashmap is well initialized before using it.
    ensure_map_initialized();

    struct write_args wa;
    if (fetch_write_args(pid, e, &wa) != 0) {
        handle_sys_enter_default(pid, e);
        return;
    }

    // Flag to check if the current syscall is vectored
    bool vectored =
        (e->syscall_nr == SYS_writev || e->syscall_nr == SYS_pwritev);

    switch (e->syscall_nr) {
    case SYS_write:
        handle_write_enter(pid, e, &wa);
        break;
    case SYS_pwrite64:
        handle_pwrite64_enter(pid, e, &wa);
        break;
    case SYS_writev:
        handle_writev_enter(pid, e, &wa);
        break;
    case SYS_pwritev:
        handle_pwritev_enter(pid, e, &wa);
        break;
    default:
        handle_sys_enter_default(pid, e);
        if (vectored) {
            // vectored write syscalls require the iovecs to be copied
            free(wa.iov);
        }
        break;
    }

    if (vectored) {
        // For vectored writes, stash the arguments into the hashmap,
        // including the copied iovec array
        hashmap_set(pending_writes_map, &(struct pending_write_item){
                                            .tid = pid,
                                            .args = wa,
                                        });
    } else {
        if (wa.count > 0) {
            dump_remote_bytes(pid, (void *)wa.buf, wa.count, wa.count);
        }
    }
}

/**
 * Dispatches the syscall exit event for write-like syscalls.
 * It calls the appropriate handler based on the syscall number.
 *
 * @param pid The process ID of the target process.
 * @param e The syscall event containing the arguments.
 */
void write_exit_dispatch(pid_t pid, const struct syscall_event *e) {
    bool vectored =
        (e->syscall_nr == SYS_writev || e->syscall_nr == SYS_pwritev);
    long n = e->exit.retval;

    switch (e->syscall_nr) {
    case SYS_write:
        handle_write_exit(pid, e);
        break;
    case SYS_pwrite64:
        handle_pwrite64_exit(pid, e);
        break;
    case SYS_writev:
        handle_writev_exit(pid, e);
        break;
    case SYS_pwritev:
        handle_pwritev_exit(pid, e);
        break;
    default:
        handle_sys_exit_default(pid, e);
        break;
    }

    if (vectored) {
        // For vectored writes, we need to retrieve the arguments from the
        // hashmap and dump the written bytes.
        struct pending_write_item *item =
            (struct pending_write_item *)hashmap_get(
                pending_writes_map, &(struct pending_write_item){.tid = pid});
        if (item) {
            if (n > 0) {
                // If bytes were actually written, dump the bytes now!
                dump_remote_iov(pid, item->args.iov, item->args.iovcnt,
                                (size_t)n, item->args.count);
            }
            free(item->args.iov);
        }
    }
}
