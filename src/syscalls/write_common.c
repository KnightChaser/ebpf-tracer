// src/syscalls/write_common.c
#define _GNU_SOURCE
#include "write_common.h"
#include "../syscalls/syscalls.h"
#include "../utils/logger.h"
#include "../utils/remote_bytes.h"
#include "handlers/handle_write.h"
#include "hashmap.h"
#include <stdlib.h>
#include <string.h>

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
    // TODO: Later, add pwrite64, writev, pwritev, etc.
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

    // NOTE: For now, we don't store pending writes in a hashmap.
    switch (e->syscall_nr) {
    case SYS_write:
        handle_write_enter(pid, e, &wa);
        break;
    default:
        handle_sys_enter_default(pid, e);
        break;
    }

    if (wa.count > 0) {
        dump_remote_bytes(pid, (void *)wa.buf, wa.count, wa.count);
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
    if (!pending_writes_map) {
        handle_sys_exit_default(pid, e);
        return;
    }

    // NOTE: For now, there is no stashed data to retrieve.
    switch (e->syscall_nr) {
    case SYS_write:
        handle_write_exit(pid, e);
        break;
    default:
        handle_sys_exit_default(pid, e);
        break;
    }
}
