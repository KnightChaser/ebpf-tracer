// src/syscalls/dup_common.c
#define _GNU_SOURCE
#include "dup_common.h"
#include "../utils/logger.h"
#include "fd_cache.h"
#include "hashmap.h"
#include <fcntl.h>
#include <string.h>

/**
 * The item that will be stored int he hashmap.
 * It must contain the key (tid) and the value (dup_args)
 */
struct pending_dup_item {
    pid_t tid;
    struct dup_args args;
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
static int pending_dup_compare(const void *a, const void *b,
                               void *udata __attribute__((unused))) {
    const struct pending_dup_item *item_a = a;
    const struct pending_dup_item *item_b = b;

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
static uint64_t pending_dup_hash(const void *item, uint64_t seed0,
                                 uint64_t seed1) {
    const struct pending_dup_item *p = item;
    return hashmap_sip(&p->tid, sizeof(p->tid), seed0, seed1);
}

// Global hash map to store pending dup requests.
static struct hashmap *pending_dup_map = NULL;

/**
 * Ensures that the pending reads hashmap is initialized.
 * If it is not initialized, it creates a new hashmap for pending reads.
 * (struct pending_dup_item)
 */
static void ensure_map_initialized(void) {
    if (pending_dup_map == NULL) {
        pending_dup_map = hashmap_new(
            sizeof(struct pending_dup_item), // size of the item
            0, 0, 0,                         // capacity and seeds
            pending_dup_hash,                // hash function
            pending_dup_compare,             // compare function
            NULL, // elfree (element free) - we will handle freeing manually
            NULL  // udata
        );
    }
}

/**
 * Cleans up the pending opens hashmap.
 * This function should be called when the program is done with the hashmap.
 */
void dup_common_cleanup(void) {
    if (pending_dup_map) {
        hashmap_free(pending_dup_map);
        pending_dup_map = NULL;
    }
}

/**
 * Fetches the arguments for dup/dup2/dup3 syscalls.
 *
 * @param pid The process ID of the syscall event.
 * @param e The syscall event containing the arguments.
 * @param o Output structure to fill with the syscall arguments.
 * @return 0 on success, -1 if the syscall is unsupported.
 */
int fetch_dup_args(pid_t pid __attribute__((unused)), // [in]
                   const struct syscall_event *e,     // [in]
                   struct dup_args *o                 // [out]
) {
    memset(o, 0, sizeof(*o));
    o->newfd = -1;
    o->flags = 0;

    switch (e->syscall_nr) {
    case SYS_dup:
        o->oldfd = (int)e->enter.args[0];
        return 0;
    case SYS_dup2:
        o->oldfd = e->enter.args[0];
        o->newfd = e->enter.args[1];
        return 0;
#ifdef SYS_dup3
    case SYS_dup3:
        o->oldfd = e->enter.args[0];
        o->newfd = e->enter.args[1];
        o->flags = e->enter.args[2];
        return 0;
#endif
    default:
        return -1; // Unsupported syscall
    }
}

/**
 * Dispatches the syscall enter events for dup/dup2/dup3 syscalls.
 * It fetches the arguments and stashes them in a hashmap for later use.
 *
 * @param pid The process ID of the syscall event.
 * @param e The syscall event containing the arguments.
 */
void stash_dup_enter(pid_t pid, const struct syscall_event *e) {
    ensure_map_initialized();

    struct dup_args args;
    if (fetch_dup_args(pid, e, &args) == 0) {
        hashmap_set(pending_dup_map, &(struct pending_dup_item){
                                         .tid = pid,
                                         .args = args,
                                     });
    }
}

/**
 * Dispatches the enter event for dup/dup2/dup3 syscalls.
 * Since dup system call copies the file descriptor,
 * their paths are the same. It updates the file descriptor cache
 * and prints the new file descriptor path, too.
 *
 * @param pid The process ID of the syscall event.
 * @param e The syscall event containing the arguments.
 */
void print_dup_exit(pid_t pid, const struct syscall_event *e) {
    long ret = e->exit.retval;
    log_ret(ret, "dup");

    if (ret >= 0) {
        // Retrieve the stashed arguments
        struct pending_dup_item *item =
            (struct pending_dup_item *)hashmap_delete(
                pending_dup_map, &(struct pending_dup_item){
                                     .tid = pid,
                                 });
        if (!item) {
            log_error("No pending dup item found for PID %d", pid);
            return;
        }

        // Cache the newfd with the same path
        const char *oldpath = fd_cache_get(item->args.oldfd);
        fd_cache_set((int)ret, oldpath);
    } else {
        log_error("dup failed with error: %s", strerror(-ret));
    }
}
