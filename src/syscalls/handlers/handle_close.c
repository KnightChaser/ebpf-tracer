// src/syscalls/handlers/handle_close.c
#define _GNU_SOURCE
#include "handle_close.h"
#include "../../controller.h"
#include "../../utils/logger.h"
#include "../fd_cache.h"
#include "hashmap.h"
#include <stdio.h>
#include <unistd.h>

/**
 * The item that will be stored int he hashmap.
 * It must contain the key (tid) and the value (fd)
 */
struct pending_close_item {
    pid_t tid;
    int fd;
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
static int pending_close_compare(const void *a, const void *b,
                                 void *udata __attribute__((unused))) {
    const struct pending_close_item *item_a = a;
    const struct pending_close_item *item_b = b;

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
static uint64_t pending_close_hash(const void *item, uint64_t seed0,
                                   uint64_t seed1) {
    const struct pending_close_item *p = item;
    return hashmap_sip(&p->tid, sizeof(p->tid), seed0, seed1);
}

// Global hash map to store pending close requests.
static struct hashmap *pending_close_map = NULL;
/**
 * Ensures that the pending reads hashmap is initialized.
 * If it is not initialized, it creates a new hashmap for pending reads.
 * (struct pending_close_item)
 */
static void ensure_map_initialized(void) {
    if (pending_close_map == NULL) {
        pending_close_map = hashmap_new(
            sizeof(struct pending_close_item), // size of the item
            0, 0, 0,                           // capacity and seeds
            pending_close_hash,                // hash function
            pending_close_compare,             // compare function
            NULL, // elfree (element free) - we will handle freeing manually
            NULL  // udata
        );
    }
}

/**
 * Cleans up the pending close hashmap.
 * This function should be called when the program is done with the hashmap.
 */
void handle_close_cleanup(void) {
    if (pending_close_map) {
        hashmap_free(pending_close_map);
        pending_close_map = NULL;
    }
}

/**
 * Handles the enter event of the close syscall.
 *
 * @param pid The process ID of the syscall event.
 * @param e The syscall event structure containing syscall information.
 */
void handle_close_enter(pid_t pid __attribute__((unused)),
                        const struct syscall_event *e) {
    ensure_map_initialized();

    int fd = (int)e->enter.args[0];

    char argbuf[16];
    snprintf(argbuf, sizeof(argbuf), "%d", fd);
    log_syscall(e->syscall_nr, e->enter.name, argbuf, /*retval*/ 0);

    const char *path = fd_cache_get(fd);
    if (path) {
        log_kv("path", "%s", path);
    }

    // Stash the fd in the hash map for the exit handler
    hashmap_set(pending_close_map,
                &(struct pending_close_item){.tid = pid, .fd = fd});
}

/**
 * Handles the exit event of the close syscall.
 *
 * @param pid The process ID of the syscall event.
 * @param e The syscall event structure containing syscall information.
 */
void handle_close_exit(pid_t pid __attribute__((unused)),
                       const struct syscall_event *e) {
    long ret = e->exit.retval;
    log_ret(ret, "close");

    // Retrieve the stashed fd from the hashmap
    struct pending_close_item *item = (struct pending_close_item *)hashmap_get(
        pending_close_map, &(struct pending_close_item){.tid = pid});

    if (item && ret >= 0) {
        // Only remove from a cache on a successful close() syscall
        // for the correct fd
        fd_cache_remove(item->fd);
    }
}
