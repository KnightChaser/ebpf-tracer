// src/syscalls/open_common.c

#define _GNU_SOURCE
#include "open_common.h"
#include "../utils/logger.h"
#include "fd_cache.h"
#include "handlers/handle_open.h"
#include "handlers/handle_openat.h"
#include "handlers/handle_openat2.h"
#include "hashmap.h"
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

/**
 * The item that will be stored int he hashmap.
 * It must contain the key (tid) and the value (abs_path)
 */
struct pending_open_item {
    pid_t tid;
    char *abs_path;
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
static int pending_open_compare(const void *a, const void *b,
                                void *udata __attribute__((unused))) {
    const struct pending_open_item *item_a = a;
    const struct pending_open_item *item_b = b;

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
static uint64_t pending_open_hash(const void *item, uint64_t seed0,
                                  uint64_t seed1) {
    const struct pending_open_item *p = item;
    return hashmap_sip(&p->tid, sizeof(p->tid), seed0, seed1);
}

/**
 * Frees the memory allocated for a pending open item.
 * This function is called when the item is removed from the hashmap.
 *
 * @param item Pointer to the item to free.
 */
static void pending_open_item_free(void *item) {
    struct pending_open_item *p = item;
    free(p->abs_path);
}

// Global hash map to store pending open requests.
static struct hashmap *pending_opens_map = NULL;

/**
 * Ensures that the pending reads hashmap is initialized.
 * If it is not initialized, it creates a new hashmap for pending reads.
 * (struct pending_open_item)
 */
static void ensure_map_initialized(void) {
    if (pending_opens_map == NULL) {
        pending_opens_map = hashmap_new(
            sizeof(struct pending_open_item), // size of the item
            0, 0, 0,                          // capacity and seeds
            pending_open_hash,                // hash function
            pending_open_compare,             // compare function
            NULL, // elfree (element free) - we will handle freeing manually
            NULL  // udata
        );
    }
}

/**
 * Cleans up the pending opens hashmap.
 * This function should be called when the program is done with the hashmap.
 */
void open_common_cleanup(void) {
    if (pending_opens_map) {
        // Since hashmap contains string pointers with dynamically-allocated
        // memory pointers, we need to free them before freeing the hashmap
        // itself.
        size_t iter = 0;
        void *item;
        while (hashmap_iter(pending_opens_map, &iter, &item)) {
            pending_open_item_free(item);
        }

        hashmap_free(pending_opens_map);
        pending_opens_map = NULL;
    }
}

/**
 * Builds an absolute path from a relative path and the current working
 * directory of the specified process.
 *
 * @param pid The process ID of the traced process.
 * @param raw The raw relative path to convert.
 * @param out The buffer to store the resulting absolute path.
 * @param outsz The size of the output buffer.
 * @return 0 on success, -1 on error.
 */
static int build_abs_path(pid_t pid,       // [IN]
                          const char *raw, // [IN]
                          char *out,       // [OUT]
                          size_t outsz     // [IN]
) {
    if (raw[0] == '/') {
        // already an absolute path
        snprintf(out, outsz, "%s", raw);
        return 0;
    }

    // read /proc/<pid>/cwd to get the current working directory
    char cwd_link[64];
    char cwd[PATH_MAX];
    int n = snprintf(cwd_link, sizeof(cwd_link), "/proc/%d/cwd", pid);
    if (n < 0 || (size_t)n >= sizeof(cwd_link)) {
        return -1;
    }
    ssize_t m = readlink(cwd_link, cwd, sizeof(cwd) - 1);
    if (m < 0 || m >= (ssize_t)(sizeof(cwd) - 1)) {
        return -1;
    }
    cwd[m] = '\0';

    // combine them to build the full path
    if ((size_t)snprintf(out, outsz, "%s/%s", cwd, raw) >= outsz) {
        return -1;
    }
    return 0;
}

/**
 * Fetches the arguments for open/openat/openat2 syscalls from the
 * syscall_event structure.
 *
 * @param pid The process ID of the traced process.
 * @param e The syscall_event structure containing syscall information.
 * @param o Pointer to the open_args structure to fill with the arguments.
 * @return 0 on success, -1 on failure.
 */
int fetch_open_args(pid_t pid,                     // [in]
                    const struct syscall_event *e, // [in]
                    struct open_args *o            // [out]
) {
    memset(o, 0, sizeof(*o));
    o->mode = -1;
    o->resolve = -1;

    switch (e->syscall_nr) {
    case SYS_open:
        // int open(const char *pathname, int flags, ... /* mode_t mode */ );
        o->dirfd = AT_FDCWD;
        if (read_string_from_process(pid, e->enter.args[0], o->path,
                                     sizeof(o->path)) <= 0) {
            snprintf(o->path, sizeof(o->path), "0x%lx", e->enter.args[0]);
        }
        o->flags = e->enter.args[1];
        if (o->flags & (O_CREAT | O_TMPFILE)) {
            // If O_CREAT or O_TMPFILE is set, we also have a mode
            o->mode = e->enter.args[2];
        }
        return 0;

    case SYS_openat:
        // int openat(int dirfd, const char *pathname, int flags, ... /* mode_t
        // mode */ );
        o->dirfd = e->enter.args[0];
        if (read_string_from_process(pid, e->enter.args[1], o->path,
                                     sizeof(o->path)) <= 0) {
            snprintf(o->path, sizeof(o->path), "0x%lx", e->enter.args[1]);
        }
        o->flags = e->enter.args[2];
        if (o->flags & (O_CREAT | O_TMPFILE)) {
            // If O_CREAT or O_TMPFILE is set, we also have a mode
            o->mode = e->enter.args[3];
        }
        return 0;

    case SYS_openat2:
        // int openat2(int dirfd, const struct open_how *how, size_t how_size);
        o->dirfd = e->enter.args[0];
        if (read_string_from_process(pid, e->enter.args[1], o->path,
                                     sizeof(o->path)) <= 0) {
            snprintf(o->path, sizeof(o->path), "0x%lx", e->enter.args[1]);
        }

        // Read the open_how structure from the process memory
        struct open_how how;
        struct iovec liov = {
            .iov_base = &how,
            .iov_len = sizeof(how),
        };
        struct iovec riov = {
            .iov_base = (void *)e->enter.args[2],
            .iov_len = sizeof(how),
        };
        if (process_vm_readv(pid, &liov, 1, &riov, 1, 0) < 0) {
            return -1;
        }
        o->flags = how.flags;
        o->mode = how.mode;
        o->resolve = how.resolve;
        return 0;

    default:
        // Unsupported syscall, return an error
        return -1;
    }
}

/**
 * Prints the exit information for open/openat/openat2 syscalls.
 * This function is called when the syscall exits and prints the return value.
 *
 * @param pid The process ID of the traced process.
 * @param e The syscall_event structure containing syscall information.
 */
void print_open_exit(pid_t pid __attribute__((unused)),
                     const struct syscall_event *e) {
    long ret = e->exit.retval;
    if (ret >= 0) {
        // If the syscall succeeded, we can try to resolve the file descriptor
        const char *path = fd_cache_get((int)ret);
        log_kv("path", "%s", path ? path : "<unknown>");
    }
}

/**
 * Dispatches the syscall enter events for open/openat/openat2 syscalls.
 *
 * @param pid The process ID of the traced process.
 * @param e The syscall_event structure containing syscall information.
 */
void open_enter_dispatch(pid_t pid, const struct syscall_event *e) {
    // NOTE: ensure the pending opens map is initialized
    ensure_map_initialized();

    switch (e->syscall_nr) {
    case SYS_open:
        handle_open_enter(pid, e);
        break;
    case SYS_openat:
        handle_openat_enter(pid, e);
        break;
    case SYS_openat2:
        handle_openat2_enter(pid, e);
        break;
    default:
        log_error("Unhandled syscall: %ld, expected either open, openat, or "
                  "openat2",
                  e->syscall_nr);
        handle_sys_enter_default(pid, e);
        return;
    }

    // NOTE: resolve & stash the absolute path for the open*_exit
    struct open_args oa;
    char abs_path_buf[PATH_MAX];
    if (fetch_open_args(pid, e, &oa) == 0 &&
        build_abs_path(pid, oa.path, abs_path_buf, sizeof(abs_path_buf)) == 0) {
        // If the arguments are successfully fetched and built the absolute
        // path as well, stash it in the hashmap
        hashmap_set(pending_opens_map,
                    &(struct pending_open_item){
                        .tid = pid,
                        // WARNING: strdup() allocates memory that must be freed
                        .abs_path = strdup(abs_path_buf),
                    });
    }
    // If anything fails, we simply don't add to the map and
    // the exit handler will find nothing from the hashmap.
}

/**
 * Dispatches the syscall exit events for open/openat/openat2 syscalls.
 *
 * @param pid The process ID of the traced process.
 * @param e The syscall_event structure containing syscall information.
 */
void open_exit_dispatch(pid_t pid, const struct syscall_event *e) {

    // Retrieve the stashed path using the tid
    struct pending_open_item *item = (struct pending_open_item *)hashmap_delete(
        pending_opens_map, &(struct pending_open_item){.tid = pid});
    long ret = e->exit.retval;

    if (item) {
        // We found the stashed path. If the syscall succeeded, cache it.
        if (ret >= 0 && item->abs_path && *item->abs_path) {
            fd_cache_set((int)ret, item->abs_path);
        }
        pending_open_item_free(item);
    }

    // After setting the fd_cache(), we can handle the exit event.
    // It will eventually call print_open_exit() to print the exit
    // information.
    switch (e->syscall_nr) {
    case SYS_open:
        handle_open_exit(pid, e);
        break;
    case SYS_openat:
        handle_openat_exit(pid, e);
        break;
    case SYS_openat2:
        handle_openat2_exit(pid, e);
        break;
    default:
        log_error("Unhandled syscall: %ld, expected either open, openat, or "
                  "openat2",
                  e->syscall_nr);
        handle_sys_exit_default(pid, e);
    }
}
