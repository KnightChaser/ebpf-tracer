// src/syscalls/utils.h
#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdio.h>

// Define a structure to hold flag names and their corresponding values
struct flag_name {
    long val;
    const char *name;
};

/**
 * Convert a set of flags to a human-readable string.
 *
 * @param flags The flags to convert.
 * @param table The table of flag names and values.
 * @param table_sz The size of the table.
 * @param buf The buffer to store the resulting string.
 * @param bufsz The size of the buffer.
 * @return A pointer to the buffer containing the string representation of the
 * flags.
 */
static inline char *flags_to_str(long flags, const struct flag_name *table,
                                 size_t table_sz, char *buf, size_t bufsz) {
    buf[0] = '\0';   // Initialize buffer
    size_t used = 0; // Number of bytes used in the buffer
    for (size_t i = 0; i < table_sz; i++) {
        if ((flags & table[i].val) == table[i].val && table[i].val != 0) {
            // Check if the flag is set
            size_t n = snprintf(buf + used, bufsz - used, "%s%s",
                                used ? "|" : "", table[i].name);
            if (n < 0 || n >= bufsz - used) {
                // Buffer overflow, stop processing
                break;
            }
            used += n;
            flags &= ~table[i].val; // Clear the flag to avoid duplication
        }
    }

    if (!used) {
        // If no flags were set, return "0"
        snprintf(buf, bufsz, "0");
    }

    return buf;
}

#endif // UTILS_H
