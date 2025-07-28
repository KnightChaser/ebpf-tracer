// src/utils/logger.h
#pragma once
#include <stdarg.h>
#include <stdbool.h>

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO,
    LOG_WARN,
    LOG_ERR,
    LOG_SYSCALL, // pretty print syscall line (number, name, arguments, retval)
} log_level_t;

// General logging functions
void log_debug(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_info(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_warn(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_error(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

// Special logging functions
void log_syscall(long num_syscall,     // syscall number
                 const char *name,     // syscall name
                 const char *args_fmt, // format string for arguments
                 long retval);         // return value

// Runtime knobs
void log_set_min_level(log_level_t level);
void log_enable_color(bool yes);
void log_set_quiet(bool yes);
