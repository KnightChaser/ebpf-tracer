// src/syscalls/handlers/consts.h
#pragma once

#include "../utils.h"
#include <fcntl.h>

/**
 * Converts flags to a string representation.
 * This function takes a set of flags and converts them into a human-readable
 * string format, using a predefined array of flag names.
 */
static const struct flag_name open_flags[] = {
    {O_CREAT, "O_CREAT"},       {O_EXCL, "O_EXCL"},
    {O_NOCTTY, "O_NOCTTY"},     {O_TRUNC, "O_TRUNC"},
    {O_APPEND, "O_APPEND"},     {O_NONBLOCK, "O_NONBLOCK"},
    {O_DSYNC, "O_DSYNC"},       {O_SYNC, "O_SYNC"},
    {O_RSYNC, "O_RSYNC"},       {O_DIRECTORY, "O_DIRECTORY"},
    {O_NOFOLLOW, "O_NOFOLLOW"}, {O_CLOEXEC, "O_CLOEXEC"},
    // NOTE: may be added if needed >_<
};
