// src/utils/path_utils.h
#pragma once
#include <sys/types.h>

int resolve_abs_path(pid_t pid, int dirfd, const char *rel_path, char *out,
                     size_t outsz);
