// src/loader.h

#ifndef LOADER_H
#define LOADER_H

#include <sys/types.h>

// Initializes the BPF loader and opens the BPF object file
// Returns 0 on success, or a negative error code on failure.
int bpf_loader_init(void);

// Loads the BPF object into the kernel, attaches probes,
// and sets the target PID to trace.
// Returns 0 on success, or a negative error code on failure.
int bpf_loader_load_and_attach(pid_t pid);

// Polls for events from the BPF ring buffer.
// It will block for a short time if no events are available.
int bpf_loader_poll_events(void);

// Detaches the BPF probes and cleans up resources.
void bpf_loader_cleanup(void);

#endif // LOADER_H
