// src/main.c
#define _POSIX_SOURCE
#include "./utils/logger.h"
#include "loader.h"
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

// A helper function for fotal errors
void fatal(const char *message) {
    perror(message);
    exit(1);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        log_error("Usage: %s <prog> [args...]", argv[0]);
        return 1;
    }

    const char *program_to_run = argv[1];
    pid_t pid = fork();

    if (pid == -1) {
        fatal("fork failed");
    }

    if (pid == 0) {
        // NOTE: Child process

        // Redirect stdout and stderr to /dev/null
        int fd = open("/dev/null", O_WRONLY);
        if (fd == -1) {
            fatal("open /dev/null failed");
        }
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        close(fd);

        // Tell the parent that we are ready and stop ourselves.
        // The parent will then attach the BPF program to us,
        // and send SIGCONT to continue us.
        kill(getpid(), SIGSTOP);

        // Continue...
        execvp(program_to_run, &argv[1]);

        // If execve returns, it means there was an error.
        fatal("execve failed");
    } else {
        // NOTE: Parent process

        // Wait for the child process to stop
        int status;
        waitpid(pid, &status, WUNTRACED);
        log_info(
            "Tracer: Child process (PID: %d) stopped, attaching BPF program...",
            pid);

        // Load and attach eBPF program
        bpf_loader_init();
        if (bpf_loader_load_and_attach(pid) != 0) {
            log_error("Failed to load and attach BPF program.");
            kill(pid, SIGKILL);
            bpf_loader_cleanup();
            return 1;
        }

        // Continue the child process after attaching the BPF program
        log_info("Tracer: BPF program attached to the child process (PID: %d).",
                 pid);
        kill(pid, SIGCONT);

        // Get the trace log
        printf("-------------- Syscall Trace ---------------\n");
        while (waitpid(pid, &status, WNOHANG) == 0) {
            bpf_loader_poll_events();
        }
        printf("\n------------ Syscall Trace Ended ------------\n");

        // Clean up resources
        bpf_loader_cleanup();
        log_info("Tracer: Child process (PID: %d) exited, resource cleaned up",
                 pid);

        if (WIFEXITED(status)) {
            log_info("Child process exited with status: %d",
                     WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            log_info("Child process killed by signal: %d", WTERMSIG(status));
        } else if (WIFSTOPPED(status)) {
            log_info("Child process stopped by signal: %d", WSTOPSIG(status));
        } else {
            log_error("Child process exited with unknown status: %d", status);
        }
    }

    return 0;
}
