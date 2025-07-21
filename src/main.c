// src/main.c
#define _POSIX_SOURCE
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
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path_to_program>\n", argv[0]);
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
        printf("Tracer: Child process stopped, attaching BPF program...\n");
        
        // Load and attach eBPF program
        bpf_loader_init();
        if (bpf_loader_load_and_attach(pid) != 0) {
            fprintf(stderr, "Failed to load and attach BPF program.\n");
            kill(pid, SIGKILL);
            bpf_loader_cleanup();
            return 1;
        }

        // Continue the child process after attaching the BPF program
        printf("Tracer: BPF program attached to the child process(PID: %d).\n",
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
        printf("Tracer: BPF program detached and resources cleaned up.\n");

        if (WIFEXITED(status)) {
            printf("Child process exited with status: %d\n",
                   WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("Child process killed by signal: %d\n", WTERMSIG(status));
        } else {
            printf("Child process did not exit normally.\n");
        }
    }

    return 0;
}
