// src/main.c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
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
        // Child process

        // Redirect stdout and stderr to /dev/null
        int fd = open("/dev/null", O_WRONLY);
        if (fd == -1) {
            fatal("open /dev/null failed");
        }
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        close(fd);

        // Replace child process with the target program.
        // assume NULL for the environment variables.
        execve(program_to_run, &argv[1], NULL);

        // If execve returns, it means there was an error.
        fatal("execve failed");
    } else {
        // Parent process

        printf("Tracer: Spawned child process with PID: %d\n", pid);
        printf("Tracer: Waiting for child process to finish...\n");

        int status;
        if (waitpid(pid, &status, 0) == -1) {
            fatal("waitpid failed");
        } else {
            if (WIFEXITED(status)) {
                printf("Tracer: Child process exited with status: %d\n",
                       WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                printf("Tracer: Child process was terminated by signal: %d\n",
                       WTERMSIG(status));
            } else {
                printf("Tracer: Child process ended abnormally.\n");
            }
        }
    }

    return 0;
}
