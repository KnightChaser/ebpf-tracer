# ebpftracer

> A simple `strace`-like syscall tracer for Linux, built with C and eBPF.

This project is a personal exploration into Linux systems programming and eBPF(extended Berkeley Packet Filter). It is not intended to be a feature-complete or production-grade replacement for tools like `strace` (Of course). Side note, I was incredibly motivated by [SH4DY's "Writing a system call tracer using eBPF" article](https://sh4dy.com/2024/08/03/beetracer/) and [its public source code on GitHub](https://github.com/0xSh4dy/bee_tracer) while making this project!

| Screenshot #1 | Screenshot #2 |
|--------|--------|
| <img width="600" height="400" alt="image" src="https://github.com/user-attachments/assets/ef9e7417-fd91-4e26-977b-51783531fceb" /> | <img width="600" height="400" alt="image" src="https://github.com/user-attachments/assets/cf352df0-0f46-4864-bfa0-3309fbeea431" /> |


## Purpose & Features

The goal of this project is to intercept and log system calls made by a specified program. It uses eBPF tracepoints (`raw_syscalls:sys_enter` and `raw_syscalls:sys_exit`) to capture events efficiently at the kernel level and sends them to a user-space C application for processing and printing.

- **Core Functionality**: Traces a target program and prints its system calls.
- **Technology**: Built entirely in C using `libbpf`, `clang`, and the Meson build system.
- **State Management**: Uses thread-safe hash maps to associate syscall correctly enter/exit events for complex I/O operations.
- **Detailed Output**:
  - Resolves file descriptor numbers to their absolute paths.
  - Dumps data for I/O syscalls like `read`, `write`, `readv`, and `writev`.
  - Resolves relative paths (e.g. `./file`) to their absolute paths (e.g. `/home/user/file`).

The tracer has dedicated handlers for the system calls planned in [my project's GitHub issue (#1)](https://github.com/KnightChaser/ebpftracer/issues/1). Other syscalls are not printed for simplicity.

## Building and Running

### Prerequisites

- A Linux system with a modern kernel that supports BTF (BSS Type Format).
- `clang` and `llvm` toolchain.
- `libbpf` development library.
- `bpftool` (to generate `vmlinux.h` header file).
- `meson` (C/C++ build system).

### Build Steps

1.  **Clone the repository (including submodules):**
    ```sh
    git clone --recurse-submodules https://github.com/KnightChaser/ebpftracer.git
    cd ebpf-tracer
    ```

2.  **Generate eBPF Artifacts:**
    The user-space program depends on a few kernel-specific headers that must be generated on the host machine.
    ```sh
    # Generate vmlinux.h for kernel type definitions
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h

    # Compile the eBPF C code and generate its user-space skeleton header
    clang -g -O2 -target bpf -c src/controller.c -o src/controller.bpf.o
    bpftool gen skeleton src/controller.bpf.o > src/controller.skel.h
    ```
    *Note: These generated files are specific to your kernel version and architecture and are not checked into version control.*

3.  **Configure and Compile with Meson:**
    ```sh
    meson setup builddir --native-file=clang.ini
    cd builddir
    meson compile
    ```
    This will create the `ebpftracer` executable in the `builddir`.

### Usage

Run the tracer by passing the program you want to trace as an argument, like `strace`.

```sh
# From the builddir directory
sudo ./src/ebpftracer /bin/ls -l /tmp
```
