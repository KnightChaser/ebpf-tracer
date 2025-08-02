# ebpf-tracer
>
> (WIP)

### Note

1. Generate `vmlinux.h` and eBPF skeleton header file from `/src/controller.c` (eBPF kernel code) by the following code:

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h
clang -g -O2 -target bpf -c src/controller.c -o src/controller.bpf.o
bpftool gen skeleton src/controller.bpf.o > src/controller.skel.h
```

2. Create the build directory with `meson setup builddir --native-file=clang.ini`
3. Inside the build directory (`/builddir`), compile the project with `meson compile`.
