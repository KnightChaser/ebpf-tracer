# ebpf-tracer
>
> (WIP)

### Note

1. Bring `vmlinux.h` to `/src` directory: `bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h`
2. Generate eBPF skeleton header file from `/src/controller.c` (eBPF kernel code) by the following code:

```sh
clang -g -O2 -target bpf -c src/controller.c -o src/controller.bpf.o
bpftool gen skeleton src/controller.bpf.o > src/controller.skel.h
```
3. Create the build directory with `meson setup builddir --native-file=clang.ini`
4. Inside the build directory (`/builddir`), compile the project with `meson compile`.
