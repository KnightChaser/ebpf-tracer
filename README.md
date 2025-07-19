# ebpf-tracer
>
> (WIP)

### Note

1. Bring `vmlinux.h` to `/src` directory: `bpftool btf dump file /sys/kernel/btf/vmlinux > src/vmlinux.h`
2. Generate eBPF skeleton header file from `/src/controller.c` (eBPF kernel code)

```sh
clang -g -O2 -target bpf -c src/controller.c -o src/controller.bpf.o
bpftool gen skeleton src/controller.bpf.o > src/controller.h
```
