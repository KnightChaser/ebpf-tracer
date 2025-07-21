# src/meson.build

# dependencies
bpftool = find_program('bpftool', required: true)
libbpf_dep = dependency('libbpf', required: true)

# 1. Generate vmlinlux.h using bpftool
vmlinux_h = custom_target(
  'vmlinux.h',
  output: 'vmlinux.h',
  command: [bpftool, 'btf', 'dump', 'file', '/sys/kernel/btf/vmlinux', 'format', 'c'],
  capture: true,
)

# 2. Compile the BPF C code into a BPF object file
bpf_obj = custom_target(
  'bpf_obj',
  input: 'controller.c',
  output: 'controller.bpf.o',
  command: [
    'clang',
    '-g',
    '-O2',
    '-target', 'bpf',
    '-c', '@INPUT@',
    '-o', '@OUTPUT@',
  ],
  depends: vmlinux_h,
)

# 3. Generate the BPF skeleton header from the object file
bpf_skel_h = custom_target(
  'bpf_skeleton',
  input: bpf_obj,
  output: 'controller.skel.h',
  command: [bpftool, 'gen', 'skeleton', '@INPUT@'],
  capture: true,
)

# 4. Compile the main user-space application
syscall_sources = files(
  'syscalls/default.c',
  'syscalls/openat.c',
)

executable(
  'ebpftracer',
  sources: ['main.c', 'loader.c', bpf_skel_h, syscall_sources],
  dependencies: libbpf_dep,
  install: true,
)
