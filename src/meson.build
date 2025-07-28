# src/meson.build

# dependencies
libbpf_dep = dependency('libbpf', required: true)
skip_bpf = get_option('skip_bpf')

if skip_bpf
  # stub (for CI/CD or CodeQL which doesn't support eBPF)
  vmlinux_h = custom_target(
    'vmlinux.h',
    output: 'vmlinux.h',
    command: ['bash', '-c', 'echo "/* stub vmlinux.h */"'],
    capture: true,
  )

  bpf_obj = custom_target(
    'controller.bpf.o',
    output: 'controller.bpf.o',
    command: ['bash', '-c', 'true > controller.bpf.o'],
  )

  bpf_skel_h = custom_target(
    'controller.skel.h',
    input: bpf_obj,
    output: 'controller.skel.h',
    command: ['bash', '-c', 'echo "/* stub skel */"'],
    capture: true,
  )
else
  # real eBPF build
  bpftool = find_program('bpftool', required: true)

  # 1. Generate vmlinux.h using bpftool
  vmlinux_h = custom_target(
    'vmlinux.h',
    output: 'vmlinux.h',
    command: [bpftool, 'btf', 'dump', 'file', '/sys/kernel/btf/vmlinux', 'format', 'c'],
    capture: true,
  )

  # 2. Compile the BPF C code into a BPF object file
  bpf_obj = custom_target(
    'controller.bpf.o',
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
    'controller.skel.h',
    input: bpf_obj,
    output: 'controller.skel.h',
    command: [bpftool, 'gen', 'skeleton', '@INPUT@'],
    capture: true,
  )
endif

# 4. Compile the main user-space application
handlers = files(
  'syscalls/fd_cache.c',
  'syscalls/handlers/handle_close.c',
  'syscalls/handlers/handle_dup.c',
  'syscalls/handlers/handle_dup2.c',
  'syscalls/handlers/handle_dup3.c',
  'syscalls/handlers/handle_fcntl.c',
  'syscalls/handlers/handle_open.c',
  'syscalls/handlers/handle_openat.c',
  'syscalls/handlers/handle_openat2.c',
  'syscalls/handlers/handle_read.c',
)

syscall_sources = files(
  'syscalls/default.c',
  'syscalls/dup_common.c',
  'syscalls/dup_common.h',
  'syscalls/fd_cache.h',
  'syscalls/handlers/handle_close.h',
  'syscalls/handlers/handle_open.h',
  'syscalls/handlers/handle_openat.h',
  'syscalls/handlers/handle_openat2.h',
  'syscalls/open_common.c',
  'syscalls/open_common.h',
  'syscalls/read_common.c',
  'syscalls/read_common.h',
  'syscalls/utils.h',
) + handlers

common_sources = ['loader.c', 'syscall_table.c'] + syscall_sources

executable(
  'ebpftracer',
  sources: ['main.c', bpf_skel_h, common_sources],
  dependencies: libbpf_dep,
  install: true,
)
