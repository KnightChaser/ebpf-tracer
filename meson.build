# meson.build

project(
  'ebpftracer',
  'c',
  version: '0.1.0',
  default_options: [
    'c_std=c11',
    'warning_level=2',
  ],
)

add_project_arguments(
  '-D_POSIX_C_SOURCE=200809L',
  language: 'c',
)

subdir('src')
subdir('test')
