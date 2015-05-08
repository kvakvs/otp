#pragma once

#include <stdint.h>
#include <stdlib.h>

namespace util {

ssize_t read_file(const char *path, char *buf, size_t size);

} // ns util

namespace erts {

typedef struct {
  size_t sz;
  char *ptr;
} EmuArg;

typedef struct {
  int argc;
  EmuArg *arg;
  size_t no_bytes;
} EmuArgs;

void save_emu_args(int argc, const char *argv[]);

} // ns erts
