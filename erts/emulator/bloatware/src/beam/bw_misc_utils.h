#pragma once

#include "bw_types.h"

#include <stdint.h>
#include <stdlib.h>

#include "erl_process.h"

namespace util {

ssize_t read_file(const char *path, char *buf, size_t size);
Eterm buf_to_intlist(Eterm **hpp, const char *buf, size_t len, Eterm tail);

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
Eterm get_emu_args(Process *c_p);

} // ns erts
