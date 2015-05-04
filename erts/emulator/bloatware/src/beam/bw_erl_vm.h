#pragma once

#include <stdint.h>

namespace vm {
// default (heap + stack) min size
const uint32_t H_DEFAULT_SIZE  = 233;
// default virtual (bin) heap min size (words)
const uint32_t VH_DEFAULT_SIZE = 32768;
}

class Vm {
public:
  static uint32_t g_h_min_size;    // minimum (heap + stack)
  static uint32_t g_bin_vh_min_size;
};
