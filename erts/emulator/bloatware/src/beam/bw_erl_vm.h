#pragma once

#include <stdint.h>
#include "erl_process.h"

namespace vm {
  // default (heap + stack) min size
  const uint32_t H_DEFAULT_SIZE  = 233;
  // default virtual (bin) heap min size (words)
  const uint32_t VH_DEFAULT_SIZE = 32768;

  const bool IS_FORCE_HEAP_FRAGS = false;

  // Swap process out after this number
  const size_t CONTEXT_REDS = 2000;
  // Max number of arguments allowed
  const size_t MAX_ARG = 255;
  // Max number of x(N) registers used
  const size_t MAX_REG = 1024;

  // Allocate heap memory, first on the ordinary heap;
  // failing that, in a heap fragment.
  inline Eterm *heap_alloc(Process *p, size_t sz, size_t xtra) {
    ASSERT(sz >= 0);
    ErtsHAllocLockCheck(p);
    return (Eterm *)(
        (vm::IS_FORCE_HEAP_FRAGS || (HEAP_LIMIT(p) - HEAP_TOP(p)) < sz)
          ? erts_heap_alloc(p,sz,xtra)
          : (INIT_HEAP_MEM(p,sz),
             HEAP_TOP(p) = HEAP_TOP(p) + (sz), HEAP_TOP(p) - sz)
      );
  }

  inline Eterm *heap_alloc(Process *P, size_t SZ) {
    return heap_alloc(P,SZ,0);
  }

  inline void heap_free(Process *p, Eterm *endp, Eterm *ptr) {
    if (ptr == endp) {
      return;
    } else if (HEAP_START(p) <= (ptr) && (ptr) < HEAP_TOP(p)) {
      HEAP_TOP(p) = (ptr);
    } else {
       erts_heap_frag_shrink(p, ptr);
    }
  }
} // end namespace vm

class Vm {
public:
  static uint32_t g_h_min_size;    // minimum (heap + stack)
  static uint32_t g_bin_vh_min_size;
};
