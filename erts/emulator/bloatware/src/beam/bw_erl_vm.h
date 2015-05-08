#pragma once

#include <stdint.h>

namespace vm {
// default (heap + stack) min size
const uint32_t H_DEFAULT_SIZE  = 233;
// default virtual (bin) heap min size (words)
const uint32_t VH_DEFAULT_SIZE = 32768;

const bool IS_FORCE_HEAP_FRAGS = false;

// Allocate heap memory, first on the ordinary heap;
// failing that, in a heap fragment.
//template <typename T> heap_alloc(Process *p, size_t sz, size_t xtra) {
//  ASSERT(sz >= 0);
//  ErtsHAllocLockCheck(p);
//  return (IS_FORCE_HEAP_FRAGS || (((HEAP_LIMIT(p) - HEAP_TOP(p)) < (sz)))
//          ? erts_heap_alloc((p),(sz),(xtra))
//          : (INIT_HEAP_MEM(p,sz),
//             HEAP_TOP(p) = HEAP_TOP(p) + (sz), HEAP_TOP(p) - (sz)));
//}
#define HAllocX(p, sz, xtra)                                  \
  (ASSERT((sz) >= 0),                       \
     ErtsHAllocLockCheck(p),                \
     (vm::IS_FORCE_HEAP_FRAGS || (((HEAP_LIMIT(p) - HEAP_TOP(p)) < (sz))) \
      ? erts_heap_alloc((p),(sz),(xtra))                              \
      : (INIT_HEAP_MEM(p,sz),                                 \
         HEAP_TOP(p) = HEAP_TOP(p) + (sz), HEAP_TOP(p) - (sz))))

#define HAlloc(P, SZ) HAllocX(P,SZ,0)

#define HRelease(p, endp, ptr)          \
  if ((ptr) == (endp)) {          \
     ;                \
  } else if (HEAP_START(p) <= (ptr) && (ptr) < HEAP_TOP(p)) { \
     HEAP_TOP(p) = (ptr);         \
  } else {              \
     erts_heap_frag_shrink(p, ptr);         \
  }

}

class Vm {
public:
  static uint32_t g_h_min_size;    // minimum (heap + stack)
  static uint32_t g_bin_vh_min_size;
};
