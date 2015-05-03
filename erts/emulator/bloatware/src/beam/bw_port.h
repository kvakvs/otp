#pragma once

#include <stdlib.h>

namespace erts {

#ifndef __WIN32__
  const size_t DEFAULT_MAX_PORTS = (1 << 16);
#else
  //  Do not default to as many max ports on Windows as there are no os limits
  // to stop system from running amok. If allowed to go too high windows rarely
  // recovers from the errors and other OS processes can be effected.
  const size_t DEFAULT_MAX_PORTS = (1 << 13);
#endif // __WIN32__

} // ns erts
