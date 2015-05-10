#pragma once

#include <stdarg.h>
#include "bw_sys.h"

namespace erl {

int start(int argc, const char *argv[]);
void BW_NORETURN exit(int n, const char *fmt, ...);
void BW_NORETURN exit_flush_async(int n, const char *fmt, ...);
void error(const char *fmt, va_list args);

} // ns erl

class Init {
public:
  static const char *g_program;
  static const char *g_init;
  static const char *g_boot;
  static int32_t     g_boot_argc;
  static char * const *g_boot_argv;

  static int32_t g_no_schedulers;
  static int32_t g_no_schedulers_online;
  #ifdef BW_ERTS_DIRTY_SCHEDULERS
  static int32_t g_no_dirty_cpu_schedulers;
  static int32_t g_no_dirty_cpu_schedulers_online;
  static int32_t g_no_dirty_io_schedulers;
  #endif
};
