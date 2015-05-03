#pragma once

#include <stdarg.h>

namespace erl {

int start(int argc, const char *argv[]);
void exit(int n, const char *fmt, ...);
void exit_flush_async(int n, const char *fmt, ...);
void error(const char *fmt, va_list args);

} // ns erl
