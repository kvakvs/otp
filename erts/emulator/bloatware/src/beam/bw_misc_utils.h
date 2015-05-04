#pragma once

#include <stdint.h>
#include <stdlib.h>

namespace util {

ssize_t read_file(const char *path, char *buf, size_t size);

} // ns util
