#include "bw_misc_utils.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

namespace util {

ssize_t read_file(const char *path, char *buf, size_t size)
{
  size_t ix = 0;
  ssize_t sz = size-1;
  int fd = ::open(path, O_RDONLY);
  if (fd < 0) {
    goto error;
  }
  while (size > ix) {
    sz = ::read(fd, &buf[ix], size - ix);
    if (sz <= 0) {
      if (sz == 0) {
        break;
      }
      if (errno == EINTR) {
        continue;
      }
      goto error;
    }
    ix += sz;
  }
  buf[ix] = '\0';
  close(fd);
  return ix;

error: {
    int saved_errno = errno;
    if (fd >= 0) {
      close(fd);
    }
    if (saved_errno) {
      return -saved_errno;
    }
    else {
      return -EINVAL;
    }
  }
}

} // ns util
