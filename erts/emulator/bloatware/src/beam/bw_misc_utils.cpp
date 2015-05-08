#include "bw_misc_utils.h"
#include "bw_sys.h"
#include "bw_beam_init.h"
#include "bw_erl_vm.h"

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

// Build a list of integers in some safe memory area
// Memory must be pre allocated prio call 2*len in size
// hp is a pointer to the "heap" pointer on return
// this_ pointer is updated to point after the list
Eterm buf_to_intlist(Eterm **hpp, const char *buf, size_t len, Eterm tail)
{
  Eterm *hp = *hpp;
  size_t i = len;

  while (i != 0) {
    --i;
    tail = CONS(hp, make_small((size_t)(uint8_t)buf[i]), tail);
    hp += 2;
  }

  *hpp = hp;
  return tail;
}
} // ns util

namespace erts {

EmuArgs g_saved_emu_args = {0};

void save_emu_args(int argc, const char *argv[])
{
#ifdef DEBUG
  char *end_ptr;
#endif
  EmuArg *ptr;
  int i;
  size_t arg_sz[100];
  size_t size;

  ASSERT(!g_saved_emu_args.argc);

  size = sizeof(EmuArg) * argc;

  for (i = 0; i < argc; i++) {
    size_t sz = sys::strlen(argv[i]);

    if (i < sizeof(arg_sz) / sizeof(arg_sz[0])) {
      arg_sz[i] = sz;
    }

    size += sz + 1;
  }

  ptr = new EmuArg[size];

  if (!ptr) {
    ERTS_INTERNAL_ERROR("malloc failed to allocate memory!");
  }

#ifdef DEBUG
  end_ptr = (char*)ptr + size;
#endif
  g_saved_emu_args.arg = ptr;
  ptr += argc;
  g_saved_emu_args.argc = argc;
  g_saved_emu_args.no_bytes = 0;

  for (i = 0; i < argc; i++) {
    size_t sz;

    if (i < sizeof(arg_sz) / sizeof(arg_sz[0])) {
      sz = arg_sz[i];
    } else {
      sz = sys::strlen(argv[i]);
    }

    g_saved_emu_args.arg[i].ptr = (char*)ptr;
    g_saved_emu_args.arg[i].sz = sz;
    g_saved_emu_args.no_bytes += sz;
    ptr += sz + 1;
    sys::strcpy(g_saved_emu_args.arg[i].ptr, argv[i]);
  }

  ASSERT(ptr == end_ptr);
}

Eterm get_emu_args(Process *c_p)
{
#ifdef DEBUG
  Eterm *end_hp;
#endif
  int i;
  size_t hsz;
  Eterm *hp, res;

  hsz = g_saved_emu_args.no_bytes * 2;
  hsz += g_saved_emu_args.argc * 2;

  hp = vm::heap_alloc(c_p, hsz);
#ifdef DEBUG
  end_hp = hp + hsz;
#endif
  res = NIL;

  for (i = g_saved_emu_args.argc - 1; i >= 0; i--) {
    Eterm arg = util::buf_to_intlist(&hp,
                               g_saved_emu_args.arg[i].ptr,
                               g_saved_emu_args.arg[i].sz,
                               NIL);
    res = CONS(hp, arg, res);
    hp += 2;
  }

  ASSERT(hp == end_hp);

  return res;
}


} // ns erts
