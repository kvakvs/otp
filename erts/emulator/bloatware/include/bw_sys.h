#pragma once

#include <cstring>
#include <stdint.h>
#include <climits>
#include <atomic>
#include <termios.h>

#define BW_NORETURN __attribute__((noreturn))

namespace sys {
  void set_signal(int sig, void(*fn)(int));
    void request_break(int /*signum*/);
    void user_signal1(int /*signum*/);
    void user_signal2(int /*signum*/);
    void do_quit(int /*signum*/);

  void tty_reset(int /*exit_code*/);

  template <typename T> void unused_result(T) {
  }

  void sig_notify(char c);

  void set_blocking(int fd);
  void set_nonblocking(int fd);

  inline size_t strlen(const char *s) { return std::strlen(s); }
  inline void strcpy(char *dst, const char *src) { std::strcpy(dst, src); }
} // ns sys

namespace erts {

  // Some special erl::exit() codes
  const uint32_t INTR_EXIT  = INT_MIN;      // called from signal handler
  const uint32_t ABORT_EXIT = (INT_MIN + 1); // no crash dump; only abort()
  const uint32_t DUMP_EXIT  = (INT_MIN + 2); // crash dump; then exit()

  const uint32_t MAX_BACKTRACE_SIZE = 64; // whatever just not too huge
  const uint32_t DEFAULT_BACKTRACE_SIZE = 8;

  // erts::DEFAULT_NO_ASYNC_THREADS
  // erts::ASYNC_THREAD_MIN_STACK_SIZE
} // ns erts

namespace erl {
  void BW_NORETURN assert_error(const char *expr, const char *func,
                                const char *file, int line);
} // ns erl

#define ERTS_INTERNAL_ERROR(What) \
  erl::exit(erts::ABORT_EXIT, "%s:%d:%s(): Internal error: %s\n", \
     __FILE__, __LINE__, __func__, What);
#define BW_ERTS_ASSERT(e) \
    ((void) ((e) ? 1 : (erl::assert_error(#e, __func__, __FILE__, __LINE__), 0)))

#ifdef DEBUG
#  define ASSERT(e) BW_ERTS_ASSERT(e)
#else
#  define ASSERT(e) ((void) 1)
#endif

class Erts {
public:
  //
  // VM global flags and state
  //
  static std::atomic<bool> g_break_requested;
  static std::atomic<bool> g_no_crash_dump;
  static bool g_initialized;
  static bool g_ignore_break;
  static bool g_replace_intr;
  static uint32_t g_backtrace_depth;
  static bool g_use_sender_punish;
  static int32_t g_compat_rel;

  //static uint32_t g_async_max_threads;
  //static uint32_t g_async_thread_suggested_stack_size;

  //
  // TTY (console)
  //
  static bool g_tty_using_oldshell;
  static struct ::termios g_tty_initial_mode;
};

// TODO: if no kernel poll - replace iofunc globs with direct calls
// to like erts_check_io_interrupt(1) etc
class IoFunc {
public:

  //static int (*select)(ErlDrvPort, ErlDrvEvent, int, int);
  //static int (*event)(ErlDrvPort, ErlDrvEvent, ErlDrvEventData);
  static void (*check_io_async_interrupt)();
  static void (*check_io_interrupt)(bool);
  //static void (*check_io_interrupt_tmd)(int, erts_short_time_t);
  static void (*check_io)(int);
  static uint32_t(*size)();
  //static Eterm(*info)(void *);
  //int (*check_io_debug)(ErtsCheckIoDebugInfo *);
};

class Termcap {
public:
  // Termcap functions.
  static int tgetent(const char *bp, const char *name);
  static int tgetnum(const char *cap);
  static int tgetflag(const char *cap);
  static char *tgetstr(const char *cap, char **buf);
  static char *tgoto(const char *cm, int col, int line);
  static int tputs(const char *cp, int affcnt, int (*outc)(int c));
};
