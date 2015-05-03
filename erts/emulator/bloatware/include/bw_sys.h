#pragma once

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
} // ns sys

class Erts {
public:
  static std::atomic<bool> g_break_requested;
  static std::atomic<bool> g_no_crash_dump;
  static bool g_initialized;
  static bool g_replace_intr;

  static bool g_tty_using_oldshell;
  static struct ::termios g_tty_initial_mode;
};

namespace erts {

  // Some special erl::exit() codes
  const uint32_t INTR_EXIT  = INT_MIN;      // called from signal handler
  const uint32_t ABORT_EXIT = (INT_MIN + 1); // no crash dump; only abort()
  const uint32_t DUMP_EXIT  = (INT_MIN + 2); // crash dump; then exit()

} // ns erts

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
