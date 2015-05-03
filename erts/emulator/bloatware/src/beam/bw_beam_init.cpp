#include "bw_beam_init.h"
#include "bw_port.h"
//#include "bw_printf.h"
#include "bw_process.h"
#include "bw_sys.h"

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <signal.h>

namespace erl {

static void init_break_handler()
{
  sys::set_signal(SIGINT, sys::request_break);
  sys::set_signal(SIGUSR1, sys::user_signal1);
#ifdef QUANTIFY
  sys::set_signal(SIGUSR2, sys::user_signal2);
#endif
  sys::set_signal(SIGQUIT, sys::do_quit);
}

int start(int argc, const char *argv[])
{
  size_t proc_tab_sz = erts::DEFAULT_MAX_PROCESSES;
  size_t port_tab_sz = erts::DEFAULT_MAX_PORTS;

  // TODO: parsing command line

  const bool ignore_break = false;  // +Bi
  Erts::g_replace_intr = false;  // +Bc
  const bool have_break_handler = true; // +Bd
  if (ignore_break) {
    //erts::set_ignore_break();
  } else if (have_break_handler) {
    init_break_handler();
  }

  if (Erts::g_replace_intr) {
    //erts::replace_intr();
  }

  return 0;
}


static void BW_NORETURN
exit_vv(int32_t n, int32_t flush_async, const char *fmt, va_list args1,
            va_list args2)
{
  uint32_t an;

  // TODO
  //system_cleanup(flush_async);

  // TODO
  //save_statistics();

  if (n < 0) {
    an = -(uint32_t)n;
  } else {
    an = n;
  }

  // TODO
  //if (erts_mtrace_enabled) {
  //  erts_mtrace_exit((uint32_t) an);
  //}

  // Produce an Erlang core dump if error
  if (((n > 0 && Erts::g_no_crash_dump == 0) || n == erts::DUMP_EXIT)
      && Erts::g_initialized) {
    // TODO
    //erl::crash_dump_v((char *) nullptr, 0, fmt, args1);
  }

  if (fmt != nullptr && *fmt != '\0') {
    erl::error(fmt, args2);  /* Print error message. */
  }

  sys::tty_reset(n);

  if (n == erts::INTR_EXIT) {
    ::exit(0);
  } else if (n == erts::DUMP_EXIT) {
    ::exit(1);
  } else if (n > 0 || n == erts::ABORT_EXIT) {
    ::abort();
  }

  ::exit(an);
}

/* Exit without flushing async threads */
void BW_NORETURN exit(int n, const char *fmt, ...)
{
  va_list args1, args2;
  va_start(args1, fmt);
  va_start(args2, fmt);
  exit_vv(n, 0, fmt, args1, args2);
  va_end(args2);
  va_end(args1);
}

/* Exit after flushing async threads */
void BW_NORETURN exit_flush_async(int n, const char *fmt, ...)
{
  va_list args1, args2;
  va_start(args1, fmt);
  va_start(args2, fmt);
  exit_vv(n, 1, fmt, args1, args2);
  va_end(args2);
  va_end(args1);
}

// Common error printout function, all error messages that don't go to the
// error logger go through here.
void error(const char *fmt, va_list args)
{
  ::vfprintf(stderr, fmt, args);
}

} // ns erl
