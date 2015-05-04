#include "bw_cpu_topology.h"
#include "bw_beam_init.h"
#include "bw_erl_vm.h"
#include "bw_port.h"
#include "bw_process.h"
#include "bw_sys.h"

// OTP stuff
#include "erl_version.h"

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <signal.h>
#include <ctype.h>

const char *Init::g_program;
const char *Init::g_init = "init";
const char *Init::g_boot = "boot";
int        Init::g_boot_argc;
char * const *Init::g_boot_argv;

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

static int32_t this_rel_num()
{
  static int32_t this_rel = -1;

  if (this_rel < 1) {
    int32_t i;
    const char *this_rel_str = ERLANG_OTP_RELEASE;

    i = 0;

    while (this_rel_str[i] && !isdigit((int) this_rel_str[i])) {
      i++;
    }

    this_rel = ::atoi(&this_rel_str[i]);

    if (this_rel < 1) {
      erl::exit(-1, "Unexpected ERLANG_OTP_RELEASE format\n");
    }
  }

  return this_rel;
}

static int early_init(int *argc, const char *argv[])
{
  //erts::save_emu_args(*argc, argv);

//  erts_sched_compact_load = 1;
//  erts_printf_eterm_func = erts_printf_term;
//  erts_disable_tolerant_timeofday = 0;
//  display_items = 200;
//  erts_async_max_threads = ERTS_DEFAULT_NO_ASYNC_THREADS;
//  erts_async_thread_suggested_stack_size = ERTS_ASYNC_THREAD_MIN_STACK_SIZE;

  int32_t ncpu;
  int32_t ncpuonln;
  int32_t ncpuavail;
  int32_t max_reader_groups;
  cpu::pre_early_init_cpu_topology(&max_reader_groups,
                                   &ncpu,
                                   &ncpuonln,
                                   &ncpuavail);
  // if not smp: reset ncpu* to 1

  Init::g_program = argv[0];
  //erts_modified_timing_level = -1;
  Erts::g_compat_rel = this_rel_num();

  erts_sys_pre_init();
}

int start(int argc, const char *argv[])
{
  // mandatory startup things
  int ncpu = early_init(&argc, argv);

  size_t proc_tab_sz = erts::DEFAULT_MAX_PROCESSES;
  size_t port_tab_sz = erts::DEFAULT_MAX_PORTS;
  bool   port_tab_sz_ignore_files = false;

  // TODO: parsing command line
  int parsed_argc_count = 0;

  //Erts::g_ignore_break // +Bi
  //Erts::g_replace_intr // +Bc
  const bool have_break_handler = true; // +Bd
  if (Erts::g_ignore_break) {
    //erts::set_ignore_break();
  } else if (have_break_handler) {
    init_break_handler();
  }

  if (Erts::g_replace_intr) {
    //erts::replace_intr();
  }

  // skip parsed recognized args
  auto boot_argc = argc - parsed_argc_count;
  auto boot_argv = &argv[parsed_argc_count];

//  erl_init(ncpu,
//           proc_tab_sz,
//           0 /*legacy_proc_tab*/,
//           port_tab_sz,
//           port_tab_sz_ignore_files,
//           0 /*legacy_port_tab*/);

  /*
  load_preloaded();
  erts_end_staging_code_ix();
  erts_commit_staging_code_ix();

  erts_initialized = 1;

  erl_first_process_otp("otp_ring0", nullptr, 0, boot_argc, boot_argv);

  erts_start_schedulers();
  // Let system specific code decide what to do with the main thread...

  erts_sys_main_thread(); // May or may not return!
  set_main_stack_size();
  process_main();
  */

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
