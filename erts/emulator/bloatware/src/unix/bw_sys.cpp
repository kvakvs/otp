#include "bw_sys.h"
#include "bw_beam_init.h"

#include <stdlib.h> // abort
#include <unistd.h> // write
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>


std::atomic<bool> Erts::g_break_requested(false);
std::atomic<bool> Erts::g_no_crash_dump(false);
bool Erts::g_initialized         = false;
bool Erts::g_tty_using_oldshell  = true;
bool Erts::g_ignore_break        = false;
bool Erts::g_replace_intr        = false; // erl::start command line parse
uint32_t Erts::g_backtrace_depth = erts::DEFAULT_BACKTRACE_SIZE;
bool Erts::g_use_sender_punish   = true;
int32_t Erts::g_compat_rel;

// set early so the break handler has access to initial mode
struct termios Erts::g_tty_initial_mode;

void (*IoFunc::check_io_async_interrupt)() = nullptr;
void (*IoFunc::check_io_interrupt)(bool) = nullptr;
void (*IoFunc::check_io)(int) = nullptr;
uint32_t(*IoFunc::size)() = nullptr;

namespace sys {

void set_signal(int sig, void (*fn)(int))
{
  struct ::sigaction act, oact;

  ::sigemptyset(&act.sa_mask);
  act.sa_flags = 0;
  act.sa_handler = fn;
  ::sigaction(sig, &act, &oact);
  //return (oact.sa_handler);
}

static void break_requested(void)
{
  // just set a flag - checked for and handled by scheduler threads
  // erts_check_io() (not signal handler).
#ifdef DEBUG
  fprintf(stderr, "break!\n");
#endif

  if (::Erts::g_break_requested) {
    erl::exit(erts::INTR_EXIT, "");
  }

  Erts::g_break_requested = true;
  IoFunc::check_io_interrupt(true); // Make sure we don't sleep in poll
}

// TODO: handler may have different signature
void request_break(int /*signum*/)
{
#ifdef ERTS_SMP
  sig_notify('I');
#else
  break_requested();
#endif
}

// TODO: handler may have different signature
void user_signal1(int /*signum*/)
{
#ifdef ERTS_SMP
  sig_notify('1');
#else
  //sigusr1_exit();
#endif
}

// TODO: handler may have different signature
void user_signal2(int /*signum*/)
{
#ifdef ERTS_SMP
  sig_notify('2');
#else
  //quantify_save_data();
#endif
}

static void quit_requested()
{
  erl::exit(erts::INTR_EXIT, "");
}

void do_quit(int /*signum*/)
{
#ifdef ERTS_SMP
  sig_notify('Q');
#else
  quit_requested();
#endif
}

// reset the terminal to the original settings on exit
void tty_reset(int /*exit_code*/)
{
  if (Erts::g_tty_using_oldshell && !Erts::g_replace_intr) {
    set_blocking(0);
  } else if (::isatty(0)) {
    ::tcsetattr(0, TCSANOW, &Erts::g_tty_initial_mode);
  }
}

class Sig {
public:
  static int notify_fds[2];
};
int Sig::notify_fds[2] = { -1, -1};

void sig_notify(char c)
{
  int res;

  do {
    // write() is async-signal safe (according to posix)
    res = ::write(Sig::notify_fds[1], &c, 1);
  } while (res < 0 && errno == EINTR);

  if (res != 1) {
    static const char msg[] =
        "sys::smp::sig_notify(): Failed to notify signal-dispatcher thread "
        "about received signal";
    unused_result(::write(2, msg, sizeof(msg)));
    ::abort();
  }
}

void set_blocking(int fd)
{
  ::fcntl((fd), F_SETFL, ::fcntl((fd), F_GETFL, 0) & ~O_NDELAY);
}

void set_nonblocking(int fd)
{
  ::fcntl((fd), F_SETFL, ::fcntl((fd), F_GETFL, 0) | O_NDELAY);
}

} // ns sys

void erl::assert_error(const char *expr, const char *func, const char *file, int line)
{
  ::fflush(stdout);
  ::fprintf(stderr, "%s:%d:%s() Assertion failed: %s\n",
            file, line, func, expr);
  ::fflush(stderr);
#if !defined(ERTS_SMP) && 0

  /* Writing a crashdump from a failed assertion when smp support
   * is enabled almost a guaranteed deadlocking, don't even bother.
   *
   * It could maybe be useful (but I'm not convinced) to write the
   * crashdump if smp support is disabled...
   */
  if (Erts::g_initialized) {
    // TODO
    // erl::crash_dump(file, line, "Assertion failed: %s\n", expr);
  }

#endif
  ::abort();
}
