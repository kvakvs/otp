project(erlang-otp)
cmake_minimum_required(VERSION 3.5)

#
# Settings. Enjoy editing this section.
#

set(CONF_HIPE 1)
set(CONF_DEBUG 1)

#
# Additional settings: Ported from original erts/configure
#
set(CONF_THREADS 1) # --enable-threads TODO: disable for bootstrap mode
set(CONF_ENABLE_LOCK_CHECK 1)
set(CONF_ENABLE_LOCK_COUNT 1)
set(CONF_DIRTY_SCHEDULERS 0)
# TODO: --disable-smp-require-native-atomics
set(CONF_KERNEL_POLL 1)
# TODO: SCTP: check decls, check funs, check record fields
# AC_CHECK_FUNCS([sctp_bindx sctp_peeloff sctp_getladdrs sctp_freeladdrs sctp_getpaddrs sctp_freepaddrs])

# TODO: Adds +native to erlc command line, TODO: affects HIPE_BOOTSTRAP_EBIN
set(CONF_NATIVE_LIBS 1)

# Enable for hipe, disable for Linux/Darwin.
# TODO: Run a fpe-test.c
set(CONF_FP_EXCEPTIONS 1)

# Only one option can be set to 1, if both are set -m32 is selected. If both are
# set to 0 then default for current platform is used
# TODO: /usr/bin/ld: i386 architecture of input file `erlexec.c.o' is incompatible with i386:x86-64 output
# TODO: Make ARCH/HIPE_ARCH in emulator/CMakeLists not conflict with these
set(CONF_M32 0)
set(CONF_M64 0)

set(CONF_VM_PROBES 1)

# TODO: Check for systemd funcs, set link libs. Use cmake-scripts/FindSystemd
#set(CONF_SYSTEMD 1)
set(CONF_SAVED_COMPILE_TIME 1)

# Enable this to force C++ compiler on all C files
# This allows to use modern C++ compiler and ease switch to C90/C++.
# Additionally C++ has better optimizer and opens nice possibilities to build
# on Windows/MSVC++ while still keeping 99% of source base in plain C.
# TODO: Fix errors, replace C++ keywords (new, this, default, export.. etc)
set(CONF_FORCE_CXX 0)

#
# End settings. Please don't edit beyond this line
#

get_filename_component(ERL_TOP ${CMAKE_SOURCE_DIR} ABSOLUTE)

file(READ ${ERL_TOP}/OTP_VERSION CONF_OTP_VERSION)
string(STRIP ${CONF_OTP_VERSION} CONF_OTP_VERSION)
string(SUBSTRING ${CONF_OTP_VERSION} 0 2 CONF_SYSTEM_VSN)


if(CONF_M32)
    set(CONF_M64 0)
    add_definitions(-m32)
    message(STATUS "-M32 build flag: enabled")
endif(CONF_M32)
if(CONF_M64)
    set(CONF_M32 0)
    add_definitions(-m64)
    message(STATUS "-M64 build flag: enabled")
endif(CONF_M64)

add_subdirectory("erts/emulator")
add_subdirectory("erts/epmd")
add_subdirectory("erts/etc")
