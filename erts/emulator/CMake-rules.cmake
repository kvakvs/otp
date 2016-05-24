set(CMAKE_CXX_STANDARD 14)

set(CURSES_NEED_NCURSES TRUE)
find_package(Curses)
if(NOT CURSES_FOUND)
    error("Curses are required")
endif()

include(FindPerl) # for generate scripts

set(BIN_DIR "${PROJECT_BINARY_DIR}")
set(SRC_DIR "${PROJECT_SOURCE_DIR}")

if(UNIX)
    set(OPSYS "unix") # unix ose or win32
elseif(WINDOWS)
    set(OPSYS "win32") # unix ose or win32
else()
    error("This OS support is not finished in CMakeLists")
endif()

# [threads, hipe, exec_alloc (on amd64), debug, purify, quantify, purecov,
# valgrind, gprof, smp, nofrag]
set(ENABLE_ALLOC_TYPE_VARS "exec_alloc ${OPSYS}")

set(ARCH "amd64") # amd64 x86 ppc ppc64 arm ultrasparc
#set(HIPE_ARCH "${ARCH}")

#
# Configure types, includes etc
#
include(CheckIncludeFiles)
include(CheckSymbolExists)
include(CheckFunctionExists)
include(CheckLibraryExists)
include(CheckTypeSize)
include(CheckCXXSourceCompiles)
function(configure_platf)
    check_include_files(sys/event.h     HAVE_SYS_EVENT_H)
    check_include_files(sys/epoll.h     HAVE_SYS_EPOLL_H)
    check_include_files(sys/devpoll.h   HAVE_SYS_DEVPOLL_H)
    check_include_files(sys/ioctl.h     HAVE_SYS_IOCTL_H)
    check_include_files(sys/ndir.h      HAVE_SYS_NDIR_H)
    check_include_files(sys/resource.h  HAVE_SYS_RESOURCE_H)
    check_include_files(sys/sdt.h       HAVE_SYS_SDT_H)
    check_include_files(sys/socket.h    HAVE_SYS_SOCKET_H)
    check_include_files(sys/socketio.h  HAVE_SYS_SOCKETIO_H)
    check_include_files(sys/sockio.h    HAVE_SYS_SOCKIO_H)
    check_include_files(sys/stat.h      HAVE_SYS_STAT_H)
    check_include_files(sys/stropts.h   HAVE_SYS_STROPTS_H)
    check_include_files(sys/sysctl.h    HAVE_SYS_SYSCTL_H)
    check_include_files(sys/time.h      HAVE_SYS_TIME_H)
    check_include_files(sys/timerfd.h   HAVE_SYS_TIMERFD_H)
    check_include_files(sys/types.h     HAVE_SYS_TYPES_H)
    check_include_files(sys/uio.h       HAVE_SYS_UIO_H)
    check_include_files(sys/wait.h      HAVE_SYS_WAIT_H)

    check_include_files(dirent.h        HAVE_DIRENT_H)
    check_include_files(dlfcn.h         HAVE_DLFCN_H)
    check_include_files(fcntl.h         HAVE_FCNTL_H)
    check_include_files(ieeefp.h        HAVE_IEEEFP_H)
    check_include_files(ifaddrs.h       HAVE_IFADDRS_H)
    check_include_files(inttypes.h      HAVE_INTTYPES_H)
    check_include_files(stdint.h        HAVE_STDINT_H)
    check_include_files(pthread.h       HAVE_PTHREAD_H) # also see find_package(Threads)
    check_include_files(netinet/sctp.h  HAVE_SCTP_H)
    check_include_files(setns.h         HAVE_SETNS_H)
    check_include_files(stdlib.h        HAVE_STDLIB_H)
    check_include_files(string.h        HAVE_STRING_H)
    check_include_files(strings.h       HAVE_STRINGS_H)
    check_include_files(syslog.h        HAVE_SYSLOG_H)
    check_include_files(systemd/sd-daemon.h HAVE_SYSTEMD_SD_DAEMON_H)
    check_include_files(time.h          HAVE_TIME_H)
    check_include_files(vfork.h         HAVE_VFORK_H)

    check_include_files(windows.h       HAVE_WINDOWS_H)
    check_include_files(winsock2.h      HAVE_WINSOCK2_H)
    check_include_files(ws2tcpip.h      HAVE_WS2TCPIP_H)

    check_include_files(pty.h           HAVE_PTY_H)
    check_function_exists(openpty HAVE_OPENPTY)

    #check_symbol_exists(errno "net/errno.h" H_ERRNO_DECLARED)

    check_type_size("void*"         CONF_VOIDP_SIZE)
    math(EXPR WORD_SIZE_BITS        ${CONF_VOIDP_SIZE}*8)
    set(WORD_SIZE_BITS ${WORD_SIZE_BITS} PARENT_SCOPE)

    check_type_size("char"          CONF_CHAR_SIZE)
    check_type_size("int"           CONF_INT_SIZE)
    check_type_size("long"          CONF_LONG_SIZE)
    check_type_size("long long"     CONF_LONG_LONG_SIZE)
    check_type_size("short"         CONF_SHORT_SIZE)
    check_type_size("__int64_t"     CONF_INT64_SIZE)
    check_type_size("__int128_t"    CONF_INT128_SIZE)
    check_type_size("off_t"         CONF_OFFT_SIZE)
    check_type_size("size_t"        CONF_SIZET_SIZE)
    check_type_size("time_t"        CONF_TIMET_SIZE)

    if (CONF_FP_EXCEPTIONS) # fixme to a proper NO_FPE_SIGNALS = NOT CONF_FP_EXCEPTIONS
        set(NO_FPE_SIGNALS 0)
    else()
        set(NO_FPE_SIGNALS 1)
    endif()

    if(CONF_M32)
        set(CONF_INT128_SIZE 0)
    endif()
    set(USE_VM_PROBES ${CONF_VM_PROBES})
    set(ERTS_SAVED_COMPILE_TIME ${CONF_SAVED_COMPILE_TIME})

    configure_file(${SRC_DIR}/config.h.in ${CMAKE_BINARY_DIR}/config.h)
    configure_file(${SRC_DIR}/../include/erl_int_sizes_config.h.in
        ${CMAKE_BINARY_DIR}/erl_int_sizes_config.h)
endfunction(configure_platf)
configure_platf()

#
# Threads detection
#
set(EHTR_LIB_NAME "ethread") # TODO

#set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads)
set(CONF_FOUND_THREADS ${CMAKE_HAVE_THREADS_LIBRARY})

if(NOT CONF_FOUND_THREADS)
    if(CONF_THREADS)
        error("Threads required but not found")
    endif()
endif()

if(CONF_THREADS)
    set(ERTS_SMP 1)
    set(ENABLE_ALLOC_TYPE_VARS "${ENABLE_ALLOC_TYPE_VARS} threads smp")
    if(CONF_DIRTY_SCHEDULERS)
        message(STATUS "Dirty schedulers: Enabled")
        add_definitions(-DERTS_DIRTY_SCHEDULERS)
    endif(CONF_DIRTY_SCHEDULERS)
else()
    set(ERTS_SMP 0)
    message(STATUS "Lock check and lock count disabled (no threads)")
    set(CONF_ENABLE_LOCK_CHECK 0)
    set(CONF_ENABLE_LOCK_COUNT 0)
endif()


if(CONF_DEBUG)
    set(EMU_FILENAME_EXT ".debug")
else()
    set(EMU_SMP "")
endif(CONF_DEBUG)
if(ERTS_SMP)
    set(EMU_SMP "smp") # smp or plain
    set(EMU_FILENAME_EXT "${EMU_FILENAME_EXT}.smp")
else()
    set(EMU_SMP "plain")
endif(ERTS_SMP)

set(EMU_THR_DEFS
    -DUSE_THREADS
    -DETHR_PTHREADS
    -D_THREAD_SAFE
    -D_REENTRANT
    -DPOSIX_THREADS
    -D_POSIX_THREAD_SAFE_FUNCTIONS
    )
if(CONF_ENABLE_LOCK_CHECK)
    set(EMU_THR_DEFS "${EMU_THR_DEFS} -DERTS_ENABLE_LOCK_CHECK=1")
endif()
if(CONF_ENABLE_LOCK_COUNT)
    set(EMU_THR_DEFS "${EMU_THR_DEFS} -DERTS_ENABLE_LOCK_COUNT=1")
endif()
if(ERTS_SMP)
    set(EMU_THR_DEFS "${EMU_THR_DEFS} -DERTS_SMP=1")
endif()

#
# Compiler options: Remaining
#
add_definitions(
    -DHAVE_CONFIG_H
    -D_GNU_SOURCE=1
    -DERLANG_INTEGRATION
    -DLIBSCTP=libsctp.so.1
    ${EMU_THR_DEFS}
    )
add_definitions(
    -Wall
    -Werror=implicit
    -Werror=return-type
    )

if(CONF_DEBUG)
    add_definitions(-O0 -g -ggdb -DDEBUG)
else()
    add_definitions(-O2)
endif()

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wstrict-prototypes \
    -Wmissing-prototypes -Wdeclaration-after-statement")

#
# Marks each C source file as C++, if CONF_FORCE_CXX is 1
#
function(to_cpp list)
    if(CONF_FORCE_CXX)
        foreach(tmp ${${list}})
            get_filename_component(tmp_ext ${tmp} EXT)
            if("${tmp_ext}" STREQUAL ".c")
                set_source_files_properties(${tmp} PROPERTIES LANGUAGE CXX )
            endif()
        endforeach(tmp)
    endif(CONF_FORCE_CXX)
endfunction(to_cpp)

#
# Files which go into project
#

include_directories(
    ${CMAKE_BINARY_DIR}
    ${BIN_DIR}

    ${SRC_DIR}/beam
    ${SRC_DIR}/hipe
    ${SRC_DIR}/pcre
    ${SRC_DIR}/drivers/common
    ${SRC_DIR}/sys/common
    ${SRC_DIR}/sys/${OPSYS}/
    ${SRC_DIR}/zlib

    ${SRC_DIR}/../include
    ${SRC_DIR}/../include/internal
    )
set(SRC_ERL_EMU_GEN
    ${BIN_DIR}/erl_alloc_types.h
    ${BIN_DIR}/beam_cold.h ${BIN_DIR}/beam_hot.h
    ${BIN_DIR}/beam_opcodes.c ${BIN_DIR}/beam_opcodes.h
    ${BIN_DIR}/beam_pred_funcs.h ${BIN_DIR}/beam_tr_funcs.h
    ${BIN_DIR}/driver_tab.c
    ${BIN_DIR}/erl_bif_table.h  ${BIN_DIR}/erl_bif_table.c
    ${BIN_DIR}/erl_bif_wrap.c   ${BIN_DIR}/erl_bif_list.h
    ${BIN_DIR}/erl_atom_table.c ${BIN_DIR}/erl_atom_table.h
    ${BIN_DIR}/erl_pbifs.c
    ${BIN_DIR}/erl_version.h
    ${BIN_DIR}/erl_compile_flags.h

    ${BIN_DIR}/preload.c

    pcre/pcre_exec_loop_break_cases.inc
    )
to_cpp(SRC_ERL_EMU_GEN)

#
# Much HiPE, such power
#
if(CONF_HIPE)
    if (CONF_NATIVE_LIBS)
        message(STATUS "Hipe enabled: disabling native libs")
        set(CONF_NATIVE_LIBS 0)
    endif()

    set(ENABLE_ALLOC_TYPE_VARS "${ENABLE_ALLOC_TYPE_VARS} hipe")
    set(HIPE_DIR "${SRC_DIR}/hipe")
    set(HIPE_ARCH64_OBJS
        ${HIPE_DIR}/hipe_bif64.c)
    set(HIPE_x86_OS_OBJS
        "")
    set(HIPE_x86_OBJS
        ${HIPE_DIR}/hipe_x86.c
        ${BIN_DIR}/hipe_x86_glue.o
        ${BIN_DIR}/hipe_x86_bifs.o
        ${HIPE_DIR}/hipe_x86_signal.c
        ${HIPE_DIR}/hipe_x86_stack.c ${HIPE_x86_OS_OBJS}
        )
    set(HIPE_amd64_OBJS
        ${HIPE_DIR}/hipe_amd64.c
        ${BIN_DIR}/hipe_amd64_glue.o
        ${BIN_DIR}/hipe_amd64_bifs.o
        ${HIPE_DIR}/hipe_x86_signal.c
        ${HIPE_DIR}/hipe_x86_stack.c ${HIPE_ARCH64_OBJS}
        )
    set(HIPE_ultrasparc_OBJS
        ${HIPE_DIR}/hipe_sparc.c
        ${BIN_DIR}/hipe_sparc_glue.o
        ${BIN_DIR}/hipe_sparc_bifs.o
        hupe/hipe_risc_stack.c
        )
    set(HIPE_ppc_OBJS
        ${HIPE_DIR}/hipe_ppc.c
        ${BIN_DIR}/hipe_ppc_glue.o
        ${BIN_DIR}/hipe_ppc_bifs.o
        ${HIPE_DIR}/hipe_risc_stack.c
        )
    set(HIPE_ppc64_OBJS ${HIPE_ppc_OBJS} ${HIPE_ARCH64_OBJS}
        )
    set(HIPE_arm_OBJS
        ${HIPE_DIR}/hipe_arm.c
        ${BIN_DIR}/hipe_arm_glue.o
        ${BIN_DIR}/hipe_arm_bifs.o
        ${HIPE_DIR}/hipe_risc_stack.c
        )
    set(SRC_ERL_HIPE_GEN
        ${BIN_DIR}/hipe_amd64_asm.h  ${BIN_DIR}/hipe_x86_asm.h
        ${BIN_DIR}/hipe_bif_list.h   ${BIN_DIR}/hipe_sparc_asm.h
        ${BIN_DIR}/hipe_arm_asm.h    ${BIN_DIR}/hipe_ppc_asm.h
        )
    set(SRC_ERL_HIPE
        # this one is not in generated because it depends on other generated
        ${BIN_DIR}/hipe_literals.h

        ${HIPE_DIR}/hipe_bif0.c            ${HIPE_DIR}/hipe_bif0.h
        ${HIPE_DIR}/hipe_bif1.c            ${HIPE_DIR}/hipe_bif1.h
        ${HIPE_DIR}/hipe_bif2.c
        ${HIPE_DIR}/hipe_bif64.c           ${HIPE_DIR}/hipe_bif64.h
        ${HIPE_DIR}/hipe_debug.c           ${HIPE_DIR}/hipe_debug.h
        ${HIPE_DIR}/hipe_gc.c              ${HIPE_DIR}/hipe_gc.h
        ${HIPE_DIR}/hipe_mode_switch.c     ${HIPE_DIR}/hipe_mode_switch.h
        ${HIPE_DIR}/hipe_native_bif.c      ${HIPE_DIR}/hipe_native_bif.h
        ${HIPE_DIR}/hipe_process.h

        ${HIPE_${ARCH}_OBJS}

        ${HIPE_DIR}/hipe_stack.c           ${HIPE_DIR}/hipe_stack.h
        )
    to_cpp(SRC_ERL_HIPE)
endif(CONF_HIPE)

# File which contains int main() for emulator
set(SRC_ERL_EMU_MAIN
    sys/unix/erl_main.c
    )
to_cpp(SRC_ERL_EMU_MAIN)

set(SRC_ERL_EMU
    beam/atom.c               beam/atom.h
    beam/beam_bif_load.c
    beam/beam_bp.c            beam/beam_bp.h
    beam/beam_catches.c       beam/beam_catches.h
    beam/beam_emu.c
    beam/beam_load.c          beam/beam_load.h
    beam/beam_ranges.c
    beam/benchmark.c          beam/benchmark.h
    beam/bif.c                beam/bif.h
    beam/big.c                beam/big.h
    beam/binary.c
    beam/break.c
    beam/code_ix.c            beam/code_ix.h
    beam/copy.c
    beam/dist.c               beam/dist.h
    beam/erl_afit_alloc.c     beam/erl_afit_alloc.h

    beam/erl_alloc.c          beam/erl_alloc.h

    beam/erl_alloc_util.c     beam/erl_alloc_util.h
    beam/erl_ao_firstfit_alloc.c   beam/erl_ao_firstfit_alloc.h
    beam/erl_arith.c
    beam/erl_async.c          beam/erl_async.h
    beam/erl_bestfit_alloc.c  beam/erl_bestfit_alloc.h
    beam/erl_bits.c             beam/erl_bits.h
      beam/erl_binary.h

    beam/erl_cpu_topology.c     beam/erl_cpu_topology.h

    beam/erl_db.c               beam/erl_db.h
    beam/erl_db_hash.c          beam/erl_db_hash.h
    beam/erl_db_tree.c          beam/erl_db_tree.h
    beam/erl_db_util.c          beam/erl_db_util.h
    beam/erl_debug.c            beam/erl_debug.h
      beam/erl_driver.h
    beam/erl_drv_thread.c
    beam/erl_fun.c              beam/erl_fun.h
    beam/erl_gc.c               beam/erl_gc.h
    beam/erl_goodfit_alloc.c    beam/erl_goodfit_alloc.h
    beam/erl_hl_timer.c         beam/erl_hl_timer.h

    beam/erl_init.c

    beam/erl_instrument.c       beam/erl_instrument.h
    beam/erl_lock_check.c       beam/erl_lock_check.h
    beam/erl_lock_count.c       beam/erl_lock_count.h
    beam/erl_map.c              beam/erl_map.h
#    beam/erl_math.c
    beam/erl_md5.c
    beam/erl_message.c          beam/erl_message.h
    beam/erl_monitors.c         beam/erl_monitors.h
    beam/erl_msacc.c            beam/erl_msacc.h
    beam/erl_mtrace.c           beam/erl_mtrace.h
    beam/erl_nif.c              beam/erl_nif.h
    beam/erl_node_tables.c      beam/erl_node_tables.h

    beam/erl_port.h

    beam/erl_port_task.c      beam/erl_port_task.h
    beam/erl_posix_str.c
    beam/erl_printf_term.c    beam/erl_printf_term.h

    beam/erl_process.c        beam/erl_process.h

    beam/erl_process_dict.c   beam/erl_process_dict.h
    beam/erl_process_dump.c
    beam/erl_process_lock.c   beam/erl_process_lock.h
    beam/erl_ptab.c           beam/erl_ptab.h
    beam/erl_sched_spec_pre_alloc.c beam/erl_sched_spec_pre_alloc.h
      beam/erl_smp.h
    beam/erl_term.c           beam/erl_term.h
      beam/erl_threads.h
    beam/erl_thr_progress.c   beam/erl_thr_progress.h
    beam/erl_thr_queue.c      beam/erl_thr_queue.h
      beam/erl_thr_queue.h
      beam/erl_time.h
    beam/erl_time_sup.c
    beam/erl_trace.c          beam/erl_trace.h
    beam/erl_unicode.c        beam/erl_unicode.h
    beam/erl_zlib.c           beam/erl_zlib.h
      beam/erl_utils.h
    beam/export.c             beam/export.h
    beam/external.c           beam/external.h
      beam/global.h
    beam/hash.c               beam/hash.h
    beam/index.c              beam/index.h
    beam/io.c
    beam/module.c             beam/module.h
    beam/packet_parser.c      beam/packet_parser.h
    beam/register.c           beam/register.h
    beam/safe_hash.c          beam/safe_hash.h
      beam/sys.h
    beam/time.c
    beam/utils.c
    )
to_cpp(SRC_ERL_EMU)

set(SRC_SYS_OS
    sys/unix/erl_unix_sys.h
    sys/unix/erl_unix_sys_ddll.c
    sys/unix/sys.c
    sys/unix/sys_drivers.c
    sys/unix/sys_float.c
    sys/unix/sys_time.c
    sys/unix/sys_uds.c
    )
set(SRC_ERL_SYS
    sys/common/erl_check_io.h
    sys/common/erl_mmap.c               sys/common/erl_mmap.h
    sys/common/erl_mtrace_sys_wrap.c
    sys/common/erl_mseg.c               sys/common/erl_mseg.h
    sys/common/erl_poll.h
    sys/common/erl_sys_common_misc.c
    ${SRC_SYS_OS}
    )
if(CONF_KERNEL_POLL)
    set(SRC_ERL_SYS ${SRC_ERL_SYS}
        sys/common/erl_check_io.kp.c
        sys/common/erl_check_io.nkp.c
        sys/common/erl_poll.kp.c
        sys/common/erl_poll.nkp.c
        )
else()
    set(SRC_ERL_SYS ${SRC_ERL_SYS}
        sys/common/erl_check_io.c
        sys/common/erl_poll.c
        )
endif(CONF_KERNEL_POLL)
to_cpp(SRC_ERL_SYS)

set(SRC_ZLIB
    zlib/adler32.c
    zlib/compress.c
    zlib/crc32.c            zlib/crc32.h
    zlib/deflate.c          zlib/deflate.h
        zlib/gzguts.h
    zlib/inffast.c          zlib/inffast.h
        zlib/inffixed.h
    zlib/inflate.c          zlib/inflate.h
    zlib/inftrees.c         zlib/inftrees.h
    zlib/trees.c            zlib/trees.h
    zlib/uncompr.c
    zlib/zconf.h
    zlib/zlib.h
    zlib/zutil.c            zlib/zutil.h
    )
to_cpp(SRC_ZLIB)

set(SRC_PCRE
    pcre/local_config.h
    pcre/pcre.h
    pcre/pcre_byte_order.c
    pcre/pcre_chartables.c
    pcre/pcre_compile.c
    pcre/pcre_config.c
    pcre/pcre_dfa_exec.c
    pcre/pcre_exec.c
    pcre/pcre_fullinfo.c
    pcre/pcre_get.c
    pcre/pcre_globals.c
    pcre/pcre_internal.h
    pcre/pcre_jit_compile.c
    #pcre/pcre_latin_1_table.c
    pcre/pcre_maketables.c
    pcre/pcre_newline.c
    pcre/pcre_ord2utf8.c
    pcre/pcre_refcount.c
    pcre/pcre_string_utils.c
    pcre/pcre_study.c
    pcre/pcre_tables.c
    pcre/pcre_ucd.c
    pcre/pcre_valid_utf8.c
    pcre/pcre_version.c
    pcre/pcre_xclass.c
    pcre/ucp.h
    )
to_cpp(SRC_PCRE)

set(SRC_ERL_DRIVERS
    drivers/common/efile_drv.c drivers/common/erl_efile.h
    drivers/common/gzio.c     drivers/common/gzio.h
    drivers/common/inet_drv.c
    drivers/common/ram_file_drv.c
    drivers/common/zlib_drv.c

    drivers/unix/ttsl_drv.c
    drivers/unix/unix_efile.c
    )
to_cpp(SRC_ERL_DRIVERS)

set(SRC_ERL_BIFS
    # Borked link order for some reason, works here, does not work from SRC_ERL_EMU
    beam/beam_debug.c
    beam/erl_math.c
    beam/erl_bif_binary.c
    beam/erl_bif_chksum.c
    beam/erl_bif_ddll.c
    beam/erl_bif_info.c
    beam/erl_bif_op.c
    beam/erl_bif_guard.c
    beam/erl_bif_lists.c
    beam/erl_bif_os.c
    beam/erl_bif_port.c
    beam/erl_bif_re.c
    beam/erl_bif_trace.c
    beam/erl_bif_unique.c       beam/erl_bif_unique.h
    nifs/common/erl_tracer_nif.c
    )
to_cpp(SRC_ERL_BIFS)

set(SRC_ERL_RUNTIME
    ${SRC_DIR}/../lib_src/common/erl_misc_utils.c
    ${SRC_DIR}/../include/internal/erl_misc_utils.h
    ${SRC_DIR}/../lib_src/common/erl_printf.c
    ${SRC_DIR}/../lib_src/common/erl_printf_format.c
    )
if(ERTS_SMP)
    set(SRC_ERL_RUNTIME ${SRC_ERL_RUNTIME}
        ${SRC_DIR}/../lib_src/common/ethr_atomics.c
        ${SRC_DIR}/../lib_src/common/ethr_mutex.c
        ${SRC_DIR}/../lib_src/common/ethr_aux.c
        ${SRC_DIR}/../lib_src/pthread/ethread.c
        ${SRC_DIR}/../include/internal/ethread.h
        ${SRC_DIR}/../lib_src/pthread/ethr_event.c
        ${SRC_DIR}/../include/internal/ethread_inline.h
        )
endif(ERTS_SMP)
to_cpp(SRC_ERL_RUNTIME)

#
# Erl Alloc types
#
string(REPLACE ";" " " ENABLE_ALLOC_TYPE_VARS "${ENABLE_ALLOC_TYPE_VARS}")
separate_arguments(MAKE_ALLOC_ARGS UNIX_COMMAND
    "-src beam/erl_alloc.types -dst ${BIN_DIR}/erl_alloc_types.h ${ENABLE_ALLOC_TYPE_VARS}"
    )
add_custom_command(OUTPUT ${BIN_DIR}/erl_alloc_types.h
    COMMAND LANG=C ${PERL_EXECUTABLE} utils/make_alloc_types
    ARGS ${MAKE_ALLOC_ARGS}
    WORKING_DIRECTORY ${SRC_DIR}
    )

#
# Atom and bif tables
#
set(ATOMS beam/atom.names)
set(BIFS  beam/bif.tab)
if(CONF_HIPE)
    set(HIPE_ARCH64_TAB ${HIPE_DIR}/hipe_bif64.tab)
    set(HIPE_x86_TAB ${HIPE_DIR}/hipe_x86.tab)
    set(HIPE_amd64_TAB ${HIPE_DIR}/hipe_amd64.tab ${HIPE_ARCH64_TAB})
    set(HIPE_ultrasparc_TAB ${HIPE_DIR}/hipe_sparc.tab)
    set(HIPE_ppc_TAB ${HIPE_DIR}/hipe_ppc.tab)
    set(HIPE_ppc64_TAB ${HIPE_DIR}/hipe_ppc64.tab ${HIPE_ARCH64_TAB})
    set(HIPE_arm_TAB ${HIPE_DIR}/hipe_arm.tab)
    set(HIPE_ARCH_TAB ${HIPE_${ARCH}_TAB})
    set(BIFS ${BIFS} ${HIPE_DIR}/hipe_bif0.tab ${HIPE_DIR}/hipe_bif1.tab
        ${HIPE_DIR}/hipe_bif2.tab ${HIPE_ARCH_TAB})
endif(CONF_HIPE)

add_custom_command(OUTPUT ${BIN_DIR}/erl_bif_table.h ${BIN_DIR}/erl_bif_table.c
                          ${BIN_DIR}/erl_bif_wrap.c ${BIN_DIR}/erl_bif_list.h
                          ${BIN_DIR}/erl_atom_table.c ${BIN_DIR}/erl_atom_table.h
                          ${BIN_DIR}/erl_pbifs.c
    COMMAND LANG=C ${PERL_EXECUTABLE} utils/make_tables
    ARGS -src ${BIN_DIR} -include ${BIN_DIR} ${ATOMS} ${BIFS}
    WORKING_DIRECTORY ${SRC_DIR}
    )

#
# Opcode tables and Hipe opcodes
#
set(OPCODE_TABLES ${ERL_TOP}/lib/compiler/src/genop.tab beam/ops.tab)

if(CONF_HIPE)
    set(OPCODE_TABLES ${OPCODE_TABLES} ${HIPE_DIR}/hipe_ops.tab)
endif(CONF_HIPE)

add_custom_command(OUTPUT ${BIN_DIR}/beam_cold.h ${BIN_DIR}/beam_hot.h
                          ${BIN_DIR}/beam_opcodes.c ${BIN_DIR}/beam_opcodes.h
                          ${BIN_DIR}/beam_pred_funcs.h ${BIN_DIR}/beam_tr_funcs.h
    COMMAND LANG=C ${PERL_EXECUTABLE} utils/beam_makeops
    ARGS -wordsize ${WORD_SIZE_BITS} -outdir ${BIN_DIR} -DUSE_VM_PROBES=${CONF_VM_PROBES} -emulator ${OPCODE_TABLES}
    WORKING_DIRECTORY ${SRC_DIR}
    )

#
# Erl_version
#
add_custom_command(OUTPUT ${BIN_DIR}/erl_version.h
    COMMAND LANG=C ${PERL_EXECUTABLE} utils/make_version
    ARGS -o ${BIN_DIR}/erl_version.h
        ${CONF_SYSTEM_VSN} ${CONF_OTP_VERSION} ${CONF_OTP_VERSION}${CONF_SERIALNO} ${OPSYS}
        # target_opsys was used here for crosscompile
    WORKING_DIRECTORY ${SRC_DIR}
    )

#
# Hipe headers M4 generation
#
if(CONF_HIPE)
    set(HIPE_M4FLAGS
        -DTARGET=${BIN_DIR} -DOPSYS=${OPSYS} -DARCH=${ARCH} -DERTS_SMP=${ERTS_SMP})

    foreach(HIPE_HDR
            hipe_amd64_asm hipe_x86_asm hipe_bif_list hipe_sparc_asm
            hipe_arm_asm hipe_ppc_asm)
        add_custom_command(OUTPUT ${BIN_DIR}/${HIPE_HDR}.h
            DEPENDS ${BIN_DIR}/erl_bif_list.h
            COMMAND m4
            ARGS ${HIPE_M4FLAGS} ${HIPE_DIR}/${HIPE_HDR}.m4 > ${BIN_DIR}/${HIPE_HDR}.h
            WORKING_DIRECTORY ${SRC_DIR}
            )
    endforeach()

    foreach(HIPE_ASM
            hipe_sparc_bifs hipe_arm_bifs hipe_ppc_bifs hipe_amd64_bifs
            hipe_x86_bifs)
        add_custom_command(OUTPUT ${BIN_DIR}/${HIPE_ASM}.S
            DEPENDS ${BIN_DIR}/hipe_literals.h
            COMMAND m4
            ARGS ${HIPE_M4FLAGS} ${HIPE_DIR}/${HIPE_ASM}.m4 > ${BIN_DIR}/${HIPE_ASM}.S
            WORKING_DIRECTORY ${SRC_DIR}
            )
        add_custom_command(OUTPUT ${BIN_DIR}/${HIPE_ASM}.o
            DEPENDS ${BIN_DIR}/hipe_literals.h
                    ${BIN_DIR}/${HIPE_ASM}.S
            COMMAND ${CMAKE_C_COMPILER}
            ARGS -o ${BIN_DIR}/${HIPE_ASM}.o -I ${CMAKE_BINARY_DIR}
                 ${BIN_DIR}/${HIPE_ASM}.S
                 -c
            WORKING_DIRECTORY ${SRC_DIR}
            )
    endforeach()

    foreach(HIPE_GLUE
            hipe_x86_glue hipe_amd64_glue hipe_ppc_glue hipe_sparc_glue
            hipe_arm_glue)
        add_custom_command(OUTPUT ${BIN_DIR}/${HIPE_GLUE}.o
            DEPENDS ${SRC_ERL_HIPE_GEN}
            COMMAND ${CMAKE_C_COMPILER}
            ARGS -I ${BIN_DIR}
                -o ${BIN_DIR}/${HIPE_GLUE}.o
                ${HIPE_DIR}/${HIPE_GLUE}.S
                -c
            WORKING_DIRECTORY ${BIN_DIR}
            )
    endforeach()
endif(CONF_HIPE)

#
# erl_compile_flags
#
add_custom_command(OUTPUT ${BIN_DIR}/erl_compile_flags.h
    COMMAND LANG=C ${PERL_EXECUTABLE} utils/make_compiler_flags
    ARGS -o ${BIN_DIR}/erl_compile_flags.h
        -v CONFIG_H "N/A" -v CFLAGS "N/A" -v LDFLAGS "N/A"
    WORKING_DIRECTORY ${SRC_DIR}
    )

#
# Driver table
#
set(NIF_OBJS
    erl_tracer_nif.o)
set(STATIC_NIF_LIBS
    #asn1rt_nif.a
    #crypto_${EMU_SMP}.a
    )
set(DRV_OBJS
    # windows - registry_drv.o
    efile_drv.o
    inet_drv.o
    zlib_drv.o
    ram_file_drv.o
    ttsl_drv.o
    )
set(STATIC_DRIVER_LIBS
    )
add_custom_command(OUTPUT ${BIN_DIR}/driver_tab.c
    COMMAND LANG=C ${PERL_EXECUTABLE} utils/make_driver_tab
    ARGS -o ${BIN_DIR}/driver_tab.c
        -nifs ${NIF_OBJS} ${STATIC_NIF_LIBS}
        -drivers ${DRV_OBJS} ${STATIC_DRIVER_LIBS}
    WORKING_DIRECTORY ${SRC_DIR}
    )

#
# Pcre exec loop break cases
#
add_custom_command(OUTPUT pcre/pcre_exec_loop_break_cases.inc
    COMMAND ERL_TOP=${ERL_TOP} make
    ARGS -f pcre.mk ${SRC_DIR}/pcre/pcre_exec_loop_break_cases.inc
    WORKING_DIRECTORY ${SRC_DIR}/pcre
    )

#
# Hipe literals
#
if(CONF_HIPE)
    add_custom_command(OUTPUT ${BIN_DIR}/hipe_literals.h
        DEPENDS hipe_mkliterals
        COMMAND hipe_mkliterals -c > ${BIN_DIR}/hipe_literals.h
        WORKING_DIRECTORY ${BIN_DIR}
        )
endif(CONF_HIPE)

#
# Preloaded beam files
#
get_filename_component(PRELOAD_DIR "${SRC_DIR}/../preloaded/ebin" ABSOLUTE)
set(PRELOAD_BEAMS
    ${PRELOAD_DIR}/otp_ring0.beam
    ${PRELOAD_DIR}/erts_code_purger.beam
    ${PRELOAD_DIR}/init.beam
    ${PRELOAD_DIR}/prim_eval.beam
    ${PRELOAD_DIR}/prim_inet.beam
    ${PRELOAD_DIR}/prim_file.beam
    ${PRELOAD_DIR}/zlib.beam
    ${PRELOAD_DIR}/prim_zip.beam
    ${PRELOAD_DIR}/erl_prim_loader.beam
    ${PRELOAD_DIR}/erlang.beam
    ${PRELOAD_DIR}/erts_internal.beam
    ${PRELOAD_DIR}/erl_tracer.beam
    )
add_custom_command(OUTPUT ${BIN_DIR}/preload.c
    COMMAND LANG=C ${PERL_EXECUTABLE} utils/make_preload
    ARGS -old ${PRELOAD_BEAMS} > ${BIN_DIR}/preload.c
    WORKING_DIRECTORY ${SRC_DIR}
    )
