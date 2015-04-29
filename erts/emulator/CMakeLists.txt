project(emulator C ASM)
cmake_minimum_required(VERSION 2.8)
#aux_source_directory(. SRC_LIST)

find_package (Threads)

#set(CXX clang++)
#set(CC  clang)
set(EMU_PLATF_TRIPLET "x86_64-unknown-linux-gnu")
set(EMU_PLATF_OS "unix") # unix ose or win32
set(EMU_SMP "smp") # smp or plain
set(HIPE_ARCH amd64)

set(emulator_PLATF_opt_SMP  ${CMAKE_SOURCE_DIR}/${EMU_PLATF_TRIPLET}/opt/${EMU_SMP})
set(emulator_PLATF          ${CMAKE_SOURCE_DIR}/${EMU_PLATF_TRIPLET})

include_directories( ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/beam
    ${CMAKE_SOURCE_DIR}/hipe
    ${CMAKE_SOURCE_DIR}/pcre
    ${CMAKE_SOURCE_DIR}/drivers/common
    ${CMAKE_SOURCE_DIR}/sys/common
    ${CMAKE_SOURCE_DIR}/sys/${EMU_PLATF_OS}
    ${CMAKE_SOURCE_DIR}/../include
    ${CMAKE_SOURCE_DIR}/../include/internal
    ${CMAKE_SOURCE_DIR}/../include/${EMU_PLATF_TRIPLET}
    ${CMAKE_SOURCE_DIR}/../${EMU_PLATF_TRIPLET}
    ${CMAKE_SOURCE_DIR}/${EMU_PLATF_TRIPLET}
    ${CMAKE_SOURCE_DIR}/${EMU_PLATF_TRIPLET}/opt/${EMU_SMP}
    )

add_definitions(-DHAVE_CONFIG_H
    -DERTS_SMP
    -DUSE_THREADS -DETHR_PTHREADS
    -D_GNU_SOURCE=1
    -DERLANG_INTEGRATION
    -DLIBSCTP=libsctp.so.1
    -O3
    )
set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS}
    -std=c++11
    )
set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS}
    -std=c99
    )
set(SRC_LIST
    beam/atom.c               beam/atom.h
    beam/beam_bif_load.c
    beam/beam_bp.c            beam/beam_bp.h
    beam/beam_catches.c       beam/beam_catches.h
    beam/beam_debug.c
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
    beam/erl_bif_timer.c      beam/erl_bif_timer.h
    beam/erl_bif_trace.c
    beam/erl_bits.c           beam/erl_bits.h
      beam/erl_binary.h
    beam/erl_cpu_topology.c   beam/erl_cpu_topology.h
    beam/erl_db.c             beam/erl_db.h
    beam/erl_db_hash.c        beam/erl_db_hash.h
    beam/erl_db_tree.c        beam/erl_db_tree.h
    beam/erl_db_util.c        beam/erl_db_util.h
      beam/erl_driver.h
    beam/erl_drv_thread.c
    beam/erl_fun.c            beam/erl_fun.h
    beam/erl_gc.c             beam/erl_gc.h
    beam/erl_goodfit_alloc.c  beam/erl_goodfit_alloc.h
    beam/erl_init.c
    beam/erl_instrument.c     beam/erl_instrument.h
    beam/erl_map.c            beam/erl_map.h
    beam/erl_math.c
    beam/erl_md5.c
    beam/erl_message.c        beam/erl_message.h
    beam/erl_monitors.c       beam/erl_monitors.h
    beam/erl_mtrace.c         beam/erl_mtrace.h
    beam/erl_nif.c            beam/erl_nif.h
    beam/erl_node_tables.c    beam/erl_node_tables.h
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

    #======================================================
    drivers/common/efile_drv.c
        drivers/common/erl_efile.h
    drivers/common/gzio.c     drivers/common/gzio.h
    drivers/common/inet_drv.c
    drivers/common/ram_file_drv.c
    drivers/common/zlib_drv.c

    drivers/unix/ttsl_drv.c
    drivers/unix/unix_efile.c

    #======================================================
    hipe/hipe_${HIPE_ARCH}.c
    hipe/hipe_${HIPE_ARCH}_glue.S
    ${emulator_PLATF_opt_SMP}/hipe_${HIPE_ARCH}_bifs.S
    ${emulator_PLATF_opt_SMP}/hipe_${HIPE_ARCH}_asm.h
    ${emulator_PLATF_opt_SMP}/hipe_literals.h
    ${emulator_PLATF_opt_SMP}/hipe_x86_asm.h

    hipe/hipe_bif0.c            hipe/hipe_bif0.h
    hipe/hipe_bif1.c            hipe/hipe_bif1.h
    hipe/hipe_bif2.c
    hipe/hipe_bif64.c           hipe/hipe_bif64.h
    hipe/hipe_debug.c           hipe/hipe_debug.h
    hipe/hipe_gc.c              hipe/hipe_gc.h
    hipe/hipe_mode_switch.c     hipe/hipe_mode_switch.h
    hipe/hipe_native_bif.c      hipe/hipe_native_bif.h
      hipe/hipe_process.h
    hipe/hipe_x86_signal.c
    hipe/hipe_x86_stack.c
    hipe/hipe_stack.c           hipe/hipe_stack.h

    #======================================================
    #pcre/dftables.c
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

    #======================================================
    sys/common/erl_check_io.kp.c
    sys/common/erl_check_io.nkp.c       sys/common/erl_check_io.h
    sys/common/erl_mmap.c               sys/common/erl_mmap.h
    sys/common/erl_mtrace_sys_wrap.c
    sys/common/erl_mseg.c               sys/common/erl_mseg.h
    sys/common/erl_poll.kp.c
    sys/common/erl_poll.nkp.c           sys/common/erl_poll.h
    sys/common/erl_sys_common_misc.c

    sys/${EMU_PLATF_OS}/erl_main.c
      sys/${EMU_PLATF_OS}/erl_unix_sys.h
    sys/${EMU_PLATF_OS}/erl_unix_sys_ddll.c
    sys/${EMU_PLATF_OS}/sys.c
    sys/${EMU_PLATF_OS}/sys_float.c
    sys/${EMU_PLATF_OS}/sys_time.c

    #======================================================
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

    #======================================================
    ../${EMU_PLATF_TRIPLET}/config.h

    ../lib_src/common/erl_misc_utils.c ../include/internal/erl_misc_utils.h
    ../lib_src/common/erl_printf.c
    ../lib_src/common/erl_printf_format.c
    ../lib_src/common/ethr_atomics.c
    ../lib_src/common/ethr_mutex.c
    ../lib_src/common/ethr_aux.c
    ../lib_src/pthread/ethread.c    ../include/internal/ethread.h
    ../lib_src/pthread/ethr_event.c
    ../include/internal/ethread_inline.h

    # generated by otp build
    #======================================================
    ${emulator_PLATF_opt_SMP}/erl_alloc_types.h
    ${emulator_PLATF_opt_SMP}/beam_opcodes.c        ${emulator_PLATF_opt_SMP}/beam_opcodes.h
    ${emulator_PLATF_opt_SMP}/driver_tab.c
    ${emulator_PLATF}/erl_atom_table.c              ${emulator_PLATF}/erl_atom_table.h
    ${emulator_PLATF}/erl_bif_table.c
    ${emulator_PLATF}/erl_bif_wrap.c
    ${emulator_PLATF}/preload.c
    )

add_executable(${PROJECT_NAME} ${SRC_LIST})
target_link_libraries(${PROJECT_NAME} ${CMAKE_THREAD_LIBS_INIT}
                      m dl curses)
