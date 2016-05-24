project(erts_common CXX C ASM)
cmake_minimum_required(VERSION 3.5)

include_directories(
    ${CMAKE_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}/erts/include
    ${CMAKE_SOURCE_DIR}/erts/include/internal

    # for dyn_erl
    ${CMAKE_SOURCE_DIR}/erts/emulator/beam
    ${CMAKE_SOURCE_DIR}/erts/emulator/sys/unix
    )
add_definitions(
    -DEPMD_PORT_NO=${EPMD_PORT}
    -D_GNU_SOURCE
    -DHAVE_CONFIG_H
    -O2
    -DOTP_SYSTEM_VERSION=\"$(SYSTEM_VSN)\"
    )

# TODO: import this from erts/emulator
#set(EMULATOR_LIBS emulator m dl curses pthread)

# On windows erl.exe is built from source, on Unix it's a script

add_library(emulator-imp STATIC IMPORTED)
set_property(TARGET emulator-imp
    PROPERTY IMPORTED_LOCATION "${CMAKE_BINARY_DIR}/export-emulator.cmake")

#
# Heart
#
set(SRC_HEART common/heart.c)
add_executable(heart ${SRC_HEART})

#
# Inet_gethost
#
set(SRC_INETGETHOST common/inet_gethost.c)
add_executable(inet_gethost ${SRC_INETGETHOST})
add_dependencies(inet_gethost erl-runtime)
target_link_libraries(inet_gethost erl-runtime m)

#
# Erlexec
#
set(SRC_ERLEXEC common/erlexec.c)
add_executable(erlexec ${SRC_ERLEXEC})
add_dependencies(erlexec erl-runtime)
target_link_libraries(erlexec erl-runtime m)

#
# Escript
#
set(SRC_ESCRIPT common/escript.c)
add_executable(escript ${SRC_ESCRIPT})
add_dependencies(escript erl-runtime)
target_link_libraries(escript erl-runtime m)

#
# Dialyzer
#
set(SRC_DIALYZER common/dialyzer.c)
add_executable(dialyzer ${SRC_DIALYZER})
add_dependencies(dialyzer erl-runtime)
target_link_libraries(dialyzer erl-runtime m)

#
# Typer
#
set(SRC_TYPER common/typer.c)
add_executable(typer ${SRC_TYPER})
add_dependencies(typer erl-runtime)
target_link_libraries(typer erl-runtime m)

if(WINDOWS)
    # win/erlexec.c win/init_file.c ertslib
    # erl
    # start_erl
    # erlsrv
endif(WINDOWS)

if(UNIX)
    #
    # Run_Erl
    #
    set(SRC_RUNERL unix/run_erl.c unix/safe_string.c)
    add_executable(run_erl ${SRC_RUNERL})
    target_link_libraries(run_erl util)

    #
    # To_Erl
    #
    set(SRC_TOERL unix/to_erl.c unix/safe_string.c)
    add_executable(to_erl ${SRC_TOERL})

    #
    # Dyn_Erl
    #
    set(SRC_DYNERL unix/dyn_erl.c unix/safe_string.c)
    add_executable(dyn_erl ${SRC_DYNERL})
endif(UNIX)
