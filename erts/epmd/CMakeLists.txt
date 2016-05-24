project(epmd CXX C ASM)
cmake_minimum_required(VERSION 3.5)

#
# Options for epmd
#

set(EPMD_PORT "4369")

#
# end options
#

include_directories(
    ${CMAKE_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}/erts/include
    ${CMAKE_SOURCE_DIR}/erts/include/internal
    )
add_definitions(
    -DEPMD_PORT_NO=${EPMD_PORT}
    -D_GNU_SOURCE
    -DHAVE_CONFIG_H
    -O2
    )

set(SRC_EPMD src/epmd.c src/epmd.h src/epmd_cli.c src/epmd_int.h src/epmd_srv.c)

add_library(emulator-imp STATIC IMPORTED)
set_property(TARGET emulator-imp
    PROPERTY IMPORTED_LOCATION "${CMAKE_BINARY_DIR}/export-emulator.cmake")

add_executable(epmd ${SRC_EPMD})
add_dependencies(epmd erl-runtime)
target_link_libraries(epmd erl-runtime m)
