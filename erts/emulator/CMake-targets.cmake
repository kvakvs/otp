###
### Defines targets (executables, libraries and fake libraries used to straighten
### dependencies) for emulator
###

# Static lib contains generated files to help sort out deps
add_library(erl-emulator-generated STATIC ${SRC_ERL_EMU_GEN})
set_target_properties(erl-emulator-generated PROPERTIES LINKER_LANGUAGE CXX)

# Static lib contains HIPE generated files to help sort out deps
if(CONF_HIPE)
    add_library(erl-hipe-generated STATIC ${SRC_ERL_HIPE_GEN})
    set_target_properties(erl-hipe-generated PROPERTIES LINKER_LANGUAGE CXX)
    add_dependencies(erl-hipe-generated erl-emulator-generated)
endif(CONF_HIPE)

#
# = hipe_mkliterals, build tool for HiPE
#
if(CONF_HIPE)
    add_executable(hipe_mkliterals ${HIPE_DIR}/hipe_mkliterals.c)
    target_link_libraries(hipe_mkliterals PUBLIC erl-emulator-generated)
    target_link_libraries(hipe_mkliterals PUBLIC erl-hipe-generated)
endif(CONF_HIPE)

#
# = erl-hipe.a
#
if(CONF_HIPE)
    add_library(erl-hipe STATIC ${SRC_ERL_HIPE})
    add_dependencies(erl-hipe hipe_mkliterals)
    target_link_libraries(erl-hipe PUBLIC erl-hipe-generated)
endif(CONF_HIPE)

#
# = liberl-runtime.a
# Pack emu stuff into a library then link it with emu main.c
#
link_directories(${BIN_DIR})
add_library(erl-runtime STATIC ${SRC_ERL_RUNTIME})
#add_dependencies(erl-runtime hipe_mkliterals emulator-gen erl-hipe-generated)

#
# liberl-drivers
#
add_library(erl-drivers STATIC ${SRC_ERL_DRIVERS})
#add_dependencies(erl-drivers emulator-gen)

#
# liberl-zlib and liberl-pcre
#
add_library(erl-pcre STATIC ${SRC_PCRE})
if(CONF_HIPE)
    add_dependencies(erl-pcre erl-hipe-generated)
endif(CONF_HIPE)

add_library(erl-zlib STATIC ${SRC_ZLIB})
if(CONF_HIPE)
    add_dependencies(erl-zlib erl-hipe-generated)
endif(CONF_HIPE)

#
# liberl-bifs
#
add_library(erl-bifs STATIC ${SRC_ERL_BIFS})
#add_dependencies(erl-bifs)

#
# liberl-sys
#
add_library(erl-sys STATIC ${SRC_ERL_SYS})
#add_dependencies(erl-sys erl-emulator-generated)
target_link_libraries(erl-sys PUBLIC erl-emulator-generated)
target_link_libraries(erl-sys PUBLIC erl-drivers)

#
# Beam emulator - liberl-emulator, minus hipe and generated files
#
add_library(erl-emulator STATIC ${SRC_ERL_EMU})
#add_dependencies(erl-emulator erl-emulator-generated)

# order matters
target_link_libraries(erl-emulator PUBLIC erl-emulator-generated)
target_link_libraries(erl-emulator PUBLIC erl-runtime)
target_link_libraries(erl-emulator PUBLIC erl-drivers)
target_link_libraries(erl-emulator PUBLIC erl-zlib)
target_link_libraries(erl-emulator PUBLIC erl-sys)
target_link_libraries(erl-emulator PUBLIC erl-bifs)
target_link_libraries(erl-emulator PUBLIC erl-pcre)

if(CONF_HIPE)
    add_dependencies(erl-emulator erl-hipe)
    target_link_libraries(erl-emulator PUBLIC erl-hipe)
endif(CONF_HIPE)

# these should go last
target_link_libraries(erl-emulator PUBLIC ${CURSES_LIBRARIES})
target_link_libraries(erl-emulator PUBLIC m dl)

#
# =beam.smp, =beam
#
link_directories(${PROJECT_BINARY_DIR})

#
# beam{.debug}{.smp}
#
set(EMU_FILENAME "beam${EMU_FILENAME_EXT}")
add_executable(${EMU_FILENAME} ${SRC_ERL_EMU_MAIN})
add_dependencies(${EMU_FILENAME} erl-emulator)
target_link_libraries(${EMU_FILENAME} PUBLIC erl-emulator)

if(ERTS_SMP)
    target_link_libraries(${EMU_FILENAME} PUBLIC Threads::Threads)
endif(ERTS_SMP)

export(TARGETS erl-emulator erl-emulator-generated erl-runtime erl-drivers
            erl-pcre erl-sys erl-zlib erl-hipe erl-hipe-generated erl-bifs
       FILE ${CMAKE_BINARY_DIR}/export-emulator.cmake)
