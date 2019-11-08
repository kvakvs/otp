cmake_minimum_required(VERSION 3.15)
project(crypto C)

set(CMAKE_C_STANDARD 11)

include_directories(c_src)
include_directories(../../erts/emulator/beam)

add_executable(crypto
        c_src/crypto.c
        c_src/eddsa.c
        c_src/crypto_callback.c
        c_src/crypto_callback.h
        c_src/otp_test_engine.c c_src/openssl_config.h c_src/atoms.h)
