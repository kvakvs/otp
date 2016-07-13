#!/bin/bash

# -g -O3
/usr/bin/clang-3.8  -Werror=return-type -g -O2 \
    -fomit-frame-pointer -I/home/kv/proj/otp/erts/x86_64-unknown-linux-gnu \
    -D_GNU_SOURCE  -DHAVE_CONFIG_H -Wall -Wstrict-prototypes -Wmissing-prototypes -Wdeclaration-after-statement \
    -DUSE_THREADS -D_THREAD_SAFE -D_REENTRANT -DPOSIX_THREADS -D_POSIX_THREAD_SAFE_FUNCTIONS \
    -DERLANG_GIT_VERSION="\"e6883e0\"" -Ix86_64-unknown-linux-gnu/opt/plain -Ibeam -Isys/unix -Isys/common \
    -Ix86_64-unknown-linux-gnu -Ipcre -Ihipe -I../include -I../include/x86_64-unknown-linux-gnu -I../include/internal \
    -I../include/internal/x86_64-unknown-linux-gnu -c beam/erl_gc.c -o erl_gc.S -S
