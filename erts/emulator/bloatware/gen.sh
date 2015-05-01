#!/bin/sh

PERL=`which perl`
TTF_DIR="gen"
ERL_TOP="../../.."
OPCODE_TABLES="$ERL_TOP/lib/compiler/src/genop.tab ../beam/ops.tab"
LANG=C $PERL scripts/beam_makeops \
                -wordsize 64 \
                -outdir $TTF_DIR \
                -DUSE_VM_PROBES=0 \
                -emulator $OPCODE_TABLES && echo $? >$TTF_DIR/OPCODES-GENERATED