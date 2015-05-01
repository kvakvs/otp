#!/bin/sh

PERL=`which perl`
TARGET_DIR="`pwd`/gen"
ERL_TOP="../../.."
rm -f $TARGET_DIR/OPCODES-GENERATED

#================================
OPCODE_TABLES="$ERL_TOP/lib/compiler/src/genop.tab ../beam/ops.tab"

LANG=C $PERL scripts/beam_makeops \
                -wordsize 64 \
                -outdir $TARGET_DIR \
                -DUSE_VM_PROBES=0 \
                -emulator $OPCODE_TABLES && echo $? >$TARGET_DIR/OPCODES-GENERATED

#================================
ATOMS="../beam/atom.names"
BIFS="../beam/bif.tab"
#ifdef HIPE_ENABLED
#HIPE_ARCH64_TAB=hipe/hipe_bif64.tab
#HIPE_x86_TAB=hipe/hipe_x86.tab
#HIPE_amd64_TAB=hipe/hipe_amd64.tab $(HIPE_ARCH64_TAB)
#HIPE_ultrasparc_TAB=hipe/hipe_sparc.tab
#HIPE_ppc_TAB=hipe/hipe_ppc.tab
#HIPE_ppc64_TAB=hipe/hipe_ppc64.tab $(HIPE_ARCH64_TAB)
#HIPE_arm_TAB=hipe/hipe_arm.tab
#HIPE_ARCH_TAB=$(HIPE_$(ARCH)_TAB)
#BIFS += hipe/hipe_bif0.tab hipe/hipe_bif1.tab hipe/hipe_bif2.tab $(HIPE_ARCH_TAB)
#ifdef USE_PERFCTR
#BIFS += hipe/hipe_perfctr.tab
#endif
#endif

LANG=C $PERL scripts/make_tables -src $TARGET_DIR -include $TARGET_DIR \
                $ATOMS $BIFS && echo $? >$TARGET_DIR/TABLES-GENERATED

#=================================
STATIC_NIF_LIBS=""
OBJDIR="../obj/x86_64-unknown-linux-gnu/opt/smp"
DRV_OBJS="$OBJDIR/efile_drv.o \
        $OBJDIR/inet_drv.o \
        $OBJDIR/zlib_drv.o \
        $OBJDIR/ram_file_drv.o \
        $OBJDIR/ttsl_drv.o"
STATIC_DRIVER_LIBS=""
LANG=C $PERL scripts/make_driver_tab -o $TARGET_DIR/driver_tab.cpp \
    -nifs $STATIC_NIF_LIBS -drivers $DRV_OBJS $STATIC_DRIVER_LIBS