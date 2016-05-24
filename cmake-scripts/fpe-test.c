/* fpe-test.c */
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>

#if defined(__clang__) || defined(__llvm__)
#error "Clang/LLVM generates broken code for FP exceptions"
#endif

volatile int erl_fp_exception;

/*
 * We expect a single SIGFPE in this test program.
 * Getting many more indicates an inadequate SIGFPE handler,
 * e.g. using the generic handler on x86.
 */
static void new_fp_exception(void)
{
    if (++erl_fp_exception > 50) {
	fprintf(stderr, "SIGFPE loop detected, bailing out\n");
	exit(1);
    }
}

/* Is there no standard identifier for Darwin/MacOSX ? */
#if defined(__APPLE__) && defined(__MACH__) && !defined(__DARWIN__)
#define __DARWIN__ 1
#endif

/*
 * Implement unmask_fpe() and check_fpe() based on CPU/OS combination
 */

#if (defined(__i386__) || defined(__x86_64__)) && defined(__GNUC__) && !defined(__CYGWIN__) && !defined(__MINGW32__)

static void unmask_x87(void)
{
    unsigned short cw;
    __asm__ __volatile__("fstcw %0" : "=m"(cw));
    cw &= ~(0x01|0x04|0x08);   /* unmask IM, ZM, OM */
    __asm__ __volatile__("fldcw %0" : : "m"(cw));
}

static void unmask_sse2(void)
{
    unsigned int mxcsr;
    __asm__ __volatile__("stmxcsr %0" : "=m"(mxcsr));
    mxcsr &= ~(0x003F|0x0680); /* clear exn flags, unmask OM, ZM, IM (not PM, UM, DM) */
    __asm__ __volatile__("ldmxcsr %0" : : "m"(mxcsr));
}

#if defined(__x86_64__)

static inline int cpu_has_sse2(void) { return 1; }

#else /* !__x86_64__ */

/*
 * Check if an x86-32 processor has SSE2.
 */
static unsigned int xor_eflags(unsigned int mask)
{
    unsigned int eax, edx;

    eax = mask;			/* eax = mask */
    __asm__("pushfl\n\t"
	    "popl %0\n\t"	/* edx = original EFLAGS */
	    "xorl %0, %1\n\t"	/* eax = mask ^ EFLAGS */
	    "pushl %1\n\t"
	    "popfl\n\t"		/* new EFLAGS = mask ^ original EFLAGS */
	    "pushfl\n\t"
	    "popl %1\n\t"	/* eax = new EFLAGS */
	    "xorl %0, %1\n\t"	/* eax = new EFLAGS ^ old EFLAGS */
	    "pushl %0\n\t"
	    "popfl"		/* restore original EFLAGS */
	    : "=d"(edx), "=a"(eax)
	    : "1"(eax));
    return eax;
}

static __inline__ unsigned int cpuid_eax(unsigned int op)
{
    unsigned int eax, save_ebx;

    /* In PIC mode i386 reserves EBX. So we must save
       and restore it ourselves to not upset gcc. */
    __asm__(
	"movl %%ebx, %1\n\t"
	"cpuid\n\t"
	"movl %1, %%ebx"
	: "=a"(eax), "=m"(save_ebx)
	: "0"(op)
	: "cx", "dx");
    return eax;
}

static __inline__ unsigned int cpuid_edx(unsigned int op)
{
    unsigned int eax, edx, save_ebx;
 
    /* In PIC mode i386 reserves EBX. So we must save
       and restore it ourselves to not upset gcc. */
    __asm__(
	"movl %%ebx, %2\n\t"
	"cpuid\n\t"
	"movl %2, %%ebx"
	: "=a"(eax), "=d"(edx), "=m"(save_ebx)
	: "0"(op)
	: "cx");
    return edx;
}

/* The AC bit, bit #18, is a new bit introduced in the EFLAGS
 * register on the Intel486 processor to generate alignment
 * faults. This bit cannot be set on the Intel386 processor.
 */
static __inline__ int is_386(void)
{
    return ((xor_eflags(1<<18) >> 18) & 1) == 0;
}

/* Newer x86 processors have a CPUID instruction, as indicated by
 * the ID bit (#21) in EFLAGS being modifiable.
 */
static __inline__ int has_CPUID(void)
{
    return (xor_eflags(1<<21) >> 21) & 1;
}

static int cpu_has_sse2(void)
{
    unsigned int maxlev, features;
    static int has_sse2 = -1;

    if (has_sse2 >= 0)
	return has_sse2;
    has_sse2 = 0;

    if (is_386())
	return 0;
    if (!has_CPUID())
	return 0;
    maxlev = cpuid_eax(0);
    /* Intel A-step Pentium had a preliminary version of CPUID.
       It also didn't have SSE2. */
    if ((maxlev & 0xFFFFFF00) == 0x0500)
	return 0;
    /* If max level is zero then CPUID cannot report any features. */
    if (maxlev == 0)
	return 0;
    features = cpuid_edx(1);
    has_sse2 = (features & (1 << 26)) != 0;

    return has_sse2;
}
#endif /* !__x86_64__ */

static void unmask_fpe(void)
{
    unmask_x87();
    if (cpu_has_sse2())
	unmask_sse2();
}

static __inline__ int check_fpe(double f)
{
    __asm__ __volatile__("fwait" : "=m"(erl_fp_exception) : "m"(f));
    if (!erl_fp_exception)
       return 0;
    __asm__ __volatile__("fninit");
    unmask_fpe();
    return 1;
}

#elif defined(__sparc__) && defined(__linux__)

#if defined(__arch64__)
#define LDX "ldx"
#define STX "stx"
#else
#define LDX "ld"
#define STX "st"
#endif

static void unmask_fpe(void)
{
    unsigned long fsr;

    __asm__(STX " %%fsr, %0" : "=m"(fsr));
    fsr &= ~(0x1FUL << 23);	/* clear FSR[TEM] field */
    fsr |= (0x1AUL << 23);	/* enable NV, OF, DZ exceptions */
    __asm__ __volatile__(LDX " %0, %%fsr" : : "m"(fsr));
}

static __inline__ int check_fpe(double f)
{
    __asm__ __volatile__("" : "=m"(erl_fp_exception) : "em"(f));
    return erl_fp_exception;
}

#elif (defined(__powerpc__) && defined(__linux__)) || (defined(__ppc__) && defined(__DARWIN__))

#if defined(__linux__)

#include <sys/prctl.h>

static void set_fpexc_precise(void)
{
    if (prctl(PR_SET_FPEXC, PR_FP_EXC_PRECISE) < 0) {
	perror("PR_SET_FPEXC");
	exit(1);
    }
}

#elif defined(__DARWIN__)

#include <mach/mach.h>
#include <pthread.h>

/*
 * FE0 FE1	MSR bits
 *  0   0	floating-point exceptions disabled
 *  0   1	floating-point imprecise nonrecoverable
 *  1   0	floating-point imprecise recoverable
 *  1   1	floating-point precise mode
 *
 * Apparently:
 * - Darwin 5.5 (MacOS X <= 10.1) starts with FE0 == FE1 == 0,
 *   and resets FE0 and FE1 to 0 after each SIGFPE.
 * - Darwin 6.0 (MacOS X 10.2) starts with FE0 == FE1 == 1,
 *   and does not reset FE0 or FE1 after a SIGFPE.
 */
#define FE0_MASK	(1<<11)
#define FE1_MASK	(1<<8)

/* a thread cannot get or set its own MSR bits */
static void *fpu_fpe_enable(void *arg)
{
    thread_t t = *(thread_t*)arg;
    struct ppc_thread_state state;
    unsigned int state_size = PPC_THREAD_STATE_COUNT;

    if (thread_get_state(t, PPC_THREAD_STATE, (natural_t*)&state, &state_size) != KERN_SUCCESS) {
	perror("thread_get_state");
	exit(1);
    }
    if ((state.srr1 & (FE1_MASK|FE0_MASK)) != (FE1_MASK|FE0_MASK)) {
#if 0
	/* This would also have to be performed in the SIGFPE handler
	   to work around the MSR reset older Darwin releases do. */
	state.srr1 |= (FE1_MASK|FE0_MASK);
	thread_set_state(t, PPC_THREAD_STATE, (natural_t*)&state, state_size);
#else
	fprintf(stderr, "srr1 == 0x%08x, your Darwin is too old\n", state.srr1);
	exit(1);
#endif
    }
    return NULL; /* Ok, we appear to be on Darwin 6.0 or later */
}

static void set_fpexc_precise(void)
{
    thread_t self = mach_thread_self();
    pthread_t enabler;

    if (pthread_create(&enabler, NULL, fpu_fpe_enable, &self)) {
	perror("pthread_create");
    } else if (pthread_join(enabler, NULL)) {
	perror("pthread_join");
    }
}

#endif

static void set_fpscr(unsigned int fpscr)
{
    union {
	double d;
	unsigned int fpscr[2];
    } u;
    u.fpscr[0] = 0xFFF80000;
    u.fpscr[1] = fpscr;
    __asm__ __volatile__("mtfsf 255,%0" : : "f"(u.d));
}

static void unmask_fpe(void)
{
    set_fpexc_precise();
    set_fpscr(0x80|0x40|0x10);	/* VE, OE, ZE; not UE or XE */
}

static __inline__ int check_fpe(double f)
{
    __asm__ __volatile__("" : "=m"(erl_fp_exception) : "fm"(f));
    return erl_fp_exception;
}

#else

#include <ieeefp.h>

#define unmask_fpe()   fpsetmask(FP_X_INV | FP_X_OFL | FP_X_DZ)

static __inline__ int check_fpe(double f)
{
    __asm__ __volatile__("" : "=m"(erl_fp_exception) : "g"(f));
    return erl_fp_exception;
}

#endif

/*
 * Implement SIGFPE handler based on CPU/OS combination
 */

#if (defined(__linux__) && (defined(__i386__) || defined(__x86_64__) || defined(__sparc__) || defined(__powerpc__))) || (defined(__DARWIN__) && (defined(__i386__) || defined(__x86_64__) || defined(__ppc__))) || (defined(__FreeBSD__) && (defined(__i386__) || defined(__x86_64__))) || ((defined(__OpenBSD__) || defined(__NetBSD__)) && defined(__x86_64__)) || (defined(__sun__) && defined(__x86_64__))

#if defined(__linux__) && defined(__i386__)
#if !defined(X86_FXSR_MAGIC)
#define X86_FXSR_MAGIC 0x0000
#endif
#elif defined(__FreeBSD__) && defined(__i386__)
#include <sys/types.h>
#include <machine/npx.h>
#elif defined(__FreeBSD__) && defined(__x86_64__)
#include <sys/types.h>
#include <machine/fpu.h>
#elif defined(__DARWIN__)
#include <machine/signal.h>
#elif defined(__OpenBSD__) && defined(__x86_64__)
#include <sys/types.h>
#include <machine/fpu.h>
#endif
#if !(defined(__OpenBSD__) && defined(__x86_64__))
#include <ucontext.h>
#endif
#include <string.h>

static void fpe_sig_action(int sig, siginfo_t *si, void *puc)
{
    ucontext_t *uc = puc;
#if defined(__linux__)
#if defined(__x86_64__)
    mcontext_t *mc = &uc->uc_mcontext;
    fpregset_t fpstate = mc->fpregs;
    fpstate->mxcsr = 0x1F80;
    fpstate->swd &= ~0xFF;
#elif defined(__i386__)
    mcontext_t *mc = &uc->uc_mcontext;
    fpregset_t fpstate = mc->fpregs;
    if ((fpstate->status >> 16) == X86_FXSR_MAGIC)
	((struct _fpstate*)fpstate)->mxcsr = 0x1F80;
    fpstate->sw &= ~0xFF;
#elif defined(__sparc__) && defined(__arch64__)
    /* on SPARC the 3rd parameter points to a sigcontext not a ucontext */
    struct sigcontext *sc = (struct sigcontext*)puc;
    sc->sigc_regs.tpc = sc->sigc_regs.tnpc;
    sc->sigc_regs.tnpc += 4;
#elif defined(__sparc__)
    /* on SPARC the 3rd parameter points to a sigcontext not a ucontext */
    struct sigcontext *sc = (struct sigcontext*)puc;
    sc->si_regs.pc = sc->si_regs.npc;
    sc->si_regs.npc = (unsigned long)sc->si_regs.npc + 4;
#elif defined(__powerpc__)
#if defined(__powerpc64__)
    mcontext_t *mc = &uc->uc_mcontext;
    unsigned long *regs = &mc->gp_regs[0];
#else
    mcontext_t *mc = uc->uc_mcontext.uc_regs;
    unsigned long *regs = &mc->gregs[0];
#endif
    regs[PT_NIP] += 4;
    regs[PT_FPSCR] = 0x80|0x40|0x10;	/* VE, OE, ZE; not UE or XE */
#endif
#elif defined(__DARWIN__)
#if defined(DARWIN_MODERN_MCONTEXT)
#if defined(__x86_64__)
    mcontext_t mc = uc->uc_mcontext;
    struct __darwin_x86_float_state64 *fpstate = &mc->__fs;
    fpstate->__fpu_mxcsr = 0x1F80;
    *(unsigned short *)&fpstate->__fpu_fsw &= ~0xFF;
#elif defined(__i386__)
    mcontext_t mc = uc->uc_mcontext;
    struct __darwin_i386_float_state *fpstate = &mc->__fs;
    fpstate->__fpu_mxcsr = 0x1F80;
    *(unsigned short *)&fpstate->__fpu_fsw &= ~0xFF;
#elif defined(__ppc__)
    mcontext_t mc = uc->uc_mcontext;
    mc->ss.srr0 += 4;
    mc->fs.fpscr = 0x80|0x40|0x10;
#endif
#else
#if defined(__x86_64__)
    mcontext_t mc = uc->uc_mcontext;
    struct x86_float_state64_t *fpstate = &mc->fs;
    fpstate->fpu_mxcsr = 0x1F80;
    *(unsigned short *)&fpstate->fpu_fsw &= ~0xFF;
#elif defined(__i386__)
    mcontext_t mc = uc->uc_mcontext;
    x86_float_state32_t	*fpstate = &mc->fs;
    fpstate->fpu_mxcsr = 0x1F80;
    *(unsigned short *)&fpstate->fpu_fsw &= ~0xFF;
#elif defined(__ppc__)
    mcontext_t mc = uc->uc_mcontext;
    mc->ss.srr0 += 4;
    mc->fs.fpscr = 0x80|0x40|0x10;
#endif
#endif
#elif defined(__FreeBSD__) && defined(__x86_64__)
    mcontext_t *mc = &uc->uc_mcontext;
    struct savefpu *savefpu = (struct savefpu*)&mc->mc_fpstate;
    struct envxmm *envxmm = &savefpu->sv_env;
    envxmm->en_mxcsr = 0x1F80;
    envxmm->en_sw &= ~0xFF;
#elif defined(__FreeBSD__) && defined(__i386__)
    mcontext_t *mc = &uc->uc_mcontext;
    union savefpu *savefpu = (union savefpu*)&mc->mc_fpstate;
    if (mc->mc_fpformat == _MC_FPFMT_XMM) {
	struct envxmm *envxmm = &savefpu->sv_xmm.sv_env;
	envxmm->en_mxcsr = 0x1F80;
	envxmm->en_sw &= ~0xFF;
    } else {
	struct env87 *env87 = &savefpu->sv_87.sv_env;
	env87->en_sw &= ~0xFF;
    }
#elif defined(__OpenBSD__) && defined(__x86_64__)
    struct fxsave64 *fxsave = uc->sc_fpstate;
    fxsave->fx_mxcsr = 0x1F80;
    fxsave->fx_fsw &= ~0xFF;
#elif defined(__NetBSD__) && defined(__x86_64__)
    mcontext_t *mc = &uc->uc_mcontext;
    struct fxsave64 *fxsave = (struct fxsave64 *)&mc->__fpregs;
    fxsave->fx_mxcsr = 0x1F80;
    fxsave->fx_fsw &= ~0xFF;
#elif defined(__sun__) && defined(__x86_64__)
    mcontext_t *mc = &uc->uc_mcontext;
    struct fpchip_state *fpstate = &mc->fpregs.fp_reg_set.fpchip_state;
    fpstate->mxcsr = 0x1F80;
    fpstate->sw &= ~0xFF;
#endif
    new_fp_exception();
}

static void catch_sigfpe(void)
{
    struct sigaction act;

    memset(&act, 0, sizeof act);
    act.sa_sigaction = fpe_sig_action;
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGFPE, &act, NULL);
}

#else

static void fpe_sig_handler(int sig)
{
    new_fp_exception();
}

static void catch_sigfpe(void)
{
    signal(SIGFPE, fpe_sig_handler);
}

#endif

/*
 * Generic test code
 */

static void do_init(void)
{
    catch_sigfpe();
    unmask_fpe();
}

double a = 3.23e133;
double b = 3.57e257;
double res;

void do_fmul(void)
{
    res = a * b;
}

int do_check(void)
{
    if (check_fpe(res)) {
       fprintf(stderr, "res = %g, FPE worked\n", res);
       return 0;
    } else {
       fprintf(stderr, "res = %g, FPE failed\n", res);
       return 1;
    }
}

int main(int argc, const char **argv)
{
    if (argc == 3) {
       a = atof(argv[1]);
       b = atof(argv[2]);
    }
    do_init();
    do_fmul();
    return do_check();
}
