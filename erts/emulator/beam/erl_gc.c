/*
 * %CopyrightBegin%
 *
 * Copyright Ericsson AB 2002-2016. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * %CopyrightEnd%
 */
#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#define ERL_WANT_GC_INTERNALS__

#include "sys.h"
#include "erl_vm.h"
#include "global.h"
#include "erl_process.h"
#include "erl_db.h"
#include "beam_catches.h"
#include "erl_binary.h"
#include "erl_bits.h"
#include "erl_map.h"
#include "error.h"
#include "big.h"
#include "erl_gc.h"
#if HIPE
#include "hipe_stack.h"
#include "hipe_mode_switch.h"
#endif
#include "dtrace-wrapper.h"
#include "erl_bif_unique.h"
#include "dist.h"

#include "erl_gc_internal.h"


static ERTS_INLINE int
gc_cost(Uint gc_moved_live_words, Uint resize_moved_words)
{
    Sint reds;

    reds = gc_moved_live_words/10;
    reds += resize_moved_words/100;
    if (reds < 1)
	return 1;
    if (reds > INT_MAX)
	return INT_MAX;
    return (int) reds;
}

ERTS_SCHED_PREF_QUICK_ALLOC_IMPL(gcireq,
                                 ErtsGCInfoReq,
                                 5,
                                 ERTS_ALC_T_GC_INFO_REQ)
/*
 * Initialize GC global data.
 */
void
erts_init_gc(void)
{
    int i = 0, ix;
    Sint max_heap_size = 0;

    ERTS_CT_ASSERT(offsetof(ProcBin,thing_word) == offsetof(OffheapHeader,thing_word));
    ERTS_CT_ASSERT(offsetof(ProcBin,thing_word) == offsetof(ErlFunThing,thing_word));
    ERTS_CT_ASSERT(offsetof(ProcBin,thing_word) == offsetof(ExternalThing,header));
    ERTS_CT_ASSERT(offsetof(ProcBin,size) == offsetof(OffheapHeader,size));
    ERTS_CT_ASSERT(offsetof(ProcBin,size) == offsetof(ErlSubBin,size));
    ERTS_CT_ASSERT(offsetof(ProcBin,size) == offsetof(ErlHeapBin,size));
    ERTS_CT_ASSERT(offsetof(ProcBin,next) == offsetof(OffheapHeader,next));
    ERTS_CT_ASSERT(offsetof(ProcBin,next) == offsetof(ErlFunThing,next));
    ERTS_CT_ASSERT(offsetof(ProcBin,next) == offsetof(ExternalThing,next));

    erts_test_long_gc_sleep = 0;

    /*
     * Heap sizes start growing in a Fibonacci sequence.
     *
     * Fib growth is not really ok for really large heaps, for
     * example is fib(35) == 14meg, whereas fib(36) == 24meg;
     * we really don't want that growth when the heaps are that big.
     */

    /* Growth stage 1 - Fibonacci + 1*/
    /* 12,38 will hit size 233, the old default */

    heap_sizes[0] = 12;
    heap_sizes[1] = 38;

    for(i = 2; i < 23; i++) {
        /* one extra word for block header */
        heap_sizes[i] = heap_sizes[i-1] + heap_sizes[i-2] + 1;
    }


    /* for 32 bit we want max_heap_size to be MAX(32bit) / 4 [words]
     * for 64 bit we want max_heap_size to be MAX(52bit) / 8 [words]
     */

    max_heap_size = sizeof(Eterm) < 8 ? (Sint)((~(Uint)0)/(sizeof(Eterm))) :
					(Sint)(((Uint64)1 << 53)/sizeof(Eterm));

    /* Growth stage 2 - 20% growth */
    /* At 1.3 mega words heap, we start to slow down. */
    for (i = 23; i < ARRAY_LENGTH(heap_sizes); i++) {
	heap_sizes[i] = heap_sizes[i-1] + heap_sizes[i-1]/5;
	if ((heap_sizes[i] < 0) || heap_sizes[i] > max_heap_size) {
	    /* Size turned negative. Discard this last size. */
	    i--;
	    break;
	}
    }
    num_heap_sizes = i;

    for (ix = 0; ix < erts_no_schedulers; ix++) {
      ErtsSchedulerData *esdp = ERTS_SCHEDULER_IX(ix);
      init_gc_info(&esdp->gc_info);
    }

    init_gcireq_alloc();
}

/*
 * Find the next heap size equal to or greater than the given size (if offset == 0).
 *
 * If offset is 1, the next higher heap size is returned (always greater than size).
 */
Uint
erts_next_heap_size(Uint size, Uint offset)
{
    if (size < heap_sizes[0]) {
	return heap_sizes[0];
    } else {
	Sint* low = heap_sizes;
	Sint* high = heap_sizes + num_heap_sizes;
	Sint* mid;

	while (low < high) {
	    mid = low + (high-low) / 2;
	    if (size < mid[0]) {
		high = mid;
	    } else if (size == mid[0]) {
		ASSERT(mid+offset-heap_sizes < num_heap_sizes);
		return mid[offset];
	    } else if (size < mid[1]) {
		ASSERT(mid[0] < size && size <= mid[1]);
		ASSERT(mid+offset-heap_sizes < num_heap_sizes);
		return mid[offset+1];
	    } else {
		low = mid + 1;
	    }
	}
	erts_exit(ERTS_ERROR_EXIT, "no next heap size found: %beu, offset %beu\n", size, offset);
    }
    return 0;
}
/*
 * Return the next heap size to use. Make sure we never return
 * a smaller heap size than the minimum heap size for the process.
 * (Use of the erlang:hibernate/3 BIF could have shrinked the
 * heap below the minimum heap size.)
 */
static Uint
next_heap_size(Process* p, Uint size, Uint offset)
{
    size = erts_next_heap_size(size, offset);
    return size < p->min_heap_size ? p->min_heap_size : size;
}

Eterm
erts_heap_sizes(Process* p)
{
    int i;
    int n = 0;
    int big = 0;
    Eterm res = NIL;
    Eterm* hp;
    Eterm* bigp;

    for (i = num_heap_sizes-1; i >= 0; i--) {
	n += 2;
	if (!MY_IS_SSMALL(heap_sizes[i])) {
	    big += BIG_UINT_HEAP_SIZE;
	}
    }

    /*
     * We store all big numbers first on the heap, followed
     * by all the cons cells.
     */
    bigp = HAlloc(p, n+big);
    hp = bigp+big;
    for (i = num_heap_sizes-1; i >= 0; i--) {
	Eterm num;
	Sint sz = heap_sizes[i];

	if (MY_IS_SSMALL(sz)) {
	    num = make_small(sz);
	} else {
	    num = uint_to_big(sz, bigp);
	    bigp += BIG_UINT_HEAP_SIZE;
	}
        res = CONS(hp, num, res);
        hp += 2;
    }
    return res;
}

void
erts_offset_heap(Eterm* hp, Uint sz, Sint offs, Eterm* low, Eterm* high)
{
    offset_heap(hp, sz, offs, (char*) low, ((char *)high)-((char *)low));
}

void
erts_offset_heap_ptr(Eterm* hp, Uint sz, Sint offs,
		     Eterm* low, Eterm* high)
{
    offset_heap_ptr(hp, sz, offs, (char *) low, ((char *)high)-((char *)low));
}


#define ptr_within(ptr, low, high) ((ptr) < (high) && (ptr) >= (low))

void
erts_offset_off_heap(ErlOffHeap *ohp, Sint offs, Eterm* low, Eterm* high)
{
    if (ohp->first && ptr_within((Eterm *)ohp->first, low, high)) {
        Eterm** uptr = (Eterm**) (void *) &ohp->first;
        *uptr += offs;
    }
}
#undef ptr_within

Eterm
erts_gc_after_bif_call_lhf(Process* p, ErlHeapFragment *live_hf_end,
			   Eterm result, Eterm* regs, Uint arity)
{
    int cost;

    if (p->flags & F_HIBERNATE_SCHED) {
	/*
	 * We just hibernated. We do *not* want to mess
	 * up the hibernation by an ordinary GC...
	 */
	return result;
    }

    if (is_non_value(result)) {
	if (p->freason == TRAP) {
	  #if HIPE
	    if (regs == NULL) {
		regs = erts_proc_sched_data(p)->x_reg_array;
	    }
	  #endif
	    cost = garbage_collect(p, live_hf_end, 0, regs, p->arity, p->fcalls);
	} else {
	    cost = garbage_collect(p, live_hf_end, 0, regs, arity, p->fcalls);
	}
    } else {
	Eterm val[1];

	val[0] = result;
	cost = garbage_collect(p, live_hf_end, 0, val, 1, p->fcalls);
	result = val[0];
    }
    BUMP_REDS(p, cost);

    return result;
}

Eterm
erts_gc_after_bif_call(Process* p, Eterm result, Eterm* regs, Uint arity)
{
    return erts_gc_after_bif_call_lhf(p, ERTS_INVALID_HFRAG_PTR,
				      result, regs, arity);
}

#ifdef DEBUG
static ERTS_FORCE_INLINE int
debug_is_in_one_of_process_heaps(Process *p, void *ptr) {
    return is_between(ptr, HEAP_START(p), HEAP_TOP(p))
            || is_between(ptr, OLD_HEAP(p), OLD_HTOP(p));
}
#endif

static ERTS_INLINE void reset_active_writer(Process *p)
{
    OffheapHeader* ptr;
    ptr = MSO(p).first;
    while (ptr) {
        ASSERT(debug_is_in_one_of_process_heaps(p, ptr));
	if (ptr->thing_word == HEADER_PROC_BIN) {
	    ProcBin *pbp = (ProcBin*) ptr;
	    pbp->flags &= ~PB_ACTIVE_WRITER;
	}
	ptr = ptr->next;
    }
}

#define ERTS_DELAY_GC_EXTRA_FREE 40
#define ERTS_ABANDON_HEAP_COST 10

static int
delay_garbage_collection(Process *p, ErlHeapFragment *live_hf_end, int need, int fcalls)
{
    ErlHeapFragment *hfrag;
    Eterm *orig_heap, *orig_hend, *orig_htop, *orig_stop;
    Eterm *stop, *hend;
    Uint hsz, ssz;
    int reds_left;

    ERTS_HOLE_CHECK(p);

    if ((p->flags & F_DISABLE_GC)
	&& p->live_hf_end == ERTS_INVALID_HFRAG_PTR) {
	/*
	 * A BIF yielded with disabled GC. Remember
	 * heap fragments created by the BIF until we
	 * do next GC.
	 */
	p->live_hf_end = live_hf_end;
    }

    if (need == 0)
	return 1;

    /*
     * Satisfy need in a heap fragment...
     */
    ASSERT(need > 0);

    orig_heap = p->heap;
    orig_hend = p->hend;
    orig_htop = p->htop;
    orig_stop = p->stop;

    ssz = orig_hend - orig_stop;
    hsz = ssz + need + ERTS_DELAY_GC_EXTRA_FREE;

    hfrag = new_message_buffer(hsz);
    hfrag->next = p->mbuf;
    p->mbuf = hfrag;
    p->mbuf_sz += hsz;
    p->heap = p->htop = &hfrag->mem[0];
    p->hend = hend = &hfrag->mem[hsz];
    p->stop = stop = hend - ssz;
    sys_memcpy((void *) stop, (void *) orig_stop, ssz * sizeof(Eterm));

    if (p->abandoned_heap) {
	/* Active heap already in a fragment; adjust it... */
	ErlHeapFragment *hfrag = ((ErlHeapFragment *)
				  (((char *) orig_heap)
				   - offsetof(ErlHeapFragment, mem)));
	Uint unused = orig_hend - orig_htop;
	ASSERT(hfrag->used_size == hfrag->alloc_size);
	ASSERT(hfrag->used_size >= unused);
	hfrag->used_size -= unused;
	p->mbuf_sz -= unused;
    }
    else {
	/* Do not leave a hole in the abandoned heap... */
	if (orig_htop < orig_hend) {
	    *orig_htop = make_pos_bignum_header(orig_hend-orig_htop-1);
	    if (orig_htop + 1 < orig_hend) {
		orig_hend[-1] = (Uint) (orig_htop - orig_heap);
		p->flags |= F_ABANDONED_HEAP_USE;
	    }
	}
	p->abandoned_heap = orig_heap;
    }

#ifdef CHECK_FOR_HOLES
    p->last_htop = p->htop;
    p->heap_hfrag = hfrag;
#endif

    /* Make sure that we do a proper GC as soon as possible... */
    p->flags |= F_FORCE_GC;
    reds_left = ERTS_REDS_LEFT(p, fcalls);
    ASSERT(CONTEXT_REDS - reds_left >= erts_proc_sched_data(p)->virtual_reds);

    if (reds_left > ERTS_ABANDON_HEAP_COST) {
	int vreds = reds_left - ERTS_ABANDON_HEAP_COST;
	erts_proc_sched_data((p))->virtual_reds += vreds;
    }

    ASSERT(CONTEXT_REDS >= erts_proc_sched_data(p)->virtual_reds);
    return reds_left;
}

static ERTS_FORCE_INLINE Uint
young_gen_usage(Process *p)
{
    Uint hsz;
    Eterm *aheap;

    hsz = p->mbuf_sz;

    if (p->flags & F_ON_HEAP_MSGQ) {
	ErtsMessage *mp;
	for (mp = p->msg.first; mp; mp = mp->next)
	    if (mp->data.attached)
		hsz += erts_msg_attached_data_size(mp);
    }

    aheap = p->abandoned_heap;
    if (!aheap)
	hsz += p->htop - p->heap;
    else {
	/* used in orig heap */
	if (p->flags & F_ABANDONED_HEAP_USE)
	    hsz += aheap[p->heap_sz-1];
	else
	    hsz += p->heap_sz;
	/* Remove unused part in latest fragment */
	hsz -= p->hend - p->htop;
    }
    return hsz;
}

#define ERTS_GET_ORIG_HEAP(Proc, Heap, HTop)			\
    do {							\
	Eterm *aheap__ = (Proc)->abandoned_heap;		\
	if (!aheap__) {						\
	    (Heap) = (Proc)->heap;				\
	    (HTop) = (Proc)->htop;				\
	}							\
	else {							\
	    (Heap) = aheap__;					\
	    if ((Proc)->flags & F_ABANDONED_HEAP_USE)		\
		(HTop) = aheap__ + aheap__[(Proc)->heap_sz-1];	\
	    else						\
		(HTop) = aheap__ + (Proc)->heap_sz;		\
	}							\
    } while (0)

/*
 * Garbage collect a process.
 *
 * p: Pointer to the process structure.
 * need: Number of Eterm words needed on the heap.
 * objv: Array of terms to add to rootset; that is to preserve.
 * nobj: Number of objects in objv.
 */
static int
garbage_collect(Process* p, ErlHeapFragment *live_hf_end,
		int need, Eterm* objv, int nobj, int fcalls)
{
    Uint reclaimed_now = 0;
    Eterm gc_trace_end_tag;
    int reds;
    ErtsMonotonicTime start_time = 0; /* Shut up faulty warning... */
    ErtsSchedulerData *esdp;
    erts_aint32_t state;
    ERTS_MSACC_PUSH_STATE_M();
#ifdef USE_VM_PROBES
    DTRACE_CHARBUF(pidbuf, DTRACE_TERM_BUF_SIZE);
#endif

    ASSERT(CONTEXT_REDS - ERTS_REDS_LEFT(p, fcalls)
	   >= erts_proc_sched_data(p)->virtual_reds);

    state = erts_smp_atomic32_read_nob(&p->state);

    if (p->flags & (F_DISABLE_GC|F_DELAY_GC) || state & ERTS_PSFLG_EXITING)
	return delay_garbage_collection(p, live_hf_end, need, fcalls);

    if (p->abandoned_heap)
	live_hf_end = ERTS_INVALID_HFRAG_PTR;
    else if (p->live_hf_end != ERTS_INVALID_HFRAG_PTR)
	live_hf_end = p->live_hf_end;

    ERTS_MSACC_SET_STATE_CACHED_M(ERTS_MSACC_STATE_GC);

    esdp = erts_get_scheduler_data();

    erts_smp_atomic32_read_bor_nob(&p->state, ERTS_PSFLG_GC);
    if (erts_system_monitor_long_gc != 0)
	start_time = erts_get_monotonic_time(esdp);

    ERTS_CHK_OFFHEAP(p);

    ErtsGcQuickSanityCheck(p);

#ifdef USE_VM_PROBES
    *pidbuf = '\0';
    if (DTRACE_ENABLED(gc_major_start)
        || DTRACE_ENABLED(gc_major_end)
        || DTRACE_ENABLED(gc_minor_start)
        || DTRACE_ENABLED(gc_minor_end)) {
        dtrace_proc_str(p, pidbuf);
    }
#endif
    /*
     * Test which type of GC to do.
     */

    if (GEN_GCS(p) < MAX_GEN_GCS(p) && !(FLAGS(p) & F_NEED_FULLSWEEP)) {
        if (IS_TRACED_FL(p, F_TRACE_GC)) {
            trace_gc(p, am_gc_minor_start, need, THE_NON_VALUE);
        }
        DTRACE2(gc_minor_start, pidbuf, need);
        reds = minor_collection(p, live_hf_end, need, objv, nobj, &reclaimed_now);
        DTRACE2(gc_minor_end, pidbuf, reclaimed_now);
        if (reds == -1) {
            if (IS_TRACED_FL(p, F_TRACE_GC)) {
                trace_gc(p, am_gc_minor_end, reclaimed_now, THE_NON_VALUE);
            }
            goto do_major_collection;
        }
        gc_trace_end_tag = am_gc_minor_end;
    } else {
do_major_collection:
        ERTS_MSACC_SET_STATE_CACHED_M_X(ERTS_MSACC_STATE_GC_FULL);
        if (IS_TRACED_FL(p, F_TRACE_GC)) {
            trace_gc(p, am_gc_major_start, need, THE_NON_VALUE);
        }
        DTRACE2(gc_major_start, pidbuf, need);
        reds = major_collection(p, live_hf_end, need, objv, nobj, &reclaimed_now);
        DTRACE2(gc_major_end, pidbuf, reclaimed_now);
        gc_trace_end_tag = am_gc_major_end;
        ERTS_MSACC_SET_STATE_CACHED_M_X(ERTS_MSACC_STATE_GC);
    }

    reset_active_writer(p);

    /*
     * Finish.
     */

    ERTS_CHK_OFFHEAP(p);

    ErtsGcQuickSanityCheck(p);

    /* Max heap size has been reached and the process was configured
       to be killed, so we kill it and set it in a delayed garbage
       collecting state. There should be no gc_end trace or
       long_gc/large_gc triggers when this happens as process was
       killed before a GC could be done. */
    if (reds == -2) {
        ErtsProcLocks locks = ERTS_PROC_LOCKS_ALL;
        int res;

        erts_smp_proc_lock(p, ERTS_PROC_LOCKS_ALL_MINOR);
        erts_send_exit_signal(p, p->common.id, p, &locks,
                              am_kill, NIL, NULL, 0);
        erts_smp_proc_unlock(p, locks & ERTS_PROC_LOCKS_ALL_MINOR);

        /* erts_send_exit_signal looks for ERTS_PSFLG_GC, so
           we have to remove it after the signal is sent */
        erts_smp_atomic32_read_band_nob(&p->state, ~ERTS_PSFLG_GC);

        /* We have to make sure that we have space for need on the heap */
        res = delay_garbage_collection(p, live_hf_end, need, fcalls);
        ERTS_MSACC_POP_STATE_M();
        return res;
    }

    erts_smp_atomic32_read_band_nob(&p->state, ~ERTS_PSFLG_GC);

    if (IS_TRACED_FL(p, F_TRACE_GC)) {
        trace_gc(p, gc_trace_end_tag, reclaimed_now, THE_NON_VALUE);
    }

    if (erts_system_monitor_long_gc != 0) {
	ErtsMonotonicTime end_time;
	Uint gc_time;
	if (erts_test_long_gc_sleep)
	    while (0 != erts_milli_sleep(erts_test_long_gc_sleep));
	end_time = erts_get_monotonic_time(esdp);
	gc_time = (Uint) ERTS_MONOTONIC_TO_MSEC(end_time - start_time);
	if (gc_time && gc_time > erts_system_monitor_long_gc) {
	    monitor_long_gc(p, gc_time);
	}
    }
    if (erts_system_monitor_large_heap != 0) {
	Uint size = HEAP_SIZE(p);
	size += OLD_HEAP(p) ? OLD_HEND(p) - OLD_HEAP(p) : 0;
	if (size >= erts_system_monitor_large_heap)
	    monitor_large_heap(p);
    }

    esdp->gc_info.garbage_cols++;
    esdp->gc_info.reclaimed += reclaimed_now;

    FLAGS(p) &= ~F_FORCE_GC;
    p->live_hf_end = ERTS_INVALID_HFRAG_PTR;

    ERTS_MSACC_POP_STATE_M();

#ifdef CHECK_FOR_HOLES
    /*
     * We intentionally do not rescan the areas copied by the GC.
     * We trust the GC not to leave any holes.
     */
    p->last_htop = p->htop;
    p->last_mbuf = 0;
#endif

#ifdef DEBUG
    /*
     * The scanning for pointers from the old_heap into the new_heap or
     * heap fragments turned out to be costly, so we remember how far we
     * have scanned this time and will start scanning there next time.
     * (We will not detect wild writes into the old heap, or modifications
     * of the old heap in-between garbage collections.)
     */
    p->last_old_htop = p->old_htop;
#endif

    return reds;
}

int
erts_garbage_collect_nobump(Process* p, int need, Eterm* objv, int nobj, int fcalls)
{
    int reds = garbage_collect(p, ERTS_INVALID_HFRAG_PTR, need, objv, nobj, fcalls);
    int reds_left = ERTS_REDS_LEFT(p, fcalls);
    if (reds > reds_left)
	reds = reds_left;
    ASSERT(CONTEXT_REDS - (reds_left - reds) >= erts_proc_sched_data(p)->virtual_reds);
    return reds;
}

void
erts_garbage_collect(Process* p, int need, Eterm* objv, int nobj)
{
    int reds = garbage_collect(p, ERTS_INVALID_HFRAG_PTR, need, objv, nobj, p->fcalls);
    BUMP_REDS(p, reds);
    ASSERT(CONTEXT_REDS - ERTS_BIF_REDS_LEFT(p)
	   >= erts_proc_sched_data(p)->virtual_reds);
}

/*
 * Place all living data on a the new heap; deallocate any old heap.
 * Meant to be used by hibernate/3.
 */
void
erts_garbage_collect_hibernate(Process* p)
{
    Uint heap_size;
    Eterm* heap;
    Eterm* htop;
    Uint actual_size;
    char* area;
    Uint area_size;
    Sint offs;
    int reds;

    if (p->flags & F_DISABLE_GC)
	ERTS_INTERNAL_ERROR("GC disabled");

    /*
     * Preliminaries.
     */
    erts_smp_atomic32_read_bor_nob(&p->state, ERTS_PSFLG_GC);
    ErtsGcQuickSanityCheck(p);
    ASSERT(p->stop == p->hend);	/* Stack must be empty. */

    /*
     * Do it.
     */


    heap_size = p->heap_sz + (p->old_htop - p->old_heap) + p->mbuf_sz;

    heap = (Eterm*) ERTS_HEAP_ALLOC(ERTS_ALC_T_TMP_HEAP,
				    sizeof(Eterm)*heap_size);
    htop = heap;

    {
        MatureArea mature_z = {NULL, 0};
        OldHeapArea oldheap_z = {NULL, 0};
        full_sweep_heaps(p,
                         1,
                         heap, &htop,
                         NULL, NULL,
                         mature_z,
                         oldheap_z,
                         p->arg_reg, p->arity);
    }

    ERTS_HEAP_FREE(ERTS_ALC_T_HEAP,
		   (p->abandoned_heap
		    ? p->abandoned_heap
		    : p->heap),
		   p->heap_sz * sizeof(Eterm));

    if (OLD_HEAP(p)) {
        ERTS_HEAP_FREE(
                ERTS_ALC_T_OLD_HEAP,
                OLD_HEAP(p),
                (OLD_HTOP(p) - OLD_HEAP(p)) * sizeof(Eterm));
        OLD_HEAP(p) = NULL;
        OLD_HTOP(p) = NULL;
        OLD_HEND(p) = NULL;
    }

    p->heap = heap;
    p->high_water = htop;
    p->htop = htop;
    p->hend = p->heap + heap_size;
    p->stop = p->hend;
    p->heap_sz = heap_size;

    heap_size = actual_size = p->htop - p->heap;
    if (heap_size == 0) {
	heap_size = 1; /* We want a heap... */
    }

    FLAGS(p) &= ~F_FORCE_GC;
    p->live_hf_end = ERTS_INVALID_HFRAG_PTR;

    /*
     * Move the heap to its final destination.
     *
     * IMPORTANT: We have garbage collected to a temporary heap and
     * then copy the result to a newly allocated heap of exact size.
     * This is intentional and important! Garbage collecting as usual
     * and then shrinking the heap by reallocating it caused serious
     * fragmentation problems when large amounts of processes were
     * hibernated.
     */

    ASSERT(p->hend - p->stop == 0); /* Empty stack */
    ASSERT(actual_size < p->heap_sz);

    heap = ERTS_HEAP_ALLOC(ERTS_ALC_T_HEAP, sizeof(Eterm)*heap_size);
    sys_memcpy((void *) heap, (void *) p->heap, actual_size*sizeof(Eterm));
    ERTS_HEAP_FREE(ERTS_ALC_T_TMP_HEAP, p->heap, p->heap_sz*sizeof(Eterm));

    remove_message_buffers(p);

    p->stop = p->hend = heap + heap_size;

    offs = heap - p->heap;
    area = (char *) p->heap;
    area_size = ((char *) p->htop) - area;
    offset_heap(heap, actual_size, offs, area, area_size);
    p->high_water = heap + (p->high_water - p->heap);
    offset_rootset(p, offs, area, area_size, p->arg_reg, p->arity);
    p->htop = heap + actual_size;
    p->heap = heap;
    p->heap_sz = heap_size;


#ifdef CHECK_FOR_HOLES
    p->last_htop = p->htop;
    p->last_mbuf = 0;
#endif
#ifdef DEBUG
    p->last_old_htop = NULL;
#endif

    /*
     * Finishing.
     */

    ErtsGcQuickSanityCheck(p);

    erts_smp_atomic32_read_band_nob(&p->state, ~ERTS_PSFLG_GC);

    reds = gc_cost(actual_size, actual_size);
    BUMP_REDS(p, reds);
}


/*
 * HiPE native code stack scanning procedures:
 * - fullsweep_nstack()
 * - gensweep_nstack()
 * - offset_nstack()
 * - sweep_literals_nstack()
 */
#if defined(HIPE)

#define GENSWEEP_NSTACK(p,old_htop,n_htop)				\
	do {								\
		Eterm *tmp_old_htop = old_htop;				\
		Eterm *tmp_n_htop = n_htop;				\
		gensweep_nstack((p), &tmp_old_htop, &tmp_n_htop);	\
		old_htop = tmp_old_htop;				\
		n_htop = tmp_n_htop;					\
	} while(0)

/*
 * offset_nstack() can ignore the descriptor-based traversal the other
 * nstack procedures use and simply call offset_heap_ptr() instead.
 * This relies on two facts:
 * 1. The only live non-Erlang terms on an nstack are return addresses,
 *    and they will be skipped thanks to the low/high range check.
 * 2. Dead values, even if mistaken for pointers into the low/high area,
 *    can be offset safely since they won't be dereferenced.
 *
 * XXX: WARNING: If HiPE starts storing other non-Erlang values on the
 * nstack, such as floats, then this will have to be changed.
 */
static ERTS_INLINE void offset_nstack(Process* p, Sint offs,
				      char* area, Uint area_size)
{
    if (p->hipe.nstack) {
	ASSERT(p->hipe.nsp && p->hipe.nstend);
	offset_heap_ptr(hipe_nstack_start(p), hipe_nstack_used(p),
			offs, area, area_size);
    }
    else {
	ASSERT(!p->hipe.nsp && !p->hipe.nstend);
    }
}

#else /* !HIPE */

#define fullsweep_nstack(p,n_htop)		        	(n_htop)
#define GENSWEEP_NSTACK(p,old_htop,n_htop)	        	do{}while(0)
#define offset_nstack(p,offs,area,area_size)	        	do{}while(0)
#define sweep_literals_nstack(p,old_htop,area,area_size)	(old_htop)

#endif /* HIPE */

void
erts_garbage_collect_literals(Process* p, Eterm* literals,
			      Uint byte_lit_size,
			      OffheapHeader* oh)
{
    Uint lit_size = byte_lit_size / sizeof(Eterm);
    Uint old_heap_size;
    Eterm* temp_lit;
    Sint offs;
    Rootset rootset;            /* Rootset for GC (stack, dictionary, etc). */
    Roots* roots;
    char* area;
    Uint area_size;
    Eterm* old_htop;
    Uint n;
    OffheapHeader** prev = NULL;

    if (p->flags & F_DISABLE_GC) {
        return;
    }

    /*
     * Set GC state.
     */
    erts_smp_atomic32_read_bor_nob(&p->state, ERTS_PSFLG_GC);

    /*
     * Assume the caller has already done a major collection. There are now
     * old from-heap and young from-heap. We will now allocate an old heap
     * to contain the literals.
     */

    if (p->old_heap != NULL) {
        /* Must NOT have an old heap, but if anything - run a full sweep,
         * evicting old heap. */
        ASSERT(0);
    }

    old_heap_size = erts_next_heap_size(lit_size, 0);
    p->old_heap = p->old_htop = (Eterm*) ERTS_HEAP_ALLOC(ERTS_ALC_T_OLD_HEAP,
							 sizeof(Eterm)*old_heap_size);
    p->old_hend = p->old_heap + old_heap_size;

    /*
     * We soon want to garbage collect the literals. But since a GC is
     * destructive (MOVED markers are written), we must copy the literals
     * to a temporary area and change all references to literals.
     */
    temp_lit = (Eterm *) erts_alloc(ERTS_ALC_T_TMP, byte_lit_size);
    sys_memcpy(temp_lit, literals, byte_lit_size);
    offs = temp_lit - literals;
    offset_heap(temp_lit, lit_size, offs, (char *) literals, byte_lit_size);
    offset_heap(p->heap, p->htop - p->heap, offs, (char *) literals, byte_lit_size);
    offset_rootset(p, offs, (char *) literals, byte_lit_size, p->arg_reg, p->arity);
    if (oh) {
	oh = (OffheapHeader *) ((Eterm *)(void *) oh + offs);
    }

    /*
     * Now the literals are placed in memory that is safe to write into,
     * so now we GC the literals into the old heap. First we go through the
     * rootset.
     */

    area = (char *) temp_lit;
    area_size = byte_lit_size;
    n = setup_rootset(p, p->arg_reg, p->arity, &rootset);

    /* TODO: Make this use generic_roots_sweep */
    roots = rootset.roots;
    old_htop = sweep_literals_nstack(p, p->old_htop, area, area_size);
    generic_roots_sweep(&rootset,
                        NULL, &old_htop, /* inout inout */
                        SweepOp_Literal, /* primary */
                        SweepOp_None,    /* secondary */
                        oh, mature);
#if 0
    while (n--) {
        Eterm* g_ptr = roots->v;
        Uint g_sz = roots->sz;
	Eterm* ptr;
	Eterm val;

	roots++;

        while (g_sz--) {
            Eterm gval = *g_ptr;

            switch (primary_tag(gval)) {
	    case TAG_PRIMARY_BOXED:
		ptr = boxed_val(gval);
		val = *ptr;
                if (IS_MOVED_BOXED(val)) {
		    ASSERT(is_boxed(val));
                    *g_ptr++ = val;
		} else if (ErtsInArea(ptr, area, area_size)) {
                    MOVE_BOXED(ptr,val,old_htop,g_ptr++);
		} else {
		    g_ptr++;
		}
		break;
	    case TAG_PRIMARY_LIST:
                ptr = list_val(gval);
                val = *ptr;
                if (IS_MOVED_CONS(val)) { /* Moved */
                    *g_ptr++ = ptr[1];
		} else if (ErtsInArea(ptr, area, area_size)) {
                    MOVE_CONS(ptr,val,old_htop,g_ptr++);
                } else {
		    g_ptr++;
		}
		break;
	    default:
                g_ptr++;
		break;
	    }
	}
    }
#endif //0
    ASSERT(p->old_htop <= old_htop && old_htop <= p->old_hend);
    cleanup_rootset(&rootset);

    /*
     * Now all references in the rootset to the literals have been updated.
     * Now we'll have to go through all heaps updating all other references.
     */

    /* TODO: make this use generic sweep */
    old_htop = sweep_literals_to_old_heap(p->heap, p->htop,
                                          old_htop,
                                          area, area_size);
    {
        OldHeapArea tmp_oldheap = {(const char *) p->old_heap,
                                   sizeof(Eterm) * old_heap_size};

        generic_sweep(p->old_heap, &old_htop, /* primary in out */
                      NULL, NULL,             /* no secondary */
                      SweepOp_Mature,         /* primary */
                      SweepOp_None,           /* secondary */
                      tmp_oldheap,
                      area, area_size);
    }
    ASSERT(p->old_htop <= old_htop && old_htop <= p->old_hend);
    p->old_htop = old_htop;

    /*
     * Prepare to sweep binaries. Since all MSOs on the new heap
     * must be come before MSOs on the old heap, find the end of
     * current MSO list and use that as a starting point.
     */

    if (oh) {
        prev = &MSO(p).first;
        while (*prev) {
            prev = &(*prev)->next;
        }
    }

    /*
     * Sweep through all binaries in the temporary literal area.
     */

    while (oh) {
	if (IS_MOVED_BOXED(oh->thing_word)) {
	    Binary* bptr;
	    OffheapHeader* ptr;

	    ptr = (OffheapHeader*) boxed_val(oh->thing_word);
	    ASSERT(thing_subtag(ptr->thing_word) == REFC_BINARY_SUBTAG);
	    bptr = ((ProcBin*)ptr)->val;

	    /*
	     * This binary has been copied to the heap.
	     * We must increment its reference count and
	     * link it into the MSO list for the process.
	     */

	    erts_refc_inc(&bptr->refc, 1);
	    *prev = ptr;
	    prev = &ptr->next;
	}
	oh = oh->next;
    }

    if (prev) {
        *prev = NULL;
    }

    /*
     * We no longer need this temporary area.
     */
    erts_free(ERTS_ALC_T_TMP, (void *) temp_lit);

    /*
     * Restore status.
     */
    erts_smp_atomic32_read_band_nob(&p->state, ~ERTS_PSFLG_GC);
}

static int
minor_collection(Process* p, ErlHeapFragment *live_hf_end,
		 int need, Eterm* objv, int nobj, Uint *recl)
{
    Uint size_before = young_gen_usage(p);
    MatureArea mature;
    mature.start = p->abandoned_heap ? (char *)p->abandoned_heap
                                     : (char *)p->heap;
    mature.bytes = (char *)p->high_water - mature.start;

    /*
     * Check if we have gone past the max heap size limit
     */

    if (MAX_HEAP_SIZE_GET(p)) {
        Uint heap_size = size_before,
            /* Note that we also count the un-allocated area
               in between the stack and heap */
            stack_size = HEAP_END(p) - HEAP_TOP(p),
            extra_heap_size,
            extra_old_heap_size = 0;

        /* Add potential old heap size */
        if (OLD_HEAP(p) == NULL && mature.bytes != 0) {
            extra_old_heap_size = erts_next_heap_size(size_before, 1);
            heap_size += extra_old_heap_size;
        } else if (OLD_HEAP(p))
            heap_size += OLD_HEND(p) - OLD_HEAP(p);

        /* Add potential new young heap size */
        extra_heap_size = next_heap_size(p, stack_size + size_before, 0);
        heap_size += extra_heap_size;

        if (heap_size > MAX_HEAP_SIZE_GET(p))
            if (reached_max_heap_size(p, heap_size, extra_heap_size, extra_old_heap_size))
                return -2;
    }

    /*
     * Allocate an old heap if we don't have one and if we'll need one.
     */

    if (OLD_HEAP(p) == NULL && mature.bytes != 0) {
        Eterm* n_old;

        /* Note: We choose a larger heap size than strictly needed,
         * which seems to reduce the number of fullsweeps.
         * This improved Estone by more than 1200 estones on my computer
         * (Ultra Sparc 10).
         */
        Uint new_sz = erts_next_heap_size(size_before, 1);

        /* Create new, empty old_heap */
        n_old = (Eterm *) ERTS_HEAP_ALLOC(ERTS_ALC_T_OLD_HEAP,
					  sizeof(Eterm)*new_sz);

        OLD_HEND(p) = n_old + new_sz;
        OLD_HEAP(p) = OLD_HTOP(p) = n_old;
    }

    /*
     * Do a minor collection if there is an old heap and if it
     * is large enough.
     */

    if (OLD_HEAP(p) &&
        ((mature.bytes <= (char *) OLD_HEND(p) - (char *) OLD_HTOP(p))
         && ((BIN_OLD_VHEAP_SZ(p) > BIN_OLD_VHEAP(p)))))
    {
	Eterm *prev_old_htop;
	Uint stack_size, size_after, adjust_size;
        Uint need_after, new_sz, new_mature;

	stack_size = p->hend - p->stop;
	new_sz = stack_size + size_before;
        new_sz = next_heap_size(p, new_sz, 0);

	prev_old_htop = p->old_htop;
        do_minor(p, live_hf_end, mature, new_sz, objv, nobj);

	if (p->flags & F_ON_HEAP_MSGQ)
	    move_msgq_to_heap(p);

	new_mature = p->old_htop - prev_old_htop;

	size_after = new_mature;
        size_after += HEAP_TOP(p) - HEAP_START(p) + p->mbuf_sz;
        *recl += (size_before - size_after);

	ErtsGcQuickSanityCheck(p);

        GEN_GCS(p)++;
        need_after = ((HEAP_TOP(p) - HEAP_START(p))
                      + need
                      + stack_size);

        /*
         * Excessively large heaps should be shrunk, but
         * don't even bother on reasonable small heaps.
         *
         * The reason for this is that after tenuring, we often
         * use a really small portion of new heap, therefore, unless
         * the heap size is substantial, we don't want to shrink.
         */

	adjust_size = 0;

        if ((HEAP_SIZE(p) > 3000)
            && (4 * need_after < HEAP_SIZE(p))
            && ((HEAP_SIZE(p) > 8000)
                || (HEAP_SIZE(p) > (OLD_HEND(p) - OLD_HEAP(p)))))
        {
	    Uint wanted = 3 * need_after;
	    Uint old_heap_sz = OLD_HEND(p) - OLD_HEAP(p);

	    /*
	     * Additional test to make sure we don't make the heap too small
	     * compared to the size of the older generation heap.
	     */
	    if (wanted*9 < old_heap_sz) {
		Uint new_wanted = old_heap_sz / 8;
		if (new_wanted > wanted) {
		    wanted = new_wanted;
		}
	    }

	    wanted = wanted < MIN_HEAP_SIZE(p) ? MIN_HEAP_SIZE(p)
					       : next_heap_size(p, wanted, 0);
            if (wanted < HEAP_SIZE(p)) {
                shrink_new_heap(p, wanted, objv, nobj);
		adjust_size = p->htop - p->heap;
            }

        }
        else if (need_after > HEAP_SIZE(p)) {
            grow_new_heap(p, next_heap_size(p, need_after, 0), objv, nobj);
            adjust_size = p->htop - p->heap;
        }
	/*else: The heap size turned out to be just right. We are done. */

	ASSERT(HEAP_SIZE(p) == next_heap_size(p, HEAP_SIZE(p), 0));

        /* The heap usage during GC should be larger than what we end up
           after a GC, even if we grow it. If this assertion is not true
           we have to check size in grow_new_heap and potentially kill the
           process from there */
        ASSERT(!MAX_HEAP_SIZE_GET(p) ||
               !(MAX_HEAP_SIZE_FLAGS_GET(p) & MAX_HEAP_SIZE_KILL) ||
               MAX_HEAP_SIZE_GET(p) > (young_gen_usage(p) +
                                       (OLD_HEND(p) - OLD_HEAP(p)) +
                                       (HEAP_END(p) - HEAP_TOP(p))));

	return gc_cost(size_after, adjust_size);
    }

    /*
     * Not enough room for a minor collection. Must force a major collection.
     */
    return -1;
}

static void
do_minor(Process *p, ErlHeapFragment *live_hf_end,
         MatureArea mature,
         Uint new_sz, Eterm *objv, int nobj)
{
    Rootset rootset;            /* Rootset for GC (stack, dictionary, etc). */
    Eterm *n_htop;
    Eterm *old_htop = OLD_HTOP(p);
    Eterm *n_heap;
    OldHeapArea oh = {(const char *) OLD_HEAP(p),
                      (char *) OLD_HTOP(p) - (char *) OLD_HEAP(p)};

    VERBOSE(DEBUG_SHCOPY, ("[pid=%T] MINOR GC: %p %p %p %p\n", p->common.id,
            HEAP_START(p), HEAP_END(p), OLD_HEAP(p), OLD_HEND(p)));

    n_htop = n_heap = (Eterm*) ERTS_HEAP_ALLOC(ERTS_ALC_T_HEAP,
					       sizeof(Eterm)*new_sz);

    debug_scan_heap(HEAP_START(p), HEAP_TOP(p), OLD_HEAP(p), OLD_HTOP(p));

    if (live_hf_end != ERTS_INVALID_HFRAG_PTR) {
	/*
	 * Move heap frags that we know are completely live
	 * directly into the new young heap generation.
	 */
	n_htop = collect_live_heap_frags(p, live_hf_end, n_heap, n_htop,
					 objv, nobj);
    }

    setup_rootset(p, objv, nobj, &rootset);
    GENSWEEP_NSTACK(p, old_htop, n_htop);
    generic_roots_sweep(&rootset,
                        &n_htop, &old_htop,        /* inout inout */
                        SweepOp_NotLiteral_NotOld, /* primary */
                        SweepOp_NotLiteral_Mature, /* secondary */
                        oh, mature);
    cleanup_rootset(&rootset);

    /*
     * Now all references in the rootset point to the new heap. However,
     * most references on the new heap point to the old heap so the next stage
     * is to scan through the new heap evacuating data from the old heap
     * until all is changed.
     */

    if (mature.bytes == 0) {
        generic_sweep(n_heap, &n_htop,           /* primary, in out */
                      NULL, NULL,                /* no secondary */
                      SweepOp_NotLiteral_NotOld, /* primary */
                      SweepOp_None,              /* secondary */
                      oh,
                      NULL, 0);
    } else {
        generic_sweep(n_heap, &n_htop,           /* primary in out */
                      OLD_HEAP(p), &old_htop,    /* secondary in out */
                      SweepOp_NotLiteral_NotOld, /* primary */
                      SweepOp_NotLiteral_Mature, /* secondary */
                      oh,
                      mature.start, mature.bytes);
        ASSERT(old_htop <= OLD_HEND(p));
    }

    /*
     * And also if we have been tenuring, references on the second generation
     * may point to the old (soon to be deleted) new_heap.
     */

    if (OLD_HTOP(p) < old_htop) {
        generic_sweep(OLD_HTOP(p), &old_htop,    /* primary in out */
                      NULL, 0,                   /* no secondary */
                      SweepOp_NotLiteral_NotOld, /* primary */
                      SweepOp_None,              /* secondary */
                      oh,
                      NULL, 0);
        ASSERT(old_htop <= OLD_HEND(p));
    }
    OLD_HTOP(p) = old_htop;
    HIGH_WATER(p) = n_htop;

    debug_scan_heap(n_heap, n_htop, (Eterm *) oh.start, old_htop);

    {
        /* to_old is larger than oh, covers even unused part of the old heap */
        OldHeapArea to_old = {(const char *)OLD_HEAP(p),
                           (char *)OLD_HEND(p) - (char *)OLD_HEAP(p)};
        YoungHeapArea to_young = {(const char *) n_heap,
                                  (char *) n_htop - (char *) n_heap};
        /* Using to_old twice here because in minor gc old heap
         * keeps growing in same space */
        sweep_off_heap(p, to_old, to_old, to_young, SweepOffheapMinor);
    }
    debug_scan_heap(n_heap, n_htop, (Eterm *) oh.start, old_htop);

#ifdef HARDDEBUG
    /*
     * Go through the old_heap before, and try to find references from the old_heap
     * into the old new_heap that has just been evacuated and is about to be freed
     * (as well as looking for reference into heap fragments, of course).
     */
    disallow_heap_frag_ref_in_old_heap(p);
#endif

    /* Copy stack to end of new heap */
    {
        Uint stk_words = p->hend - p->stop;
        sys_memcpy(n_heap + new_sz - stk_words,
                   p->stop,
                   stk_words * sizeof(Eterm));
        p->stop = n_heap + new_sz - stk_words;
    }

#ifdef USE_VM_PROBES
    if (HEAP_SIZE(p) != new_sz && DTRACE_ENABLED(process_heap_grow)) {
        DTRACE_CHARBUF(pidbuf, DTRACE_TERM_BUF_SIZE);

        dtrace_proc_str(p, pidbuf);
        DTRACE3(process_heap_grow, pidbuf, HEAP_SIZE(p), new_sz);
    }
#endif

    ERTS_HEAP_FREE(ERTS_ALC_T_HEAP,
		   (p->abandoned_heap
		    ? p->abandoned_heap
		    : HEAP_START(p)),
		   HEAP_SIZE(p) * sizeof(Eterm));
    p->abandoned_heap = NULL;
    p->flags &= ~F_ABANDONED_HEAP_USE;
    HEAP_START(p) = n_heap;
    HEAP_TOP(p) = n_htop;
    HEAP_SIZE(p) = new_sz;
    HEAP_END(p) = n_heap + new_sz;

#ifdef HARDDEBUG
    disallow_heap_frag_ref_in_heap(p);
#endif
    remove_message_buffers(p);
}

/*
 * Major collection.
 */

static int
major_collection(Process* p, ErlHeapFragment *live_hf_end,
		 int need, Eterm* objv, int nobj, Uint *recl)
{
    Uint size_before, size_after, stack_size;
    Eterm *n_heap, *o_heap = NULL;
    Eterm *n_htop, *o_htop = NULL;
    Uint new_sz, old_sz, stk_sz;
    int adjusted;
    OldHeapArea oh = {(const char *) OLD_HEAP(p),
                      (char *) OLD_HTOP(p) - (char *) OLD_HEAP(p)};
    MatureArea mature;
    mature.start = p->abandoned_heap ? (const char *) p->abandoned_heap
                                     : (const char *) HEAP_START(p);
    mature.bytes = p->high_water ? (char *)p->high_water - mature.start : 0;

    VERBOSE(DEBUG_SHCOPY, ("[pid=%T] MAJOR GC: %p %p %p %p\n", p->common.id,
                           HEAP_START(p), HEAP_END(p), OLD_HEAP(p), OLD_HEND(p)));

    debug_scan_heap(HEAP_START(p), HEAP_TOP(p), OLD_HEAP(p), OLD_HTOP(p));

    /*
     * Do a fullsweep GC. First figure out the size of the heap
     * to receive all live data.
     */

    size_before = young_gen_usage(p);
    size_before += p->old_htop - p->old_heap;
    stack_size = p->hend - p->stop;

    new_sz = stack_size + size_before;
    new_sz = next_heap_size(p, new_sz, 0);

    /*
     * Should we grow although we don't actually need to?
     */

    if (new_sz == HEAP_SIZE(p) && FLAGS(p) & F_HEAP_GROW) {
        new_sz = next_heap_size(p, HEAP_SIZE(p), 1);
    }
    old_sz = next_heap_size(p, new_sz, 1);

    if (MAX_HEAP_SIZE_GET(p)) {
        Uint heap_size = size_before;

        /* Add unused space in old heap */
        heap_size += OLD_HEND(p) - OLD_HTOP(p);

        /* Add stack + unused space in young heap */
        heap_size += HEAP_END(p) - HEAP_TOP(p);

        /* Add size of new young and new old heap */
        heap_size += new_sz;
        heap_size += old_sz;

        if (MAX_HEAP_SIZE_GET(p) < heap_size)
            if (reached_max_heap_size(p, heap_size, new_sz, 0))
                return -2;
    }

    FLAGS(p) &= ~(F_HEAP_GROW|F_NEED_FULLSWEEP);
    n_htop = n_heap = (Eterm *) ERTS_HEAP_ALLOC(ERTS_ALC_T_HEAP,
						sizeof(Eterm)*new_sz);
    if (mature.bytes || oh.start) {
        o_htop = o_heap = (Eterm *) ERTS_HEAP_ALLOC(ERTS_ALC_T_OLD_HEAP,
                                                    sizeof(Eterm) * old_sz);
    }

    if (live_hf_end != ERTS_INVALID_HFRAG_PTR) {
	/*
	 * Move heap frags that we know are completely live
	 * directly into the heap.
	 */
	n_htop = collect_live_heap_frags(p, live_hf_end, n_heap, n_htop,
					 objv, nobj);
    }

    full_sweep_heaps(p, 0,
                     n_heap, &n_htop,
                     o_heap, &o_htop,
                     mature, oh,
                     objv, nobj);

    /* Move the stack to the end of the heap */
    stk_sz = HEAP_END(p) - p->stop;
    sys_memcpy(n_heap + new_sz - stk_sz, p->stop, stk_sz * sizeof(Eterm));
    p->stop = n_heap + new_sz - stk_sz;

#ifdef USE_VM_PROBES
    if (HEAP_SIZE(p) != new_sz && DTRACE_ENABLED(process_heap_grow)) {
        DTRACE_CHARBUF(pidbuf, DTRACE_TERM_BUF_SIZE);

        dtrace_proc_str(p, pidbuf);
        DTRACE3(process_heap_grow, pidbuf, HEAP_SIZE(p), new_sz);
    }
#endif

    {
        Eterm *free_young = p->abandoned_heap ? p->abandoned_heap
                                              : HEAP_START( p);
        ERTS_HEAP_FREE(ERTS_ALC_T_HEAP,
                       free_young,
                       p->heap_sz * sizeof(Eterm));
    }

    if (OLD_HEAP(p)) {
        ERTS_HEAP_FREE(ERTS_ALC_T_OLD_HEAP,
                       OLD_HEAP(p),
                       (OLD_HTOP(p) - OLD_HEAP(p)) * sizeof(Eterm));
    }
    if (o_heap) {
        OLD_HEAP(p) = o_heap;
        OLD_HTOP(p) = o_htop;
        OLD_HEND(p) = o_heap + old_sz;
    } else {
        OLD_HEAP(p) = OLD_HTOP(p) = OLD_HEND(p) = NULL;
    }

    p->abandoned_heap = NULL;
    p->flags &= ~F_ABANDONED_HEAP_USE;
    HEAP_START(p) = n_heap;
    HEAP_TOP(p) = n_htop;
    HEAP_SIZE(p) = new_sz;
    HEAP_END(p) = n_heap + new_sz;
    GEN_GCS(p) = 0;

    debug_scan_heap(n_heap, n_htop, o_heap, o_htop);

    HIGH_WATER(p) = HEAP_TOP(p);

#ifdef HARDDEBUG
    disallow_heap_frag_ref_in_heap(p);
#endif
    remove_message_buffers(p);

    if (p->flags & F_ON_HEAP_MSGQ) {
        move_msgq_to_heap(p);
    }

    ErtsGcQuickSanityCheck(p);

    size_after = HEAP_TOP(p) - HEAP_START(p) + p->mbuf_sz;
    *recl += size_before - size_after;

    adjusted = adjust_after_fullsweep(p, need, objv, nobj);

    ErtsGcQuickSanityCheck(p);

    return gc_cost(size_after, adjusted ? size_after : 0);
}

static void
full_sweep_heaps(Process *p,
                 int hibernate,
                 Eterm *n_heap, Eterm **n_htopp,
                 Eterm *o_heap, Eterm **o_htopp,
                 MatureArea mature,
                 OldHeapArea from_old,
                 Eterm *objv, int nobj)
{
    Rootset rootset;
    Eterm *n_htop = *n_htopp;
    Eterm *o_htop = o_htopp ? *o_htopp : NULL;

    /*
     * Copy all top-level terms directly referenced by the rootset to
     * the new new_heap or old heap.
     */

    setup_rootset(p, objv, nobj, &rootset);
#ifdef HIPE
    if (hibernate)
	hipe_empty_nstack(p);
    else
	n_htop = fullsweep_nstack(p, n_htop);
#endif
    generic_roots_sweep(&rootset,
                        &n_htop, &o_htop,               /* inout inout */
                        SweepOp_NotLiteral,             /* primary */
                        SweepOp_NotLiteral_OldOrMature, /* secondary */
                        from_old, mature);
    cleanup_rootset(&rootset);

    /*
     * Now all references on the stack point to the new heap. However,
     * most references on the new heap point to the old heap so the next stage
     * is to scan through the new heap evacuating data from the old heap
     * until all is copied.
     */
    generic_sweep(n_heap, &n_htop,                /* primary in out */
                  o_heap, &o_htop,                /* secondary in out */
                  SweepOp_NotLiteral,             /* primary */
                  SweepOp_NotLiteral_OldOrMature, /* secondary */
                  from_old,
                  mature.start, mature.bytes);
    generic_sweep(o_heap, &o_htop,                /* primary in out */
                  NULL, NULL,                     /* no secondary */
                  SweepOp_NotLiteral,             /* primary */
                  SweepOp_NotLiteral_OldOrMature, /* secondary */
                  from_old,
                  NULL, 0);

    {
        OldHeapArea to_old = {(const char *)o_heap,
                              (char *)o_htop - (char *)o_heap};
        YoungHeapArea to_young = {(const char *) n_heap,
                                  (char *) n_htop - (char *) n_heap};
        sweep_off_heap(p, from_old,
                       to_old, to_young, /* used for debug */
                       SweepOffheapMajor);
    }

    *n_htopp = n_htop;
    if (o_htopp) { *o_htopp = o_htop; }
}

static int
adjust_after_fullsweep(Process *p, int need, Eterm *objv, int nobj)
{
    int adjusted = 0;
    Uint wanted, sz, need_after;
    Uint stack_size = stack_sz_on_heap(p);

    /*
     * Resize the heap if needed.
     */

    need_after = (HEAP_TOP(p) - HEAP_START(p)) + need + stack_size;
    if (HEAP_SIZE(p) < need_after) {
        /* Too small - grow to match requested need */
        sz = next_heap_size(p, need_after, 0);
        grow_new_heap(p, sz, objv, nobj);
	adjusted = 1;
    } else if (3 * HEAP_SIZE(p) < 4 * need_after){
        /* Need more than 75% of current, postpone to next GC.*/
        FLAGS(p) |= F_HEAP_GROW;
    } else if (4 * need_after < HEAP_SIZE(p) && HEAP_SIZE(p) > H_MIN_SIZE){
        /* We need less than 25% of the current heap, shrink.*/
        /* XXX - This is how it was done in the old GC:
           wanted = 4 * need_after;
           I think this is better as fullsweep is used mainly on
           small memory systems, but I could be wrong... */
        wanted = 2 * need_after;

	sz = wanted < p->min_heap_size ? p->min_heap_size
				       : next_heap_size(p, wanted, 0);

        if (sz < HEAP_SIZE(p)) {
            shrink_new_heap(p, sz, objv, nobj);
	    adjusted = 1;
        }
    }
    return adjusted;
}

/*
 * Remove all message buffers.
 */
static void
remove_message_buffers(Process* p)
{
    if (MBUF(p) != NULL) {
	free_message_buffer(MBUF(p));
	MBUF(p) = NULL;
    }
    if (p->msg_frag) {
	erts_cleanup_messages(p->msg_frag);
	p->msg_frag = NULL;
    }
    MBUF_SIZE(p) = 0;
}
#ifdef HARDDEBUG

/*
 * Routines to verify that we don't have pointer into heap fragments from
 * that are not allowed to have them.
 *
 * For performance reasons, we use _unchecked_list_val(), _unchecked_boxed_val(),
 * and so on to avoid a function call.
 */

static void
disallow_heap_frag_ref_in_heap(Process* p)
{
    Eterm* hp;
    Eterm* htop;
    Eterm* heap;
    Uint heap_size;

    if (p->mbuf == 0) {
	return;
    }

    htop = p->htop;
    heap = p->heap;
    heap_size = (htop - heap)*sizeof(Eterm);

    hp = heap;
    while (hp < htop) {
	ErlHeapFragment* qb;
	Eterm* ptr;
	Eterm val;

	val = *hp++;
	switch (primary_tag(val)) {
	case TAG_PRIMARY_BOXED:
	    ptr = _unchecked_boxed_val(val);
	    if (!ErtsInArea(ptr, heap, heap_size)) {
		for (qb = MBUF(p); qb != NULL; qb = qb->next) {
		    if (ErtsInArea(ptr, qb->mem, qb->alloc_size*sizeof(Eterm))) {
			abort();
		    }
		}
	    }
	    break;
	case TAG_PRIMARY_LIST:
	    ptr = _unchecked_list_val(val);
	    if (!ErtsInArea(ptr, heap, heap_size)) {
		for (qb = MBUF(p); qb != NULL; qb = qb->next) {
		    if (ErtsInArea(ptr, qb->mem, qb->alloc_size*sizeof(Eterm))) {
			abort();
		    }
		}
	    }
	    break;
	case TAG_PRIMARY_HEADER:
	    if (header_is_thing(val)) {
		hp += _unchecked_thing_arityval(val);
	    }
	    break;
	}
    }
}

static void
disallow_heap_frag_ref_in_old_heap(Process* p)
{
    Eterm* hp;
    Eterm* htop;
    Eterm* old_heap;
    Uint old_heap_size;
    Eterm* new_heap;
    Uint new_heap_size;

    htop = p->old_htop;
    old_heap = p->old_heap;
    old_heap_size = (htop - old_heap)*sizeof(Eterm);
    new_heap = p->heap;
    new_heap_size = (p->htop - new_heap)*sizeof(Eterm);

    ASSERT(!p->last_old_htop
	   || (old_heap <= p->last_old_htop && p->last_old_htop <= htop));
    hp = p->last_old_htop ? p->last_old_htop : old_heap;
    while (hp < htop) {
	ErlHeapFragment* qb;
	Eterm* ptr;
	Eterm val;

	val = *hp++;
	switch (primary_tag(val)) {
	case TAG_PRIMARY_BOXED:
	    ptr = (Eterm *) val;
	    if (!ErtsInArea(ptr, old_heap, old_heap_size)) {
		if (ErtsInArea(ptr, new_heap, new_heap_size)) {
		    abort();
		}
		for (qb = MBUF(p); qb != NULL; qb = qb->next) {
		    if (ErtsInArea(ptr, qb->mem, qb->alloc_size*sizeof(Eterm))) {
			abort();
		    }
		}
	    }
	    break;
	case TAG_PRIMARY_LIST:
	    ptr = (Eterm *) val;
	    if (!ErtsInArea(ptr, old_heap, old_heap_size)) {
		if (ErtsInArea(ptr, new_heap, new_heap_size)) {
		    abort();
		}
		for (qb = MBUF(p); qb != NULL; qb = qb->next) {
		    if (ErtsInArea(ptr, qb->mem, qb->alloc_size*sizeof(Eterm))) {
			abort();
		    }
		}
	    }
	    break;
	case TAG_PRIMARY_HEADER:
	    if (header_is_thing(val)) {
		hp += _unchecked_thing_arityval(val);
		if (!ErtsInArea(hp, old_heap, old_heap_size+1)) {
		    abort();
		}
	    }
	    break;
	}
    }
}
#endif

#ifdef DEBUG
static void
debug_sweep_check(const Eterm *hp, const Eterm *hend) {
    while (hp != hend) {
        Eterm gval = *hp;
        ASSERT(hp < hend);

        switch (primary_tag(gval)) {
            case TAG_PRIMARY_BOXED: {
                ASSERT(is_header(*boxed_val(gval))
                       || is_boxed(*boxed_val(gval)));
                hp++;
            } break;
            case TAG_PRIMARY_LIST: {
                ASSERT(!is_header(CAR(list_val(gval)))
                       || (IS_MOVED_CONS(CAR(list_val(gval)))
                           && is_list(CDR(list_val(gval)))));
                hp++;
            } break;
            case TAG_PRIMARY_HEADER: {
                if (!header_is_thing(gval)) {
                    hp++;
                } else {
                    hp += (thing_arityval(gval) + 1);
                }
            } break;
            case TAG_PRIMARY_IMMED1: {
                hp++;
            } break;
            default:
                ASSERT(!"should not be here");
        }
    }
}
#endif

/* TODO: Can this possibly be covered by generic sweep? */
static Eterm*
sweep_literals_to_old_heap(Eterm* heap_ptr, Eterm* heap_end, Eterm* htop,
			   char* src, Uint src_size)
{
    while (heap_ptr < heap_end) {
	Eterm* ptr;
	Eterm val;
	Eterm gval = *heap_ptr;

	switch (primary_tag(gval)) {
	case TAG_PRIMARY_BOXED: {
	    ptr = boxed_val(gval);
	    val = *ptr;
	    if (IS_MOVED_BOXED(val)) {
		ASSERT(is_boxed(val));
		*heap_ptr++ = val;
	    } else if (ErtsInArea(ptr, src, src_size)) {
		MOVE_BOXED(ptr,val,htop,heap_ptr++);
	    } else {
		heap_ptr++;
	    }
	    break;
	}
	case TAG_PRIMARY_LIST: {
	    ptr = list_val(gval);
	    val = *ptr;
	    if (IS_MOVED_CONS(val)) {
		*heap_ptr++ = ptr[1];
	    } else if (ErtsInArea(ptr, src, src_size)) {
		MOVE_CONS(ptr,val,htop,heap_ptr++);
	    } else {
		heap_ptr++;
	    }
	    break;
	}
	case TAG_PRIMARY_HEADER: {
	    if (!header_is_thing(gval)) {
		heap_ptr++;
	    } else {
		if (header_is_bin_matchstate(gval)) {
		    ErlBinMatchState *ms = (ErlBinMatchState*) heap_ptr;
		    ErlBinMatchBuffer *mb = &(ms->mb);
		    Eterm* origptr;
		    origptr = &(mb->orig);
		    ptr = boxed_val(*origptr);
		    val = *ptr;
		    if (IS_MOVED_BOXED(val)) {
			*origptr = val;
			mb->base = binary_bytes(*origptr);
		    } else if (ErtsInArea(ptr, src, src_size)) {
			MOVE_BOXED(ptr,val,htop,origptr);
			mb->base = binary_bytes(*origptr);
		    }
		}
		heap_ptr += (thing_arityval(gval)+1);
	    }
	    break;
	}
	default:
	    heap_ptr++;
	    break;
	}
    }
    return htop;
}

/*
 * Move an area (heap fragment) by sweeping over it and set move markers.
 */
static Eterm*
move_one_area(Eterm* n_htop, char* src, Uint src_size)
{
    Eterm* ptr = (Eterm*) src;
    Eterm* end = ptr + src_size/sizeof(Eterm);
    Eterm dummy_ref;

    while (ptr != end) {
	Eterm val;
	ASSERT(ptr < end);
	val = *ptr;
	ASSERT(val != ERTS_HOLE_MARKER);
	if (is_header(val)) {
	    ASSERT(ptr + header_arity(val) < end);
	    MOVE_BOXED(ptr, val, n_htop, &dummy_ref);
	}
	else { /* must be a cons cell */
	    ASSERT(ptr+1 < end);
	    MOVE_CONS(ptr, val, n_htop, &dummy_ref);
	    ptr += 2;
	}
    }

    return n_htop;
}

/*
 * Collect heap fragments and check that they point in the correct direction.
 */

static Eterm*
collect_live_heap_frags(Process* p, ErlHeapFragment *live_hf_end,
			Eterm* n_hstart, Eterm* n_htop,
			Eterm* objv, int nobj)
{
    ErlHeapFragment* qb;
    char* frag_begin;
    Uint frag_size;

    /*
     * Move the heap fragments to the new heap. Note that no GC is done on
     * the heap fragments. Any garbage will thus be moved as well and survive
     * until next GC.
     */
    qb = MBUF(p);
    while (qb != live_hf_end) {
        ASSERT(!qb->off_heap.first);  /* process fragments use the MSO(p) list */
	frag_size = qb->used_size * sizeof(Eterm);
	if (frag_size != 0) {
	    frag_begin = (char *) qb->mem;
	    n_htop = move_one_area(n_htop, frag_begin, frag_size);
	}
	qb = qb->next;
    }
    return n_htop;
}

static ERTS_INLINE void
copy_one_frag(Eterm** hpp, ErlOffHeap* off_heap,
	      ErlHeapFragment *bp, Eterm *refs, int nrefs)
{
    Uint sz;
    int i;
    Sint offs;
    OffheapHeader* oh;
    Eterm *fhp, *hp;

    OH_OVERHEAD(off_heap, bp->off_heap.overhead);
    sz = bp->used_size;

    fhp = bp->mem;
    hp = *hpp;
    offs = hp - fhp;

    oh = NULL;
    while (sz--) {
	Uint cpy_sz;
	Eterm val = *fhp++;

	switch (primary_tag(val)) {
	case TAG_PRIMARY_IMMED1:
	    *hp++ = val;
	    break;
	case TAG_PRIMARY_LIST:
            if (erts_is_literal(val,list_val(val))) {
                *hp++ = val;
            } else {
                *hp++ = offset_ptr(val, offs);
            }
            break;
	case TAG_PRIMARY_BOXED:
            if (erts_is_literal(val,boxed_val(val))) {
                *hp++ = val;
            } else {
                *hp++ = offset_ptr(val, offs);
            }
	    break;
	case TAG_PRIMARY_HEADER:
	    *hp++ = val;
	    switch (val & _HEADER_SUBTAG_MASK) {
	    case ARITYVAL_SUBTAG:
		break;
	    case REFC_BINARY_SUBTAG:
	    case FUN_SUBTAG:
	    case EXTERNAL_PID_SUBTAG:
	    case EXTERNAL_PORT_SUBTAG:
	    case EXTERNAL_REF_SUBTAG:
		oh = (OffheapHeader*) (hp-1);
		cpy_sz = thing_arityval(val);
		goto cpy_words;
	    default:
		cpy_sz = header_arity(val);

	    cpy_words:
		ASSERT(sz >= cpy_sz);
		sz -= cpy_sz;
		while (cpy_sz >= 8) {
		    cpy_sz -= 8;
		    *hp++ = *fhp++;
		    *hp++ = *fhp++;
		    *hp++ = *fhp++;
		    *hp++ = *fhp++;
		    *hp++ = *fhp++;
		    *hp++ = *fhp++;
		    *hp++ = *fhp++;
		    *hp++ = *fhp++;
		}
		switch (cpy_sz) {
		case 7: *hp++ = *fhp++;
		case 6: *hp++ = *fhp++;
		case 5: *hp++ = *fhp++;
		case 4: *hp++ = *fhp++;
		case 3: *hp++ = *fhp++;
		case 2: *hp++ = *fhp++;
		case 1: *hp++ = *fhp++;
		default: break;
		}
		if (oh) {
		    /* Add to offheap list */
		    oh->next = off_heap->first;
		    off_heap->first = oh;
		    ASSERT(*hpp <= (Eterm*)oh);
		    ASSERT(hp > (Eterm*)oh);
		    oh = NULL;
		}
		break;
	    }
	    break;
	}
    }

    ASSERT(bp->used_size == hp - *hpp);
    *hpp = hp;

    for (i = 0; i < nrefs; i++) {
	if (is_not_immed(refs[i]))
	    refs[i] = offset_ptr(refs[i], offs);
    }
    bp->off_heap.first = NULL;
}

static void
move_msgq_to_heap(Process *p)
{
    ErtsMessage **mpp = &p->msg.first;

    while (*mpp) {
	ErtsMessage *mp = *mpp;

	if (mp->data.attached) {
	    ErlHeapFragment *bp;
	    ErtsHeapFactory factory;

	    erts_factory_proc_prealloc_init(&factory, p,
					    erts_msg_attached_data_size(mp));

	    if (is_non_value(ERL_MESSAGE_TERM(mp))) {
		if (mp->data.dist_ext) {
		    ASSERT(mp->data.dist_ext->heap_size >= 0);
		    if (is_not_nil(ERL_MESSAGE_TOKEN(mp))) {
			bp = erts_dist_ext_trailer(mp->data.dist_ext);
                        /* Tokens does not use literal optimization */
			ERL_MESSAGE_TOKEN(mp) = copy_struct(ERL_MESSAGE_TOKEN(mp),
							    bp->used_size,
                                                            &factory.hp,
                                                            factory.off_heap);

			erts_cleanup_offheap(&bp->off_heap);
		    }
		    ERL_MESSAGE_TERM(mp) = erts_decode_dist_ext(&factory,
								mp->data.dist_ext);
		    erts_free_dist_ext_copy(mp->data.dist_ext);
		    mp->data.dist_ext = NULL;
		}
	    }
	    else {

                bp = erts_message_to_heap_frag(mp);

		if (bp->next)
		    erts_move_multi_frags(&factory.hp, factory.off_heap, bp,
					  mp->m, ERL_MESSAGE_REF_ARRAY_SZ, 0);
		else
		    copy_one_frag(&factory.hp, factory.off_heap, bp,
				  mp->m, ERL_MESSAGE_REF_ARRAY_SZ);

		if (mp->data.attached != ERTS_MSG_COMBINED_HFRAG) {
		    mp->data.heap_frag = NULL;
		    free_message_buffer(bp);
		}
		else {
		    ErtsMessage *new_mp = erts_alloc_message(0, NULL);
		    sys_memcpy((void *) new_mp->m, (void *) mp->m,
			       sizeof(Eterm)*ERL_MESSAGE_REF_ARRAY_SZ);
		    erts_msgq_replace_msg_ref(&p->msg, new_mp, mpp);
		    mp->next = NULL;
		    erts_cleanup_messages(mp);
		    mp = new_mp;
		}
	    }

	    erts_factory_close(&factory);
	}

	mpp = &(*mpp)->next;
    }
}

static Uint
setup_rootset(Process *p, Eterm *objv, int nobj, Rootset *rootset)
{
    Roots* roots;
    Uint n;

    n = 0;
    roots = rootset->roots = rootset->def;
    rootset->size = ARRAY_LENGTH(rootset->def);

    roots[n].v  = p->stop;
    roots[n].sz = STACK_START(p) - p->stop;
    ++n;

    if (p->dictionary != NULL) {
        roots[n].v = ERTS_PD_START(p->dictionary);
        roots[n].sz = ERTS_PD_SIZE(p->dictionary);
        ++n;
    }
    if (nobj > 0) {
        roots[n].v  = objv;
        roots[n].sz = nobj;
        ++n;
    }

    ASSERT((is_nil(p->seq_trace_token) ||
	    is_tuple(follow_moved(p->seq_trace_token, (Eterm) 0)) ||
	    is_atom(p->seq_trace_token)));
    if (is_not_immed(p->seq_trace_token)) {
	roots[n].v = &p->seq_trace_token;
	roots[n].sz = 1;
	n++;
    }
#ifdef USE_VM_PROBES
    if (is_not_immed(p->dt_utag)) {
	roots[n].v = &p->dt_utag;
	roots[n].sz = 1;
	n++;
    }
#endif
    ASSERT(IS_TRACER_VALID(ERTS_TRACER(p)));

    ASSERT(is_pid(follow_moved(p->group_leader, (Eterm) 0)));
    if (is_not_immed(p->group_leader)) {
	roots[n].v  = &p->group_leader;
	roots[n].sz = 1;
	n++;
    }

    /*
     * The process may be garbage-collected while it is terminating.
     * (fvalue contains the EXIT reason and ftrace the saved stack trace.)
     */
    if (is_not_immed(p->fvalue)) {
	roots[n].v  = &p->fvalue;
	roots[n].sz = 1;
	n++;
    }
    if (is_not_immed(p->ftrace)) {
	roots[n].v  = &p->ftrace;
	roots[n].sz = 1;
	n++;
    }

    /*
     * If a NIF has saved arguments, they need to be added
     */
    if (ERTS_PROC_GET_NIF_TRAP_EXPORT(p)) {
	Eterm* argv;
	int argc;
	if (erts_setup_nif_gc(p, &argv, &argc)) {
	    roots[n].v = argv;
	    roots[n].sz = argc;
	    n++;
	}
    }

    ASSERT(n <= rootset->size);

    switch (p->flags & (F_OFF_HEAP_MSGQ|F_OFF_HEAP_MSGQ_CHNG)) {
    case F_OFF_HEAP_MSGQ|F_OFF_HEAP_MSGQ_CHNG:
	(void) erts_move_messages_off_heap(p);
    case F_OFF_HEAP_MSGQ:
	break;
    case F_OFF_HEAP_MSGQ_CHNG:
    case 0: {
	/*
	 * We do not have off heap message queue enabled, i.e. we
	 * need to add message queue to rootset...
	 */
	ErtsMessage *mp;

	/* Ensure large enough rootset... */
	if (n + p->msg.len > rootset->size) {
	    Uint new_size = n + p->msg.len;
	    ERTS_GC_ASSERT(roots == rootset->def);
	    roots = erts_alloc(ERTS_ALC_T_ROOTSET,
			       new_size*sizeof(Roots));
	    sys_memcpy(roots, rootset->def, n*sizeof(Roots));
	    rootset->size = new_size;
	}

	for (mp = p->msg.first; mp; mp = mp->next) {

	    if (!mp->data.attached) {
		/*
		 * Message may refer data on heap;
		 * add it to rootset...
		 */
		roots[n].v = mp->m;
		roots[n].sz = ERL_MESSAGE_REF_ARRAY_SZ;
		n++;
	    }
	}
	break;
    }
    }

    ASSERT(rootset->size >= n);

    rootset->roots = roots;
    rootset->num_roots = n;
    return n;
}

static
void cleanup_rootset(Rootset* rootset)
{
    if (rootset->roots != rootset->def) {
        erts_free(ERTS_ALC_T_ROOTSET, rootset->roots);
    }
}

static void
grow_new_heap(Process *p, Uint new_sz, Eterm* objv, int nobj)
{
    Eterm* new_heap;
    Uint heap_size = HEAP_TOP(p) - HEAP_START(p);
    Uint stack_size = p->hend - p->stop;
    Sint offs;

    ASSERT(HEAP_SIZE(p) < new_sz);
    new_heap = (Eterm *) ERTS_HEAP_REALLOC(ERTS_ALC_T_HEAP,
					   (void *) HEAP_START(p),
					   sizeof(Eterm)*(HEAP_SIZE(p)),
					   sizeof(Eterm)*new_sz);

    if ((offs = new_heap - HEAP_START(p)) == 0) { /* No move. */
        HEAP_END(p) = new_heap + new_sz;
        sys_memmove(p->hend - stack_size, p->stop, stack_size * sizeof(Eterm));
        p->stop = p->hend - stack_size;
    } else {
	char* area = (char *) HEAP_START(p);
	Uint area_size = (char *) HEAP_TOP(p) - area;
        Eterm* prev_stop = p->stop;

        offset_heap(new_heap, heap_size, offs, area, area_size);

        HIGH_WATER(p) = new_heap + (HIGH_WATER(p) - HEAP_START(p));

        HEAP_END(p) = new_heap + new_sz;
        prev_stop = new_heap + (p->stop - p->heap);
        p->stop = p->hend - stack_size;
        sys_memmove(p->stop, prev_stop, stack_size * sizeof(Eterm));

        offset_rootset(p, offs, area, area_size, objv, nobj);
        HEAP_TOP(p) = new_heap + heap_size;
        HEAP_START(p) = new_heap;
    }

#ifdef USE_VM_PROBES
    if (DTRACE_ENABLED(process_heap_grow)) {
	DTRACE_CHARBUF(pidbuf, DTRACE_TERM_BUF_SIZE);

        dtrace_proc_str(p, pidbuf);
	DTRACE3(process_heap_grow, pidbuf, HEAP_SIZE(p), new_sz);
    }
#endif

    HEAP_SIZE(p) = new_sz;
}

static void
shrink_new_heap(Process *p, Uint new_sz, Eterm *objv, int nobj)
{
    Eterm* new_heap;
    Uint heap_size = HEAP_TOP(p) - HEAP_START(p);
    Sint offs;
    Uint stack_size = p->hend - p->stop;

    ASSERT(new_sz < p->heap_sz);
    sys_memmove(p->heap + new_sz - stack_size, p->stop, stack_size *
                                                        sizeof(Eterm));
    new_heap = (Eterm *) ERTS_HEAP_REALLOC(ERTS_ALC_T_HEAP,
					   (void*)p->heap,
					   sizeof(Eterm)*(HEAP_SIZE(p)),
					   sizeof(Eterm)*new_sz);
    p->hend = new_heap + new_sz;
    p->stop = p->hend - stack_size;

    if ((offs = new_heap - HEAP_START(p)) != 0) {
	char* area = (char *) HEAP_START(p);
	Uint area_size = (char *) HEAP_TOP(p) - area;

        /*
         * Normally, we don't expect a shrunk heap to move, but you never
         * know on some strange embedded systems...  Or when using purify.
         */

        offset_heap(new_heap, heap_size, offs, area, area_size);

        HIGH_WATER(p) = new_heap + (HIGH_WATER(p) - HEAP_START(p));
        offset_rootset(p, offs, area, area_size, objv, nobj);
        HEAP_TOP(p) = new_heap + heap_size;
        HEAP_START(p) = new_heap;
    }

#ifdef USE_VM_PROBES
    if (DTRACE_ENABLED(process_heap_shrink)) {
	DTRACE_CHARBUF(pidbuf, DTRACE_TERM_BUF_SIZE);

        dtrace_proc_str(p, pidbuf);
	DTRACE3(process_heap_shrink, pidbuf, HEAP_SIZE(p), new_sz);
    }
#endif

    HEAP_SIZE(p) = new_sz;
}

static Uint64
do_next_vheap_size(Uint64 vheap, Uint64 vheap_sz) {

    /*                grow
     *
     * vheap_sz ======================
     *
     * vheap 75% +    grow
     *          ----------------------
     *
     * vheap 25 - 75% same
     *          ----------------------
     *
     * vheap ~ - 25% shrink
     *
     *          ----------------------
     */

    if ((Uint64) vheap/3 > (Uint64) (vheap_sz/4)) {
	Uint64 new_vheap_sz = vheap_sz;

	while((Uint64) vheap/3 > (Uint64) (vheap_sz/4)) {
	    /* the golden ratio = 1.618 */
	    new_vheap_sz = (Uint64) vheap_sz * 1.618;
	    if (new_vheap_sz < vheap_sz ) {
	        return vheap_sz;
	    }
	    vheap_sz = new_vheap_sz;
	}

	return vheap_sz;
    }

    if (vheap < (Uint64) (vheap_sz/4)) {
	return (vheap_sz >> 1);
    }

    return vheap_sz;

}

static Uint64
next_vheap_size(Process* p, Uint64 vheap, Uint64 vheap_sz) {
    Uint64 new_vheap_sz = do_next_vheap_size(vheap, vheap_sz);
    return new_vheap_sz < p->min_vheap_size ? p->min_vheap_size : new_vheap_sz;
}

static ERTS_INLINE void
link_live_proc_bin(SweepOffheapState *state,
                   const int new_heap)
{
    ProcBin *proc_bin = (ProcBin*) state->ptr;
    enum { WRITER_OR_WRITABLE = (PB_ACTIVE_WRITER|PB_IS_WRITABLE) };
    ASSERT(*state->prev == state->ptr);

    state->ptr = proc_bin->next;

    if (proc_bin->flags & WRITER_OR_WRITABLE) {
        ASSERT(((proc_bin->flags & WRITER_OR_WRITABLE) == WRITER_OR_WRITABLE)
               || ((proc_bin->flags & WRITER_OR_WRITABLE) == PB_IS_WRITABLE));

        if (proc_bin->flags & PB_ACTIVE_WRITER) {
            state->shrink.no_of_active++;
        }
        else { /* inactive */
            Uint unused = proc_bin->val->orig_size - proc_bin->size;

            /* Our allocators are 8 byte aligned, i.e., shrinking with
               less than 8 bytes will have no real effect */
            if (unused >= 8) { /* A shrink candidate; save in candidate list */
                *state->prev = proc_bin->next;
                if (new_heap) {
                    if (!state->shrink.new_candidates) {
                        state->shrink.new_candidates_end = (OffheapHeader *) proc_bin;
                    }
                    proc_bin->next = state->shrink.new_candidates;
                    state->shrink.new_candidates = (OffheapHeader *) proc_bin;
                }
                else {
                    proc_bin->next = state->shrink.old_candidates;
                    state->shrink.old_candidates = (OffheapHeader *) proc_bin;
                }
                state->shrink.no_of_candidates++;
                return;
            }
        }
    }

    /* Not a shrink candidate; keep in original mso list */
    state->prev = &(proc_bin->next);
}

static int ERTS_FORCE_INLINE
is_ptr_in_old(const OffheapHeader *ptr,
              OldHeapArea oh) {
    return ErtsInArea(ptr, oh.start, oh.bytes);
}

#ifdef DEBUG /* only used from debug_check_offheap */
static int ERTS_FORCE_INLINE
is_ptr_in_young(const OffheapHeader *ptr,
                YoungHeapArea yng) {
    return ErtsInArea(ptr, yng.start, yng.bytes);
}
#endif

/* Scan off-heap, ensure that young objects are followed by old objects */
static void ERTS_INLINE
debug_check_offheap(Process *p,
                    YoungHeapArea to_young,
                    OldHeapArea to_old)
{
#ifdef DEBUG
    OffheapHeader *ptr = MSO(p).first;
    int is_in_old = 0;

    while (ptr) {
        ASSERT(is_ptr_in_young(ptr, to_young) || is_ptr_in_old(ptr, to_old));
        if (is_ptr_in_old(ptr, to_old) && !is_in_old) {
            is_in_old = 1;
        }
        if (is_in_old) {
            ASSERT(is_ptr_in_old(ptr, to_old));
        }
        ptr = ptr->next;
    }
#endif
}

/*
 * Reads: MSO(p), BIN_OLD_VHEAP(p)
 * Modifies: MSO(p), BIN_VHEAP_SZ(p), BIN_OLD_VHEAP(p)
 */
static void
sweep_off_heap(Process *p,
               OldHeapArea from_old,
               OldHeapArea to_old,      /* used for debug */
               YoungHeapArea to_young,  /* used for debug */
               SweepOffheapMode mode)
{
    Uint64 bin_vheap = 0, bin_ovheap = 0;
#ifdef DEBUG
    int seen_mature = 0;
#endif
    SweepOffheapState state;
    sys_memset(&state, 0, sizeof(state));

    if (!MSO(p).first) { return; }
    if (mode == SweepOffheapMinor) {
        bin_ovheap = BIN_OLD_VHEAP(p);
    }

    state.prev = &MSO(p).first;
    state.ptr = MSO(p).first;

    /* First part of the list will reside on the (old) young-heap.
     * Keep if moved, otherwise deref.
     */
    while (state.ptr) {
        const int ptr_in_old = is_ptr_in_old(state.ptr, to_old);

	if (IS_MOVED_BOXED(state.ptr->thing_word)) {
	    ASSERT(mode == SweepOffheapMajor || !ptr_in_old);

            *state.prev = state.ptr
                        = (OffheapHeader*) boxed_val(state.ptr->thing_word);
	    if (state.ptr->thing_word == HEADER_PROC_BIN) {
		const int to_new_heap = !is_ptr_in_old(state.ptr, to_old);
		ASSERT(to_new_heap == !seen_mature
                       || (!to_new_heap && (seen_mature = /*intentional*/ 1)));

                if (to_new_heap) {
		    bin_vheap += state.ptr->size / sizeof(Eterm);
		} else { /* for binary gc (words)*/
                    bin_ovheap += state.ptr->size / sizeof(Eterm);
		}
		link_live_proc_bin(&state, to_new_heap);
	    }
	    else {
                state.prev = &(state.ptr->next);
                state.ptr = state.ptr->next;
	    }
	}
	else if (! ptr_in_old || mode == SweepOffheapMajor) {
	    /* garbage */
	    switch (thing_subtag(state.ptr->thing_word)) {
                case REFC_BINARY_SUBTAG: {
                    Binary *bptr = ((ProcBin *) state.ptr)->val;
                    if (erts_refc_dectest(&bptr->refc, 0) == 0) {
                        erts_bin_free(bptr);
                    }
                    break;
                }
                case FUN_SUBTAG: {
                    ErlFunEntry *fe = ((ErlFunThing *) state.ptr)->fe;
                    if (erts_refc_dectest(&fe->refc, 0) == 0) {
                        erts_erase_fun_entry(fe);
                    }
                    break;
                }
                default:
                    ASSERT(is_external_header(state.ptr->thing_word));
                    erts_deref_node_entry(((ExternalThing *) state.ptr)->node);
            }
	    *state.prev = state.ptr = state.ptr->next;
	}
	else break; /* and let old-heap loop continue */
    }

    /* If we are doing a minor gc, we have to go through
     * the off_heap list of the old heap to look for any
     * proc bin that should be shrunk. proc bins are shrunk
     * when they have not been actively written to in-between
     * two minor GC and they have a lot of unused memory.
     */
    while (state.ptr) {
        ASSERT(is_ptr_in_old(state.ptr, to_old));
        ASSERT(!IS_MOVED_BOXED(state.ptr->thing_word));
        if (state.ptr->thing_word == HEADER_PROC_BIN) {
            link_live_proc_bin(&state, 0);
        }
        else {
            ASSERT(is_fun_header(state.ptr->thing_word) ||
                   is_external_header(state.ptr->thing_word));
            state.prev = &state.ptr->next;
            state.ptr = state.ptr->next;
        }
    }

    debug_check_offheap(p, to_young, to_old);

    if (mode == SweepOffheapMinor) {
        BIN_OLD_VHEAP_SZ(p) = next_vheap_size(
                p, BIN_OLD_VHEAP(p) + MSO(p).overhead, BIN_OLD_VHEAP_SZ(p));
    }
    BIN_VHEAP_SZ(p)  = next_vheap_size(p, bin_vheap, BIN_VHEAP_SZ(p));
    BIN_OLD_VHEAP(p) = bin_ovheap;
    MSO(p).overhead  = bin_vheap;

    /*
     * If we got any shrink candidates, check them out.
     */

    if (state.shrink.no_of_candidates) {
        ProcBin *candlist[] = {(ProcBin *) state.shrink.new_candidates,
                               (ProcBin *) state.shrink.old_candidates};
	Uint leave_unused = 0;
	int i;

        if (state.shrink.no_of_active == 0) {
            if (state.shrink.no_of_candidates <= INACT_WR_PB_LEAVE_MUCH_LIMIT) {
                leave_unused = INACT_WR_PB_LEAVE_MUCH_PERCENTAGE;
            } else if (state.shrink.no_of_candidates <= INACT_WR_PB_LEAVE_LIMIT) {
                leave_unused = INACT_WR_PB_LEAVE_PERCENTAGE;
            }
        }

        for (i = 0; i < ARRAY_LENGTH(candlist); i++) {
            ProcBin *pb;
	    for (pb = candlist[i]; pb; pb = (ProcBin*)pb->next) {
		Uint new_size = pb->size;

		if (leave_unused) {
		    new_size += (new_size * 100) / leave_unused;
		    /* Our allocators are 8 byte aligned, i.e., shrinking with
		       less than 8 bytes will have no real effect */
		    if (new_size + 8 >= pb->val->orig_size)
			continue;
		}

		pb->val = erts_bin_realloc(pb->val, new_size);
		pb->bytes = (byte *) pb->val->orig_bytes;
	    }
	}

	/*
	 * We now potentially have the mso list divided into three lists:
	 * - shrink candidates on new heap (inactive writable with unused data)
	 * - shrink candidates on old heap (inactive writable with unused data)
	 * - other binaries (read only + active writable ...) + funs and externals
	 *
	 * Put them back together: new candidates -> other -> old candidates
	 * This order will ensure that the list only refers from new
	 * generation to old and never from old to new *which is important*.
	 */
	if (state.shrink.new_candidates) {
            if (state.prev == &MSO(p).first) { /* empty other binaries list */
                state.prev = &(state.shrink.new_candidates_end->next);
            } else {
                state.shrink.new_candidates_end->next = MSO(p).first;
            }
            MSO(p).first = state.shrink.new_candidates;
        }
    }
    *state.prev = state.shrink.old_candidates;

    debug_check_offheap(p, to_young, to_old);
}

/*
 * Offset pointers into the heap (not stack).
 */

static void
offset_heap(Eterm* hp, Uint sz, Sint offs, char* area, Uint area_size)
{
    while (sz--) {
	Eterm val = *hp;
	switch (primary_tag(val)) {
	  case TAG_PRIMARY_LIST:
	  case TAG_PRIMARY_BOXED:
	      if (ErtsInArea(ptr_val(val), area, area_size)) {
		  *hp = offset_ptr(val, offs);
	      }
	      hp++;
	      break;
	  case TAG_PRIMARY_HEADER: {
	      Uint tari;

	      if (header_is_transparent(val)) {
		  hp++;
		  continue;
	      }
	      tari = thing_arityval(val);
	      switch (thing_subtag(val)) {
	      case REFC_BINARY_SUBTAG:
	      case FUN_SUBTAG:
	      case EXTERNAL_PID_SUBTAG:
	      case EXTERNAL_PORT_SUBTAG:
	      case EXTERNAL_REF_SUBTAG:
		  {
		      OffheapHeader* oh = (OffheapHeader*) hp;

		      if (ErtsInArea(oh->next, area, area_size)) {
			  Eterm** uptr = (Eterm **) (void *) &oh->next;
			  *uptr += offs; /* Patch the mso chain */
		      }
		  }
		  break;
	      case BIN_MATCHSTATE_SUBTAG:
		{
		  ErlBinMatchState *ms = (ErlBinMatchState*) hp;
		  ErlBinMatchBuffer *mb = &(ms->mb);
		  if (ErtsInArea(ptr_val(mb->orig), area, area_size)) {
		      mb->orig = offset_ptr(mb->orig, offs);
		      mb->base = binary_bytes(mb->orig);
		  }
		}
		break;
	      }
	      sz -= tari;
	      hp += tari + 1;
	      break;
	  }
	  default:
	      hp++;
	      continue;
	}
    }
}

/*
 * Offset pointers to heap from stack.
 */

static void
offset_heap_ptr(Eterm* hp, Uint sz, Sint offs, char* area, Uint area_size)
{
    while (sz--) {
	Eterm val = *hp;
	switch (primary_tag(val)) {
	case TAG_PRIMARY_LIST:
	case TAG_PRIMARY_BOXED:
	    if (ErtsInArea(ptr_val(val), area, area_size)) {
		*hp = offset_ptr(val, offs);
	    }
	    hp++;
	    break;
	default:
	    hp++;
	    break;
	}
    }
}

static void
offset_off_heap(Process* p, Sint offs, char* area, Uint area_size)
{
    if (MSO(p).first && ErtsInArea((Eterm *)MSO(p).first, area, area_size)) {
        Eterm** uptr = (Eterm**) (void *) &MSO(p).first;
        *uptr += offs;
    }
}

/*
 * Offset pointers in message queue.
 */
static void
offset_mqueue(Process *p, Sint offs, char* area, Uint area_size)
{
    ErtsMessage* mp = p->msg.first;

    if ((p->flags & (F_OFF_HEAP_MSGQ|F_OFF_HEAP_MSGQ_CHNG)) != F_OFF_HEAP_MSGQ) {

	while (mp != NULL) {
	    Eterm mesg = ERL_MESSAGE_TERM(mp);
	    if (is_value(mesg)) {
		switch (primary_tag(mesg)) {
		case TAG_PRIMARY_LIST:
		case TAG_PRIMARY_BOXED:
		    if (ErtsInArea(ptr_val(mesg), area, area_size)) {
			ERL_MESSAGE_TERM(mp) = offset_ptr(mesg, offs);
		    }
		    break;
		}
	    }
	    mesg = ERL_MESSAGE_TOKEN(mp);
	    if (is_boxed(mesg) && ErtsInArea(ptr_val(mesg), area, area_size)) {
		ERL_MESSAGE_TOKEN(mp) = offset_ptr(mesg, offs);
	    }
#ifdef USE_VM_PROBES
	    mesg = ERL_MESSAGE_DT_UTAG(mp);
	    if (is_boxed(mesg) && ErtsInArea(ptr_val(mesg), area, area_size)) {
		ERL_MESSAGE_DT_UTAG(mp) = offset_ptr(mesg, offs);
	    }
#endif

	    ASSERT((is_nil(ERL_MESSAGE_TOKEN(mp)) ||
		    is_tuple(ERL_MESSAGE_TOKEN(mp)) ||
		    is_atom(ERL_MESSAGE_TOKEN(mp))));
	    mp = mp->next;
	}

    }
}

static void ERTS_INLINE
offset_one_rootset(Process *p, Sint offs, char* area, Uint area_size,
	       Eterm* objv, int nobj)
{
    if (p->dictionary)  {
	offset_heap(ERTS_PD_START(p->dictionary),
		    ERTS_PD_SIZE(p->dictionary),
		    offs, area, area_size);
    }

    offset_heap_ptr(&p->fvalue, 1, offs, area, area_size);
    offset_heap_ptr(&p->ftrace, 1, offs, area, area_size);
    offset_heap_ptr(&p->seq_trace_token, 1, offs, area, area_size);
#ifdef USE_VM_PROBES
    offset_heap_ptr(&p->dt_utag, 1, offs, area, area_size);
#endif
    offset_heap_ptr(&p->group_leader, 1, offs, area, area_size);
    offset_mqueue(p, offs, area, area_size);
    offset_heap_ptr(p->stop, (STACK_START(p) - p->stop), offs, area, area_size);
    offset_nstack(p, offs, area, area_size);
    if (nobj > 0) {
	offset_heap_ptr(objv, nobj, offs, area, area_size);
    }
    offset_off_heap(p, offs, area, area_size);
}

static void
offset_rootset(Process *p, Sint offs, char* area, Uint area_size,
	       Eterm* objv, int nobj)
{
    offset_one_rootset(p, offs, area, area_size, objv, nobj);
}

static void
init_gc_info(ErtsGCInfo *gcip)
{
  gcip->reclaimed = 0;
  gcip->garbage_cols = 0;
}

static void
reply_gc_info(void *vgcirp)
{
    Uint64 reclaimed = 0, garbage_cols = 0;
    ErtsSchedulerData *esdp = erts_get_scheduler_data();
    ErtsGCInfoReq *gcirp = (ErtsGCInfoReq *) vgcirp;
    ErtsProcLocks rp_locks = (gcirp->req_sched == esdp->no
			      ? ERTS_PROC_LOCK_MAIN
			      : 0);
    Process *rp = gcirp->proc;
    Eterm ref_copy = NIL, msg;
    Eterm *hp = NULL;
    Eterm **hpp;
    Uint sz, *szp;
    ErlOffHeap *ohp = NULL;
    ErtsMessage *mp = NULL;

    ASSERT(esdp);

    reclaimed = esdp->gc_info.reclaimed;
    garbage_cols = esdp->gc_info.garbage_cols;

    sz = 0;
    hpp = NULL;
    szp = &sz;

    while (1) {
	if (hpp)
	    ref_copy = STORE_NC(hpp, ohp, gcirp->ref);
	else
	    *szp += REF_THING_SIZE;

	msg = erts_bld_tuple(hpp, szp, 3,
			     make_small(esdp->no),
			     erts_bld_uint64(hpp, szp, garbage_cols),
			     erts_bld_uint64(hpp, szp, reclaimed));

	msg = erts_bld_tuple(hpp, szp, 2, ref_copy, msg);
	if (hpp)
	  break;

	mp = erts_alloc_message_heap(rp, &rp_locks, sz, &hp, &ohp);

	szp = NULL;
	hpp = &hp;
    }

    erts_queue_message(rp, rp_locks, mp, msg, am_system);

    if (gcirp->req_sched == esdp->no)
	rp_locks &= ~ERTS_PROC_LOCK_MAIN;

    if (rp_locks)
	erts_smp_proc_unlock(rp, rp_locks);

    erts_proc_dec_refc(rp);

    if (erts_smp_atomic32_dec_read_nob(&gcirp->refc) == 0)
	gcireq_free(vgcirp);
}

Eterm
erts_gc_info_request(Process *c_p)
{
    ErtsSchedulerData *esdp = erts_proc_sched_data(c_p);
    Eterm ref;
    ErtsGCInfoReq *gcirp;
    Eterm *hp;

    gcirp = gcireq_alloc();
    ref = erts_make_ref(c_p);
    hp = &gcirp->ref_heap[0];

    gcirp->proc = c_p;
    gcirp->ref = STORE_NC(&hp, NULL, ref);
    gcirp->req_sched = esdp->no;
    erts_smp_atomic32_init_nob(&gcirp->refc,
			       (erts_aint32_t) erts_no_schedulers);

    erts_proc_add_refc(c_p, (Sint) erts_no_schedulers);

#ifdef ERTS_SMP
    if (erts_no_schedulers > 1)
	erts_schedule_multi_misc_aux_work(1,
					  erts_no_schedulers,
					  reply_gc_info,
					  (void *) gcirp);
#endif

    reply_gc_info((void *) gcirp);

    return ref;
}

Eterm
erts_process_gc_info(Process *p, Uint *sizep, Eterm **hpp,
                     Uint extra_heap_block,
                     Uint extra_old_heap_block_size)
{
    ERTS_DECL_AM(bin_vheap_size);
    ERTS_DECL_AM(bin_vheap_block_size);
    ERTS_DECL_AM(bin_old_vheap_size);
    ERTS_DECL_AM(bin_old_vheap_block_size);
    Eterm tags[] = {
        /* If you increase the number of elements here, make sure to update
           any call sites as they may have stack allocations that depend
           on the number of elements here. */
        am_old_heap_block_size,
        am_heap_block_size,
        am_mbuf_size,
        am_recent_size,
        am_stack_size,
        am_old_heap_size,
        am_heap_size,
        AM_bin_vheap_size,
        AM_bin_vheap_block_size,
        AM_bin_old_vheap_size,
        AM_bin_old_vheap_block_size
    };
    UWord values[] = {
        OLD_HEAP(p) ? OLD_HEND(p) - OLD_HEAP(p) + extra_old_heap_block_size
                    : extra_old_heap_block_size,
        HEAP_SIZE(p) + extra_heap_block,
        MBUF_SIZE(p),
        HIGH_WATER(p) - HEAP_START(p),
        STACK_START(p) - p->stop,
        OLD_HEAP(p) ? OLD_HTOP(p) - OLD_HEAP(p) : 0,
        HEAP_TOP(p) - HEAP_START(p),
        MSO(p).overhead,
        BIN_VHEAP_SZ(p),
        BIN_OLD_VHEAP(p),
        BIN_OLD_VHEAP_SZ(p)
    };

    Eterm res = THE_NON_VALUE;
    ErtsMessage *mp;

    ERTS_CT_ASSERT(sizeof(values)/sizeof(*values) == sizeof(tags)/sizeof(*tags));
    ERTS_CT_ASSERT(sizeof(values)/sizeof(*values) == ERTS_PROCESS_GC_INFO_MAX_TERMS);

    if (p->abandoned_heap) {
        Eterm *htop, *heap;
        ERTS_GET_ORIG_HEAP(p, heap, htop);
        values[3] = HIGH_WATER(p) - heap;
        values[6] = htop - heap;
    }

    if (p->flags & F_ON_HEAP_MSGQ) {
        /* If on heap messages in the internal queue are counted
           as being part of the heap, so we have to add them to the
           am_mbuf_size value. process_info(total_heap_size) should
           be the same as adding old_heap_block_size + heap_block_size
           + mbuf_size.
        */
        for (mp = p->msg.first; mp; mp = mp->next)
            if (mp->data.attached)
                values[2] += erts_msg_attached_data_size(mp);
    }

    res = erts_bld_atom_uword_2tup_list(hpp,
                                        sizep,
                                        sizeof(values)/sizeof(*values),
                                        tags,
                                        values);

    return res;
}

static int
reached_max_heap_size(Process *p, Uint total_heap_size,
                      Uint extra_heap_size, Uint extra_old_heap_size)
{
    Uint max_heap_flags = MAX_HEAP_SIZE_FLAGS_GET(p);
    if (IS_TRACED_FL(p, F_TRACE_GC) ||
        max_heap_flags & MAX_HEAP_SIZE_LOG) {
        Eterm msg;
        Uint size = 0;
        Eterm *o_hp , *hp;
        erts_process_gc_info(p, &size, NULL, extra_heap_size,
                             extra_old_heap_size);
        o_hp = hp = erts_alloc(ERTS_ALC_T_TMP, size * sizeof(Eterm));
        msg = erts_process_gc_info(p, NULL, &hp, extra_heap_size,
                                   extra_old_heap_size);

        if (max_heap_flags & MAX_HEAP_SIZE_LOG) {
            int alive = erts_is_alive;
            erts_dsprintf_buf_t *dsbufp = erts_create_logger_dsbuf();
            Eterm *o_hp, *hp, args = NIL;

            /* Build the format message */
            erts_dsprintf(dsbufp, "     Process:          ~p ");
            if (alive)
                erts_dsprintf(dsbufp, "on node ~p");
            erts_dsprintf(dsbufp, "~n     Context:          maximum heap size reached~n");
            erts_dsprintf(dsbufp, "     Max Heap Size:    ~p~n");
            erts_dsprintf(dsbufp, "     Total Heap Size:  ~p~n");
            erts_dsprintf(dsbufp, "     Kill:             ~p~n");
            erts_dsprintf(dsbufp, "     Error Logger:     ~p~n");
            erts_dsprintf(dsbufp, "     GC Info:          ~p~n");

            /* Build the args in reverse order */
            o_hp = hp = erts_alloc(ERTS_ALC_T_TMP, 2*(alive ? 7 : 6) * sizeof(Eterm));
            args = CONS(hp, msg, args); hp += 2;
            args = CONS(hp, am_true, args); hp += 2;
            args = CONS(hp, (max_heap_flags & MAX_HEAP_SIZE_KILL ? am_true : am_false), args); hp += 2;
            args = CONS(hp, make_small(total_heap_size), args); hp += 2;
            args = CONS(hp, make_small(MAX_HEAP_SIZE_GET(p)), args); hp += 2;
            if (alive) {
                args = CONS(hp, erts_this_node->sysname, args); hp += 2;
            }
            args = CONS(hp, p->common.id, args); hp += 2;

            erts_send_error_term_to_logger(p->group_leader, dsbufp, args);
            erts_free(ERTS_ALC_T_TMP, o_hp);
        }

        if (IS_TRACED_FL(p, F_TRACE_GC))
            trace_gc(p, am_gc_max_heap_size, 0, msg);

        erts_free(ERTS_ALC_T_TMP, o_hp);
    }
    /* returns true if we should kill the process */
    return max_heap_flags & MAX_HEAP_SIZE_KILL;
}

Eterm
erts_max_heap_size_map(Sint max_heap_size, Uint max_heap_flags,
                       Eterm **hpp, Uint *sz)
{
    if (!hpp) {
        *sz += (2*3 + 1 + MAP_HEADER_FLATMAP_SZ);
        return THE_NON_VALUE;
    } else {
        Eterm *hp = *hpp;
        Eterm keys = TUPLE3(hp, am_error_logger, am_kill, am_size);
        flatmap_t *mp;
        hp += 4;
        mp = (flatmap_t*) hp;
        mp->thing_word = MAP_HEADER_FLATMAP;
        mp->size = 3;
        mp->keys = keys;
        hp += MAP_HEADER_FLATMAP_SZ;
        *hp++ = max_heap_flags & MAX_HEAP_SIZE_LOG ? am_true : am_false;
        *hp++ = max_heap_flags & MAX_HEAP_SIZE_KILL ? am_true : am_false;
        *hp++ = make_small(max_heap_size);
        *hpp = hp;
        return make_flatmap(mp);
    }
}

int
erts_max_heap_size(Eterm arg, Uint *max_heap_size, Uint *max_heap_flags)
{
    Sint sz;
    *max_heap_flags = H_MAX_FLAGS;
    if (is_small(arg)) {
        sz = signed_val(arg);
        *max_heap_flags = H_MAX_FLAGS;
    } else if (is_map(arg)) {
        const Eterm *size = erts_maps_get(am_size, arg);
        const Eterm *kill = erts_maps_get(am_kill, arg);
        const Eterm *log = erts_maps_get(am_error_logger, arg);
        if (size && is_small(*size)) {
            sz = signed_val(*size);
        } else {
            /* size is mandatory */
            return 0;
        }
        if (kill) {
            if (*kill == am_true)
                *max_heap_flags |= MAX_HEAP_SIZE_KILL;
            else if (*kill == am_false)
                *max_heap_flags &= ~MAX_HEAP_SIZE_KILL;
            else
                return 0;
        }
        if (log) {
            if (*log == am_true)
                *max_heap_flags |= MAX_HEAP_SIZE_LOG;
            else if (*log == am_false)
                *max_heap_flags &= ~MAX_HEAP_SIZE_LOG;
            else
                return 0;
        }
    } else
        return 0;
    if (sz < 0)
        return 0;
    *max_heap_size = sz;
    return 1;
}

#if defined(DEBUG) || defined(ERTS_OFFHEAP_DEBUG)

static int
within2(Eterm *ptr, Process *p, Eterm *real_htop)
{
    ErlHeapFragment* bp;
    ErtsMessage* mp;
    Eterm *htop, *heap;

    if (p->abandoned_heap)
	ERTS_GET_ORIG_HEAP(p, heap, htop);
    else {
	heap = p->heap;
	htop = real_htop ? real_htop : HEAP_TOP(p);
    }

    if (OLD_HEAP(p) && (OLD_HEAP(p) <= ptr && ptr < OLD_HEND(p))) {
        return 1;
    }
    if (heap <= ptr && ptr < htop) {
        return 1;
    }

    mp = p->msg_frag;
    bp = p->mbuf;

    if (bp)
	goto search_heap_frags;

    while (mp) {

        bp = erts_message_to_heap_frag(mp);
	mp = mp->next;

    search_heap_frags:

	while (bp) {
	    if (bp->mem <= ptr && ptr < bp->mem + bp->used_size) {
		return 1;
	    }
	    bp = bp->next;
	}
    }

    return 0;
}

int
within(Eterm *ptr, Process *p)
{
    return within2(ptr, p, NULL);
}

#endif

#ifdef ERTS_OFFHEAP_DEBUG

#define ERTS_CHK_OFFHEAP_ASSERT(EXP)			\
do {							\
    if (!(EXP))						\
	erts_exit(ERTS_ABORT_EXIT,			\
		 "%s:%d: Assertion failed: %s\n",	\
		 __FILE__, __LINE__, #EXP);		\
} while (0)


#ifdef ERTS_OFFHEAP_DEBUG_CHK_CIRCULAR_LIST
#  define ERTS_OFFHEAP_VISITED_BIT ((Eterm) 1 << 31)
#endif

void
erts_check_off_heap2(Process *p, Eterm *htop)
{
    Eterm *oheap = (Eterm *) OLD_HEAP(p);
    Eterm *ohtop = (Eterm *) OLD_HTOP(p);
    int old;
    union erl_off_heap_ptr u;
//    erts_printf("debug_chk_off_heap2 %T ", p->common.id);

    old = 0;
    for (u.hdr = MSO(p).first; u.hdr; u.hdr = u.hdr->next) {
	erts_aint_t refc;
//        erts_printf("%p ", u.ep);

	switch (thing_subtag(u.hdr->thing_word)) {
	case REFC_BINARY_SUBTAG:
	    refc = erts_refc_read(&u.pb->val->refc, 1);
	    break;
	case FUN_SUBTAG:
	    refc = erts_refc_read(&u.fun->fe->refc, 1);
	    break;
	case EXTERNAL_PID_SUBTAG:
	case EXTERNAL_PORT_SUBTAG:
	case EXTERNAL_REF_SUBTAG:
	    refc = erts_refc_read(&u.ext->node->refc, 1);
	    break;
	default:
	    ASSERT(!"erts_check_off_heap2: Invalid thing_word");
	}
	ERTS_CHK_OFFHEAP_ASSERT(refc >= 1);
#ifdef ERTS_OFFHEAP_DEBUG_CHK_CIRCULAR_LIST
	ERTS_CHK_OFFHEAP_ASSERT(!(u.hdr->thing_word & ERTS_OFFHEAP_VISITED_BIT));
	u.hdr->thing_word |= ERTS_OFFHEAP_VISITED_BIT;
#endif
	if (old) {
	    ERTS_CHK_OFFHEAP_ASSERT(oheap <= u.ep && u.ep < ohtop);
	}
	else if (oheap <= u.ep && u.ep < ohtop)
	    old = 1;
	else {
	    ERTS_CHK_OFFHEAP_ASSERT(within2(u.ep, p, htop));
	}
    }

#ifdef ERTS_OFFHEAP_DEBUG_CHK_CIRCULAR_LIST
    for (u.hdr = MSO(p).first; u.hdr; u.hdr = u.hdr->next)
	u.hdr->thing_word &= ~ERTS_OFFHEAP_VISITED_BIT;
#endif
//    erts_printf("\r\n");
}

void
erts_check_off_heap(Process *p)
{
    erts_check_off_heap2(p, NULL);
}

#endif

#ifdef DEBUG
static void debug_scan_heap_1(const Eterm *hp, const Eterm *last,
                              const Eterm *n_heap, const Eterm *n_htop,
                              const Eterm *old_heap, const Eterm *old_htop)
{
    while (hp != last) {
        Eterm gval;
        ASSERT(hp < last);
        gval = *hp;

        switch (primary_tag(gval)) {
            case TAG_PRIMARY_IMMED1:
                hp++;
                break;
            case TAG_PRIMARY_BOXED: {
//                Eterm *pbox = boxed_val(gval);
//                if (IS_MOVED_BOXED(*pbox)) {
//                    pbox = boxed_val(pbox[0]);
//                }
//                ASSERT(erts_is_literal(gval, pbox)
//                       || is_between(pbox, n_heap, n_htop)
//                       || is_between(pbox, old_heap, old_htop));
                ASSERT(is_header(*boxed_val(gval))
                       || is_boxed(*boxed_val(gval)));
                hp++;
                break;
            }
            case TAG_PRIMARY_LIST: {
//                Eterm *pcons = list_val(gval);
//                ASSERT(!IS_MOVED_CONS(*pcons));
                ASSERT(!is_header(CAR(list_val(gval)))
                       || (IS_MOVED_CONS(CAR(list_val(gval)))
                           && is_list(CDR(list_val(gval)))));
//                ASSERT(erts_is_literal(gval, pcons)
//                       || is_between(pcons, n_heap, n_htop)
//                       || is_between(pcons, old_heap, old_htop));
                hp++;
                break;
            }
            case TAG_PRIMARY_HEADER: {
                if (!header_is_thing(gval)) {
                    hp++;
                } else {
                    hp += (thing_arityval(gval)+1);
                }
                break;
            }
            default:
                ASSERT(! "should not be here");
        }
    }
}
#endif

#ifdef DEBUG
static void debug_scan_heap(const Eterm *n_heap, const Eterm *n_htop,
                            const Eterm *old_heap, const Eterm *old_htop)
{
    debug_scan_heap_1(n_heap, n_htop, n_heap, n_htop, old_heap, old_htop);
    if (old_heap) {
        debug_scan_heap_1(old_heap, old_htop, n_heap, n_htop,
                          old_heap, old_htop);
    }
}
#endif