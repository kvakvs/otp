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
#include "erl_process.h"
#include "erl_gc.h"

#include "global.h" /* Goes before binary.h */

#include "erl_binary.h"
#include "erl_bits.h"
#include "sys.h"
#include "erl_gc_sweep.h"

#if HIPE
    #include "hipe_stack.h"
    #include "hipe_mode_switch.h"
#endif

#define ERTS_INACT_WR_PB_LEAVE_MUCH_LIMIT 1
#define ERTS_INACT_WR_PB_LEAVE_MUCH_PERCENTAGE 20
#define ERTS_INACT_WR_PB_LEAVE_LIMIT 10
#define ERTS_INACT_WR_PB_LEAVE_PERCENTAGE 10

/*
 * Offheap sweeping facilities
 */
typedef struct {
    struct erl_off_heap_header* new_candidates;
    struct erl_off_heap_header* new_candidates_end;
    struct erl_off_heap_header* old_candidates;
    Uint no_of_candidates;
    Uint no_of_active;
} ShrinkCandidates;

Uint
erts_gc_rootset_new(Process *p, Eterm *objv, int nobj, ErtsGCRootset *rootset)
{
    ErtsGCRoots* roots;
    Uint n;

    n = 0;
    roots = rootset->roots = rootset->def;
    rootset->size = ALENGTH(rootset->def);

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
                                   new_size*sizeof(ErtsGCRoots));
                sys_memcpy(roots, rootset->def, n*sizeof(ErtsGCRoots));
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

void erts_gc_rootset_done(ErtsGCRootset *rootset)
{
    if (rootset->roots != rootset->def) {
        erts_free(ERTS_ALC_T_ROOTSET, rootset->roots);
    }
}

void
erts_gc_full_sweep_heaps(Process *p, int hibernate,
                         Eterm *primary_hp, Eterm **primary_topp,
                         Eterm *secondary_hp, Eterm **secondary_topp,
                         const char *oh_start, Uint oh_bytes,
                         const char *mature_start, Uint mature_bytes,
                         Eterm *objv, int nobj)
{
    ErtsGCRootset rootset;
    erts_gc_rootset_new(p, objv, nobj, &rootset);

#ifdef HIPE
    if (hibernate) {
        hipe_empty_nstack(p);
    } else {
        *primary_topp = fullsweep_nstack(p, *primary_topp);
    }
#endif

    /* All that is not literal -> n_htop */
    erts_gc_generic_roots_sweep(&rootset,
                                primary_topp,       /* in out */
                                secondary_topp,     /* in out */
                                ErtsGC_SweepOp_NotLiteral_OldOrMature, /* primary */
                                ErtsGC_SweepOp_NotLiteral,             /* secondary */
                                NULL, 0,            /* oh_start, bytes */
                                NULL, 0);           /* mature_start, bytes */

    erts_gc_rootset_done(&rootset);

    /*
     * Now all references on the stack point to the new heap. However,
     * most references on the new heap point to the old heap so the next stage
     * is to scan through the new heap evacuating data from the old heap
     * until all is copied.
     */

    erts_gc_generic_sweep(primary_hp, primary_topp,
                          secondary_hp, secondary_topp,
                          ErtsGC_SweepOp_NotLiteral,
                          ErtsGC_SweepOp_NotLiteral_OldOrMature,
                          oh_start, oh_bytes,
                          mature_start, mature_bytes);

    erts_gc_generic_sweep(secondary_hp, secondary_topp,
                          NULL, NULL,
                          ErtsGC_SweepOp_NotLiteral_OldOrMature,
                          ErtsGC_SweepOp_None,
                          oh_start, oh_bytes,
                          NULL, 0);

    if (MSO(p).first) {
        erts_gc_sweep_off_heap(p, 1);
    }

    if (OLD_HEAP(p) != NULL) {
        ERTS_HEAP_FREE(ERTS_ALC_T_OLD_HEAP,
                       OLD_HEAP(p),
                       (OLD_HEND(p) - OLD_HEAP(p)) * sizeof(Eterm));
        OLD_HEAP(p) = OLD_HTOP(p) = OLD_HEND(p) = NULL;
    }
}

static ERTS_INLINE void
link_live_proc_bin(ShrinkCandidates *shrink,
                   struct erl_off_heap_header*** prevppp,
                   struct erl_off_heap_header** currpp,
                   int new_heap)
{
    ProcBin *pbp = (ProcBin*) *currpp;
    ASSERT(**prevppp == *currpp);

    *currpp = pbp->next;
    if (pbp->flags & (PB_ACTIVE_WRITER|PB_IS_WRITABLE)) {
        ASSERT(((pbp->flags & (PB_ACTIVE_WRITER|PB_IS_WRITABLE))
                == (PB_ACTIVE_WRITER|PB_IS_WRITABLE))
               || ((pbp->flags & (PB_ACTIVE_WRITER|PB_IS_WRITABLE))
                   == PB_IS_WRITABLE));


        if (pbp->flags & PB_ACTIVE_WRITER) {
            shrink->no_of_active++;
        }
        else { /* inactive */
            Uint unused = pbp->val->orig_size - pbp->size;
            /* Our allocators are 8 byte aligned, i.e., shrinking with
               less than 8 bytes will have no real effect */
            if (unused >= 8) { /* A shrink candidate; save in candidate list */
                **prevppp = pbp->next;
                if (new_heap) {
                    if (!shrink->new_candidates)
                        shrink->new_candidates_end = (struct erl_off_heap_header*)pbp;
                    pbp->next = shrink->new_candidates;
                    shrink->new_candidates = (struct erl_off_heap_header*)pbp;
                }
                else {
                    pbp->next = shrink->old_candidates;
                    shrink->old_candidates = (struct erl_off_heap_header*)pbp;
                }
                shrink->no_of_candidates++;
                return;
            }
        }
    }

    /* Not a shrink candidate; keep in original mso list */
    *prevppp = &pbp->next;
}

void
erts_gc_sweep_off_heap(Process *p, int fullsweep)
{
    ShrinkCandidates shrink = {0};
    struct erl_off_heap_header* ptr;
    struct erl_off_heap_header** prev;
    char* oheap = NULL;
    Uint oheap_sz = 0;
    Uint64 bin_vheap = 0;
#ifdef DEBUG
    int seen_mature = 0;
#endif

    if (fullsweep == 0) {
        oheap = (char *) OLD_HEAP(p);
        oheap_sz = (char *) OLD_HEND(p) - oheap;
    }

    BIN_OLD_VHEAP(p) = 0;

    prev = &MSO(p).first;
    ptr = MSO(p).first;

    /* Firts part of the list will reside on the (old) new-heap.
     * Keep if moved, otherwise deref.
     */
    while (ptr) {
        if (IS_MOVED_BOXED(ptr->thing_word)) {
            ASSERT(!ErtsInArea(ptr, oheap, oheap_sz));
            *prev = ptr = (struct erl_off_heap_header*) boxed_val(ptr->thing_word);
            ASSERT(!IS_MOVED_BOXED(ptr->thing_word));
            if (ptr->thing_word == HEADER_PROC_BIN) {
                int to_new_heap = !ErtsInArea(ptr, oheap, oheap_sz);
                ASSERT(to_new_heap == !seen_mature || (!to_new_heap && (seen_mature=1)));
                if (to_new_heap) {
                    bin_vheap += ptr->size / sizeof(Eterm);
                } else {
                    BIN_OLD_VHEAP(p) += ptr->size / sizeof(Eterm); /* for binary gc (words)*/
                }
                link_live_proc_bin(&shrink, &prev, &ptr, to_new_heap);
            }
            else {
                prev = &ptr->next;
                ptr = ptr->next;
            }
        }
        else if (!ErtsInArea(ptr, oheap, oheap_sz)) {
            /* garbage */
            switch (thing_subtag(ptr->thing_word)) {
                case REFC_BINARY_SUBTAG:
                {
                    Binary* bptr = ((ProcBin*)ptr)->val;
                    if (erts_refc_dectest(&bptr->refc, 0) == 0) {
                        erts_bin_free(bptr);
                    }
                    break;
                }
                case FUN_SUBTAG:
                {
                    ErlFunEntry* fe = ((ErlFunThing*)ptr)->fe;
                    if (erts_refc_dectest(&fe->refc, 0) == 0) {
                        erts_erase_fun_entry(fe);
                    }
                    break;
                }
                default:
                    ASSERT(is_external_header(ptr->thing_word));
                    erts_deref_node_entry(((ExternalThing*)ptr)->node);
            }
            *prev = ptr = ptr->next;
        }
        else break; /* and let old-heap loop continue */
    }

    /* The rest of the list resides on old-heap, and we just did a
     * generational collection - keep objects in list.
     */
    while (ptr) {
        ASSERT(ErtsInArea(ptr, oheap, oheap_sz));
        ASSERT(!IS_MOVED_BOXED(ptr->thing_word));
        if (ptr->thing_word == HEADER_PROC_BIN) {
            BIN_OLD_VHEAP(p) += ptr->size / sizeof(Eterm); /* for binary gc (words)*/
            link_live_proc_bin(&shrink, &prev, &ptr, 0);
        }
        else {
            ASSERT(is_fun_header(ptr->thing_word) ||
                   is_external_header(ptr->thing_word));
            prev = &ptr->next;
            ptr = ptr->next;
        }
    }

    if (fullsweep) {
        BIN_OLD_VHEAP_SZ(p) = erts_gc_next_vheap_size(p, BIN_OLD_VHEAP(p) +
                                                         MSO(p).overhead,
                                                      BIN_OLD_VHEAP_SZ(p));
    }
    BIN_VHEAP_SZ(p)     = erts_gc_next_vheap_size(p, bin_vheap, BIN_VHEAP_SZ(p));
    MSO(p).overhead     = bin_vheap;

    /*
     * If we got any shrink candidates, check them out.
     */

    if (shrink.no_of_candidates) {
        ProcBin *candlist[] = { (ProcBin*)shrink.new_candidates,
                                (ProcBin*)shrink.old_candidates };
        Uint leave_unused = 0;
        int i;

        if (shrink.no_of_active == 0) {
            if (shrink.no_of_candidates <= ERTS_INACT_WR_PB_LEAVE_MUCH_LIMIT)
                leave_unused = ERTS_INACT_WR_PB_LEAVE_MUCH_PERCENTAGE;
            else if (shrink.no_of_candidates <= ERTS_INACT_WR_PB_LEAVE_LIMIT)
                leave_unused = ERTS_INACT_WR_PB_LEAVE_PERCENTAGE;
        }

        for (i = 0; i < sizeof(candlist)/sizeof(candlist[0]); i++) {
            ProcBin* pb;
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
        if (shrink.new_candidates) {
            if (prev == &MSO(p).first) /* empty other binaries list */
                prev = &shrink.new_candidates_end->next;
            else
                shrink.new_candidates_end->next = MSO(p).first;
            MSO(p).first = shrink.new_candidates;
        }
    }
    *prev = shrink.old_candidates;
}
