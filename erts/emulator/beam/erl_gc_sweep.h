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
#ifndef __ERL_GC_SWEEP_H
#define __ERL_GC_SWEEP_H

#if defined(DEBUG) || 0
#define ERTS_GC_DEBUG
#else
#undef ERTS_GC_DEBUG
#endif
#ifdef ERTS_GC_DEBUG
#  define ERTS_GC_ASSERT ASSERT
#else
#  define ERTS_GC_ASSERT(B) ((void) 1)
#endif

/*
 * Returns number of elements in an array.
 */
#define ALENGTH(a) (sizeof(a)/sizeof(a[0]))

/*
 * This structure describes the rootset for the GC.
 */
typedef struct {
    Eterm* v;   /* Pointers to vectors with terms to GC (e.g. the stack). */
    Uint sz;    /* Size of each vector. */
} ErtsGCRoots;

typedef struct {
    ErtsGCRoots def[32];    /* Default storage. */
    ErtsGCRoots *roots;     /* Pointer to root set array. */
    Uint size;	            /* Storage size. */
    int num_roots;          /* Number of root arrays. */
} ErtsGCRootset;

Uint erts_gc_rootset_new(Process *p,
                         Eterm *objv, int nobj,
                         ErtsGCRootset *rootset);
void erts_gc_rootset_done(ErtsGCRootset *rootset);

void erts_gc_full_sweep_heaps(Process *p, int hibernate, Eterm *primary_hp,
                              Eterm **primary_topp, Eterm *secondary_hp,
                              Eterm **secondary_topp, const char *oh_start,
                              Uint oh_bytes, const char *mature_start,
                              Uint mature_bytes, Eterm *objv, int nobj);

void erts_gc_sweep_off_heap(Process *p, int fullsweep);

static Uint64 ERTS_INLINE
erts_gc_do_next_vheap_size(Uint64 vheap, Uint64 vheap_sz) {

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

static Uint64 ERTS_INLINE
erts_gc_next_vheap_size(Process *p, Uint64 vheap, Uint64 vheap_sz) {
    Uint64 new_vheap_sz = erts_gc_do_next_vheap_size(vheap, vheap_sz);
    return new_vheap_sz < p->min_vheap_size ? p->min_vheap_size : new_vheap_sz;
}

typedef enum {
    ErtsGC_SweepOp_None,
    ErtsGC_SweepOp_NotLiteral,
    ErtsGC_SweepOp_NotLiteral_NotOld,
    ErtsGC_SweepOp_NotLiteral_OldOrMature,
    ErtsGC_SweepOp_NotLiteral_Mature,
    ErtsGC_SweepOp_Mature
} ErtsGCSweepOp;

/* NOTE: during sweeps primary condition is checked AFTER secondary! */
static ERTS_FORCE_INLINE int
erts_gc_is_in_primary_area(const Eterm *ptr,
                           const ErtsGCSweepOp type,
                           const char *oh_start, Uint oh_size,
                           const char *mature_start, Uint mature_size,
                           const int is_literal)
{
    switch (type) {
        case ErtsGC_SweepOp_NotLiteral:
            return !is_literal;

        case ErtsGC_SweepOp_NotLiteral_NotOld:
            return !is_literal
                   && !ErtsInArea(ptr, oh_start, oh_size);

        case ErtsGC_SweepOp_Mature:
            return ErtsInArea(ptr, mature_start, mature_size);

        case ErtsGC_SweepOp_NotLiteral_OldOrMature:
            return !is_literal
                   && (ErtsInArea(ptr, mature_start, mature_size)
                       || ErtsInArea(ptr, oh_start, oh_size));

        case ErtsGC_SweepOp_NotLiteral_Mature:
            return !is_literal
                   && ErtsInArea(ptr, mature_start, mature_size);

        case ErtsGC_SweepOp_None:
            return 0;

        default:
            ASSERT(!"unsupported sweep op");
    }
    ASSERT(0); return 0;
}

/* NOTE: in sweep secondary (this) condition is checked first */
static ERTS_FORCE_INLINE int
erts_gc_is_in_secondary_area(const Eterm *ptr,
                             const ErtsGCSweepOp type,
                             const char *oh_start, Uint oh_size,
                             const char *mature_start, Uint mature_size,
                             const Eterm *secondary_top,
                             const int is_literal)
{
    if (!secondary_top) { return 0; }
    return erts_gc_is_in_primary_area(ptr, type,
                                      oh_start, oh_size,
                                      mature_start, mature_size,
                                      is_literal);
}

static ERTS_FORCE_INLINE void
erts_gc_generic_sweep(Eterm *hp, Eterm **primary_topp,
                      Eterm *secondary_hp, Eterm **secondary_topp,
                      const ErtsGCSweepOp primary_op,
                      const ErtsGCSweepOp secondary_op,
                      const char *oh_start, Uint oh_bytes,
                      const char *mature_start, Uint mature_bytes)
{
    Eterm gval;
    Eterm *primary_top = *primary_topp;
    Eterm *secondary_top = secondary_topp ? *secondary_topp : NULL;
    int is_lit;
//#ifdef DEBUG
//    /* Back up heap start to debug_sweep_check later */
//    const Eterm *primary_hp0 = hp;
//    const Eterm *secondary_hp0 = secondary_hp;
//#endif

    while (hp != primary_top) {
        ASSERT(hp < primary_top);
        gval = *hp;

        switch (primary_tag(gval)) {
            case TAG_PRIMARY_BOXED: {
                Eterm *ptr = boxed_val(gval);
                Eterm val = *ptr;
                is_lit = erts_is_literal(gval, ptr);

                if (IS_MOVED_BOXED(val)) {
                    ASSERT(is_boxed(val));
                    *hp++ = val;
                } else if (erts_gc_is_in_secondary_area(ptr, secondary_op,
                                                        oh_start, oh_bytes,
                                                        mature_start,
                                                        mature_bytes,
                                                        secondary_top, is_lit)) {
                    MOVE_BOXED(ptr, val, secondary_top, hp++);
                } else if (erts_gc_is_in_primary_area(ptr, primary_op,
                                                      oh_start, oh_bytes,
                                                      mature_start,
                                                      mature_bytes,
                                                      is_lit)) {
                    MOVE_BOXED(ptr, val, primary_top, hp++);
                } else {
                    hp++;
                }
                break;
            }
            case TAG_PRIMARY_LIST: {
                Eterm *ptr = list_val(gval);
                Eterm val = *ptr;
                is_lit = erts_is_literal(gval, ptr);

                if (IS_MOVED_CONS(val)) {
                    *hp++ = ptr[1];
                } else if (erts_gc_is_in_secondary_area(ptr, secondary_op,
                                                        oh_start, oh_bytes,
                                                        mature_start,
                                                        mature_bytes,
                                                        secondary_top, is_lit)) {
                    MOVE_CONS(ptr, val, secondary_top, hp++);
                } else if (erts_gc_is_in_primary_area(ptr, primary_op,
                                                      oh_start, oh_bytes,
                                                      mature_start,
                                                      mature_bytes,
                                                      is_lit)) {
                    MOVE_CONS(ptr, val, primary_top, hp++);
                } else {
                    hp++;
                }
                break;
            }
            case TAG_PRIMARY_HEADER: {
                if (!header_is_thing(gval)) {
                    hp++;
                } else {
                    if (header_is_bin_matchstate(gval)) {
                        ErlBinMatchState *ms = (ErlBinMatchState *) hp;
                        ErlBinMatchBuffer *mb = &(ms->mb);
                        Eterm *origptr = &(mb->orig);
                        Eterm *ptr = boxed_val(*origptr);
                        Eterm val = *ptr;
                        is_lit = erts_is_literal(*origptr, ptr);

                        if (IS_MOVED_BOXED(val)) {
                            *origptr = val;
                            mb->base = binary_bytes(*origptr);
                        } else if (erts_gc_is_in_secondary_area(ptr,
                                                                secondary_op,
                                                                oh_start,
                                                                oh_bytes,
                                                                mature_start,
                                                                mature_bytes,
                                                                secondary_top,
                                                                is_lit)) {
                            MOVE_BOXED(ptr, val, secondary_top, origptr);
                            mb->base = binary_bytes(*origptr);
                        } else if (erts_gc_is_in_primary_area(ptr, primary_op,
                                                              oh_start,
                                                              oh_bytes,
                                                              mature_start,
                                                              mature_bytes,
                                                              is_lit)) {
                            MOVE_BOXED(ptr, val, primary_top, origptr);
                            mb->base = binary_bytes(*origptr);
                        }
                    }
                    hp += (thing_arityval(gval)+1);
                }
                break;
            }
            default:
                hp++;
                break;
        }
    }
//#ifdef DEBUG
//    debug_sweep_check(primary_hp0, primary_top);
//    debug_sweep_check(secondary_hp0, secondary_top);
//#endif

    *primary_topp = primary_top;
    if (secondary_topp) { *secondary_topp = secondary_top; }
}

static void ERTS_FORCE_INLINE
erts_gc_generic_roots_sweep(ErtsGCRootset *rs,
                            Eterm **primary_topp,   /* in out */
                            Eterm **secondary_topp, /* in out */
                            ErtsGCSweepOp primary_op,
                            ErtsGCSweepOp secondary_op,
                            const char *oh_start, Uint oh_bytes,
                            const char *mature_start, Uint mature_bytes)
{
    ErtsGCRoots *roots = rs->roots;
    int n = rs->num_roots;
    Eterm *primary_top = *primary_topp;
    Eterm *secondary_top = secondary_topp ? *secondary_topp : NULL;

    while (n--) {
        Eterm* g_ptr = roots->v;
        Eterm g_sz = roots->sz;

        roots++;
        while (g_sz--) {
            Eterm val;
            Eterm gval = *g_ptr;

            switch (primary_tag(gval)) {
                case TAG_PRIMARY_BOXED: {
                    Eterm *ptr = boxed_val(gval);
                    const int is_lit = erts_is_literal(gval, ptr);
                    val = *ptr;
                    if (IS_MOVED_BOXED(val)) {
                        ASSERT(is_boxed(val));
                        *g_ptr++ = val;
                    } else if (erts_gc_is_in_secondary_area(ptr, secondary_op,
                                                            oh_start, oh_bytes,
                                                            mature_start,
                                                            mature_bytes,
                                                            secondary_top,
                                                            is_lit)) {
                        MOVE_BOXED(ptr, val, secondary_top, g_ptr++);
                    } else if (erts_gc_is_in_primary_area(ptr, primary_op,
                                                          oh_start, oh_bytes,
                                                          mature_start,
                                                          mature_bytes,
                                                          is_lit)) {
                        MOVE_BOXED(ptr, val, primary_top, g_ptr++);
                    } else {
                        g_ptr++;
                    }
                    break;
                }

                case TAG_PRIMARY_LIST: {
                    Eterm *ptr = list_val(gval);
                    const int is_lit = erts_is_literal(gval, ptr);
                    val = *ptr;
                    if (IS_MOVED_CONS(val)) {
                        *g_ptr++ = ptr[1];
                    } else if (erts_gc_is_in_secondary_area(ptr, secondary_op,
                                                            oh_start, oh_bytes,
                                                            mature_start,
                                                            mature_bytes,
                                                            secondary_top,
                                                            is_lit)) {
                        MOVE_CONS(ptr, val, secondary_top, g_ptr++);
                    } else if (erts_gc_is_in_primary_area(ptr, primary_op,
                                                          oh_start, oh_bytes,
                                                          mature_start,
                                                          mature_bytes,
                                                          is_lit)) {
                        MOVE_CONS(ptr, val, primary_top, g_ptr++);
                    } else {
                        g_ptr++;
                    }
                    break;
                }
                default:
                    g_ptr++;
                    break;
            }
        }
    }

    *primary_topp = primary_top;
    if (secondary_topp) { *secondary_topp = secondary_top; }
}

#endif /* __ERL_GC_SWEEP_H */
