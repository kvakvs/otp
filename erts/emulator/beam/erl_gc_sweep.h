#pragma once

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
} Roots;

typedef struct {
    Roots def[32];  /* Default storage. */
    Roots* roots;   /* Pointer to root set array. */
    Uint size;	    /* Storage size. */
    int num_roots;  /* Number of root arrays. */
} Rootset;

Uint setup_rootset(Process*, Eterm*, int, Rootset*);
void cleanup_rootset(Rootset *rootset);

Eterm *full_sweep_heaps(Process *p, int hibernate, Eterm *primary_hp,
                        Eterm **primary_topp, Eterm *secondary_hp,
                        Eterm **secondary_topp, const char *oh_start,
                        Uint oh_bytes, const char *mature_start,
                        Uint mature_bytes, Eterm *objv, int nobj);

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

void sweep_off_heap(Process *p, int fullsweep);

typedef enum {
    SweepOp_None,
    SweepOp_NotLiteral,
    SweepOp_NotLiteral_NotOld,
    SweepOp_NotLiteral_OldOrMature,
    SweepOp_NotLiteral_Mature,
    SweepOp_Mature
} SweepOp;

/* NOTE: during sweeps primary condition is checked AFTER secondary! */
static ERTS_FORCE_INLINE int
is_in_primary_area(const Eterm *ptr,
                   const SweepOp type,
                   const char *oh_start, Uint oh_size,
                   const char *mature_start, Uint mature_size,
                   const int is_literal)
{
    switch (type) {
        case SweepOp_NotLiteral:
            return ! is_literal;

        case SweepOp_NotLiteral_NotOld:
            return ! is_literal
                   && ! ErtsInArea(ptr, oh_start, oh_size);

        case SweepOp_Mature:
            return ErtsInArea(ptr, mature_start, mature_size);

        case SweepOp_NotLiteral_OldOrMature:
            return ! is_literal
                   && (ErtsInArea(ptr, mature_start, mature_size)
                       || ErtsInArea(ptr, oh_start, oh_size));

        case SweepOp_NotLiteral_Mature:
            return ! is_literal
                   && ErtsInArea(ptr, mature_start, mature_size);

        case SweepOp_None:
            return 0;

        default:
            ASSERT(!"unsupported sweep op");
    }
    ASSERT(0); return 0;
}

/* NOTE: in sweep secondary (this) condition is checked first */
static ERTS_FORCE_INLINE int
is_in_secondary_area(const Eterm *ptr,
                     const SweepOp type,
                     const char *oh_start, Uint oh_size,
                     const char *mature_start, Uint mature_size,
                     const Eterm *secondary_top,
                     const int is_literal)
{
    if (!secondary_top) { return 0; }
    return is_in_primary_area(ptr, type,
                              oh_start, oh_size,
                              mature_start, mature_size,
                              is_literal);
}

static ERTS_FORCE_INLINE void
generic_sweep(Eterm *hp, Eterm **primary_topp,
              Eterm *secondary_hp, Eterm **secondary_topp,
              const SweepOp primary_op,
              const SweepOp secondary_op,
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
                } else if (is_in_secondary_area(ptr, secondary_op,
                                                oh_start, oh_bytes,
                                                mature_start, mature_bytes,
                                                secondary_top, is_lit)) {
                    MOVE_BOXED(ptr, val, secondary_top, hp++);
                } else if (is_in_primary_area(ptr, primary_op,
                                              oh_start, oh_bytes,
                                              mature_start, mature_bytes,
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
                } else if (is_in_secondary_area(ptr, secondary_op,
                                                oh_start, oh_bytes,
                                                mature_start, mature_bytes,
                                                secondary_top, is_lit)) {
                    MOVE_CONS(ptr, val, secondary_top, hp++);
                } else if (is_in_primary_area(ptr, primary_op,
                                              oh_start, oh_bytes,
                                              mature_start, mature_bytes,
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
                        } else if (is_in_secondary_area(ptr, secondary_op,
                                                        oh_start, oh_bytes,
                                                        mature_start, mature_bytes,
                                                        secondary_top, is_lit)) {
                            MOVE_BOXED(ptr, val, secondary_top, origptr);
                            mb->base = binary_bytes(*origptr);
                        } else if (is_in_primary_area(ptr, primary_op,
                                                      oh_start, oh_bytes,
                                                      mature_start, mature_bytes,
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
generic_roots_sweep(Rootset *rs,
                    Eterm **primary_topp,   /* in out */
                    Eterm **secondary_topp, /* in out */
                    SweepOp primary_op, SweepOp secondary_op,
                    const char *oh_start, Uint oh_bytes,
                    const char *mature_start, Uint mature_bytes)
{
    Roots *roots = rs->roots;
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
                    } else if (is_in_secondary_area(ptr, secondary_op,
                                                    oh_start, oh_bytes,
                                                    mature_start, mature_bytes,
                                                    secondary_top, is_lit)) {
                        MOVE_BOXED(ptr, val, secondary_top, g_ptr++);
                    } else if (is_in_primary_area(ptr, primary_op,
                                                  oh_start, oh_bytes,
                                                  mature_start, mature_bytes,
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
                    } else if (is_in_secondary_area(ptr, secondary_op,
                                                    oh_start, oh_bytes,
                                                    mature_start, mature_bytes,
                                                    secondary_top, is_lit)) {
                        MOVE_CONS(ptr, val, secondary_top, g_ptr++);
                    } else if (is_in_primary_area(ptr, primary_op,
                                                  oh_start, oh_bytes,
                                                  mature_start, mature_bytes,
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
