#pragma once
/*
 * Definitions from this file are only visible inside erl_gc.c
 */

#define INACT_WR_PB_LEAVE_MUCH_LIMIT 1
#define INACT_WR_PB_LEAVE_MUCH_PERCENTAGE 20
#define INACT_WR_PB_LEAVE_LIMIT 10
#define INACT_WR_PB_LEAVE_PERCENTAGE 10

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
#define ARRAY_LENGTH(a) (sizeof(a)/sizeof(a[0]))

int ERTS_FORCE_INLINE is_between(const void *p, const void *a, const void *b) {
    return p >= a && p <= b;
}

Uint ERTS_FORCE_INLINE stack_sz_on_heap(Process *p) {
    return p->hend - p->stop;
}

# define OverRunCheck(P) \
    if ((P)->stop < (P)->htop) { \
        erts_fprintf(stderr, "hend=%p\n", (p)->hend); \
        erts_fprintf(stderr, "stop=%p\n", (p)->stop); \
        erts_fprintf(stderr, "htop=%p\n", (p)->htop); \
        erts_fprintf(stderr, "heap=%p\n", (p)->heap); \
        erts_exit(ERTS_ABORT_EXIT, "%s, line %d: %T: Overrun stack and heap\n", \
		 __FILE__,__LINE__,(P)->common.id); \
    }

#ifdef DEBUG
#define ErtsGcQuickSanityCheck(P)					\
do {									\
    ASSERT((P)->heap < (P)->hend);					\
    ASSERT((p)->abandoned_heap || (P)->heap_sz == (P)->hend - (P)->heap); \
    ASSERT((P)->heap <= (P)->htop && (P)->htop <= (P)->hend);		\
    ASSERT((P)->heap <= (P)->stop && (P)->stop <= (P)->hend);		\
    ASSERT((p)->abandoned_heap || ((P)->heap <= (P)->high_water && (P)->high_water <= (P)->hend)); \
    OverRunCheck((P));							\
} while (0)
#else
#define ErtsGcQuickSanityCheck(P)					\
do {									\
    OverRunCheck((P));							\
} while (0)
#endif

typedef struct erl_off_heap_header OffheapHeader;

/*
 * This structure describes the rootset for the GC.
 */
typedef struct {
    Eterm* v;		/* Pointers to vectors with terms to GC
			 * (e.g. the stack).
			 */
    Uint sz;		/* Size of each vector. */
} Roots;

typedef struct {
    Roots def[32];		/* Default storage. */
    Roots* roots;		/* Pointer to root set array. */
    Uint size;			/* Storage size. */
    int num_roots;		/* Number of root arrays. */
} Rootset;

/* Two different types to avoid confusing argument order */
typedef struct { const char *start; Uint bytes; } MatureArea;
typedef struct { const char *start; Uint bytes; } OldHeapArea;
typedef struct { const char *start; Uint bytes; } YoungHeapArea;
typedef struct { Uint words; } Words;
typedef struct { char *start; Uint bytes; } LiteralArea;
typedef struct {
    Eterm *start;
    Eterm *top;
    Eterm *end;
    Uint words;
} Heap;

#ifdef DEBUG
static void debug_sweep_check(const Eterm *hp, const Eterm *hend);
/* Scan 2 heaps, check that all terms belong to these 2 heaps or are literals */
static void
debug_scan_heap(const Eterm *n_heap, const Eterm *n_htop,
                const Eterm *old_heap, const Eterm *old_htop);
#else
static void ERTS_FORCE_INLINE
debug_sweep_check(const Eterm *hp, const Eterm *hend) {}
static void ERTS_FORCE_INLINE
debug_scan_heap(const Eterm *n_heap, const Eterm *n_htop,
                const Eterm *old_heap, const Eterm *old_htop) {}
#endif

static Uint setup_rootset(Process*, Eterm*, int, Rootset*);
static void cleanup_rootset(Rootset *rootset);
static void remove_message_buffers(Process* p);
static void full_sweep_heaps(Process *p,
                             int hibernate,
                             Eterm *n_heap, Eterm **n_htopp,
                             Eterm *o_heap, Eterm **o_htopp,
                             MatureArea mature,
                             OldHeapArea from_old,
                             Eterm *objv, int nobj);
static int garbage_collect(Process* p, ErlHeapFragment *live_hf_end,
                           int need, Eterm* objv, int nobj, int fcalls);
static int major_collection(Process* p, ErlHeapFragment *live_hf_end,
                            int need, Eterm* objv, int nobj, Uint *recl);
static int minor_collection(Process* p, ErlHeapFragment *live_hf_end,
                            int need, Eterm* objv, int nobj, Uint *recl);
static void do_minor(Process *p, ErlHeapFragment *live_hf_end,
                     MatureArea mature,
                     Uint new_sz, Eterm* objv, int nobj);

static Eterm *collect_live_heap_frags(Process* p, ErlHeapFragment *live_hf_end,
                                      Eterm* heap, Eterm* htop, Eterm* objv, int nobj);
static int adjust_after_fullsweep(Process *p, int need, Eterm *objv, int nobj);
static void shrink_new_heap(Process *p, Uint new_sz, Eterm *objv, int nobj);
static void grow_new_heap(Process *p, Uint new_sz, Eterm* objv, int nobj);

typedef enum {
    SweepOffheapMinor, SweepOffheapMajor
} SweepOffheapMode;

typedef struct {
    struct {
        OffheapHeader* new_candidates;
        OffheapHeader* new_candidates_end;
        OffheapHeader* old_candidates;
        Uint no_of_candidates;
        Uint no_of_active;
    } shrink;
    OffheapHeader* ptr;
    OffheapHeader** prev;
} SweepOffheapState;

static void sweep_off_heap(Process *p,
                           OldHeapArea from_old,
                           OldHeapArea to_old,  /* used for debug */
                           YoungHeapArea young, /* used for debug */
                           SweepOffheapMode mode);

static void offset_heap(Eterm* hp, Uint sz, Sint offs, char* area, Uint area_size);
static void offset_heap_ptr(Eterm* hp, Uint sz, Sint offs, char* area, Uint area_size);
static void offset_rootset(Process *p, Sint offs, char* area, Uint area_size,
                           Eterm* objv, int nobj);
static void offset_off_heap(Process* p, Sint offs, char* area, Uint area_size);
static void offset_mqueue(Process *p, Sint offs, char* area, Uint area_size);
static void move_msgq_to_heap(Process *p);
static int reached_max_heap_size(Process *p, Uint total_heap_size,
                                 Uint extra_heap_size, Uint extra_old_heap_size);
static void init_gc_info(ErtsGCInfo *gcip);

#ifdef HARDDEBUG
static void disallow_heap_frag_ref_in_heap(Process* p);
static void disallow_heap_frag_ref_in_old_heap(Process* p);
#endif

#if defined(ARCH_64)
# define MAX_HEAP_SIZES 154
#else
# define MAX_HEAP_SIZES 59
#endif

static Sint heap_sizes[MAX_HEAP_SIZES];	/* Suitable heap sizes. */
static int num_heap_sizes;	/* Number of heap sizes. */

Uint erts_test_long_gc_sleep; /* Only used for testing... */

typedef struct {
    Process *proc;
    Eterm ref;
    Eterm ref_heap[REF_THING_SIZE];
    Uint req_sched;
    erts_smp_atomic32_t refc;
} ErtsGCInfoReq;

typedef enum {
    SweepOp_None,
    SweepOp_Literal,
    SweepOp_NotLiteral,
    SweepOp_NotLiteral_NotOld,
    SweepOp_NotLiteral_OldOrMature,
    SweepOp_NotLiteral_Mature,
    SweepOp_Mature
} SweepOp;

/*
 * NOTE: This (primary) condition is checked after secondary condition!
 * Optimizer does fairly good job merging these checks with calling code
 */
static ERTS_FORCE_INLINE int
is_in_primary_area(const Eterm *ptr,
                   const SweepOp type,
                   const char *oh, Uint oh_size,
                   const char *mature, Uint mature_size,
                   const int is_literal)
{
    switch (type) {
        case SweepOp_None:
            return 0;
        case SweepOp_NotLiteral:
            return ! is_literal;
        case SweepOp_NotLiteral_NotOld:
            return ! is_literal && !ErtsInArea(ptr, oh, oh_size);
        case SweepOp_Mature:
            return ErtsInArea(ptr, mature, mature_size);
        case SweepOp_Literal:
            /* Tmp literal area is passed in oh */
            return ErtsInArea(ptr, oh, oh_size);
        default:
            ASSERT(!"unsupported primary sweep op");
    }
    ASSERT(0); return 0;
}

/*
 * NOTE: in sweep secondary (this) condition is checked first
 * Optimizer does fairly good job merging these checks with calling code
 */
static ERTS_FORCE_INLINE int
is_in_secondary_area(const Eterm *ptr,
                     const SweepOp type,
                     const char *oh, Uint oh_size,
                     const char *mature, Uint mature_size,
                     const Eterm *o_htop,
                     const int is_literal)
{
    if (!o_htop) { return 0; }

    switch (type) {
        case SweepOp_None:
            return 0;
        case SweepOp_NotLiteral_OldOrMature:
            return ! is_literal
                   && (ErtsInArea(ptr, mature, mature_size)
                       || ErtsInArea(ptr, oh, oh_size));
        case SweepOp_NotLiteral_Mature:
            return ! is_literal && ErtsInArea(ptr, mature, mature_size);
        case SweepOp_Literal:
            /* Tmp literal area is passed in oh */
            return ErtsInArea(ptr, oh, oh_size);
        case SweepOp_Mature:
            return ErtsInArea(ptr, mature, mature_size);
        default:
            ASSERT(!"unsupported secondary sweep op");
    }
    ASSERT(0); return 0;
}

/*
 * Performs sweep through given heap hp, moving values to primary_top or to
 * secondary_top depending on SweepOps provided as arguments.
 * Optimizer does fairly good job merging generic sweep with checks above
 */
static ERTS_FORCE_INLINE void
generic_sweep(Eterm *hp, Eterm **primary_topp,
              Eterm *secondary_hp, Eterm **secondary_topp,
              const SweepOp primary_op,
              const SweepOp secondary_op,
              OldHeapArea oh,
              const char *mature, Uint mature_size)
{
    Eterm gval;
    Eterm *primary_top = *primary_topp;
    Eterm *secondary_top = secondary_topp ? *secondary_topp : NULL;
    int is_lit;
#ifdef DEBUG
    /* Back up heap start to debug_sweep_check later */
    const Eterm *primary_hp0 = hp;
    const Eterm *secondary_hp0 = secondary_hp;
#endif

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
                                                oh.start, oh.bytes,
                                                mature, mature_size,
                                                secondary_top, is_lit)) {
                    MOVE_BOXED(ptr, val, secondary_top, hp++);
                } else if (is_in_primary_area(ptr, primary_op,
                                              oh.start, oh.bytes,
                                              mature, mature_size,
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
                                                oh.start, oh.bytes,
                                                mature, mature_size,
                                                secondary_top, is_lit)) {
                    MOVE_CONS(ptr, val, secondary_top, hp++);
                } else if (is_in_primary_area(ptr, primary_op,
                                              oh.start, oh.bytes,
                                              mature, mature_size,
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
                                                        oh.start, oh.bytes,
                                                        mature, mature_size,
                                                        secondary_top, is_lit)) {
                            MOVE_BOXED(ptr, val, secondary_top, origptr);
                            mb->base = binary_bytes(*origptr);
                        } else if (is_in_primary_area(ptr, primary_op,
                                                      oh.start, oh.bytes,
                                                      mature, mature_size,
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
#ifdef DEBUG
    debug_sweep_check(primary_hp0, primary_top);
    debug_sweep_check(secondary_hp0, secondary_top);
#endif

    *primary_topp = primary_top;
    if (secondary_topp) { *secondary_topp = secondary_top; }
}

static void ERTS_FORCE_INLINE
generic_roots_sweep(Rootset *rs,
                    Eterm **primary_topp,   /* in out */
                    Eterm **secondary_topp, /* in out */
                    SweepOp primary_op, SweepOp secondary_op,
                    OldHeapArea oh, MatureArea mature)
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
                                                    oh.start, oh.bytes,
                                                    mature.start, mature.bytes,
                                                    secondary_top, is_lit)) {
                        MOVE_BOXED(ptr, val, secondary_top, g_ptr++);
                    } else if (is_in_primary_area(ptr, primary_op,
                                                  oh.start, oh.bytes,
                                                  mature.start, mature.bytes,
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
                                                    oh.start, oh.bytes,
                                                    mature.start, mature.bytes,
                                                    secondary_top, is_lit)) {
                        MOVE_CONS(ptr, val, secondary_top, g_ptr++);
                    } else if (is_in_primary_area(ptr, primary_op,
                                                  oh.start, oh.bytes,
                                                  mature.start, mature.bytes,
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
