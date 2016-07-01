#ifndef ERTS_GC_HEAPDUMP_UTIL
#define ERTS_GC_HEAPDUMP_UTIL

/* Adding:
 *   In your erl_gc.c somewhere have:
 *   #include "erl_gc_heapdump.h"
 * Then functions below become available. Usage:
    {
        Heaps h;
        debug_heapdump_ctor(&h, p, "minor1");
        debug_heapdump_roots(&h, &rootset);
        debug_heapdump_process(&h, p);
        debug_heapdump_heap(&h, new_hp, new_htop, new_hp + new_sz,
                            "NEW", "new_hp");
        debug_heapdump_dtor(&h);
    }
 * With every call it will produce a dump text file, named:
 * heapdump-<0.1.0>-$1-minor1.txt, where pid is current process' pid and
 * $1 is a monotonous static counter.
 *
 * Dumps can be rendered by calling heap-draw.py script like this:
 *      heap-draw/heap-draw.py FILENAME
 * or for all dumps at once:
 *      for f in `ls heapdump-*.txt`; do heap-draw/heap-draw.py $f; done
 *
 * Script is a Python3 program which uses PIL (imaging library)
 */

#ifdef DEBUG
typedef struct {
    FILE *f;
} Heaps;

/*
 * Saves a pointer with a name
 */
static void debug_tag_pointer(FILE *f, const void *ptr, const char *tag)
{
    fprintf(f, "NAMED %p %s\n", ptr, tag);
}

/*
 * Output zone limits with a name (may be nested within other zones)
 */
static void debug_tag_zone(FILE *f, const void *from, const void *to,
                           const char *tag, const char *parent_tag)
{
    fprintf(f, "ZONEDEF %s RANGE %p %p PARENT %s\n",
            tag, from, to, parent_tag);
    fflush(f);
}
/*
 * Same as zonedef but will display any terms if they belong to it
 */
static void debug_tag_heap(FILE *f, const void *from, const void *to,
                           const char *tag, const char *parent_tag)
{
    if (to == from || ! from) {
        return; /* zero size or NULL */
    }
    fprintf(f, "HEAPDEF %s RANGE %p %p PARENT %s\n",
            tag, from, to, parent_tag);
    fflush(f);
}

/*
 * Output zone limits with a name (may be nested within other zones)
 */
typedef enum {
    DTF_MOVED = 0x01,   /* value is marked as moved */
    DTF_BOXED = 0x02,   /* value is some box */
    DTF_CONS  = 0x04,   /* value is a cons pointer */
    DTF_ROOTSET = 0x08, /* value belongs to rootset */
    DTF_HEADER = 0x10,  /* some header, like bin match state */
    DTF_IMMED = 0x20,   /* immediate term value */
    DTF_CP    = 0x40    /* CP value */
} DebugTermFlags;

/*
 * Given a pointer to header returns its size
 */
static Uint debug_header_size(const Eterm *box)
{
    Eterm val = box[0];
    switch (val & _HEADER_SUBTAG_MASK) {
    case EXPORT_SUBTAG:
    case EXTERNAL_PID_SUBTAG:
    case EXTERNAL_PORT_SUBTAG:
    case EXTERNAL_REF_SUBTAG:
    case REF_SUBTAG:
    case ARITYVAL_SUBTAG:       /* tuple or something non transparent */
    case SUB_BINARY_SUBTAG:
    case HEAP_BINARY_SUBTAG:
    case REFC_BINARY_SUBTAG:
    case BIN_MATCHSTATE_SUBTAG:
    case FUN_SUBTAG:
    case MAP_SUBTAG:
        break;
    case POS_BIG_SUBTAG:
    case NEG_BIG_SUBTAG:
        return bignum_header_arity(val);
    case FLOAT_SUBTAG:
        return sizeof(double);
    default:
        printf("NYI subtag %zu\r\n", val & _HEADER_SUBTAG_MASK);
        ASSERT(!"NYI header type");
    }
    return header_arity(val);
}

/*
 * Prints address p and flags for the given term to file
 */
static void debug_write_tagged_term(FILE *f, const Eterm *p, int flags)
{
    fprintf(f, "TERM %p ", p);
    if (flags & DTF_ROOTSET) { fprintf(f, "R"); }
    if (flags & DTF_BOXED) { fprintf(f, "B"); }
    if (flags & DTF_MOVED) { fprintf(f, "M"); }
    if (flags & DTF_CONS) { fprintf(f, "C"); }
    if (flags & DTF_IMMED) { fprintf(f, "I"); }
    if (flags & DTF_CP) { fprintf(f, "*"); }
    fprintf(f, "\n");
}

static void debug_tag_heap_term(FILE *f, const Eterm **heap_ptr, int flags)
{
    const Eterm *heap_ptr0 = *heap_ptr; /* value at start, to be logged later */
    Eterm heap_val = *(*heap_ptr);

    switch (primary_tag(heap_val)) {
    case TAG_PRIMARY_BOXED: {
        Eterm *box_ptr = boxed_val(heap_val);
        Eterm val = *box_ptr;
        flags |= DTF_BOXED;
        if (IS_MOVED_BOXED(val)) {
            flags |= DTF_MOVED;
        }
        (*heap_ptr)++;
        break;
    }
    case TAG_PRIMARY_LIST: {
        Eterm *box_ptr = list_val(heap_val);
        Eterm val = *box_ptr;
        flags |= DTF_CONS;
        if (IS_MOVED_CONS(val)) { /* Moved */
            flags |= DTF_MOVED;
        }
        (*heap_ptr)++;
        break;
    }
    case TAG_PRIMARY_HEADER: {
        Uint arity = debug_header_size(*heap_ptr);
        (*heap_ptr) += arity + 1;
        flags |= DTF_HEADER;
        } break;
    case TAG_PRIMARY_IMMED1:
        (*heap_ptr)++;
        flags |= DTF_IMMED;
        break;
    default:
        ASSERT(0);
    }
    debug_write_tagged_term(f, heap_ptr0, flags);
}

static void debug_tag_root_term(FILE *f, const Eterm **heap_ptr, int flags)
{
    const Eterm *heap_ptr0 = *heap_ptr; /* value at start, to be logged later */
    Eterm heap_val = *(*heap_ptr);

    switch (primary_tag(heap_val)) {
    case TAG_PRIMARY_BOXED: {
        Eterm *box_ptr = boxed_val(heap_val);
        Eterm val = *box_ptr;
        flags |= DTF_BOXED;
        if (IS_MOVED_BOXED(val)) {
            flags |= DTF_MOVED;
        }
        (*heap_ptr)++;
        break;
    }
    case TAG_PRIMARY_LIST: {
        Eterm *box_ptr = list_val(heap_val);
        Eterm val = *box_ptr;
        flags |= DTF_CONS;
        if (IS_MOVED_CONS(val)) { /* Moved */
            flags |= DTF_MOVED;
        }
        (*heap_ptr)++;
        break;
    }
    case TAG_PRIMARY_IMMED1:
        (*heap_ptr)++;
        flags |= DTF_IMMED;
        break;
    case TAG_PRIMARY_HEADER:
        (*heap_ptr)++;
        flags |= DTF_CP; /* only the stack can have CP */
        break;
    default:
        ASSERT(!"strange root term tag found");
    }
    debug_write_tagged_term(f, heap_ptr0, flags);
}

static void debug_tag_roots(FILE *f, const Rootset *rs)
{
    for (int n = 0; n < rs->num_roots; ++n) {
        const Eterm *g_ptr = rs->roots[n].v;
        for (int m = 0; m < rs->roots[n].sz; ++m) {
            debug_tag_root_term(f, &g_ptr, DTF_ROOTSET);
        }
    }
    fflush(f);
}

/*
 * Dumps every term between hbegin and hend
 */
static void debug_dump_heap_terms(FILE *f,
                                  const Eterm *hbegin, const Eterm *htop)
{
    printf("Dumping heap terms...\r\n");
    const Eterm *p = hbegin;
    while (p != htop) {
        const Eterm *loopdetect = p;
        debug_tag_heap_term(f, &p, 0);
        ASSERT(p > loopdetect);
    }
    fflush(f);
}

static size_t g_heap_dump_id = 0;

/*
 * Constructs a Heaps struct from process to display existing situation in
 * the process
 */
static void debug_heapdump_ctor(Heaps *h, Process *p, const char *tag)
{
    sys_memset(h, 0, sizeof(Heaps));

    char filename[256], pid_s[32];
    ASSERT(is_pid(p->common.id));
    erts_sprintf(pid_s, "%T", p->common.id);
    sprintf(filename, "heapdump-%s-%03zu-%s.txt",
                 pid_s, g_heap_dump_id++, tag);

    h->f = fopen(filename, "wt");
    ASSERT(h->f);
}

static void debug_heapdump_process(Heaps *h, Process *p)
{
    debug_tag_zone(h->f, p->heap, p->hend, "PROC", "-");
    /* Current stack */
    if (p->stop) {
        debug_tag_heap(h->f, p->stop, p->hend, "stack", "PROC");
        debug_tag_heap(h->f, p->heap, p->htop, "heap", "PROC");

        //debug_dump_heap_terms(h->f, p->stop, p->hend);
        debug_dump_heap_terms(h->f, p->heap, p->htop);
    }

    /* Define some zones, possibly nested */
    if (p->old_heap) {
        debug_tag_zone(h->f, p->old_heap, p->old_hend, "PROC_OLD", "-");
        debug_tag_heap(h->f, p->old_heap, p->old_htop, "old_heap", "PROC_OLD");

        /* Old heap */
        debug_dump_heap_terms(h->f, p->old_heap, p->old_htop);
    }
}

static void debug_heapdump_heap(Heaps *h, const Eterm *hp, const Eterm *htop,
                                const Eterm *hend, const char *zonetag,
                                const char *heaptag)
{
    if (hp) {
        debug_tag_zone(h->f, hp, hend, zonetag, "-");
        debug_tag_heap(h->f, hp, htop, heaptag, zonetag);
        debug_dump_heap_terms(h->f, hp, htop);
    }
}

static void debug_heapdump_roots(Heaps *h, Rootset *rs)
{
    /* Rootset */
    if (rs) {
        printf("Dumping roots...\r\n");
        debug_tag_roots(h->f, rs);
    }
}

static void debug_heapdump_dtor(Heaps *h)
{
    fprintf(h->f, "END\n");
    fclose(h->f);

    sys_memset(h, 0, sizeof(Heaps));
}

#endif // DEBUG

#endif // ERTS_GC_HEAPDUMP_UTIL
