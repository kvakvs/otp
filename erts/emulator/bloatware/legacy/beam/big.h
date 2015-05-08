/*
 * %CopyrightBegin%
 *
 * Copyright Ericsson AB 1996-2014. All Rights Reserved.
 *
 * The contents of this_ file are subject to the Erlang Public License,
 * Version 1.1, (the "License"); you may not use this_ file except in
 * compliance with the License. You should have received a copy of the
 * Erlang Public License along with this_ software. If not, it can be
 * retrieved online at http://www.erlang.org/.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * %CopyrightEnd%
 */

#ifndef __BIG_H__
#define __BIG_H__

#ifndef __SYS_H__
#include "sys.h"
#endif

#ifndef __CONFIG_H__
#include "erl_vm.h"
#endif

#ifndef __GLOBAL_H__
#include "global.h"
#endif

typedef size_t     ErtsDigit;

#if ((SIZEOF_VOID_P == 4) || HALFWORD_HEAP) && defined(SIZEOF_LONG_LONG) && (SIZEOF_LONG_LONG == 8)
/* Assume 32-bit machine with long long support */
typedef uint64_t   ErtsDoubleDigit;
typedef uint16_t   ErtsHalfDigit;
#define BIG_HAVE_DOUBLE_DIGIT 1

#elif (SIZEOF_VOID_P == 4)
/* Assume 32-bit machine with no long support */
#undef  BIG_HAVE_DOUBLE_DIGIT
typedef uint16_t   ErtsHalfDigit;

#elif (SIZEOF_VOID_P == 8)
/* Assume 64-bit machine, does it exist 128 bit long long long ? */
#undef  BIG_HAVE_DOUBLE_DIGIT
typedef uint32_t   ErtsHalfDigit;
#else
#error "can not determine machine size"
#endif

#define D_DECIMAL_EXP 9
#define D_DECIMAL_BASE  1000000000

typedef size_t  dsize_t;   /* Vector size type */

#define D_EXP (ERTS_SIZEOF_ETERM*8)
#define D_MASK     ((ErtsDigit)(-1))      /* D_BASE-1 */

/* macros for bignum objects */
#define big_v(x)       BIG_V(big_val(x))
#define big_sign(x)    BIG_SIGN(big_val(x))
#define big_arity(x)   BIG_ARITY(big_val(x))
#define big_digit(x,i) BIG_DIGIT(big_val(x),i)
#define big_size(x)    BIG_SIZE(big_val(x))


/* macros for thing pointers */

#define BIG_V(xp)        ((ErtsDigit*)((xp)+1))
#define BIG_SIGN(xp)     (!!bignum_header_is_neg(*xp))
#define BIG_ARITY(xp)    ((size_t)bignum_header_arity(*(xp)))
#define BIG_DIGIT(xp,i)  *(BIG_V(xp)+(i))
#define BIG_DIGITS_PER_WORD (sizeof(size_t)/sizeof(ErtsDigit))

#define BIG_SIZE(xp)  BIG_ARITY(xp)

/* Check for small */
#define IS_USMALL(sgn,x)  ((sgn) ? ((x) <= MAX_SMALL+1) : ((x) <= MAX_SMALL))
#define IS_SSMALL(x)      (((x) >= MIN_SMALL) && ((x) <= MAX_SMALL))

/* The heap size needed for a bignum */
#define BIG_NEED_SIZE(x)  ((x) + 1)

#define BIG_UINT_HEAP_SIZE (1 + 1)  /* always, since sizeof(size_t) <= sizeof(Eterm) */

#if HALFWORD_HEAP
#define BIG_UWORD_HEAP_SIZE(UW) (((UW) >> (sizeof(size_t) * 8)) ? 3 : 2)
#else
#define BIG_UWORD_HEAP_SIZE(UW) BIG_UINT_HEAP_SIZE
#endif

#if defined(ARCH_32) || HALFWORD_HEAP

#define ERTS_UINT64_BIG_HEAP_SIZE__(X) \
  ((X) >= (((uint64_t) 1) << 32) ? (1 + 2) : (1 + 1))
#define ERTS_SINT64_HEAP_SIZE(X)        \
  (IS_SSMALL((X))           \
   ? 0                \
   : ERTS_UINT64_BIG_HEAP_SIZE__((X) >= 0 ? (X) : -(uint64_t)(X)))
#define ERTS_UINT64_HEAP_SIZE(X)        \
  (IS_USMALL(0, (X)) ? 0 : ERTS_UINT64_BIG_HEAP_SIZE__((X)))

#else

#define ERTS_SINT64_HEAP_SIZE(X)        \
  (IS_SSMALL((X)) ? 0 : (1 + 1))
#define ERTS_UINT64_HEAP_SIZE(X)        \
  (IS_USMALL(0, (X)) ? 0 : (1 + 1))

#endif

int big_decimal_estimate(Wterm);
Eterm erts_big_to_list(Eterm, Eterm **);
char *erts_big_to_string(Wterm x, char *buf, size_t buf_sz);
size_t erts_big_to_binary_bytes(Eterm x, char *buf, size_t buf_sz);

Eterm small_times(ssize_t, ssize_t, Eterm *);

Eterm big_plus(Wterm, Wterm, Eterm *);
Eterm big_minus(Eterm, Eterm, Eterm *);
Eterm big_times(Eterm, Eterm, Eterm *);
Eterm big_div(Eterm, Eterm, Eterm *);
Eterm big_rem(Eterm, Eterm, Eterm *);
Eterm big_neg(Eterm, Eterm *);

Eterm big_minus_small(Eterm, size_t, Eterm *);
Eterm big_plus_small(Eterm, size_t, Eterm *);
Eterm big_times_small(Eterm, size_t, Eterm *);

Eterm big_band(Eterm, Eterm, Eterm *);
Eterm big_bor(Eterm, Eterm, Eterm *);
Eterm big_bxor(Eterm, Eterm, Eterm *);
Eterm big_bnot(Eterm, Eterm *);

Eterm big_lshift(Eterm, ssize_t, Eterm *);
int big_comp(Wterm, Wterm);
int big_ucomp(Eterm, Eterm);
int big_to_double(Wterm x, double *resp);
Eterm double_to_big(double, Eterm *, size_t hsz);
Eterm small_to_big(ssize_t, Eterm *);
Eterm uint_to_big(size_t, Eterm *);
Eterm uword_to_big(UWord, Eterm *);
Eterm erts_make_integer(size_t, Process *);
Eterm erts_make_integer_from_uword(UWord x, Process *p);

dsize_t big_bytes(Eterm);
Eterm bytes_to_big(uint8_t *, dsize_t, int, Eterm *);
uint8_t *big_to_bytes(Eterm, uint8_t *);

int term_to_Uint(Eterm, size_t *);
int term_to_UWord(Eterm, UWord *);
int term_to_Sint(Eterm, ssize_t *);
#if HAVE_INT64
int term_to_Uint64(Eterm, uint64_t *);
int term_to_Sint64(Eterm, int64_t *);
#endif

uint32_t big_to_uint32(Eterm b);
int term_equals_2pow32(Eterm);

Eterm erts_uint64_to_big(uint64_t, Eterm **);
Eterm erts_sint64_to_big(int64_t, Eterm **);

Eterm erts_chars_to_integer(Process *, char *, size_t, const int);

#endif

