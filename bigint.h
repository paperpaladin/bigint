/* bigint -- arbitrary-precision signed integers, sign-magnitude, 32-bit limbs.
 *
 * Python's `int` is the reference implementation: where this header and Python
 * disagree, Python is right and this is a bug. In particular floor division,
 * modulo, shifts and bitwise operations follow Python's semantics, NOT C's.
 */
#ifndef BIGINT_H
#define BIGINT_H

#include <stdint.h>

typedef uint32_t bi_limb;

/* Error codes. BI_ETOOBIG is a self-imposed ceiling, not a property of the
 * mathematics: Python would happily evaluate 1 << (1 << 40) until the machine
 * ran out of memory, and this refuses instead. The fuzzer models the same
 * rule so the two still agree. */
#define BI_OK         0
#define BI_EDIVZERO   1
#define BI_ENEGSHIFT  2
#define BI_ENEGPOW    3
#define BI_ETOOBIG    4

/* shortcut: 16 Mbit, i.e. 2 MB of limbs, as the largest value any single
 * operation will produce from a small input. Raise it, or drop the check and
 * let malloc fail, if anyone ever wants bigger. */
#define BI_MAX_BITS   (1u << 24)

/* Normalised at all times: n == 0 || d[n-1] != 0, and sign == 0 iff n == 0.
 * An unnormalised value with leading zero limbs compares unequal to the same
 * number normalised, so every mutating path ends in norm(). */
typedef struct {
    bi_limb *d;   /* little-endian; d[0] is least significant */
    int n;        /* limbs in use */
    int cap;      /* limbs allocated */
    int sign;     /* -1, 0, +1 */
} bi;

void bi_init(bi *x);
void bi_free(bi *x);
void bi_set_i64(bi *x, int64_t v);

/* Returns 0 on success, -1 if s is not a valid decimal literal.
 * Accepts an optional leading sign. */
int bi_set_dec(bi *x, const char *s);

/* Malloc'd, NUL-terminated decimal. Caller frees. */
char *bi_to_dec(const bi *x);

/* -1, 0, +1. A total order, so an unnormalised operand would break it. */
int bi_cmp(const bi *a, const bi *b);

/* r may alias either operand. */
void bi_add(bi *r, const bi *a, const bi *b);
void bi_sub(bi *r, const bi *a, const bi *b);
void bi_mul(bi *r, const bi *a, const bi *b);

/* Floor division and modulo with PYTHON's semantics, not C's: the quotient
 * rounds toward negative infinity and the remainder takes the sign of the
 * divisor, so bi_divmod(-7, 2) is (-4, 1) and not (-3, -1). Returns -1 and
 * changes nothing if b is zero. q and rem may be NULL or alias a or b. */
int bi_divmod(bi *q, bi *rem, const bi *a, const bi *b);

/* Shifts, again with PYTHON's semantics: >> on a negative value floors, so
 * -1 >> 1 is -1 and not 0. A negative shift count is BI_ENEGSHIFT, matching
 * Python's ValueError; a left shift whose result would exceed BI_MAX_BITS is
 * BI_ETOOBIG. */
int bi_shl(bi *r, const bi *a, const bi *k);
int bi_shr(bi *r, const bi *a, const bi *k);

/* Bitwise, on Python's infinite two's-complement model: -1 & 5 == 5,
 * -1 | 0 == -1, -1 ^ -1 == 0. Not C's fixed-width behaviour, and not
 * sign-magnitude bit twiddling, which would get every negative case wrong. */
void bi_and(bi *r, const bi *a, const bi *b);
void bi_or (bi *r, const bi *a, const bi *b);
void bi_xor(bi *r, const bi *a, const bi *b);

int bi_bits(const bi *x);   /* bit length of |x|; 0 for zero, as Python */





void bi_neg(bi *r, const bi *a);   /* r = -a; r may alias a */
void bi_abs(bi *r, const bi *a);   /* r = |a|; r may alias a */




#endif
