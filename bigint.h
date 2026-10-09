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

void bi_neg(bi *r, const bi *a);   /* r = -a; r may alias a */



#endif
