/* bigint -- arbitrary-precision signed integers in one C11 file.
 *
 * Representation: sign-magnitude, little-endian array of 32-bit limbs, always
 * normalised (no leading zero limbs, sign == 0 iff the value is zero).
 *
 * 32-bit limbs rather than 64 because every intermediate product then fits in
 * a uint64_t, which keeps Knuth algorithm D writable in portable C11 with no
 * __int128 and no inline assembly.
 * shortcut: half the throughput of 64-bit limbs; upgrade means a 128-bit
 * intermediate (__int128 on gcc/clang) throughout mul and divmod.
 *
 * Python's int is the oracle. See t/fuzz.py.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bigint.h"

#define LIMB_BITS 32
#define LIMB_MAX  0xffffffffu

static void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) { fputs("bigint: out of memory\n", stderr); exit(70); }
    return q;
}

void bi_init(bi *x) { x->d = NULL; x->n = x->cap = x->sign = 0; }
void bi_free(bi *x) { free(x->d); bi_init(x); }

static void grow(bi *x, int cap)
{
    if (cap <= x->cap) return;
    if (cap < x->cap * 2) cap = x->cap * 2;
    x->d = xrealloc(x->d, (size_t)cap * sizeof *x->d);
    x->cap = cap;
}

/* The one invariant: trim leading zero limbs and keep sign consistent. */
static void norm(bi *x)
{
    while (x->n > 0 && x->d[x->n - 1] == 0) x->n--;
    if (x->n == 0) x->sign = 0;
    else if (x->sign == 0) x->sign = 1;
}

static void bi_set_zero(bi *x) { x->n = 0; x->sign = 0; }

void bi_set_i64(bi *x, int64_t v)
{
    uint64_t m = v < 0 ? -(uint64_t)v : (uint64_t)v;
    grow(x, 2);
    x->d[0] = (bi_limb)m;
    x->d[1] = (bi_limb)(m >> 32);
    x->n = 2;
    x->sign = v < 0 ? -1 : 1;
    norm(x);
}

/* |x| *= m; |x| += a.  m, a < 2^32. */
static void umul_add_small(bi *x, bi_limb m, bi_limb a)
{
    uint64_t carry = a;
    int i;
    grow(x, x->n + 1);
    for (i = 0; i < x->n; i++) {
        carry += (uint64_t)x->d[i] * m;
        x->d[i] = (bi_limb)carry;
        carry >>= 32;
    }
    if (carry) x->d[x->n++] = (bi_limb)carry;
    norm(x);
}

/* |x| /= d, returns |x| % d.  d != 0. */
static bi_limb udiv_small(bi *x, bi_limb d)
{
    uint64_t rem = 0;
    int i;
    for (i = x->n - 1; i >= 0; i--) {
        uint64_t cur = (rem << 32) | x->d[i];
        x->d[i] = (bi_limb)(cur / d);
        rem = cur % d;
    }
    norm(x);
    return (bi_limb)rem;
}

int bi_set_dec(bi *x, const char *s)
{
    int sign = 1;
    const char *p = s;
    if (*p == '-') { sign = -1; p++; }
    else if (*p == '+') p++;
    if (!*p) return -1;
    bi_set_zero(x);
    for (; *p; p++) {
        if (*p < '0' || *p > '9') return -1;
        /* shortcut: O(n^2) base conversion. Fine to a few thousand digits;
         * upgrade path is divide-and-conquer splitting on powers of 10. */
        umul_add_small(x, 10, (bi_limb)(*p - '0'));
    }
    x->sign = x->n ? sign : 0;
    return 0;
}

char *bi_to_dec(const bi *x)
{
    /* 9 decimal digits per 10^9 chunk; 32 bits is under 10 digits per limb. */
    size_t cap = (size_t)x->n * 10 + 16;   /* 9.65 digits per limb, plus sign, NUL,
                                            and the tail of a padded chunk */
    char *buf = xrealloc(NULL, cap);
    size_t len = 0;
    bi t;

    if (x->n == 0) { buf[0] = '0'; buf[1] = 0; return buf; }

    bi_init(&t);
    grow(&t, x->n);
    memcpy(t.d, x->d, (size_t)x->n * sizeof *x->d);
    t.n = x->n;
    t.sign = 1;

    while (t.n) {
        bi_limb r = udiv_small(&t, 1000000000u);
        int k;
        for (k = 0; k < 9; k++) { buf[len++] = (char)('0' + r % 10); r /= 10; }
    }
    bi_free(&t);
    while (len > 1 && buf[len - 1] == '0') len--;
    if (x->sign < 0) buf[len++] = '-';
    buf[len] = 0;
    /* reverse */
    for (size_t i = 0, j = len - 1; i < j; i++, j--) {
        char c = buf[i]; buf[i] = buf[j]; buf[j] = c;
    }
    return buf;
}

static void bi_swap(bi *x, bi *y) { bi t = *x; *x = *y; *y = t; }

static void bi_copy(bi *r, const bi *a)
{
    if (r == a) return;
    grow(r, a->n ? a->n : 1);
    memcpy(r->d, a->d, (size_t)a->n * sizeof *a->d);
    r->n = a->n;
    r->sign = a->sign;
}

/* Magnitude comparison. -1, 0, +1 for |a| <, ==, > |b|. */
static int ucmp(const bi *a, const bi *b)
{
    int i;
    if (a->n != b->n) return a->n < b->n ? -1 : 1;
    for (i = a->n - 1; i >= 0; i--)
        if (a->d[i] != b->d[i]) return a->d[i] < b->d[i] ? -1 : 1;
    return 0;
}

int bi_cmp(const bi *a, const bi *b)
{
    if (a->sign != b->sign) return a->sign < b->sign ? -1 : 1;
    if (a->sign == 0) return 0;
    return a->sign * ucmp(a, b);
}

/* |r| = |a| + |b|. r must not alias either operand. Sign is the caller's. */
static void uadd(bi *r, const bi *a, const bi *b)
{
    const bi *lo = a->n < b->n ? a : b, *hi = a->n < b->n ? b : a;
    uint64_t carry = 0;
    int i;

    grow(r, hi->n + 1);
    for (i = 0; i < lo->n; i++) {
        carry += (uint64_t)hi->d[i] + lo->d[i];
        r->d[i] = (bi_limb)carry;
        carry >>= 32;
    }
    for (; i < hi->n; i++) {
        carry += hi->d[i];
        r->d[i] = (bi_limb)carry;
        carry >>= 32;
    }
    r->d[i] = (bi_limb)carry;      /* the one extra limb, usually zero */
    r->n = hi->n + 1;
}

/* |r| = |a| - |b|, and |a| >= |b| is the caller's problem. r must not alias.
 * The result can be many limbs shorter than a (999...9 - 999...8), so the
 * norm() at the end is not optional. */
static void usub(bi *r, const bi *a, const bi *b)
{
    int64_t borrow = 0;
    int i;

    grow(r, a->n ? a->n : 1);
    for (i = 0; i < a->n; i++) {
        int64_t t = (int64_t)a->d[i] - borrow - (i < b->n ? b->d[i] : 0);
        if (t < 0) { t += (int64_t)1 << 32; borrow = 1; } else borrow = 0;
        r->d[i] = (bi_limb)t;
    }
    r->n = a->n;
}

/* shortcut: every binary op builds its answer in a fresh temp and swaps it
 * into place, which costs a malloc/free pair per call but makes aliasing
 * (bi_add(&x, &x, &x)) correct by construction. Upgrade path is an in-place
 * fast path guarded by a pointer-equality check, once a profile says so. */
void bi_add(bi *r, const bi *a, const bi *b)
{
    bi t;
    bi_init(&t);
    if (a->sign == 0) bi_copy(&t, b);
    else if (b->sign == 0) bi_copy(&t, a);
    else if (a->sign == b->sign) { uadd(&t, a, b); t.sign = a->sign; }
    else {
        int c = ucmp(a, b);
        if (c == 0) bi_set_zero(&t);
        else if (c > 0) { usub(&t, a, b); t.sign = a->sign; }
        else { usub(&t, b, a); t.sign = b->sign; }
    }
    norm(&t);
    bi_swap(r, &t);
    bi_free(&t);
}

/* |r| = |a| * |b|, schoolbook, O(n*m). r must not alias either operand.
 *
 * Row i writes slots i .. i+b->n, and no earlier row has touched slot
 * i+b->n yet, so the row's final carry can be stored rather than added. */
static void umul_school(bi *r, const bi *a, const bi *b)
{
    int i, j;

    if (a->n == 0 || b->n == 0) { bi_set_zero(r); return; }
    grow(r, a->n + b->n);
    memset(r->d, 0, (size_t)(a->n + b->n) * sizeof *r->d);
    for (i = 0; i < a->n; i++) {
        uint64_t carry = 0;
        bi_limb ai = a->d[i];
        if (ai == 0) continue;
        for (j = 0; j < b->n; j++) {
            carry += (uint64_t)ai * b->d[j] + r->d[i + j];
            r->d[i + j] = (bi_limb)carry;
            carry >>= 32;
        }
        r->d[i + b->n] = (bi_limb)carry;
    }
    r->n = a->n + b->n;
}

void bi_mul(bi *r, const bi *a, const bi *b)
{
    bi t;
    bi_init(&t);
    umul_school(&t, a, b);
    t.sign = a->sign * b->sign;
    norm(&t);
    bi_swap(r, &t);
    bi_free(&t);
}

static int nlz32(bi_limb x)
{
    int n = 0;
    if (x == 0) return 32;
    while (!(x & 0x80000000u)) { x <<= 1; n++; }
    return n;
}

/* Truncating magnitude division: |Q| = |A| / |B|, |R| = |A| % |B|.
 * B must be nonzero; Q and R must not alias A or B; either may be NULL.
 *
 * Knuth algorithm D, in the form given as divmnu in Hacker's Delight. The
 * 32-bit limb choice pays off here: every intermediate (qhat * vn[i], the
 * two-limb numerator, b * rhat) fits a uint64_t exactly, with nothing to
 * spare, so there is no 128-bit arithmetic and no inline assembly.
 *
 * The qhat estimate can be one too large, and detecting that requires a
 * signed borrow that goes negative, so the inner loop shifts int64_t values
 * right. gcc defines that as arithmetic; the implementation is gcc-only and
 * says so in the README rather than pretending to be portable. */
static void udivmod(bi *Q, bi *R, const bi *A, const bi *B)
{
    const uint64_t b = (uint64_t)1 << 32;
    int m = A->n, n = B->n, i, j, s;
    bi_limb *un, *vn;

    if (m < n) {                       /* |A| < |B|: quotient 0, remainder A */
        if (Q) bi_set_zero(Q);
        if (R) { bi_copy(R, A); R->sign = A->n ? 1 : 0; }
        return;
    }
    if (n == 1) {                      /* single-limb divisor: one pass */
        bi t;
        bi_limb rem;
        bi_init(&t);
        bi_copy(&t, A);
        t.sign = A->n ? 1 : 0;
        rem = udiv_small(&t, B->d[0]);
        if (R) { grow(R, 1); R->d[0] = rem; R->n = rem ? 1 : 0;
                 R->sign = rem ? 1 : 0; }
        if (Q) bi_swap(Q, &t);
        bi_free(&t);
        return;
    }

    /* Normalise the divisor so its top limb has its high bit set, which is
     * what bounds the qhat error at 2. Shifting by (32 - s) with s == 0 is
     * done in 64 bits on purpose: a 32-bit shift by 32 would be UB. */
    s = nlz32(B->d[n - 1]);
    vn = xrealloc(NULL, (size_t)n * sizeof *vn);
    for (i = n - 1; i > 0; i--)
        vn[i] = (B->d[i] << s) | (bi_limb)((uint64_t)B->d[i - 1] >> (32 - s));
    vn[0] = B->d[0] << s;

    un = xrealloc(NULL, (size_t)(m + 1) * sizeof *un);
    un[m] = (bi_limb)((uint64_t)A->d[m - 1] >> (32 - s));
    for (i = m - 1; i > 0; i--)
        un[i] = (A->d[i] << s) | (bi_limb)((uint64_t)A->d[i - 1] >> (32 - s));
    un[0] = A->d[0] << s;

    if (Q) { grow(Q, m - n + 1); Q->n = m - n + 1; Q->sign = 1; }

    for (j = m - n; j >= 0; j--) {
        uint64_t num = (uint64_t)un[j + n] * b + un[j + n - 1];
        uint64_t qhat = num / vn[n - 1];
        uint64_t rhat = num - qhat * vn[n - 1];
        int64_t k, t;

        for (;;) {
            /* Short-circuit matters: when qhat >= b the product below would
             * overflow, so it must not be evaluated. */
            if (qhat >= b || qhat * vn[n - 2] > b * rhat + un[j + n - 2]) {
                qhat--;
                rhat += vn[n - 1];
                if (rhat < b) continue;
            }
            break;
        }

        k = 0;                         /* multiply and subtract */
        for (i = 0; i < n; i++) {
            uint64_t p = qhat * vn[i];
            t = (int64_t)un[i + j] - k - (int64_t)(uint32_t)p;
            un[i + j] = (bi_limb)t;
            k = (int64_t)(p >> 32) - (t >> 32);
        }
        t = (int64_t)un[j + n] - k;
        un[j + n] = (bi_limb)t;
        if (Q) Q->d[j] = (bi_limb)qhat;

        if (t < 0) {                   /* qhat was one too big: add back */
            if (Q) Q->d[j]--;
            k = 0;
            for (i = 0; i < n; i++) {
                uint64_t tt = (uint64_t)un[i + j] + vn[i] + (uint64_t)k;
                un[i + j] = (bi_limb)tt;
                k = (int64_t)(tt >> 32);
            }
            un[j + n] = (bi_limb)((uint64_t)un[j + n] + (uint64_t)k);
        }
    }

    if (Q) norm(Q);
    if (R) {
        grow(R, n);
        for (i = 0; i < n - 1; i++)
            R->d[i] = (bi_limb)(((uint64_t)un[i] >> s) |
                                ((uint64_t)un[i + 1] << (32 - s)));
        R->d[n - 1] = un[n - 1] >> s;
        R->n = n;
        R->sign = 1;
        norm(R);
    }
    free(un);
    free(vn);
}

/* Floor division and modulo, with PYTHON's semantics, not C's.
 *
 * C truncates toward zero: -7 / 2 == -3, -7 % 2 == -1.
 * Python floors toward negative infinity: -7 // 2 == -4, -7 % 2 == 1.
 *
 * Python is the oracle here, so Python's rule wins. The remainder always
 * carries the sign of the divisor and satisfies a == q*b + r with
 * 0 <= |r| < |b|. Returns -1 if b is zero, leaving q and rem untouched. */
int bi_divmod(bi *q, bi *rem, const bi *a, const bi *b)
{
    bi tq, tr;

    if (b->sign == 0) return BI_EDIVZERO;

    bi_init(&tq);
    bi_init(&tr);
    udivmod(&tq, &tr, a, b);
    tq.sign = tq.n ? a->sign * b->sign : 0;
    tr.sign = tr.n ? a->sign : 0;

    if (tr.n != 0 && a->sign * b->sign < 0) {
        bi one;
        bi_init(&one);
        bi_set_i64(&one, 1);
        bi_sub(&tq, &tq, &one);        /* round down instead of toward zero */
        bi_add(&tr, &tr, b);           /* and move r into b's sign */
        bi_free(&one);
    }

    if (q) bi_swap(q, &tq);
    if (rem) bi_swap(rem, &tr);
    bi_free(&tq);
    bi_free(&tr);
    return BI_OK;
}

/* Python's bitwise operators act on an infinite two's-complement
 * representation, so -1 & 5 is 5 and -1 | 0 is -1. Sign-magnitude has no
 * such representation, so build one: n limbs where n is one more than either
 * operand needs, which guarantees the top limb is 0 for a non-negative value
 * and 0xffffffff for a negative one, making the sign bit of limb n-1 a
 * reliable sign for the result. */
static void twos(bi_limb *out, int n, const bi *x)
{
    int i;
    for (i = 0; i < n; i++) out[i] = i < x->n ? x->d[i] : 0;
    if (x->sign < 0) {
        for (i = 0; i < n; i++) out[i] = ~out[i];
        for (i = 0; i < n; i++) if (++out[i] != 0) break;
    }
}

static void bitop(bi *r, const bi *a, const bi *b, char kind)
{
    int n = (a->n > b->n ? a->n : b->n) + 1, i;
    bi_limb *ta = xrealloc(NULL, (size_t)n * sizeof *ta);
    bi_limb *tb = xrealloc(NULL, (size_t)n * sizeof *tb);
    bi t;

    bi_init(&t);
    twos(ta, n, a);
    twos(tb, n, b);
    grow(&t, n);
    for (i = 0; i < n; i++)
        t.d[i] = kind == '&' ? (ta[i] & tb[i])
               : kind == '|' ? (ta[i] | tb[i])
                             : (ta[i] ^ tb[i]);
    t.n = n;
    if (t.d[n - 1] & 0x80000000u) {        /* negate back to sign-magnitude */
        for (i = 0; i < n; i++) t.d[i] = ~t.d[i];
        for (i = 0; i < n; i++) if (++t.d[i] != 0) break;
        t.sign = -1;
    } else {
        t.sign = 1;
    }
    norm(&t);
    bi_swap(r, &t);
    bi_free(&t);
    free(ta);
    free(tb);
}

void bi_and(bi *r, const bi *a, const bi *b) { bitop(r, a, b, '&'); }
void bi_or (bi *r, const bi *a, const bi *b) { bitop(r, a, b, '|'); }
void bi_xor(bi *r, const bi *a, const bi *b) { bitop(r, a, b, '^'); }

int bi_bits(const bi *x)
{
    if (x->n == 0) return 0;
    return x->n * 32 - nlz32(x->d[x->n - 1]);
}

/* |r| = |a| << c. r must not alias a. */
static void ushl(bi *r, const bi *a, uint64_t c)
{
    int limbs = (int)(c / 32), bits = (int)(c % 32);
    int n = a->n + limbs + 1, i;

    grow(r, n);
    memset(r->d, 0, (size_t)n * sizeof *r->d);
    for (i = 0; i < a->n; i++) {
        uint64_t v = (uint64_t)a->d[i] << bits;
        r->d[limbs + i]     |= (bi_limb)v;
        r->d[limbs + i + 1] |= (bi_limb)(v >> 32);
    }
    r->n = n;
    norm(r);
}

/* |r| = |a| >> c, returning 1 if any set bit was discarded. That flag is
 * what makes Python's floor semantics possible for negative values. */
static int ushr(bi *r, const bi *a, uint64_t c)
{
    int limbs, bits, n, i, lost = 0;

    if (c >= (uint64_t)a->n * 32) {
        lost = a->n != 0;
        bi_set_zero(r);
        return lost;
    }
    limbs = (int)(c / 32);
    bits = (int)(c % 32);
    for (i = 0; i < limbs; i++) if (a->d[i]) lost = 1;
    if (bits && (a->d[limbs] & ((1u << bits) - 1))) lost = 1;

    n = a->n - limbs;
    grow(r, n);
    for (i = 0; i < n; i++) {
        uint64_t v = a->d[limbs + i] >> bits;
        if (bits && limbs + i + 1 < a->n)
            v |= (uint64_t)a->d[limbs + i + 1] << (32 - bits);
        r->d[i] = (bi_limb)v;
    }
    r->n = n;
    norm(r);
    return lost;
}

/* k as a uint64_t, saturating: anything beyond two limbs is "enormous",
 * which is all either caller needs to know. */
static uint64_t shift_count(const bi *k)
{
    uint64_t c;
    if (k->n > 2) return UINT64_MAX;
    c = k->n > 0 ? k->d[0] : 0;
    if (k->n > 1) c |= (uint64_t)k->d[1] << 32;
    return c;
}

int bi_shl(bi *r, const bi *a, const bi *k)
{
    bi t;
    uint64_t c;

    if (k->sign < 0) return BI_ENEGSHIFT;
    if (a->sign == 0) { bi_set_zero(r); return BI_OK; }  /* 0 << anything */
    c = shift_count(k);
    if (c > BI_MAX_BITS || c + (uint64_t)bi_bits(a) > BI_MAX_BITS)
        return BI_ETOOBIG;

    bi_init(&t);
    ushl(&t, a, c);
    t.sign = t.n ? a->sign : 0;
    bi_swap(r, &t);
    bi_free(&t);
    return BI_OK;
}

/* Python's >> on a negative value floors, it does not truncate:
 * -1 >> 1 is -1, not 0, and -5 >> 1 is -3, not -2. So shift the magnitude
 * and add one back whenever a set bit fell off the bottom. */
int bi_shr(bi *r, const bi *a, const bi *k)
{
    bi t;
    int lost;

    if (k->sign < 0) return BI_ENEGSHIFT;
    if (a->sign == 0) { bi_set_zero(r); return BI_OK; }

    bi_init(&t);
    lost = ushr(&t, a, shift_count(k));
    t.sign = t.n ? 1 : 0;
    if (a->sign < 0) {
        if (lost) {
            bi one;
            bi_init(&one);
            bi_set_i64(&one, 1);
            bi_add(&t, &t, &one);
            bi_free(&one);
        }
        t.sign = t.n ? -1 : 0;
    }
    bi_swap(r, &t);
    bi_free(&t);
    return BI_OK;
}

void bi_sub(bi *r, const bi *a, const bi *b)
{
    bi nb = *b;                 /* read-only view of b with the sign flipped */
    nb.sign = -nb.sign;
    bi_add(r, a, &nb);
}

void bi_neg(bi *r, const bi *a)
{
    bi_copy(r, a);
    r->sign = -a->sign;
}

void bi_abs(bi *r, const bi *a)
{
    bi_copy(r, a);
    if (r->sign < 0) r->sign = 1;
}

/* a ** e by binary exponentiation. Python's rules: 0 ** 0 is 1, and a
 * negative exponent is an error here rather than Python's float result --
 * this is an integer library, and returning 0 for 2 ** -1 would be worse
 * than refusing.
 *
 * The size check is an exact upper bound: the result cannot exceed
 * bits(a) * e bits. Values with bits(a) <= 1 are exactly 0, 1 and -1, whose
 * powers are bounded whatever the exponent, so they are answered before the
 * check and 1 ** (10**30) costs nothing. */
int bi_pow(bi *r, const bi *a, const bi *e)
{
    bi acc, base;
    uint64_t ee;
    int ab = bi_bits(a);

    if (e->sign < 0) return BI_ENEGPOW;
    if (ab <= 1) {
        int odd = e->n != 0 && (e->d[0] & 1);
        bi_set_i64(r, a->sign == 0 ? (e->n == 0 ? 1 : 0)
                                   : (a->sign > 0 || !odd) ? 1 : -1);
        return BI_OK;
    }
    if (e->n > 1) return BI_ETOOBIG;       /* ab >= 2 and e >= 2^32 */
    ee = e->n ? e->d[0] : 0;
    if ((uint64_t)ab * ee > BI_MAX_BITS) return BI_ETOOBIG;

    bi_init(&acc);
    bi_init(&base);
    bi_set_i64(&acc, 1);
    bi_copy(&base, a);
    while (ee) {
        if (ee & 1) bi_mul(&acc, &acc, &base);
        ee >>= 1;
        if (ee) bi_mul(&base, &base, &base);
    }
    bi_swap(r, &acc);
    bi_free(&acc);
    bi_free(&base);
    return BI_OK;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Hex is limb-aligned, so unlike decimal it is linear in both directions and
 * shares no code with the quadratic base-10 loops. Accepts an optional sign,
 * an optional 0x/0X prefix, either case, and leading zeros -- which is the
 * subset of what Python's int(s, 16) takes; see the README for the rest. */
int bi_set_hex(bi *x, const char *s)
{
    const char *p = s, *dig;
    int sign = 1, ndig, nl, i;

    if (*p == '-') { sign = -1; p++; }
    else if (*p == '+') p++;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    dig = p;
    for (; *p; p++)
        if (hexval(*p) < 0) return -1;
    ndig = (int)(p - dig);
    if (ndig == 0) return -1;

    nl = (ndig + 7) / 8;
    grow(x, nl);
    memset(x->d, 0, (size_t)nl * sizeof *x->d);
    x->n = nl;
    for (i = 0; i < ndig; i++)
        x->d[i / 8] |= (bi_limb)hexval(dig[ndig - 1 - i]) << (4 * (i % 8));
    x->sign = sign;
    norm(x);
    return 0;
}

/* Formatted exactly like Python's hex(): lowercase, "0x" prefix inside the
 * sign, no leading zeros, "0x0" for zero. */
char *bi_to_hex(const bi *x)
{
    char *buf = xrealloc(NULL, (size_t)x->n * 8 + 4);
    char *p = buf;
    int i;

    if (x->sign < 0) *p++ = '-';
    *p++ = '0';
    *p++ = 'x';
    if (x->n == 0) { *p++ = '0'; *p = 0; return buf; }
    p += sprintf(p, "%x", x->d[x->n - 1]);
    for (i = x->n - 2; i >= 0; i--)
        p += sprintf(p, "%08x", x->d[i]);
    *p = 0;
    return buf;
}

/* ---------------------------------------------------------------- driver --
 * One operation per stdin line, one result line per input line, so the
 * differential fuzzer can push millions of cases through one process.
 * Errors are reported as "E <reason>" and do not stop the stream.
 */

static int split(char *line, char *arg[3])
{
    int n = 0;
    char *p = line;
    while (*p && n < 3) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        arg[n++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) *p++ = 0;
    }
    return n;
}

/* Operation table: name, operand count. An operand-count mismatch is a parse
 * error, which is also what Python says about int("") -- the line protocol
 * cannot carry an empty or space-containing operand. */
static const struct { const char *name; int ary; int hexin; } OPS[] = {
    { "dec", 1, 0 }, { "neg", 1, 0 }, { "abs", 1, 0 },
    { "cmp", 2, 0 }, { "add", 2, 0 }, { "sub", 2, 0 }, { "mul", 2, 0 },
    { "divf", 2, 0 }, { "mod", 2, 0 }, { "divmod", 2, 0 },
    { "shl", 2, 0 }, { "shr", 2, 0 },
    { "and", 2, 0 }, { "or", 2, 0 }, { "xor", 2, 0 },
    { "hex", 1, 0 }, { "hexrt", 1, 0 }, { "unhex", 1, 1 },
    { "pow", 2, 0 },
};

/* Decimal output cannot reveal an unnormalised result: bi_to_dec divides the
 * value down and ignores leading zero limbs, so an untrimmed answer prints
 * identically to a trimmed one and the oracle sees nothing wrong. Only
 * bi_cmp notices, and by then the bug is months old. So the invariant is
 * checked here directly, on every result of every case the fuzzer runs. */
static int normal(const bi *x)
{
    if (x->n < 0 || x->n > x->cap) return 0;
    if (x->n == 0) return x->sign == 0;
    return x->sign != 0 && x->d[x->n - 1] != 0;
}

static void emit(const bi *x)
{
    char *s;
    if (!normal(x)) { puts("E unnormalised"); return; }
    s = bi_to_dec(x);
    puts(s);
    free(s);
}

static int fail(int e)
{
    static const char *const msg[] = { "", "divzero", "negshift", "negpow",
                                       "toobig" };
    printf("E %s\n", msg[e]);
    return 1;
}

static void emit2(const bi *x, const bi *y)
{
    char *s1, *s2;
    if (!normal(x) || !normal(y)) { puts("E unnormalised"); return; }
    s1 = bi_to_dec(x);
    s2 = bi_to_dec(y);
    printf("%s %s\n", s1, s2);
    free(s1);
    free(s2);

}


int main(void)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    bi a, b, r, r2;

    bi_init(&a);
    bi_init(&b);
    bi_init(&r);
    bi_init(&r2);
    while ((len = getline(&line, &cap, stdin)) > 0) {
        char *arg[4];
        int n, i, ary = -1, hexin = 0;
        const char *op;

        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = 0;
        n = split(line, arg);
        if (n == 0) continue;
        op = arg[0];

        for (i = 0; i < (int)(sizeof OPS / sizeof *OPS); i++)
            if (!strcmp(op, OPS[i].name)) {
                ary = OPS[i].ary; hexin = OPS[i].hexin; break;
            }
        if (ary < 0) { printf("E unknown op %s\n", op); continue; }
        if (n != ary + 1) { puts("E parse"); continue; }
        if ((hexin ? bi_set_hex(&a, arg[1]) : bi_set_dec(&a, arg[1])) != 0) {
            puts("E parse");
            continue;
        }
        if (ary == 2 && bi_set_dec(&b, arg[2]) != 0) { puts("E parse"); continue; }

        if (!strcmp(op, "dec")) emit(&a);
        else if (!strcmp(op, "neg")) { bi_neg(&r, &a); emit(&r); }
        else if (!strcmp(op, "cmp")) printf("%d\n", bi_cmp(&a, &b));
        else if (!strcmp(op, "add")) { bi_add(&r, &a, &b); emit(&r); }
        else if (!strcmp(op, "sub")) { bi_sub(&r, &a, &b); emit(&r); }
        else if (!strcmp(op, "abs")) { bi_abs(&r, &a); emit(&r); }
        else if (!strcmp(op, "mul")) { bi_mul(&r, &a, &b); emit(&r); }
        else if (!strcmp(op, "divf")) {
            int e = bi_divmod(&r, NULL, &a, &b);
            if (e) fail(e); else emit(&r);
        } else if (!strcmp(op, "mod")) {
            int e = bi_divmod(NULL, &r, &a, &b);
            if (e) fail(e); else emit(&r);
        } else if (!strcmp(op, "divmod")) {
            int e = bi_divmod(&r, &r2, &a, &b);
            if (e) fail(e); else emit2(&r, &r2);
        } else if (!strcmp(op, "shl")) {
            int e = bi_shl(&r, &a, &b);
            if (e) fail(e); else emit(&r);
        } else if (!strcmp(op, "shr")) {
            int e = bi_shr(&r, &a, &b);
            if (e) fail(e); else emit(&r);
        }
        else if (!strcmp(op, "and")) { bi_and(&r, &a, &b); emit(&r); }
        else if (!strcmp(op, "or"))  { bi_or(&r, &a, &b);  emit(&r); }
        else if (!strcmp(op, "xor")) { bi_xor(&r, &a, &b); emit(&r); }
        else if (!strcmp(op, "unhex")) emit(&a);
        else if (!strcmp(op, "pow")) {
            int e2 = bi_pow(&r, &a, &b);
            if (e2) fail(e2); else emit(&r);
        }

        else if (!strcmp(op, "hex")) {
            char *s = bi_to_hex(&a);
            puts(s);
            free(s);
        } else if (!strcmp(op, "hexrt")) {
            /* Full round trip: decimal in, hex out, hex back in, decimal
             * out. Must be the identity at every length. */
            char *s = bi_to_hex(&a);
            if (bi_set_hex(&r, s) != 0) puts("E parse"); else emit(&r);
            free(s);
        }






    }
    bi_free(&a);
    bi_free(&b);
    bi_free(&r);
    bi_free(&r2);

    free(line);
    return 0;
}
