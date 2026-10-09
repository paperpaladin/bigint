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

void bi_neg(bi *r, const bi *a)
{
    bi_copy(r, a);
    r->sign = -a->sign;
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
static const struct { const char *name; int ary; } OPS[] = {
    { "dec", 1 }, { "neg", 1 }, { "cmp", 2 }, { "add", 2 },
};

static void emit(const bi *x) { char *s = bi_to_dec(x); puts(s); free(s); }

int main(void)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    bi a, b, r;

    bi_init(&a);
    bi_init(&b);
    bi_init(&r);
    while ((len = getline(&line, &cap, stdin)) > 0) {
        char *arg[4];
        int n, i, ary = -1;
        const char *op;

        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = 0;
        n = split(line, arg);
        if (n == 0) continue;
        op = arg[0];

        for (i = 0; i < (int)(sizeof OPS / sizeof *OPS); i++)
            if (!strcmp(op, OPS[i].name)) { ary = OPS[i].ary; break; }
        if (ary < 0) { printf("E unknown op %s\n", op); continue; }
        if (n != ary + 1) { puts("E parse"); continue; }
        if (bi_set_dec(&a, arg[1]) != 0) { puts("E parse"); continue; }
        if (ary == 2 && bi_set_dec(&b, arg[2]) != 0) { puts("E parse"); continue; }

        if (!strcmp(op, "dec")) emit(&a);
        else if (!strcmp(op, "neg")) { bi_neg(&r, &a); emit(&r); }
        else if (!strcmp(op, "cmp")) printf("%d\n", bi_cmp(&a, &b));
        else if (!strcmp(op, "add")) { bi_add(&r, &a, &b); emit(&r); }

    }
    bi_free(&a);
    bi_free(&b);
    bi_free(&r);

    free(line);
    return 0;
}
