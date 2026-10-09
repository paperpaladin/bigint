#!/usr/bin/env python3
"""Differential fuzzer: bigint vs Python's native int.

Python's int is arbitrary-precision, so for every operation this library
implements there is an exact Python equivalent and zero ambiguity about the
right answer. Python is the oracle; any disagreement is a bug in bigint.

The driver takes one operation per stdin line and emits one result line, so a
million cases cost one process rather than a million.

Usage: fuzz.py [CASES] [SEED]
"""
import os
import random
import subprocess
import sys

# 16000-bit operands are ~4817 decimal digits; Python 3.11+ caps int<->str at
# 4300 by default, which is a limit of the oracle's front door, not of its
# arithmetic.
sys.set_int_max_str_digits(1000000)

BIN = os.environ.get("BIGINT", "./bigint")
CHUNK = 20000

# Magnitude buckets, in bits. The wide spread is deliberate: operands of
# wildly different sizes are where carry/borrow and limb-count logic breaks.
BUCKETS = [(0, 0), (1, 4), (28, 36), (60, 70), (120, 200), (900, 1100),
           (15800, 16000)]
WEIGHTS = [6, 14, 18, 18, 20, 18, 6]

# bigint refuses to build a value wider than this from a shift or a power.
# It is bigint's own ceiling, not Python's, so the oracle has to know it.
MAX_BITS = 1 << 24

# Shift counts clustered on the limb and word boundaries, where an off-by-one
# in the limbs/bits split shows up.
SHIFT_EDGES = [0, 1, 31, 32, 33, 63, 64, 65, 95, 96, 127, 128,
               1023, 1024, 1025]



def rand_mag(rnd, cap=None):
    lo, hi = rnd.choices(BUCKETS, WEIGHTS)[0]
    if cap is not None and lo > cap:
        lo, hi = 0, cap
    bits = rnd.randint(lo, min(hi, cap) if cap is not None else hi)
    if bits <= 0:
        return 0
    v = rnd.getrandbits(bits) | (1 << (bits - 1))
    return v


def rand_val(rnd, cap=None, nonneg=False):
    v = rand_mag(rnd, cap)
    if not nonneg and v and rnd.random() < 0.5:
        v = -v
    return v


def rand_shift(rnd):
    r = rnd.random()
    if r < 0.20:
        return rnd.choice(SHIFT_EDGES)
    if r < 0.85:
        return rnd.randint(0, 2500)
    if r < 0.93:
        return -rnd.randint(1, 1000)            # must be rejected
    return rnd.choice([MAX_BITS, MAX_BITS + 1, 2**70, 10**30])


def ev(op, args):
    """The oracle. Returns the exact line bigint is expected to print."""
    try:
        if op == "unhex":
            return str(int(args[0], 16))
        vals = [int(s) for s in args]
    except ValueError:
        return "E parse"

    if op in ("dec", "hexrt"):
        return str(vals[0])
    if op == "hex":
        return hex(vals[0])
    if op == "neg":
        return str(-vals[0])
    if op == "add":
        return str(vals[0] + vals[1])
    if op == "sub":
        return str(vals[0] - vals[1])
    if op == "mul":
        return str(vals[0] * vals[1])
    if op == "pow":
        x, e = vals
        if e < 0:
            return "E negpow"
        if x == 0:
            return "1" if e == 0 else "0"
        if x == 1:
            return "1"
        if x == -1:
            return "1" if e % 2 == 0 else "-1"
        if x.bit_length() * e > MAX_BITS:
            return "E toobig"
        return str(x ** e)
    if op == "and":
        return str(vals[0] & vals[1])
    if op == "or":
        return str(vals[0] | vals[1])
    if op == "xor":
        return str(vals[0] ^ vals[1])
    if op in ("shl", "shr"):
        x, c = vals
        if c < 0:
            return "E negshift"
        if op == "shr":
            return str(x >> c) if x else "0"
        if x == 0:
            return "0"
        if c + x.bit_length() > MAX_BITS:
            return "E toobig"
        return str(x << c)
    if op in ("divf", "mod", "divmod"):
        if vals[1] == 0:
            return "E divzero"
        if op == "divf":
            return str(vals[0] // vals[1])
        if op == "mod":
            return str(vals[0] % vals[1])
        return "%d %d" % divmod(vals[0], vals[1])
    if op == "abs":
        return str(abs(vals[0]))
    if op == "cmp":
        x, y = vals
        return str((x > y) - (x < y))
    raise AssertionError("unknown op " + op)


ARITY = {"dec": 1, "neg": 1, "abs": 1, "cmp": 2, "add": 2, "sub": 2,
         "mul": 2, "divf": 2, "mod": 2, "divmod": 2,
         "shl": 2, "shr": 2, "and": 2, "or": 2, "xor": 2,
         "hex": 1, "hexrt": 1, "unhex": 1, "pow": 2}
OPS = list(ARITY)


def rand_hexlit(rnd):
    """A hex literal in one of the spellings Python's int(s, 16) accepts."""
    v = rand_val(rnd)
    s = format(abs(v), "x")
    if rnd.random() < 0.3:
        s = s.upper()
    if rnd.random() < 0.3:
        s = "0" * rnd.randint(1, 5) + s
    if rnd.random() < 0.5:
        s = ("0X" if rnd.random() < 0.3 else "0x") + s
    if v < 0:
        return "-" + s
    return ("+" + s) if rnd.random() < 0.1 else s


def rand_pow_exp(rnd, x):
    """Exponents that stay out of the 'legal but takes a minute to print'
    band: bigint's ceiling is 16 Mbit, but quadratic base conversion means
    anything over ~30 Kbit dominates the whole run."""
    r = rnd.random()
    if r < 0.08:
        return -rnd.randint(1, 100)
    if r < 0.20:
        return rnd.choice([0, 1, 2, 3])
    if r < 0.30 or abs(x) <= 1:
        return rnd.choice([MAX_BITS, MAX_BITS + 1, 2**70, 10**30])
    return rnd.randint(0, max(1, 30000 // x.bit_length()))


def gen(rnd):
    op = rnd.choice(OPS)
    if op == "pow":
        x = rand_val(rnd)
        return op, [str(x), str(rand_pow_exp(rnd, x))]
    if op in ("shl", "shr"):
        return op, [str(rand_val(rnd)), str(rand_shift(rnd))]
    if op == "unhex":
        return op, [rand_hexlit(rnd)]
    return op, [str(rand_val(rnd)) for _ in range(ARITY[op])]


CORPUS = [
    ("dec", ["0"]), ("dec", ["-0"]), ("dec", ["+0"]), ("dec", ["7"]),
    ("dec", ["-7"]), ("dec", ["0000123"]), ("dec", ["4294967295"]),
    ("dec", ["4294967296"]), ("dec", ["18446744073709551615"]),
    ("dec", ["18446744073709551616"]), ("dec", ["-18446744073709551617"]),
    ("dec", ["9" * 300]), ("dec", ["-" + "9" * 300]),
    ("dec", [""]), ("dec", ["-"]), ("dec", ["12x"]), ("dec", ["0x10"]),
    ("neg", ["0"]), ("neg", ["-1"]),
    # Comparison has to be a total order, which is where a result that was
    # left unnormalised stops being equal to itself.
    ("cmp", ["0", "0"]), ("cmp", ["0", "-0"]), ("cmp", ["-1", "1"]),
    ("cmp", ["1", "-1"]), ("cmp", ["-2", "-1"]), ("cmp", ["-1", "-2"]),
    ("cmp", ["4294967296", "4294967295"]), ("cmp", ["4294967295", "4294967296"]),
    ("cmp", ["-4294967296", "-4294967295"]),
    ("cmp", ["18446744073709551616", "18446744073709551616"]),
    ("cmp", ["1" + "0" * 400, "1" + "0" * 400]),
    ("cmp", ["1" + "0" * 400, "9" * 400]),
    # Carry propagating the full length of the number, in both directions.
    ("add", ["9" * 500, "1"]), ("add", ["1", "9" * 500]),
    ("add", ["-" + "9" * 500, "-1"]), ("add", ["9" * 500, "-1"]),
    ("add", ["4294967295", "1"]), ("add", ["18446744073709551615", "1"]),
    ("add", ["0", "0"]), ("add", ["0", "-5"]), ("add", ["-5", "0"]),
    ("add", ["5", "-5"]), ("add", ["-5", "5"]),
    # Borrow chains, and subtraction whose result is many limbs shorter than
    # either operand: the leading zero limbs must be trimmed or bi_cmp lies.
    ("sub", ["1" + "0" * 500, "1"]), ("sub", ["1" + "0" * 500, "9" * 500]),
    ("sub", ["9" * 500, "9" * 500]), ("sub", [str(10**500), str(10**500 - 1)]),
    ("sub", ["4294967296", "1"]), ("sub", ["18446744073709551616", "1"]),
    ("sub", ["0", "0"]), ("sub", ["0", "-5"]), ("sub", ["-5", "0"]),
    ("sub", ["5", "5"]), ("sub", ["-5", "-5"]),
    ("abs", ["0"]), ("abs", ["-" + "9" * 300]),
    # One limb against five hundred, both orders, and the limb-boundary
    # squares where a 32x32 product is exactly one limb short of overflowing.
    ("mul", ["0", "9" * 500]), ("mul", ["9" * 500, "0"]),
    ("mul", ["1", "9" * 500]), ("mul", ["9" * 500, "1"]),
    ("mul", ["-1", "9" * 500]), ("mul", ["9" * 500, "-1"]),
    ("mul", ["4294967295", "4294967295"]), ("mul", ["4294967296", "4294967296"]),
    ("mul", ["18446744073709551615", "18446744073709551615"]),
    ("mul", [str(10**500), str(10**500)]),
    ("mul", [str(2**16000 - 1), str(2**32 + 1)]),
    # Division by zero must error, not crash, in every operand sign.
    ("divf", ["0", "0"]), ("mod", ["0", "0"]), ("divmod", ["0", "0"]),
    ("divf", ["7", "0"]), ("divf", ["-7", "0"]), ("mod", ["-7", "0"]),
    # THE disagreement: C truncates toward zero, Python floors. All four
    # sign combinations of 7 and 2, exhaustively, for all three operations.
    ("divmod", ["7", "2"]), ("divmod", ["-7", "2"]),
    ("divmod", ["7", "-2"]), ("divmod", ["-7", "-2"]),
    ("divf", ["7", "2"]), ("divf", ["-7", "2"]),
    ("divf", ["7", "-2"]), ("divf", ["-7", "-2"]),
    ("mod", ["7", "2"]), ("mod", ["-7", "2"]),
    ("mod", ["7", "-2"]), ("mod", ["-7", "-2"]),
    # Exact division: the remainder is zero, so NO floor correction applies
    # even though the signs differ. Getting this wrong is off-by-one on an
    # exact quotient, which the sign cases above would not catch.
    ("divmod", ["-8", "2"]), ("divmod", ["8", "-2"]),
    ("divmod", ["-8", "-2"]), ("divmod", [str(-(10**500)), str(10**250)]),
    # Knuth D corner cases: the add-back path, a divisor whose top limb is
    # already normalised (s == 0), and one that needs a full 31-bit shift.
    ("divmod", [str(2**64), str(2**32 + 1)]),
    ("divmod", [str(2**96 - 1), str(2**64 - 1)]),
    ("divmod", [str(2**16000 - 1), str(2**8000 + 1)]),
    ("divmod", [str(2**16000 - 1), "3"]),
    ("divmod", [str(2**16000 - 1), str(2**31)]),
    ("divmod", [str(2**16000 - 1), str(2**16000 - 1)]),
    ("divmod", [str(2**16000 - 1), str(2**16000)]),
    ("divmod", ["1", str(10**500)]), ("divmod", ["-1", str(10**500)]),
    # >> on a negative value floors in Python. -1 >> n is -1 forever.
    ("shr", ["-1", "1"]), ("shr", ["-1", "1000"]), ("shr", ["-1", str(2**70)]),
    ("shr", ["-5", "1"]), ("shr", ["-5", "2"]), ("shr", ["-5", "3"]),
    ("shr", ["5", "1"]), ("shr", ["-4", "1"]), ("shr", ["-4", "2"]),
    ("shr", ["0", "0"]), ("shr", ["0", str(2**70)]), ("shr", ["7", "-1"]),
    ("shr", [str(2**16000 - 1), "16000"]), ("shr", [str(2**16000), "16000"]),
    ("shr", [str(-(2**16000) - 1), "15999"]),
    ("shl", ["0", str(2**70)]), ("shl", ["1", "-1"]), ("shl", ["0", "-1"]),
    ("shl", ["1", "31"]), ("shl", ["1", "32"]), ("shl", ["1", "33"]),
    ("shl", ["-1", "32"]), ("shl", [str(2**32 - 1), "1"]),
    # The ceiling itself: 1 << MAX_BITS is one bit too wide and must be
    # refused. The largest *accepted* shift is deliberately not exercised --
    # a 16-Mbit value costs seconds to print, because base conversion is
    # quadratic -- so the success side is checked at 64 Kbit instead.
    ("shl", ["1", "65535"]), ("shl", ["1", str(MAX_BITS)]),
    ("shl", ["1", str(MAX_BITS + 1)]), ("shl", ["1", str(2**70)]),
    # Bitwise on Python's infinite two's-complement model. Sign-magnitude
    # bit twiddling gets all of these wrong.
    ("and", ["-1", "5"]), ("and", ["5", "-1"]), ("and", ["-1", "-1"]),
    ("or", ["-1", "0"]), ("or", ["0", "-1"]), ("xor", ["-1", "-1"]),
    ("xor", ["-1", "0"]), ("and", ["-2", "-3"]), ("or", ["-2", "-3"]),
    ("xor", ["-2", "-3"]), ("and", ["0", "0"]), ("or", ["0", "0"]),
    ("and", ["-4294967296", "4294967295"]),
    ("or", ["-4294967296", "4294967295"]),
    ("xor", [str(-(2**64)), str(2**64 - 1)]),
    ("and", [str(-(2**16000)), str(2**16000 - 1)]),
    ("or", [str(-(2**16000)), "255"]), ("and", ["-1", str(2**16000 - 1)]),
    # Operands of very different length, with the shorter one negative so
    # the sign extension has to run the whole way up.
    ("and", ["-3", str(2**16000 - 1)]), ("or", ["-3", str(2**16000 - 1)]),
    ("xor", ["-3", str(2**16000 - 1)]), ("and", [str(2**16000 - 1), "-3"]),
    # Hex round trips at every length that crosses a nibble or limb edge.
    ("hex", ["0"]), ("hex", ["-1"]), ("hex", ["15"]), ("hex", ["16"]),
    ("hex", ["255"]), ("hex", ["4294967295"]), ("hex", ["4294967296"]),
    ("hex", ["-4294967296"]), ("hex", ["18446744073709551615"]),
    ("hex", [str(2**16000 - 1)]), ("hex", [str(-(2**16000))]),
    ("unhex", ["0"]), ("unhex", ["0x0"]), ("unhex", ["-0x0"]),
    ("unhex", ["0X1F"]), ("unhex", ["1f"]), ("unhex", ["0000001f"]),
    ("unhex", ["+0xff"]), ("unhex", ["-0xFF"]),
    ("unhex", ["f" * 8]), ("unhex", ["f" * 9]), ("unhex", ["1" + "0" * 8]),
    ("unhex", [""]), ("unhex", ["0x"]), ("unhex", ["-"]), ("unhex", ["0xg"]),
    ("unhex", ["zz"]), ("unhex", ["12 34"]),
] + [("hexrt", [str((-1) ** k * (2**k - 1))]) for k in range(0, 300)] + [
    ("hexrt", ["0"]), ("hexrt", [str(2**16000 - 1)]),
    # 0 ** 0 is 1. Everything else about zero and one in an exponent.
    ("pow", ["0", "0"]), ("pow", ["0", "1"]), ("pow", ["0", "500"]),
    ("pow", ["1", "0"]), ("pow", ["-1", "0"]), ("pow", ["5", "0"]),
    ("pow", ["-5", "0"]), ("pow", ["-5", "1"]), ("pow", ["-5", "2"]),
    ("pow", ["-5", "3"]), ("pow", ["-1", "1"]), ("pow", ["-1", "2"]),
    # 1 and -1 answer instantly whatever the exponent, so their fast path
    # must agree with the parity rule rather than falling into the ceiling.
    ("pow", ["1", str(10**30)]), ("pow", ["-1", str(10**30)]),
    ("pow", ["-1", str(10**30 + 1)]), ("pow", ["0", str(10**30)]),
    ("pow", ["2", "-1"]), ("pow", ["0", "-1"]), ("pow", ["-1", "-2"]),
    ("pow", ["2", str(MAX_BITS)]), ("pow", ["2", str(MAX_BITS + 1)]),
    ("pow", ["2", "16000"]), ("pow", ["-2", "16001"]),
    ("pow", [str(2**64 - 1), "3"]), ("pow", [str(-(2**64)), "5"]),
    ("pow", ["10", "500"]), ("pow", ["-10", "501"]),










]


def run_chunk(cases):
    """cases: list of (op, args). Returns (agree, failures)."""
    lines = []
    for op, args in cases:
        lines.append(" ".join([op] + list(args)))
    inp = "\n".join(lines) + "\n"
    p = subprocess.run([BIN], input=inp, capture_output=True, text=True)
    got = p.stdout.splitlines()
    agree = 0
    failures = []
    for i, (op, args) in enumerate(cases):
        want = ev(op, args)
        have = got[i] if i < len(got) else "<no output>"
        if have == want:
            agree += 1
        else:
            failures.append((lines[i], want, have))
    if p.returncode != 0:
        failures.append(("<driver exit %d>" % p.returncode, "", p.stderr[-400:]))
    return agree, failures


def main():
    iters = int(sys.argv[1]) if len(sys.argv) > 1 else 100000
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    rnd = random.Random(seed)

    agree = disagree = 0
    failures = []

    # The fixed corpus first: boundaries, degenerate inputs, past regressions.
    a, f = run_chunk(CORPUS)
    agree += a
    disagree += len(f)
    failures += [("corpus",) + x for x in f]

    done = 0
    while done < iters:
        k = min(CHUNK, iters - done)
        cases = [gen(rnd) for _ in range(k)]
        a, f = run_chunk(cases)
        agree += a
        disagree += len(f)
        failures += [("seed=%d case=%d" % (seed, done + j),) + x
                     for j, x in enumerate(f)]
        done += k

    print("%d agree, %d disagree" % (agree, disagree))
    for where, line, want, have in failures[:20]:
        print("  %s\n    in:   %s\n    want: %s\n    got:  %s"
              % (where, line[:200], want[:200], have[:200]))
    if len(failures) > 20:
        print("  ... and %d more" % (len(failures) - 20))
    if disagree:
        print("  failing seed: %d" % seed)
    return 1 if disagree else 0


if __name__ == "__main__":
    sys.exit(main())
