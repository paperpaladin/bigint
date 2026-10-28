#!/usr/bin/env python3
"""Differential fuzzer: bigint vs Python's native int.

Python's int is arbitrary-precision, so for every operation this library
implements there is an exact Python equivalent and zero ambiguity about the
right answer. Python is the oracle; any disagreement is a bug in bigint.

The driver takes one operation per stdin line and emits one result line, so a
million cases cost one process rather than a million.

Usage: fuzz.py [CASES] [SEED]
"""
import math
import os
import random
import shlex
import subprocess
import sys

# 16000-bit operands are ~4817 decimal digits; Python 3.11+ caps int<->str at
# 4300 by default, which is a limit of the oracle's front door, not of its
# arithmetic.
sys.set_int_max_str_digits(1000000)

# BIGINT may carry arguments, so that the whole suite can be run under a
# wrapper: BIGINT="valgrind --quiet ./bigint" is how test-valgrind works.
# A bare string would be execed as one filename with spaces in it.
BIN = shlex.split(os.environ.get("BIGINT", "./bigint"))
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



# ---------------------------------------------------------------------------
# Fuzz case class: values sitting exactly on a limb boundary.
#
# A uniformly random 64-bit value is nowhere near 2^64, and the limb-count
# and carry logic only changes behaviour within one of a boundary. These are
# the values where "did this need an extra limb" is decided.
EDGES = sorted({2**k + d
                for k in (1, 15, 16, 31, 32, 33, 63, 64, 65, 95, 96, 127,
                          128, 159, 160, 255, 256, 511, 512, 1023, 1024,
                          15999, 16000, 16001)
                for d in (-1, 0, 1)})


# ---------------------------------------------------------------------------
# Fuzz case class: carry and borrow chains that run the whole number.
#
# 999...9 + 1 propagates a carry through every limb and then grows by one.
# 1000...0 - 1 borrows through every limb and then shrinks. All-ones in binary
# (2^b - 1) is the same thing at limb granularity: every limb is 0xffffffff,
# so every single-limb addition carries.
CHAINS = sorted({v for k in (1, 2, 3, 9, 10, 19, 20, 21, 30, 100, 300,
                             1000, 2000, 4800)
                 for v in (10**k - 1, 10**k)} |
                {2**b - 1 for b in (32, 64, 96, 128, 256, 1024, 4096, 16000)})


def from_bucket(rnd, bucket):
    lo, hi = bucket
    bits = rnd.randint(lo, hi)
    if bits <= 0:
        return 0
    return rnd.getrandbits(bits) | (1 << (bits - 1))


def signed(rnd, v):
    return -v if v and rnd.random() < 0.5 else v


def rand_val(rnd):
    if rnd.random() < 0.18:
        return signed(rnd, rnd.choice(EDGES))
    return signed(rnd, from_bucket(rnd, rnd.choices(BUCKETS, WEIGHTS)[0]))


def rand_pair(rnd):
    """Two operands, deliberately mismatched in magnitude a third of the time.

    Picking both buckets independently makes a 1-limb-against-500-limb pair
    roughly a 1-in-120 event, and that pair is exactly where a loop bound
    written in terms of the wrong operand's limb count shows up. So a third
    of pairs are forced to opposite ends of the bucket list, in both orders.
    """
    if rnd.random() < 0.30:
        lo = from_bucket(rnd, rnd.choice(BUCKETS[:4]))
        hi = from_bucket(rnd, rnd.choice(BUCKETS[-2:]))
        pair = [signed(rnd, lo), signed(rnd, hi)]
        if rnd.random() < 0.5:
            pair.reverse()
        return pair
    if rnd.random() < 0.12:
        # Both operands on limb boundaries, so their sum or difference lands
        # on one too: (2^64 - 1) + 1, 2^64 - (2^64 - 1), and so on.
        return [signed(rnd, rnd.choice(EDGES)), signed(rnd, rnd.choice(EDGES))]
    if rnd.random() < 0.15:
        # A full-length carry or borrow chain against a tiny operand, which
        # is the arrangement that makes the chain actually propagate.
        pair = [signed(rnd, rnd.choice(CHAINS)),
                signed(rnd, rnd.randint(1, 3))]
        if rnd.random() < 0.4:
            pair.reverse()
        return pair


    return [rand_val(rnd), rand_val(rnd)]


def rand_shift(rnd):
    r = rnd.random()
    if r < 0.20:
        return rnd.choice(SHIFT_EDGES)
    if r < 0.85:
        return rnd.randint(0, 2500)
    if r < 0.93:
        return -rnd.randint(1, 1000)            # must be rejected
    return rnd.choice([MAX_BITS, MAX_BITS + 1, 2**70, 10**30])


def oper(s):
    """One operand, decimal or hex.

    A "hex:" marker means hex, for any operation, matching the driver. The
    marker rather than a bare 0x prefix: "dec 0x10" is a corpus case
    asserting the DECIMAL parser rejects a hex literal, and reading 0x as
    hex everywhere would turn that assertion into its opposite.
    """
    neg = s[:1] == "-"
    t = s[1:] if s[:1] in "+-" else s
    if t[:4] == "hex:":
        return int(("-" if neg else "") + t[4:], 16)
    return int(s)


def as_hex(s):
    """The same operand written for the hex path, or None if it will not go.

    Leading zeros and a stray sign are the decimal parser's business, so
    anything that is not a plain integer is left to it alone.
    """
    try:
        v = int(s)
    except ValueError:
        return None
    return ("-" if v < 0 else "") + "hex:" + format(abs(v), "x")


def hex_twin(cases):
    """For each case, the same case with every operand in hex.

    The result must be identical, which is the whole point: the arithmetic
    is unchanged and only the input path differs, so a disagreement
    between the two is a parser bug and nothing else. Ops whose operand is
    already a hex literal, or whose purpose is to test one parser, are
    left alone.
    """
    out = []
    for op, args in cases:
        if op in ("unhex", "dec", "hex", "hexrt"):
            continue
        twins = [as_hex(a) for a in args]
        if any(t is None for t in twins):
            continue
        out.append((op, twins))
    return out


def ev(op, args):
    """The oracle. Returns the exact line bigint is expected to print."""
    if len(args) != ARITY[op]:
        # The driver reports an operand-count mismatch as a parse error,
        # which is also what Python says about int("") -- the line protocol
        # cannot carry an empty or space-containing operand.
        return "E parse"
    try:
        if op == "unhex":
            return str(int(args[0], 16))
        vals = [oper(s) for s in args]
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
    if op in ("mul", "mulsb", "mulk"):
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
    if op in ("powm", "powmc"):
        x, e, m = vals
        # Python checks the modulus before the exponent and so does bigint:
        # pow(2, -1, 0) is the 3rd-argument ValueError, not the negative
        # exponent one.
        if m == 0:
            return "E divzero"
        if e < 0:
            # bigint refuses, where Python returns a modular inverse when the
            # base is invertible and raises when it is not. A deviation, and
            # modelled here so it stays tested.
            return "E negpow"
        v = pow(x, e, m)
        if op == "powm":
            return str(v)
        # powmc also prints the loop's work, which is fixed by the exponent
        # alone: one squaring per bit, one multiplication per set bit.
        return "%d %d %d" % (v, e.bit_length(), bin(e).count("1"))
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
    if op == "gcd":
        # math.gcd drops both signs and answers 0 for gcd(0, 0).
        return str(math.gcd(vals[0], vals[1]))
    if op == "isqrt":
        # math.isqrt raises ValueError on a negative operand, and bigint
        # refuses with BI_ENEGSQRT, so the two agree that there is no answer
        # rather than agreeing on a value. Modelled here, in the same shape
        # as negpow above, so the refusal stays compared rather than being
        # excluded from the generator and quietly untested.
        if vals[0] < 0:
            return "E negsqrt"
        return str(math.isqrt(vals[0]))
    if op == "abs":
        return str(abs(vals[0]))
    if op == "cmp":
        x, y = vals
        return str((x > y) - (x < y))
    raise AssertionError("unknown op " + op)


ARITY = {"dec": 1, "neg": 1, "abs": 1, "cmp": 2, "add": 2, "sub": 2,
         "mul": 2, "mulsb": 2, "mulk": 2, "divf": 2, "mod": 2, "divmod": 2,
         "shl": 2, "shr": 2, "and": 2, "or": 2, "xor": 2,
         "hex": 1, "hexrt": 1, "unhex": 1, "pow": 2,
         "powm": 3, "powmc": 3, "gcd": 2, "isqrt": 1}
# mulsb and mulk are not picked directly: every "mul" case is emitted three
# times, once per multiplication path, on identical operands.
#
# powm is not picked directly either: a random draw emits powmc instead,
# which is the same function printing the squaring and multiplication counts
# after the value. One case then checks the answer AND that the
# square-and-multiply loop ran, and modular exponentiation is too expensive
# to run twice for that. powm itself is covered by the corpus and the sign
# matrix.
OPS = [o for o in ARITY if o not in ("mulsb", "mulk", "powm")]


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


# Modular exponentiation costs one squaring per bit of the exponent, each
# one quadratic in the limb count of the modulus, so an unguarded draw from
# the magnitude buckets puts a single case into the minutes: a 16000-bit
# exponent against a 16000-bit modulus is 16000 squarings of 500 limbs.
# POWM_BUDGET caps bits(e) * limbs(m)^2 and keeps a random case in the low
# milliseconds. The sizes real use has, 2048 and 4096 bits, are in the
# corpus instead, where there are a fixed few of them rather than one in
# every draw.
POWM_BUDGET = 500000

# Moduli that random sampling would hardly ever produce and that each rule
# out a different shortcut: 1 and -1 make every answer 0, an even modulus
# is the one Montgomery multiplication cannot take, and the rest sit on or
# beside a limb boundary.
POWM_MODULI = [1, -1, 2, -2, 3, 4, 10, 2**32 - 1, 2**32, 2**32 + 1,
               2**64 - 1, 2**64, 2**64 + 1, 2**31, 2**128 - 1, 2**128]


def rand_powm(rnd):
    """(base, exponent, modulus) for one powm case."""
    r = rnd.random()
    if r < 0.20:
        m = signed(rnd, rnd.choice(POWM_MODULI))
    elif r < 0.26:
        m = 0                                   # must be refused
    else:
        m = signed(rnd, from_bucket(rnd, rnd.choices(BUCKETS[1:6],
                                                     WEIGHTS[1:6])[0]))

    # The base has to be reduced before the loop starts, so the cases that
    # matter are the ones where it is not already a residue: larger than the
    # modulus, an exact multiple of it, negative, or zero.
    r = rnd.random()
    if r < 0.10:
        a = 0
    elif r < 0.18 and m:
        a = m * rnd.randint(1, 5)                      # residue 0
    elif r < 0.26 and m:
        a = signed(rnd, abs(m) + rnd.randint(0, 2))    # just past the modulus
    else:
        a = rand_val(rnd)

    r = rnd.random()
    if r < 0.10:
        e = rnd.choice([0, 1, 2, 3])
    elif r < 0.18:
        e = -rnd.randint(1, 10**20)                    # must be refused
    else:
        limbs = max(1, (abs(m).bit_length() + 31) // 32)
        k = rnd.randint(1, max(1, min(16000, POWM_BUDGET // (limbs * limbs))))
        shape = rnd.random()
        if shape < 0.15:
            e = (1 << k) - 1        # every bit set: the most work
        elif shape < 0.30:
            e = 1 << (k - 1)        # one bit set: the least
        elif shape < 0.38:
            e = 65537               # the exponent most RSA keys use
        else:
            e = rnd.getrandbits(k) | (1 << (k - 1))
    return a, e, m


def gen(rnd):
    """One draw, one or more cases."""
    op = rnd.choice(OPS)
    if op == "pow":
        x = rand_val(rnd)
        cases = [(op, [str(x), str(rand_pow_exp(rnd, x))])]
        return cases + hex_twin(cases) if rnd.random() < 0.25 else cases
    if op in ("shl", "shr"):
        cases = [(op, [str(rand_val(rnd)), str(rand_shift(rnd))])]
        return cases + hex_twin(cases) if rnd.random() < 0.25 else cases
    if op == "powmc":
        cases = [(op, [str(v) for v in rand_powm(rnd)])]
        return cases + hex_twin(cases) if rnd.random() < 0.25 else cases
    if op == "unhex":
        return [(op, [rand_hexlit(rnd)])]
    if op == "mul":
        # All three multiplication paths on the same operands. Python is the
        # oracle for each, which also makes the schoolbook and Karatsuba
        # implementations oracles for each other.
        args = [str(v) for v in rand_pair(rnd)]
        cases = [("mul", args), ("mulsb", args), ("mulk", args)]
        if rnd.random() < 0.25:
            cases = cases + hex_twin(cases)
        return cases
    if ARITY[op] == 2:
        cases = [(op, [str(v) for v in rand_pair(rnd)])]
    else:
        cases = [(op, [str(rand_val(rnd))])]
    # A quarter of draws go through the hex parser as well as the decimal
    # one, on the same operands and against the same oracle value.
    if rnd.random() < 0.25:
        cases = cases + hex_twin(cases)
    return cases



# Moduli at the sizes modular exponentiation is actually used at, each the
# product of two factors half its width, which is the shape of an RSA
# modulus. Nothing here depends on either factor being prime and nothing
# claims they are; the oracle computes whatever the right answer is.
M2048 = (2**1024 - 105) * (2**1024 - 2027)
M4096 = (2**2048 - 1557) * (2**2048 - 361)

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

    # --- three-argument pow -------------------------------------------
    # Python's pow(a, e, m) is exact for every one of these, so each line
    # below is a byte-for-byte comparison rather than an approximation.
    # What they cover is the inputs a random draw reaches rarely or never.
    #
    # A modulus of 1 or -1: every answer is 0, pow(0, 0, 1) included. No
    # special case in the library produces that, it falls out of 1 mod 1.
    ("powm", ["0", "0", "1"]), ("powm", ["5", "3", "1"]),
    ("powm", ["-5", "3", "1"]), ("powm", ["0", "0", "-1"]),
    ("powm", ["5", "3", "-1"]), ("powmc", ["7", "255", "1"]),
    ("powm", [str(2**16000 - 1), "255", "1"]),
    # An exponent of 0 or 1, where the answer is a reduction and not an
    # exponentiation. 1 mod m is not always 1: it is 0 for a modulus of 1
    # and negative for a negative modulus.
    ("powm", ["5", "0", "7"]), ("powm", ["5", "0", "-7"]),
    ("powm", ["5", "1", "7"]), ("powm", ["5", "1", "-7"]),
    ("powm", ["0", "0", "7"]), ("powm", ["0", "1", "7"]),
    ("powm", ["7", "1", "7"]), ("powm", ["-5", "0", "7"]),
    ("powm", ["-5", "1", "7"]), ("powmc", ["5", "0", "7"]),
    ("powmc", ["5", "1", "7"]),
    # An even modulus, which is the one Montgomery multiplication cannot
    # take, and a power of two, where reduction is a mask.
    ("powm", ["3", "100", "4"]), ("powm", ["3", "100", "1000"]),
    ("powm", ["3", "100", str(2**32)]), ("powm", ["3", "100", str(2**64)]),
    ("powm", [str(2**64 + 1), "1000", str(2**128)]),
    ("powm", ["3", "1000", str(2**1024)]),
    # A modulus of one limb, and one either side of a limb boundary.
    ("powm", ["7", "1000", "2"]), ("powm", ["7", "1000", "3"]),
    ("powm", ["7", "1000", "4294967295"]),
    ("powm", ["7", "1000", "4294967296"]),
    ("powm", ["7", "1000", "4294967297"]),
    ("powm", ["7", "1000", str(2**64 - 1)]),
    ("powm", ["7", "1000", str(2**64)]),
    ("powm", ["7", "1000", str(2**64 + 1)]),
    ("powm", ["7", "1000", str(2**96 + 1)]),
    # A base of 0, a base that is an exact multiple of the modulus, and a
    # base far wider than it: the reduction has to happen before the loop,
    # not after it.
    ("powm", ["0", "1000", "7"]), ("powm", ["0", "0", "7"]),
    ("powm", ["49", "1000", "7"]), ("powm", ["-49", "1001", "7"]),
    ("powm", [str(10**500), "1000", "7"]),
    ("powm", [str(-(10**500)), "1001", "7"]),
    ("powm", [str(2**16000 - 1), "3", str(2**32 + 1)]),
    ("powm", [str(2**16000 - 1), "3", str(2**16000 - 1)]),
    # Both signs of the base against both signs of the modulus, at both
    # exponent parities. The result takes the sign of the modulus because
    # Python's % does, which is the same rule bi_divmod already follows.
    ("powm", ["-3", "3", "7"]), ("powm", ["-3", "4", "7"]),
    ("powm", ["-3", "3", "-7"]), ("powm", ["-3", "4", "-7"]),
    ("powm", ["3", "3", "-7"]), ("powm", ["3", "4", "-7"]),
    ("powm", ["-1", "1", "-7"]), ("powm", ["-7", "1", "-7"]),
    # Refusals. The modulus is checked before the exponent, in Python too:
    # pow(2, -1, 0) is the 3rd-argument error and not the exponent one.
    ("powm", ["2", "3", "0"]), ("powm", ["0", "0", "0"]),
    ("powm", ["-2", "3", "0"]), ("powm", ["2", "-1", "0"]),
    # A negative exponent is refused whether or not the base is invertible.
    # Python inverts the first and raises on the second; bigint refuses
    # both, which is a deviation and is why it is pinned here.
    ("powm", ["2", "-1", "5"]), ("powm", ["2", "-1", "4"]),
    ("powm", ["2", str(-(10**30)), "7"]), ("powmc", ["2", "-1", "5"]),
    # The line protocol, on the operand the other ops do not have.
    ("powm", ["2", "3", "1x"]), ("powm", ["2", "3", "0x10"]),
    ("powm", ["2", "3"]),
    # The counts powmc prints are the exponent's bit length and popcount,
    # so an exponent of a known shape pins them exactly: all bits set, one
    # bit set, and the 17-bit 2-bit exponent most RSA keys use.
    ("powmc", ["3", str(2**64 - 1), "1000000007"]),
    ("powmc", ["3", str(2**64), "1000000007"]),
    ("powmc", ["3", "65537", "1000000007"]),
    ("powmc", ["3", "0", "1000000007"]), ("powmc", ["3", "1", "7"]),
    ("powmc", [str(M2048 - 3), "65537", str(M2048)]),
    # --- isqrt --------------------------------------------------------
    # The exact answer is floor(sqrt(a)), so every case here is checked
    # against math.isqrt rather than against a tolerance. The interesting
    # inputs are the ones either side of a perfect square, because an
    # iteration that stops one step early or late is right on the square
    # and wrong on its neighbours.
    # The refusal, which is the only answer that is not a lie: there is no
    # integer whose square is negative, and Python raises rather than
    # returning one.
    ("isqrt", ["-1"]), ("isqrt", ["-4"]), ("isqrt", [str(-(2**4096))]),
    ("isqrt", ["0"]), ("isqrt", ["1"]), ("isqrt", ["2"]), ("isqrt", ["3"]),
    ("isqrt", ["4"]), ("isqrt", ["8"]), ("isqrt", ["9"]), ("isqrt", ["10"]),
    ("isqrt", ["15"]), ("isqrt", ["16"]), ("isqrt", ["17"]),
    ("isqrt", ["24"]), ("isqrt", ["25"]), ("isqrt", ["26"]),
    # A perfect square and its two neighbours at a limb boundary, where the
    # first guess 2^ceil(bits/2) is itself the answer or one off it.
    ("isqrt", [str(2**64)]), ("isqrt", [str(2**64 - 1)]),
    ("isqrt", [str(2**64 + 1)]), ("isqrt", [str(2**32)]),
    ("isqrt", [str((2**32) ** 2)]), ("isqrt", [str((2**32) ** 2 - 1)]),
    ("isqrt", [str((2**32) ** 2 + 1)]),
    # An odd and an even bit length, which pick different first guesses.
    ("isqrt", [str(2**101)]), ("isqrt", [str(2**100)]),
    # Large, where the answer is itself many limbs: a 4096-bit operand has
    # a 2048-bit root, and the two squares either side of it.
    ("isqrt", [str(2**4096)]), ("isqrt", [str(2**4096 - 1)]),
    ("isqrt", [str((2**2048 - 1) ** 2)]),
    ("isqrt", [str((2**2048 - 1) ** 2 - 1)]),
    ("isqrt", [str((2**2048 - 1) ** 2 + 1)]),
    # A long run of ones and a value just under a perfect square, both of
    # which make the iteration take its maximum number of steps.
    ("isqrt", [str(2**8000 - 1)]), ("isqrt", [str((2**1000 + 12345) ** 2 - 1)]),

    # --- gcd ----------------------------------------------------------
    # Zero on either side, where the answer is the other operand's
    # magnitude, and gcd(0, 0), which math.gcd answers 0 rather than
    # refusing.
    ("gcd", ["0", "0"]), ("gcd", ["0", "7"]), ("gcd", ["7", "0"]),
    ("gcd", ["0", "-7"]), ("gcd", ["-7", "0"]), ("gcd", ["-0", "0"]),
    # Both signs, because math.gcd drops them and a sign-magnitude
    # implementation could easily carry one through.
    ("gcd", ["12", "18"]), ("gcd", ["-12", "18"]), ("gcd", ["12", "-18"]),
    ("gcd", ["-12", "-18"]), ("gcd", ["-1", "-1"]),
    # Equal operands, one dividing the other, and coprime pairs.
    ("gcd", ["7", "7"]), ("gcd", ["-7", "7"]), ("gcd", ["6", "36"]),
    ("gcd", ["36", "6"]), ("gcd", ["17", "19"]), ("gcd", ["1", "1"]),
    ("gcd", ["1", str(2**16000 - 1)]), ("gcd", [str(2**16000 - 1), "1"]),
    # Powers of two on both sides, which is the path that pulls out the
    # shared twos and then has nothing left to do. Also one even against
    # one odd, where only one side shifts.
    ("gcd", [str(2**100), str(2**60)]), ("gcd", [str(2**60), str(2**100)]),
    ("gcd", [str(2**100), str(3 * 2**60)]), ("gcd", [str(2**64), "1"]),
    ("gcd", [str(2**4096), str(2**4096)]), ("gcd", [str(2**1000), "6"]),
    ("gcd", ["1024", "768"]), ("gcd", [str(2**32), str(2**32 - 1)]),
    ("gcd", [str(2**32 - 1), str(2**32)]),
    # 2^a - 1 and 2^b - 1 have gcd 2^gcd(a,b) - 1, so these have answers
    # that are themselves many limbs long rather than small.
    ("gcd", [str(2**16000 - 1), str(2**8000 - 1)]),
    ("gcd", [str(2**16000 - 1), str(2**15999 - 1)]),
    ("gcd", [str(2**4096 - 1), str(2**2048 - 1)]),
    # Consecutive Fibonacci numbers are Euclid's worst case and a long run
    # of single-bit steps for binary GCD too.
    ("gcd", ["514229", "832040"]), ("gcd", ["832040", "514229"]),
    ("gcd", [str(10**500), str(2**1000)]),
    ("gcd", [str(10**500 + 1), str(10**500)]),
    ("gcd", [str(-(10**500)), str(2**1000)]),
    # 2048 and 4096 bits, which is what this operation is for. The
    # all-bits-set exponent is the worst case for the loop and the reason
    # the running time leaks the exponent; see the README.
    ("powm", ["7", "65537", str(M2048)]),
    ("powm", [str(M2048 - 3), str(2**2048 - 1), str(M2048)]),
    ("powm", [str(M2048 + 7), str(M2048 // 3), str(M2048)]),
    ("powm", ["7", "65537", str(M4096)]),
    ("powm", [str(M4096 - 3), str(2**1024 - 1), str(M4096)]),
]


# ---------------------------------------------------------------------------
# Fuzz case class: every sign combination of every binary operation.
#
# Random generation gives each of the four combinations about a quarter of the
# cases, which is fine on average and no use at all when a specific
# combination of a specific operation is the broken one. This enumerates them.

SIGN_PAIRS = [(1, 1), (1, -1), (-1, 1), (-1, -1)]

MAG_PAIRS = [
    (3, 7),                          # both single-limb
    (7, 3),
    (4294967296, 4294967295),        # straddling a limb boundary
    (18446744073709551615, 3),       # 2 limbs against 1
    (10**100, 7),                    # 11 limbs against 1
    (1, 2**16000 - 1),               # 1 limb against 500
    (2**16000 - 1, 2**31 + 1),       # 500 limbs against 1
    (2**64, 2**32),                  # exact powers, exact division
    (2**128 - 1, 2**64 - 1),         # all-ones at both lengths
]

BIN_OPS = ["add", "sub", "mul", "mulsb", "mulk", "divf", "mod", "divmod",
           "and", "or", "xor", "cmp", "gcd"]



def sign_matrix():
    cases = []
    for op in BIN_OPS:
        for x, y in MAG_PAIRS:
            for sx, sy in SIGN_PAIRS:
                cases.append((op, [str(sx * x), str(sy * y)]))
    for op in ("shl", "shr"):
        for x, _ in MAG_PAIRS:
            for sx in (1, -1):
                for c in ("0", "1", "33", "64", "100", "-1"):
                    cases.append((op, [str(sx * x), c]))
    for x in (2, 3, 7, 10, 4294967295, 4294967296, 2**64 - 1):
        for sx in (1, -1):
            for e in ("0", "1", "2", "3", "17", "-1"):
                cases.append(("pow", [str(sx * x), e]))
    # Three-argument pow has a third sign to enumerate, and the result's
    # sign comes from the modulus rather than from the base.
    for x in (3, 7, 2**32 + 1, 2**64 - 1):
        for m in (7, 2**32, 2**64 + 1, 10**20):
            for sx in (1, -1):
                for sm in (1, -1):
                    for e in ("0", "1", "2", "17"):
                        cases.append(("powm",
                                      [str(sx * x), e, str(sm * m)]))
    return cases


# ---------------------------------------------------------------------------
# Fuzz case class: every pair of limb lengths, for all three multiply paths.
#
# Karatsuba's split is at half the shorter operand, so the behaviour depends
# on both lengths and on their parity, and unbalanced pairs are where a
# bignum multiply usually breaks. This enumerates the pairs rather than
# hoping to sample them, and runs each through schoolbook, Karatsuba and the
# dispatching bi_mul, so the two implementations are checked against each
# other on identical operands as well as against Python.

def limbs(rnd, n, dense):
    """An n-limb value whose top limb is either full (dense) or exactly 1.

    The top-limb style matters more than it looks. Forcing the top bit set,
    which is the obvious way to pin a limb count, makes every partial product
    wide -- so a Karatsuba term that is one limb short of what the code
    assumes can never occur, and a dropped z2 subtraction goes unnoticed. A
    top limb of 1 is the opposite extreme and makes those terms as short as
    they can be.
    """
    v = rnd.getrandbits(32 * n)
    if dense:
        return v | (1 << (32 * n - 1))
    return (v & ((1 << (32 * (n - 1))) - 1)) | (1 << (32 * (n - 1)))


def length_matrix(rnd):
    lens = list(range(1, 17)) + [95, 96, 97, 191, 192, 193]
    cases = []
    for na in lens:
        for nb in lens:
            if (na > 16 or nb > 16) and na != nb and {na, nb} != {96, 192}:
                continue            # keep the expensive corner small
            for da in (True, False):
                for db in (True, False):
                    a = limbs(rnd, na, da)
                    b = limbs(rnd, nb, db)
                    for sa, sb in ((1, 1), (1, -1)):
                        args = [str(sa * a), str(sb * b)]
                        for op in ("mul", "mulsb", "mulk"):
                            cases.append((op, args))
    return cases



# Operands a reducer must not shrink to zero, by operation and position.
# Dividing by zero disagrees for its own reasons, and so does a modulus of
# zero, so a reducer that wanders into either turns a real arithmetic bug
# into the trivial one and reports the wrong thing. This is the slippage a
# reducer has to be stopped from doing.
NONZERO_ARG = {"divf": {1}, "mod": {1}, "divmod": {1},
               "powm": {2}, "powmc": {2}}


BUDGET = 120


def minimise_one(v, test, budget):
    """Smallest magnitude at or below |v| that still satisfies test.

    The search is over the BIT LENGTH, not over the value. The first
    version binary-searched the value itself, which for a 16000-bit
    operand is 16000 probes, each one a process, and it hung rather than
    finished. Searching the length is 14 probes for the same operand.

    Monotone predicates land on a power of two, so a linear walk down
    from there finds the real boundary cheaply. A short candidate sweep
    follows for the predicates that are not monotone, where the search
    can step straight over the only failing value.

    budget is a mutable one-element list of probes remaining. A reducer
    with no budget is a reducer that hangs on the case you most want
    reduced.
    """
    sign = -1 if v < 0 else 1
    mag = abs(v)
    if mag == 0:
        return v

    def ok(m):
        if budget[0] <= 0:
            return False
        budget[0] -= 1
        return test(sign * m)

    # Fewest bits that still fails.
    lo, hi = 0, mag.bit_length()
    while lo < hi:
        mid = (lo + hi) // 2
        if ok(mag >> (mag.bit_length() - mid) if mid else 0):
            hi = mid
        else:
            lo = mid + 1
    best = mag
    cand = mag >> (mag.bit_length() - lo) if lo else 0
    if cand < best and ok(cand):
        best = cand

    # Walk down from there while it keeps failing. This halts at a
    # power-of-two boundary, so `floor` is the largest magnitude known NOT
    # to fail and `best` the smallest known to.
    floor = 0
    while best > 0 and budget[0] > 0:
        nxt = best // 2
        if nxt < best and ok(nxt):
            best = nxt
        else:
            floor = nxt
            break

    # Shapes before sizes, because shapes are cheap and bounded. Reducing
    # the magnitude alone cannot minimise a carry bug: "add 1 X" only
    # fails when X has its whole top limb set, and halving X clears that
    # bit, so every smaller value passes and the search stops holding
    # whatever large value it had. It stopped at 1207 digits for a case
    # whose minimal form is ten. All-ones and power-of-two values at each
    # limb boundary are where carry and borrow break.
    for bits in range(32, best.bit_length() + 1, 32):
        for c in ((1 << bits) - 1, 1 << bits, (1 << bits) + 1):
            if 0 <= c < best and ok(c):
                best = c
                floor = 0
                break
        if best.bit_length() <= bits:
            break

    for c in (0, 1, 2, 10, best - 1, mag // 10):
        if 0 <= c < best and ok(c):
            best = c

    # Then the real boundary, between the smallest failing value and the
    # largest passing one. Only when that gap is narrow: between two
    # 4000-bit numbers it is 4000 probes, which is how the first version
    # spent its whole budget here and never reached the shapes above.
    steps = 0
    while floor + 1 < best and budget[0] > 0 and steps < 24:
        mid = (floor + best) // 2
        if ok(mid):
            best = mid
        else:
            floor = mid
        steps += 1

    return sign * best


def shrink(args, pred, skip_zero=()):
    """Reduce each operand while pred still holds, to a fixpoint.

    Greedy and one operand at a time, which is enough here: the operands
    are independent magnitudes, so there is no pair that only fails
    together in a way a per-operand pass cannot reach.

    pred takes the full argument list. Everything returned has been
    checked against it, so a reduced case always still fails. What it does
    not promise is that it fails for the original reason, and that is why
    the caller prints the case it started from as well.
    """
    # oper(), not int(): a hex-twin case carries "hex:" operands, and the
    # first version of this called int() on them and died with a
    # ValueError that took the whole report down with it. Candidates go
    # back out in the spelling they came in with, so the reduced case
    # still runs through the same parser as the one that failed.
    cur = [oper(a) for a in args]
    ishex = [(a[1:] if a[:1] in "+-" else a)[:4] == "hex:" for a in args]

    def fmt(v, i):
        return as_hex(str(v)) if ishex[i] else str(v)

    budget = [BUDGET]
    moved = True
    while moved and budget[0] > 0:
        moved = False
        for i in range(len(cur)):
            def test(v, i=i):
                if v == 0 and i in skip_zero:
                    return False
                trial = list(cur)
                trial[i] = v
                return pred([fmt(x, j) for j, x in enumerate(trial)])
            got = minimise_one(cur[i], test, budget)
            if got != cur[i]:
                cur[i] = got
                moved = True
    out = [fmt(x, i) for i, x in enumerate(cur)]
    assert pred(out), "reducer returned a case that does not fail"
    return out


def disagrees(op, args):
    """The predicate the reducer runs against: does this one case fail?"""
    _, f = run_chunk([(op, list(args))])
    return bool(f)


def shrink_failure(op, args):
    """Reduce a failing case, or return it unchanged if it will not shrink."""
    skip = NONZERO_ARG.get(op, set())
    try:
        return shrink(args, lambda a: disagrees(op, a), skip_zero=skip)
    except AssertionError:
        return list(args)


def self_test():
    """Exercise the reducer without needing a broken bigint.

    The predicate is synthetic and monotone, so the answer is known
    exactly: the smallest first operand at or above 1000 is 1000. A
    reducer that merely gets smaller, which is the easy thing to write and
    the useless thing to have, lands somewhere above it and fails here.
    """
    ok = 0
    got = shrink(["987654321", "55555"], lambda a: int(a[0]) >= 1000)
    assert got[0] == "1000", got
    assert got[1] == "0", got
    ok += 1

    # Sign is part of the operand, so a reducer must not cross zero to
    # find something smaller in absolute terms.
    got = shrink(["-987654321", "1"], lambda a: int(a[0]) <= -1000)
    assert got[0] == "-1000", got
    ok += 1

    # The divisor guard: the predicate here is satisfied by a zero second
    # operand, and the reducer must refuse to go there anyway.
    got = shrink(["12345", "678"], lambda a: True, skip_zero={1})
    assert got[1] == "1", got
    ok += 1

    # A predicate that is not monotone: only one value fails, and the
    # binary search walks past it. The candidate sweep is what catches it.
    got = shrink(["10", "0"], lambda a: int(a[0]) in (10, 2))
    assert got[0] == "2", got
    ok += 1

    print("%d reducer self-tests passed, 0 failed" % ok)
    return 0


def run_chunk(cases):
    """cases: list of (op, args). Returns (agree, failures)."""
    lines = []
    for op, args in cases:
        lines.append(" ".join([op] + list(args)))
    inp = "\n".join(lines) + "\n"
    p = subprocess.run(BIN, input=inp, capture_output=True, text=True)
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
        # The whole tail, not 400 characters of it. Under valgrind this is
        # the report, and a tail cut mid-word drops the line that names
        # what went wrong: the first version of this printed "llocation".
        failures.append(("<driver exit %d>" % p.returncode, "",
                         p.stderr[-4000:]))
    return agree, failures


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return self_test()
    iters = int(sys.argv[1]) if len(sys.argv) > 1 else 100000
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    rnd = random.Random(seed)

    agree = disagree = 0
    failures = []

    # The fixed corpus first: boundaries, degenerate inputs, past regressions.
    for name, batch in (("corpus", CORPUS), ("signs", sign_matrix()),
                        ("lengths", length_matrix(rnd))):

        a, f = run_chunk(batch)
        agree += a
        disagree += len(f)
        failures += [(name,) + x for x in f]


    done = 0
    while done < iters:
        k = min(CHUNK, iters - done)
        cases = []
        while len(cases) < k:
            cases.extend(gen(rnd))
        a, f = run_chunk(cases)
        agree += a
        disagree += len(f)
        failures += [("seed=%d case=%d" % (seed, done + j),) + x
                     for j, x in enumerate(f)]
        done += k

    print("%d agree, %d disagree" % (agree, disagree))
    # A dead driver outranks any wrong answer, and only the first 20
    # failures are printed: a mutation that made the driver take SIGFPE
    # 181 lines into a chunk filled those 20 with the knock-on
    # comparisons and never mentioned the signal at all.
    failures.sort(key=lambda f: not f[1].startswith("<driver exit"))
    for where, line, want, have in failures[:20]:
        if line.startswith("<driver exit"):
            # Not a wrong answer but a dead driver, so the want/got shape
            # does not fit it. Print what the driver said instead.
            print("  %s\n    %s" % (where, line))
            for ln in have.rstrip().split("\n")[-25:]:
                print("      %s" % ln)
            continue
        print("  %s\n    in:   %s\n    want: %s\n    got:  %s"
              % (where, line[:200], want[:200], have[:200]))
        # A 500-limb operand is 4800 digits, which is why the line above
        # is truncated and why that truncation makes it useless. Reduce
        # the case and print the small one underneath.
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ARITY and parts[0] != "unhex":
            small = shrink_failure(parts[0], parts[1:])
            if small != parts[1:]:
                line2 = " ".join([parts[0]] + small)
                print("    reduced from %d characters to %d:"
                      % (len(line), len(line2)))
                print("      in:   %s" % line2)
                print("      want: %s" % ev(parts[0], small)[:200])
                print("      got:  %s" % (run_chunk([(parts[0], small)])[1]
                                          or [("", "", "?")])[0][-1][:200])
                print("    still fails, though not necessarily for the "
                      "original reason: the line above is the one to trust.")
    if len(failures) > 20:
        print("  ... and %d more" % (len(failures) - 20))
    if disagree:
        print("  failing seed: %d" % seed)
    return 1 if disagree else 0


if __name__ == "__main__":
    sys.exit(main())
