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


def ev(op, args):
    """The oracle. Returns the exact line bigint is expected to print."""
    try:
        if op == "unhex":
            return str(int(args[0], 16))
        vals = [int(s) for s in args]
    except ValueError:
        return "E parse"

    if op == "dec":
        return str(vals[0])
    if op == "neg":
        return str(-vals[0])
    if op == "add":
        return str(vals[0] + vals[1])
    if op == "sub":
        return str(vals[0] - vals[1])
    if op == "abs":
        return str(abs(vals[0]))
    if op == "cmp":
        x, y = vals
        return str((x > y) - (x < y))
    raise AssertionError("unknown op " + op)


ARITY = {"dec": 1, "neg": 1, "abs": 1, "cmp": 2, "add": 2, "sub": 2}
OPS = list(ARITY)


def gen(rnd):
    op = rnd.choice(OPS)
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
