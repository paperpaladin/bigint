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
    raise AssertionError("unknown op " + op)


OPS = ["dec", "neg"]


def gen(rnd):
    op = rnd.choice(OPS)
    return op, [str(rand_val(rnd))]


CORPUS = [
    ("dec", ["0"]), ("dec", ["-0"]), ("dec", ["+0"]), ("dec", ["7"]),
    ("dec", ["-7"]), ("dec", ["0000123"]), ("dec", ["4294967295"]),
    ("dec", ["4294967296"]), ("dec", ["18446744073709551615"]),
    ("dec", ["18446744073709551616"]), ("dec", ["-18446744073709551617"]),
    ("dec", ["9" * 300]), ("dec", ["-" + "9" * 300]),
    ("dec", [""]), ("dec", ["-"]), ("dec", ["12x"]), ("dec", ["0x10"]),
    ("neg", ["0"]), ("neg", ["-1"]),
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
    iters = int(sys.argv[1]) if len(sys.argv) > 1 else 200000
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
