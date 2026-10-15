# bigint

Arbitrary-precision signed integers in one C11 file, measured against Python's
native `int` on millions of cases.

```
$ make test
107571 agree, 0 disagree

$ make test-asan
22571 agree, 0 disagree
```

Across 68 seeds at 100k cases each: **7,314,868 agree, 0 disagree**, with
operand magnitudes from 0 bits to 16,000 bits (500 limbs).


Python's `int` is arbitrary-precision and is the reference implementation for
every operation here, so a differential fuzzer can check millions of cases
with no ambiguity at all about what the right answer is. That is the whole
design: there is no hand-computed expected value anywhere in this repository.

## Python's division semantics, not C's

This is the single most common source of disagreement between bignum
libraries, so it gets its own section.

**C truncates toward zero. Python floors toward negative infinity. This
library follows Python.**

```
                C          Python / bigint
  -7 /  2      -3               -4
  -7 %  2      -1                1
   7 / -2      -3               -4
   7 % -2       1               -1
```

The rule is `a == q*b + r` with `0 <= |r| < |b|` and `r` carrying the sign of
the divisor. A remainder is never negative when the divisor is positive.

Python is the oracle, so Python's rule wins; overruling your oracle on the one
operation where implementations disagree would make the whole exercise
pointless. If you want C's behaviour, `bi_divmod` is not the function you
want, and there is no flag to change it.

The same choice applies to the right shift (`-1 >> 1` is `-1`, not `0`, and it
stays `-1` however far you shift) and to the bitwise operations, which act on
Python's infinite two's-complement model (`-1 & 5` is `5`, `-1 | 0` is `-1`).

## Build and run

```
make            # ./bigint
make test       # the differential fuzzer; prints "N agree, M disagree"
make test-asan  # the same under ASan + UBSan, fewer cases
make bench      # where Karatsuba starts paying, measured
make clean
```

`t/run.sh [CASES] [SEED]` is the test entry point and takes both as
arguments, so `t/run.sh 2000000 17` is a two-million-case run on seed 17. A
disagreement prints the operation, the operands, Python's answer, bigint's
answer, and the failing seed.

It then prints the case again, reduced. Operands here run to 16000 bits,
which is 4817 decimal digits, and a failure printed at that width is not
something anybody reads. The reducer shrinks each operand while the case
still fails: against a planted mutant that drops the final carry limb of
`uadd`, a 4823-character case comes out as `add 1 4294967295`, which is
the exact boundary of that bug.

Two things it does not claim. A reduced case still fails, by
construction, and may fail for a different reason than the one you
started with, so the original line is printed too and is the one to
trust. And it will not reduce a divisor to zero, because division by zero
disagrees for its own reasons and a reducer that wanders into it reports
the wrong bug.

The reducer has four self-tests of its own, run by `make test` before the
fuzzer. They use synthetic predicates whose answers are known exactly,
which is the only way to check a reducer without a broken bigint to hand:
a monotone predicate must reduce to 1000 and not merely to something
under it, sign must not be crossed, a predicate with a single failing
value must still be found, and the divisor guard must hold.

A quarter of generated draws run twice, once with decimal operands and
once with the same values written in hex, marked `hex:`, against the same
oracle answer. Every case otherwise rests on `bi_set_dec` being right, and
a parse bug that is symmetric with a format bug cancels out and leaves the
run green. 14.8% of cases take the hex path.

What that buys is visible with a planted bug. A decimal parser that drops
the last digit past 40 digits makes 1107 of 2515 decimal cases disagree
while all 485 hex twins pass, so the failure says "parser" instead of
looking like a thousand broken arithmetic results. The carry mutant in
`uadd` fails on both paths, 40 of 2515 and 9 of 485, which is the check
that says the twins are sensitive rather than agreeing with themselves.

The marker is `hex:` and not a bare `0x` prefix. `dec 0x10` is a corpus
case asserting that the decimal parser rejects a hex literal, and the
first version of this read `0x` as hex everywhere, which turned that
assertion into its opposite and stayed green.

`bigint` itself reads one operation per stdin line and writes one result line,
which is how the fuzzer spends a single process on millions of cases instead
of a million processes:

```
$ printf 'divmod -7 2\npow 2 64\nhex -255\nand -1 5\n' | ./bigint
-4 1
18446744073709551616
-0xff
5
```

Errors are reported as `E <reason>` on stdout and do not stop the stream:
`E parse`, `E divzero`, `E negshift`, `E negpow`, `E toobig`.

`bigint.h` is the library API. It is worth having separately here because the
arithmetic is genuinely reusable and the line-protocol driver is not.

## How it works

Sign-magnitude: a little-endian array of 32-bit limbs plus a sign of -1, 0 or
+1, always normalised.

32-bit limbs, not 64. Every intermediate product then fits a `uint64_t`
exactly: `ai*bj + r + carry` peaks at `(2^32-1)^2 + 2*(2^32-1) = 2^64 - 1`,
with nothing to spare, and that is what makes Knuth algorithm D writable in
portable C11 with no `__int128` and no inline assembly. The cost is roughly
half the throughput of a 64-bit-limb implementation. Marked `shortcut:` in the
source with the upgrade path.

Multiplication is schoolbook below 96 limbs and Karatsuba above. Division is
Knuth algorithm D in the `divmnu` form from Hacker's Delight. Hex conversion
is limb-aligned and linear. Decimal conversion is quadratic in both
directions.

### The invariant the oracle cannot see

Every `bi` is normalised: no leading zero limbs, `sign == 0` exactly when the
value is zero. Python cannot check this. `bi_to_dec` divides the value down by
10^9 and simply never looks at leading zero limbs, so an **untrimmed result
prints identically to a trimmed one** and a million-case differential run
reports zero disagreements. The only observer is `bi_cmp`, which compares limb
counts first, so the bug sits there silently until some unrelated comparison
starts returning the wrong answer.

So the driver asserts it directly, on every result of every case, and prints
`E unnormalised` if it is violated. Deleting the trim loop out of `norm()`
makes `10^500 - (10^500 - 1)` report `E unnormalised` instead of `1`; a plain
decimal comparison calls that same case a pass.

## The oracle

`t/fuzz.py` generates cases, computes the answer with Python, feeds them all
through one `bigint` process, and compares the output lines. Operand
magnitudes are drawn from buckets spanning 0 bits to 16000 bits (500 limbs).

Beyond uniform random, these case classes run on every invocation, because
each one covers something that breaks real bignum libraries and that random
sampling covers badly:

| class | why random sampling is not enough |
| --- | --- |
| every sign combination of every binary op, enumerated | random signs give each combination a quarter of the cases, which tells you nothing about which quarter covered which operation |
| operands of mismatched magnitude, forced for 30% of pairs | with buckets chosen independently, 1 limb against 500 limbs is a 1-in-120 event, and it is exactly where a loop bound written against the wrong operand goes wrong |
| values on the limb boundaries: 2^k - 1, 2^k, 2^k + 1 | a uniformly random 64-bit value is nowhere near 2^64, and nothing changes behaviour except within one of a boundary |
| carry and borrow chains: 999...9 against 1, 10^k against 1, 2^b - 1 | a chain value against another big number does not propagate anything; the carry dies in the first few limbs |
| every pair of limb lengths 1x1 to 16x16, plus the cutoff straddles, through all three multiply paths | Karatsuba splits at half the shorter operand, so behaviour depends on both lengths and their parity |
| hex round trip over 2^k - 1 for every k in 0..299 | a nibble or limb indexing error that shows up at one length in eight has nowhere to hide in 300 consecutive lengths |
| division by zero in every operand sign, and all twelve sign/op combinations of 7 and 2 | must error instead of crashing, and the floor correction must be conditional on a nonzero remainder |

Plus a fixed corpus of degenerate inputs: empty and malformed literals, `-0`,
`0 ** 0`, `0 << 10^30`, `1 ** 10^30`, exact quotients with mixed signs.

### The fuzzer has been watched failing

A suite that passes because it is quietly doing nothing is the failure mode
that matters, so each check was confirmed to fail before being trusted:

- Deleting the trim loop from `norm()`: `E unnormalised` on the subtraction
  cases, which the decimal comparison alone passes.
- Disabling the floor correction in `bi_divmod`, which turns the library into
  C semantics: `1120 agree, 43 disagree`, naming `divmod -7 2` wanting `-4 1`
  and getting `-3 -1`.
- Deleting Karatsuba's `z1 -= z2` step when `z2` is a single limb:
  `6591 agree, 980 disagree`, naming `mulk 14569622272581922214 6221450333`.

That last one is why the limb-length matrix generates each operand twice, once
with a full top limb and once with a top limb of exactly 1.

## Writing this found two real bugs

`bi_to_dec` wrote 20 bytes into a 14-byte buffer. It sized the buffer at
10 bytes per limb, which is correct for the digits, but the 10^9 chunk loop
emits 9 digits whether or not they are significant, so a 1-limb value
overflowed. glibc caught it as `corrupted size vs. prev_size` on the very
first corpus case of the very first run.

`umul_school` never normalised its own result, so a 1-limb-by-1-limb
product came back with `n == 2` and a leading zero limb. Every public caller
normalises afterwards, so this was invisible from outside the library and the
oracle had nothing to complain about, and it was found only because it
silently disarmed the Karatsuba fault injection above, by making `z2` never a
single limb. The fix is one `norm()` call. What is interesting is that six million agreeing cases had not noticed.

## Karatsuba, measured

Both paths are kept. `bi_mul` dispatches on size, `bi_mul_school` forces
schoolbook, `bi_mul_karatsuba` forces Karatsuba down to 2 limbs. Every random
`mul` case runs through all three on identical operands, so the two
implementations are oracles for each other as well as being measured against
Python.

```
One Karatsuba level vs schoolbook (cutoff = n): the break-even point
 limbs  school/ms  karats./ms  faster
    24      0.00050      0.00067  schoolbook
    32      0.00082      0.00095  schoolbook
    40      0.00160      0.00131  karatsuba
    96      0.00818      0.00589  karatsuba

Full recursion at BI_KARATSUBA_CUTOFF = 96, against schoolbook
 limbs  school/ms  karats./ms  faster
    96      0.00779      0.00609  karatsuba
   256      0.05263      0.03536  karatsuba
  1024      0.75498      0.36462  karatsuba
  4096     12.59023      3.38986  karatsuba
```

A single Karatsuba level breaks even near 32 limbs, but the best cutoff for
the recursive version is 96, three times that, because each level
allocates six temporaries. Cutoffs 8 through 128 were scanned at 256, 1024 and
4096 limbs. The optimum sat in the 80 to 112 band and 96 is the middle of it.

## What does NOT work

Plainly, because a README that only lists successes is not finished.

Not portable. gcc only, as stated. Knuth D needs a signed borrow that goes
negative, so the inner loop shifts `int64_t` values right, which the C
standard leaves implementation-defined. gcc and clang define it as arithmetic.
A compiler that does not would produce wrong quotients, silently.

Out of memory aborts the process with exit code 70. There is no allocation
failure path through the API, so a caller cannot recover.

Parsing is stricter than Python's. `bi_set_dec` and `bi_set_hex` take an
optional sign, digits, and (for hex) an optional `0x`/`0X` prefix and leading
zeros. They reject what Python accepts: surrounding whitespace (`int(" 12 ")`),
digit group underscores (`int("1_000")`), and any other base. The fuzzer does
not generate those forms, so this is a documented restriction, not a
tested one.

Two operations refuse inputs Python accepts. A negative exponent is
`E negpow`, where Python returns a float. A shift or power whose result would
exceed `BI_MAX_BITS` (16 Mbit) is `E toobig`, where Python would try. Both
are deviations from the oracle; `t/fuzz.py` models both rules explicitly so
they stay tested, but they are deviations.

Base conversion is quadratic. Decimal parse is repeated multiply-by-10,
decimal format is repeated divide-by-10^9. At 500 limbs that is already the
dominant cost of the whole test run, and it is why the Karatsuba benchmark
stops at 4096 limbs: printing the answer costs more than computing it. Hex is
linear in both directions. Marked `shortcut:` with divide-and-conquer
splitting as the upgrade path.

Division is quadratic too. Knuth D is `O(n*m)`. There is no
Burnikel-Ziegler, so dividing a 4096-limb number by a 2048-limb one is slow in
a way multiplication at the same size no longer is.

Every binary operation allocates. The result is built in a fresh temporary
and swapped into place, which makes `bi_add(&x, &x, &x)` correct by
construction but costs a malloc/free pair per call. Marked `shortcut:`.

The largest accepted shift is not tested. `1 << (BI_MAX_BITS - 1)` is
legal and would take seconds to print under quadratic base conversion, so the
success side of the ceiling is checked at 64 Kbit and only the error side is
checked at the exact boundary.

The random classes stop at 500 limbs, and the length matrix at 192.
Karatsuba's recursion only gets deep past about 1000 limbs, which no fuzz case
reaches, for the base-conversion reason above. The `make bench` numbers at
4096 limbs are therefore measured on values the fuzzer has never checked.

Every case depends on the decimal parser being correct. Operands go in as
decimal strings and results come out as decimal strings, so a parser bug that
happens to be symmetric with a formatter bug would cancel out and the run
would stay green. Queued as milestone item 18.

`grow()` hands back uninitialised limbs, and the only thing stopping them
from being read is the `n` field. ASan does not catch uninitialised reads.
A 400-case run under `valgrind -q --track-origins=yes` is clean, but that was
done by hand once and is not wired into `make test`, so nothing re-checks it;
queued as milestone item 19.


Not implemented at all: modular exponentiation (three-argument `pow`),
GCD, integer square root, primality testing, conversion to or from floating
point, bases other than 10 and 16, bitwise NOT as a named operation (it is
`-x - 1`), and bit counting.

The line protocol cannot carry every operand. Operands are separated by
whitespace, so an empty operand or one containing a space is not
representable. The driver reports `E parse` for those, which happens to be
what Python says about `int("")` too.

## License

GPL-3.0-or-later.
