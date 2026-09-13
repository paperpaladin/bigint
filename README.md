# bigint

Arbitrary-precision signed integers in one C11 file, measured against Python's
native `int` on millions of cases.

```
$ make test
107899 agree, 0 disagree

$ make test-asan
22898 agree, 0 disagree
```

Across 68 seeds at 100k cases each, measured at commit 20: **7,314,868
agree, 0 disagree**, with operand magnitudes from 0 bits to 16,000 bits
(500 limbs). The two counts above are the suite as it stands now; the long
sweep is re-run at the end of a milestone and not after every item, which
is why its total names the commit it was taken at.


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
make test-valgrind  # the same under valgrind, fewer cases still
make bench      # where Karatsuba starts paying, measured
make clean
```

ASan and valgrind are not interchangeable here. A bignum library indexes
limb arrays constantly, which is ASan's subject, but `grow()` hands back
uninitialised limbs with only `n` stopping them being read, and to ASan
that memory is allocated and reading it is legal. Planting exactly that
read, one limb past the end of the value, ASan reports nothing: 7872
comparisons, 0 disagree. valgrind exits 99 and names `ucmp` as the reader
and `grow` as where the memory came from. `make test-valgrind` runs 300
cases on seed 11 with `--track-origins=yes`, and prints a loud skip
instead of passing quietly if valgrind is not installed.

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

It reduces a hex-twin case in hex. It used to call `int()` on every
operand, so the first disagreement that landed on a `hex:` case killed the
fuzzer with a `ValueError` and printed no report at all: item 18 added the
marker and the reducer predates it. Candidates go back out in the spelling
they came in with, so the reduced case runs through the same parser as the
one that failed.

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
run green. 15.7% of cases take the hex path, counted over what a run at
seed 0 actually emits; it is 15.5% to 16.0% across five seeds. This figure
had said 14.8% since item 18 and was wrong when written: the same count
against the suite as it stood before item 21 gives 15.6%.

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
$ printf 'divmod -7 2\npow 2 64\npowm 2 3 -5\nhex -255\nand -1 5\n' | ./bigint
-4 1
18446744073709551616
-2
-0xff
5
```

Errors are reported as `E <reason>` on stdout and do not stop the stream:
`E parse`, `E divzero`, `E negshift`, `E negpow`, `E toobig`. Two more are
not errors the library can return but assertions the driver makes with
`bi_check()`: `E unnormalised operand` and `E unnormalised`, for an operand
or a result that violates the representation invariant. They cannot be
triggered by any input; seeing one means a bug in the library.

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
Knuth algorithm D in the `divmnu` form from Hacker's Delight. Modular
exponentiation is square-and-multiply with a reduction after every step. Hex
conversion is limb-aligned and linear. Decimal conversion is quadratic in
both directions.

### The invariant the oracle cannot see

Every `bi` is normalised: no leading zero limbs, `sign == 0` exactly when the
value is zero. Python cannot check this. `bi_to_dec` divides the value down by
10^9 and simply never looks at leading zero limbs, so an **untrimmed result
prints identically to a trimmed one** and a million-case differential run
reports zero disagreements. The only observer is `bi_cmp`, which compares limb
counts first, so the bug sits there silently until some unrelated comparison
starts returning the wrong answer.

So the invariant is a predicate in the library, `bi_check()`, exported from
`bigint.h` precisely because nothing the library prints can reveal a
violation. The driver asserts it on every result and prints `E unnormalised`
if it is violated. Deleting the trim loop out of `norm()` makes
`10^500 - (10^500 - 1)` report `E unnormalised` instead of `1`; a plain
decimal comparison calls that same case a pass.

It asserts it on both operands too, straight after parsing, with the
separate message `E unnormalised operand`, because which side is wrong is
the whole question. Only `dec` and `unhex` ever print an operand back, so
until this every other parse went unchecked, and an unnormalised operand is
consumed by arithmetic that normalises its own answer and so comes back out
correct. Delete `norm()` from `bi_set_hex` and `add hex:0 hex:5`,
`mul hex:0 hex:5`, `sub hex:0 hex:7`, `and hex:0 hex:5`, `cmp hex:0 hex:0`
and `divf hex:0 hex:3` all still agree with Python, 6 out of 6, with a zero
operand carrying a limb and a sign it should not have. With the operand
check they are 0 out of 6, and a 3000-case run goes from clean to 86
disagreements.

What that buys is not only an earlier message. The same class of defect,
planted instead in the `hex:` branch of `set_operand` so that it sets the
sign itself rather than delegating, takes the whole driver down with SIGFPE
181 lines into a chunk: an unnormalised zero walks past `b->sign == 0` in
`bi_divmod` and divides by it. With the operand check it is 49 ordinary
disagreements that reduce to `cmp hex:0 hex:0`.

One clause of `bi_check` is not tested. `n > cap` has no planted defect that
reaches it: a `grow(r, hi->n)` off-by-one in `uadd` does produce `n > cap`,
but it writes past the allocation first and the process dies in `free()`
before anything reads the flag. It stays as a cheap assertion and is not
claimed as a checked one.

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

## Modular exponentiation, and what its running time says

`powm a e m` is Python's `pow(a, e, m)`: square-and-multiply over the bits of
`e` with a reduction after every squaring and every multiplication. The
oracle is exact here in a way it is not for a benchmark, so every answer is
checked rather than sampled. A `make test` run puts 5,024 cases through it,
4,707 of them random draws, every one against Python's own three-argument
`pow`.

Three of Python's rules are where a modular exponentiation usually goes
wrong, and none of them is special-cased in the library:

```
  pow(2, 3, -5)   is -2, not 3        the result takes the sign of m
  pow(0, 0, 1)    is 0, not 1         |m| == 1 makes every answer 0
  pow(-2, 3, 5)   is 2, not -3        the base is reduced with Python's %
```

The second falls out of `1 mod 1` rather than from a test for it, which is
why deleting that one reduction is caught by `powm 0 0 1` and by nothing
else. The third is `bi_divmod` already flooring the way Python does, so a
negative base arrives in the loop as a residue in `[0, |m|)` and no later
step has to think about signs.

A modulus of 0 is `E divzero`, which is Python's ValueError, and it is
checked before the exponent: `pow(2, -1, 0)` complains about the modulus in
both.

**A negative exponent is refused.** `E negpow`, where Python returns a
modular inverse when the base is invertible and raises when it is not.
Implementing it needs an extended GCD, which this library does not have, and
the failure mode of guessing is returning a plausible wrong residue for a
non-invertible base. That is a deviation from the oracle, it is the third
one, and `t/fuzz.py` models it so it stays tested rather than drifting.

### It is not constant time, and here is the gap

A modular exponentiation whose running time depends on the exponent's bits
reveals the exponent. This one does: the loop performs one modular
multiplication per **set** bit, so the work is a function of the exponent's
Hamming weight and nothing hides that.

Measured, not argued. `make bench` runs three exponents of the same bit
length against one modulus, the first with every bit set, the second with a
single bit set, the third random:

```
mod/bits  exp/bits  all ones/ms  one bit/ms   random/ms  ratio
    1024      1024        5.631       2.803       3.995   2.01x
    2048      1024       19.116       9.540      14.549   2.00x
    4096      1024       65.909      33.195      49.853   1.99x
    2048      2048       37.967      19.285      28.072   1.97x
    4096      4096      269.289     132.817     202.739   2.03x
```

Twice the time for twice the set bits, at every size, and the random
exponent lands where its popcount puts it. A constant-time implementation
would print three equal columns. `bigint.h` says so above `bi_powm` as well,
because a header is where somebody about to exponentiate a secret will look.

Flattening it is not queued. It would mean Montgomery multiplication for the
odd case, a recoding that gives every exponent the same weight, and
branchless limb code throughout, and none of that is what this repository is
for.

### Asserting that the loop ran

A correct answer is no evidence that it came from the code it was meant to
come from. `bi_pow` followed by one reduction returns exactly the same value
for every case small enough to compute that way, so a `bi_powm` wired to do
that would pass a differential test that only looks at values.

So `bi_powm_counted` reports the loop's work and the driver's `powmc` op
prints it after the result. Both numbers are fixed by the exponent alone,
one squaring per bit and one multiplication per set bit, so Python computes
them with `bit_length` and `popcount` and the comparison is exact:

```
$ printf 'powmc 3 65537 1000000007\n' | ./bigint
754428556 17 2
```

That earned itself immediately. Replacing the loop with `bi_pow` and a
single reduction leaves 308 of 312 small powm cases agreeing, and all four
disagreements are `powmc` count lines whose values are right:

```
  powmc 7 255 1              want 0 8 8          got 0 0 0
  powmc 5 1 7                want 5 1 1          got 5 0 0
  powmc 3 65537 1000000007   want 754428556 17 2 got 754428556 0 0
  powmc 3 1 7                want 3 1 1          got 3 0 0
```

### The input classes

Random draws cover the ordinary case and cover none of these, so each is in
the fixed corpus and runs on every invocation:

| class | what it would otherwise hide |
| --- | --- |
| a modulus of 1 and of -1 | every answer is 0, so a reduction left out of the `1 mod m` step is visible nowhere else |
| an even modulus, and a power of two | rules out Montgomery multiplication for anyone who reaches for it later, and a mask instead of a division |
| a modulus of one limb, and 2^32 and 2^64 either side | Knuth D takes a different path for a single-limb divisor |
| an exponent of 0 and of 1 | the answer is a reduction and not an exponentiation, and `1 mod m` is 0 for `|m| == 1` and negative for `m < 0` |
| a base of 0, a base that is a multiple of the modulus, a base far wider than it | the reduction has to happen before the loop, not after |
| both signs of the base against both signs of the modulus, at both exponent parities | the sign comes from the modulus, which is the opposite of what `pow` with two arguments does |
| a negative exponent, and a zero modulus, and both at once | refusals, in the order Python checks them |
| 2048-bit and 4096-bit moduli, each a product of two half-width factors | the size this operation is actually used at, and the only cases where a 2048-bit exponent runs |

A random `powm` draw is cost-capped: one squaring per exponent bit, each
quadratic in the modulus, means a 16000-bit exponent against a 16000-bit
modulus is 16000 squarings of 500 limbs and one draw in a hundred thousand
would own the whole run. `POWM_BUDGET` caps `bits(e) * limbs(m)^2`, and the
large sizes are in the corpus where there are a fixed few of them.

### The mutation run

Thirteen mutants, each built and run against `t/run.sh 3000 0` (10,898
cases clean) and against the 312 small `powm` cases on their own. Twelve
died. The survivor is recorded as a survivor:

| mutant | suite | small cases |
| --- | --- | --- |
| drop the base reduction before the loop | 0 disagree | 0 disagree, SURVIVES |
| drop the reduction after the squaring | does not finish | 51 of 312 |
| drop the reduction after the multiplication | 65 | 35 of 312 |
| drop the negative-modulus sign fix | 158 | 129 of 312 |
| apply the sign fix to a zero result too | 32 | 9 of 312 |
| walk the exponent's bits low to high | 122 | 67 of 312 |
| start the loop one bit above the top | 196 | 68 of 312 |
| `bi_pow` and one reduction instead of the loop | 131 | 4 of 312, all counts |
| use the modulus without stripping its sign | 158 | 129 of 312 |
| check the exponent before the modulus | 1 | 1 of 312 |
| swap the two counts in the driver | 104 | 1 of 312 |
| test two bits of the exponent instead of one | 223 | 117 of 312 |
| leave `1` unreduced by the modulus | 1 | 1 of 312 |

The survivor is equivalent, not missed. Reducing the base before the loop is
a size measure and not a correctness one: `(acc * a) mod m` equals
`(acc * (a mod m)) mod m`, and since every multiplication is reduced
immediately afterwards, a 16000-bit base gives exactly the same answers as
its residue would. What it costs is one wide multiplication per set bit
instead of one narrow one, which no comparison against Python can see and no
assertion here tries to.

Two of the thirteen are worth naming for what caught them rather than for
dying. Starting the loop one bit above the top changes no value for an
exponent whose top bit is where it should be, because the extra iteration
squares 1; it is caught by the counts, and separately by `powm 5 0 7`, where
an exponent of 0 makes it read `e->d[0]` of a value with no limbs at all.
And checking the exponent before the modulus is a single case, `powm 2 -1 0`,
which is in the corpus only because Python was asked which error it reports
first.

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

Three operations refuse inputs Python accepts. A negative exponent to
`pow` is `E negpow`, where Python returns a float, and a negative exponent to
`powm` is the same error, where Python returns a modular inverse. A shift or power whose result would
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

Most cases still depend on the decimal parser being correct. The hex twins
cover 15.7% of them, and `dec`, `hex`, `hexrt` and `unhex` are excluded from
twinning by construction, so a parser bug symmetric with a formatter bug
would still cancel out on the other 85%. The twins narrow where such a bug
can hide; they do not remove it.

valgrind runs 300 cases on one seed, not the whole suite, because every case
costs roughly fifty times what it costs natively. An uninitialised read that
only a rare operand shape reaches is therefore still possible: the gate
proves the common paths are clean, not all of them.


Not implemented at all: GCD, integer square root, primality testing,
conversion to or from floating point, bases other than 10 and 16, bitwise
NOT as a named operation (it is `-x - 1`), and bit counting.

`bi_powm` is not constant time and is not a cryptographic primitive. The
measurement above says by how much its running time varies with the
exponent; nothing here is hardened against a timing attack, a cache-timing
attack or anything else of that kind.

The line protocol cannot carry every operand. Operands are separated by
whitespace, so an empty operand or one containing a space is not
representable. The driver reports `E parse` for those, which happens to be
what Python says about `int("")` too.

## License

GPL-3.0-or-later.
