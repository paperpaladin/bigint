# bigint: plan

## Contract

Arbitrary-precision signed integers in one C11 file, with **Python's `int` as
the specification**. Addition, subtraction, multiplication, floor division,
modulo, power, comparison, shifts, bitwise and/or/xor, negation, absolute
value, and conversion to and from decimal and hexadecimal strings.

For every one of those, `bigint` must produce exactly what Python produces,
byte for byte on the string forms. Where C and Python differ, floor division
and modulo signs, shifts of negative values, bitwise operations on negative
values, **Python wins**, because Python is the oracle and an oracle you
overrule is not an oracle.

The two deliberate deviations from Python are both errors, not wrong
answers, and both are in `bigint.h`: a negative exponent is refused instead of
returning a float, and a shift or power whose result would exceed
`BI_MAX_BITS` is refused instead of attempted. `t/fuzz.py` models both rules,
so they are tested as well as documented.

## Hard invariant

**Every `bi` reachable by any caller is normalised: no leading zero limbs, and
`sign == 0` if and only if the value is zero.**

This is the one property that, if violated, means the project failed, and it
is the one Python cannot check. `bi_to_dec` divides the value down and never
looks at leading zero limbs, so an untrimmed result prints identically to a
trimmed one and a million-case differential run reports zero disagreements.
The only observer is `bi_cmp`, which compares limb counts first, so the bug
sits silently until some unrelated comparison returns the wrong answer months
later.

So the invariant is asserted directly, not inferred: the driver checks it on
every result of every case the fuzzer runs. That check has already earned its
place twice, once when deleting `norm()`'s trim loop was confirmed to make
`10^500 - (10^500 - 1)` report "E unnormalised" instead of passing, and once
when `umul_school` was found returning unnormalised products that disarmed a
fault injection (commit 16).

## Oracle

1. Python's native `int`, via `t/fuzz.py`. It is arbitrary-precision, it
   is the reference implementation for every operation here, and there is zero
   ambiguity about the right answer. Nothing about it is under this project's
   control. Currently 7,314,868 cases across 68 seeds, zero disagreements.

2. Schoolbook multiply against Karatsuba multiply. Two independent
   implementations of one function, checked against each other on identical
   operands as well as against Python. Weaker than Python. A shared
   misunderstanding would agree, but far cheaper, so every `mul` case runs
   through both.
3. ASan and UBSan, via `make test-asan`. A bignum indexes limb arrays
   constantly, `addat()` writes past the end of its operand by design, and the
   Karatsuba windows alias the parent's buffer; UBSan also covers the shift
   widths, where `>> (32 - s)` with `s == 0` would be undefined in 32 bits.
4. `../unrepro` for build reproducibility. Verified REPRODUCIBLE across
   varied build directory, TZ, locale, umask, hostname, user and
   `SOURCE_DATE_EPOCH`.

## Non-goals

Modular exponentiation (three-argument `pow`), GCD, integer square root,
primality, random number generation. Bases other than 10 and 16. Conversion
to or from floating point. Bitwise NOT as a named operation (`~x` is
`-x - 1`, and the library has both).

Subquadratic base conversion, Toom-Cook or FFT multiplication, and
Burnikel-Ziegler division are not permanent non-goals, but they are not
queued either: nothing here needs them, and each one is a second
implementation that has to be differential-tested against the first.

Thread safety is not a goal because there is no shared state to protect; every
function's output is its arguments.

## Commit sequence

- [x] 00 limb representation, normalisation, decimal parse and format
      files: bigint.c bigint.h Makefile t/fuzz.py t/run.sh LICENSE .gitignore
      proves: 200019 agree, 0 disagree
      found: `bi_to_dec` sized its buffer at 10 bytes per limb while the
             10^9 chunk loop always emits 9 digits significant or not, so a
             1-limb value wrote 20 bytes into 14. glibc caught it as
             "corrupted size vs. prev_size" on the first corpus case.
- [x] 01 comparison, and a corpus aimed at normalisation
      why: `bi_cmp` compares limb counts first, so it is the only thing that
           can see a trimming bug at all
- [x] 02 magnitude add/sub helpers and signed addition
- [x] 03 signed subtraction, absolute value, and the normalisation assert
      why: the oracle is blind to leading zero limbs; watched the check fail
           by deleting the trim loop before trusting it
- [x] 04 schoolbook multiplication
- [x] 05 floor division and modulo, with Python's sign rule
      why: the single most common disagreement between bignum libraries, and
           the floor correction must be conditional on a nonzero remainder or
           every exact quotient with mixed signs is off by one
- [x] 06 shifts, with Python's floor semantics on the right shift
- [x] 07 bitwise and/or/xor on Python's two's-complement model
      why: one extra limb makes the sign bit of the result reliable, which
           collapses all four input sign cases into no case analysis at all
- [x] 08 hexadecimal input and output, and a round-trip op
      proves: `hexrt` is the identity over 2^k - 1 for k in 0..299
- [x] 09 integer power by binary exponentiation
      why: 0 ** 0 is 1, and the bits(a) * e ceiling has to be applied AFTER
           the 0/1/-1 fast paths or 1 ** (10^30) fails
- [x] 10 fuzz class: every sign combination of every binary operation
      why: random signs give each combination a quarter of the cases, which
           says nothing about which quarter covered which op
      proves: disabling the floor correction drops it to 43 disagreements
- [x] 11 fuzz class: operands of wildly mismatched magnitude
      why: independent bucket choice makes 1-limb-against-500-limb a
           1-in-120 event
- [x] 12 fuzz class: values exactly on the limb boundaries
- [x] 13 fuzz class: carry and borrow chains the full length of the number
      why: the arrangement matters as much as the value: a chain operand
           against another big number does not propagate anything
- [x] 14 Karatsuba, with the schoolbook path kept and benchmarked
      proves: 3.7x at 4096 limbs; cutoff 96 measured, not guessed
- [x] 15 fuzz class: every pair of limb lengths, all three multiply paths
      found: `umul_school` never normalised its own result, so a
             1-limb-by-1-limb product came back with a leading zero limb.
             Invisible from outside the library, but it silently disarmed a
             fault injection into Karatsuba's z2 subtraction, the
             "suite passes because it is doing nothing" failure mode.
- [x] 16 README and PLAN

### Milestone 1: make the oracle harder to satisfy

- [ ] 17 shrink on disagreement: minimise both operands before printing them
      why: the first real disagreement at a 500-limb magnitude will otherwise
           print 4800 digits and be unreadable
- [ ] 18 feed the fuzzer's generated operands through the C parser as hex as
      well as decimal, so parse and format are not trusted while arithmetic
      is being measured
      why: every case currently depends on `bi_set_dec` being correct. A
           parser bug that is symmetric with a formatter bug cancels out and
           the differential run stays green.
- [ ] 19 wire valgrind into the Makefile alongside ASan, on a short seed
      why: ASan misses uninitialised reads, and `grow()` hands back
           uninitialised limbs with only `n` stopping them being read. A
           400-case run with `--track-origins=yes` is clean, but it was run
           by hand once and nothing re-checks it.

- [ ] 20 a `bi_check()` exported invariant checker, called from the driver on
      every operand as well as every result
      why: the current check only sees results, so an unnormalised value that
           is produced and consumed internally is still invisible

### Milestone 2: the operations that need a second implementation

- [ ] 21 three-argument `pow(a, e, m)` by square-and-multiply with reduction
      at every step, differential against Python's `pow(a, e, m)`
      why: the obvious use for a bignum library, and the only way to make
           `pow` usable at cryptographic sizes
- [ ] 22 `bi_gcd` by binary GCD, against `math.gcd`
- [ ] 23 `bi_isqrt` by Newton iteration, against `math.isqrt`
      note: 21 to 23 are all "second implementation of something Python
            already has", the cheapest kind of work here: the oracle
            is free and exact.

### Milestone 3: asymptotics

- [ ] 24 subquadratic base conversion by recursive splitting on powers of 10,
      keeping the quadratic path and differential-testing the two against
      each other as well as against Python
      why: decimal conversion dominates every measurement in this repo. The
           4096-limb benchmark cannot be extended because printing the answer
           costs more than computing it.
- [ ] 25 a scratch arena threaded through the Karatsuba recursion, and a
      re-measured cutoff
      why: six malloc/free pairs per level is why the recursive cutoff is 96
           when a single level breaks even at 32
- [ ] 26 Burnikel-Ziegler division, keeping Knuth D as the fallback and the
      differential partner
- [ ] 27 benchmark against GMP, reporting where we lose and by how much
      note: GMP as a BENCHMARK is fine. GMP as a dependency is not, writing
            this is the point.

## Open questions

- Whether `BI_MAX_BITS` should exist at all. It makes two operations refuse
  inputs Python accepts, a real deviation, and the alternative is
  letting `malloc` fail and aborting. The current answer is that refusing is
  more useful than dying, but it does mean `t/fuzz.py` has to model a rule
  that belongs to the implementation, not to arithmetic.
- Whether to expose the quotient and remainder separately at all, given that
  `bi_divmod` computes both and callers mostly want one. Passing NULL works
  but costs a branch in the hot loop.
- Where the fuzzer's magnitude ceiling should be. 500 limbs is enough to
  exercise every code path, but Karatsuba's interesting behaviour starts at
  96 limbs and only gets deep past 1000, which the random classes never
  reach because quadratic decimal conversion makes those cases dominate the
  run. Milestone 3 item 24 is the prerequisite for raising it.
