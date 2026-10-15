CFLAGS = -std=c11 -g -O2 -Wall -Wextra -ffile-prefix-map=$(CURDIR)=.

bigint: bigint.c bigint.h
	$(CC) $(CFLAGS) -o $@ bigint.c

# The oracle: Python's native int must agree on every generated case.
test: bigint
	@t/run.sh

# A bignum library indexes limb arrays constantly; ASan is the right tool.
test-asan:
	$(CC) -std=c11 -g -O1 -Wall -Wextra -fsanitize=address,undefined \
	      -fno-omit-frame-pointer -ffile-prefix-map=$(CURDIR)=. \
	      -o bigint-asan bigint.c
	@BIGINT=./bigint-asan t/run.sh 15000

# ASan does not see an uninitialised read: the memory is allocated, so
# reading a limb past n is legal to it. grow() hands back uninitialised
# limbs with only n stopping them being read, which makes that exactly the
# mistake this library is placed to make. valgrind is the tool that sees
# it, and --track-origins=yes names the allocation it came from.
#
# A loud skip when valgrind is absent, not a quiet pass: this is one
# checker among several here, so a missing one should not stop the suite,
# and it must not look like it ran either.
test-valgrind: bigint
	@command -v valgrind >/dev/null 2>&1 || { 	  echo "SKIP test-valgrind: valgrind is not installed"; exit 0; }
	@valgrind --error-exitcode=99 --errors-for-leak-kinds=definite 	          --leak-check=full --track-origins=yes --quiet 	          ./bigint </dev/null >/dev/null
	@BIGINT="valgrind --error-exitcode=99 --leak-check=full 	         --track-origins=yes --quiet ./bigint" t/run.sh 300 11

# Where Karatsuba starts paying, measured. BI_KARATSUBA_CUTOFF comes from here.
bench: bigint
	@echo "One Karatsuba level vs schoolbook (cutoff = n): the break-even point"
	@echo " limbs  school/ms  karats./ms  faster"
	@for n in 8 16 24 28 32 40 48 64 96 128; do echo "mulbench $$n 0 $$n"; \
	 done | ./bigint
	@echo
	@echo "Full recursion at BI_KARATSUBA_CUTOFF, against schoolbook"
	@echo " limbs  school/ms  karats./ms  faster"
	@for n in 96 128 256 512 1024 2048 4096; do echo "mulbench $$n 0"; \
	 done | ./bigint

clean:
	rm -f bigint bigint-asan

.PHONY: test test-asan test-valgrind bench clean

