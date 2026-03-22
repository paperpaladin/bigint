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

.PHONY: test test-asan bench clean

