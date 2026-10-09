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


clean:
	rm -f bigint bigint-asan
	rm -rf scratch/*

.PHONY: test test-asan clean
