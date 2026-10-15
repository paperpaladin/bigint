#!/bin/sh
# Differential run against Python's int. Prints "N agree, M disagree".
# Usage: t/run.sh [CASES] [SEED]
set -e
cd "$(dirname "$0")/.."
: "${BIGINT:=./bigint}"
# BIGINT may be a command with arguments, so test only its first word.
# Not "set -- $BIGINT", which overwrites this script's own arguments and
# turns the case count into the binary's name.
[ -x "${BIGINT%% *}" ] || make -s bigint
export BIGINT
# The reducer first, against a synthetic predicate whose answer is known
# exactly. It needs no broken bigint and costs nothing.
python3 t/fuzz.py --self-test

exec python3 t/fuzz.py "${1:-100000}" "${2:-0}"
