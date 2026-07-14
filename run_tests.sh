#!/usr/bin/env bash
#
# Runs the five screening test cases against the packet assembler and prints
# each result with its exit code.
#
# Tests 1-4 each use an isolated, throwaway SQLite counter DB so their output is
# reproducible (every "first" packet of the day is BAP-YYYYMMDD-001). Test 5
# deliberately reuses ONE DB to show the atomic counter incrementing, and adds a
# concurrency check that proves no duplicate IDs are produced under overlap.

set -u
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
DBDIR="$(mktemp -d)"
trap 'rm -rf "$DBDIR"' EXIT

run() {
  # $1 = title, $2 = db path, $3 = yaml input
  echo "=================================================================="
  echo "$1"
  echo "------------------------------------------------------------------"
  "$PY" -m packet_assembler assemble "$3" --db "$2"
  echo "(exit code: $?)"
  echo
}

run "TEST 1 - valid C-007  (expect: all rules pass, signed packet, exit 0)" \
    "$DBDIR/t1.db" tests/C-007.yaml

run "TEST 2 - does_not_own='None'  (expect: RULE-004 fails, exit 1)" \
    "$DBDIR/t2.db" tests/C-007-none.yaml

run "TEST 3 - acceptance_tests=[]  (expect: RULE-006 fails, exit 1)" \
    "$DBDIR/t3.db" tests/C-007-empty-acceptance-tests.yaml

run "TEST 4 - release='Release2'  (expect: RULE-002 fails, exit 1)" \
    "$DBDIR/t4.db" tests/C-007-release2.yaml

echo "=================================================================="
echo "TEST 5 - atomic counter: run TEST 1 twice on one DB (expect 001 then 002)"
echo "------------------------------------------------------------------"
"$PY" -m packet_assembler assemble tests/C-007.yaml --db "$DBDIR/t5.db" | grep '"packet_id"'
"$PY" -m packet_assembler assemble tests/C-007.yaml --db "$DBDIR/t5.db" | grep '"packet_id"'
echo

echo "=================================================================="
echo "TEST 5b - concurrency: 20 overlapping assemblies, assert unique IDs"
echo "------------------------------------------------------------------"
CDB="$DBDIR/conc.db"
CONC_OUT="$DBDIR/conc.out"
for _ in $(seq 1 20); do
  "$PY" -m packet_assembler assemble tests/C-007.yaml --db "$CDB" &
done > "$CONC_OUT"
wait

TOTAL=$(grep -c '"packet_id"' "$CONC_OUT")
UNIQUE=$(grep '"packet_id"' "$CONC_OUT" | sort -u | wc -l | tr -d ' ')
echo "assembled $TOTAL packets, $UNIQUE unique packet IDs"
if [ "$TOTAL" = "$UNIQUE" ]; then
  echo "PASS - no duplicate packet IDs under concurrent execution"
else
  echo "FAIL - duplicate packet IDs detected"
fi
echo
