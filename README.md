# Minimal Policy-Gated Packet Assembler

Engineer #1 Screening Task — a small, spec-driven command-line pipeline that
ingests a YAML component definition, assembles a "micro-packet", runs it through
a fail-closed policy gate, and produces a deterministically hashed ("signed")
packet on success or a structured rejection on failure.

## Design overview

The pipeline is four stages, each in its own single-responsibility module:

```
ingest  ->  assemble  ->  policy gate  ->  sign
(YAML)      (+ atomic     (7 named        (SHA-256
             packet ID)    rules)          integrity hash)
```

| Module | Responsibility |
| --- | --- |
| `packet_assembler/ingest.py`    | Read & validate the YAML, return the `component` mapping |
| `packet_assembler/assembler.py` | Assemble the packet; reserve an atomic packet ID from SQLite |
| `packet_assembler/policy.py`    | Seven named policy rules; each returns `(passed, reason)` |
| `packet_assembler/signing.py`   | Deterministic SHA-256 hashing + verification |
| `packet_assembler/cli.py`       | Orchestration, JSON output, exit codes |

### Process contract

| Outcome | stdout | Exit code |
| --- | --- | --- |
| All rules pass | signed packet JSON | `0` |
| One or more rules fail | structured rejection listing every failing rule | `1` |
| Ingestion error (missing file / bad YAML) | structured `ingest_error` | `2` |

The gate is **fail-closed**: a packet is released only when *no* rule fails, and
a rejection reports *all* failing rules at once (not just the first).

## Requirements

- Python 3.10 or later (developed and tested on 3.13)
- `PyYAML` (only third-party dependency; `sqlite3` is in the standard library)

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt   # just PyYAML
```

## Execution

Assemble a packet from a YAML component:

```bash
python -m packet_assembler assemble tests/C-007.yaml
```

Optionally point the atomic counter at a specific database file:

```bash
python -m packet_assembler assemble tests/C-007.yaml --db my_counter.db
```

Verify the integrity hash of a produced packet (the "signing" round-trip):

```bash
python -m packet_assembler assemble tests/C-007.yaml > packet.json
python -m packet_assembler verify packet.json
```

Run all five screening test cases end to end:

```bash
./run_tests.sh
# or, to pick the interpreter explicitly:
PYTHON=.venv/bin/python ./run_tests.sh
```

## Test cases & example outputs

`run_tests.sh` runs each of tests 1–4 against an isolated, throwaway counter DB
(so every "first packet of the day" is `-001` and output is reproducible), then
runs test 5 twice against **one** DB to show the counter incrementing, plus a
concurrency check.

### Test 1 — valid C-007 → all rules pass, signed packet (exit 0)

```json
{
  "packet_id": "BAP-20260714-001",
  "component_id": "C-007",
  "component_name": "Sentinel Request Gateway",
  "release": "Release1-MVP",
  "owns": "Inbound request authentication, rate limiting, structured request logging",
  "does_not_own": "Downstream service routing, payload transformation, response caching",
  "fail_closed_behaviour": "If the gateway is unavailable, all inbound requests are rejected with HTTP 503. No requests are passed downstream without gateway validation.",
  "cr_authority": "BFS-SPEC-003 Section 4.2",
  "zones": [
    "Zone-External"
  ],
  "acceptance_tests": [
    "AT-REQ-001",
    "AT-REQ-002",
    "AT-REQ-004"
  ],
  "assembled_at": "2026-07-14T14:44:49Z",
  "assembler_version": "test-assembler-v0.1",
  "packet_hash": "2da4d17ed482499747a01628e8733f58cd2ce973aa2445387de0fc6b71b8ee0b"
}
```

Exit code: `0`

### Test 2 — `does_not_own: "None"` → RULE-004 fails (exit 1)

```json
{
  "status": "rejected",
  "packet_id": "BAP-20260714-001",
  "assembled_at": "2026-07-14T14:44:49Z",
  "failed_rules": [
    {
      "rule": "RULE-004",
      "reason": "does_not_own must be explicit; the value \"None\" is not acceptable"
    }
  ]
}
```

Exit code: `1`

### Test 3 — `acceptance_tests: []` → RULE-006 fails (exit 1)

```json
{
  "status": "rejected",
  "packet_id": "BAP-20260714-001",
  "assembled_at": "2026-07-14T14:44:49Z",
  "failed_rules": [
    {
      "rule": "RULE-006",
      "reason": "acceptance_tests must be a non-empty list"
    }
  ]
}
```

Exit code: `1`

### Test 4 — `release: "Release2"` → RULE-002 fails (exit 1)

```json
{
  "status": "rejected",
  "packet_id": "BAP-20260714-001",
  "assembled_at": "2026-07-14T14:44:49Z",
  "failed_rules": [
    {
      "rule": "RULE-002",
      "reason": "release must be exactly \"Release1-MVP\""
    }
  ]
}
```

Exit code: `1`

### Test 5 — run Test 1 twice → atomic counter increments

```
  "packet_id": "BAP-20260714-001",
  "packet_id": "BAP-20260714-002",
```

### Test 5b — concurrency (extra, beyond the brief)

20 assemblies launched in parallel against one DB; every packet ID is unique:

```
assembled 20 packets, 20 unique packet IDs
PASS - no duplicate packet IDs under concurrent execution
```

## Design decisions

- **Atomic counter via `BEGIN IMMEDIATE`.** The spec is explicit that the packet
  ID must come from an atomic sequence that "cannot generate duplicate packet
  IDs during overlapping executions." I use a SQLite `BEGIN IMMEDIATE`
  transaction so contending processes take the write lock up front and the
  read-then-write is one indivisible critical section, plus a 30s `busy_timeout`
  so a blocked writer waits for the lock instead of erroring. Test 5b
  demonstrates this holds under 20 overlapping processes. The counter is scoped
  per UTC day, so the `NNN` in `BAP-YYYYMMDD-NNN` reflects that day's count.

- **Named policy functions, not a schema validator.** Each rule is its own
  function returning `(passed, reason)`, registered in an ordered list. This is
  what makes the gate *auditable*: every accept/reject maps to a specific rule ID
  and a human-readable reason, which is the whole point of a policy gate in an
  evidence-producing pipeline. A JSON-schema validator would be terser but would
  collapse that traceability.

- **All rules always evaluated.** A rejection lists *every* failing rule, so an
  author fixing a packet sees all problems in one pass rather than one-at-a-time.

- **Deterministic hashing as the "signing" stand-in.** `packet_hash` is a SHA-256
  over a canonical (sorted-key, compact) JSON encoding of the packet, excluding
  the hash field itself. Sorting keys makes the hash reproducible regardless of
  field order; excluding the hash field lets `verify` recompute over the exact
  same payload. This mirrors why real Sigstore signing matters — packet
  integrity — without pulling in Cosign/Rekor, which the brief said not to.

- **packet_id reserved at assembly time (per the spec's step order).** Step 2
  (assembly, which lists `packet_id`) precedes Step 3 (policy gate), so the ID is
  reserved during assembly. A consequence is that a *rejected* packet still
  consumes a sequence number. I kept the spec ordering rather than deferring ID
  allocation until after the gate, and made the trade-off visible by surfacing
  the reserved `packet_id` in the rejection output so the attempt stays
  auditable. See "deliberately simplified" below for the alternative.

- **Explicit field mapping.** The packet is built field-by-field from the YAML
  rather than by copying the whole mapping, so unexpected extra YAML keys can
  never be silently carried into a released packet.

- **UTC everywhere.** `assembled_at` is stamped as ISO 8601 UTC ending in `Z`,
  matching the programme's timestamp requirement, and RULE-007 enforces it.

## Assumptions

- Input is a single component under a top-level `component:` key (as given).
- The per-day atomic sequence resets each UTC day; `NNN` is zero-padded to 3
  digits, which is enough for the expected packet volume in this exercise.
- "Non-empty" for text fields means non-empty after stripping whitespace.
- RULE-005's keyword check is case-insensitive and satisfied by any of
  "rejected"/"blocked"/"denied"/"refused" appearing in the text.
- `verify` is a small extra command (not required by the brief) included to make
  the integrity-hash round-trip demonstrable.

## Deliberately simplified

- **No real Sigstore.** The brief explicitly said a hash is sufficient to
  demonstrate the integrity concept; integrating keyless Cosign signing and a
  Rekor transparency log would add real supply-chain infrastructure without
  changing what this exercise assesses.
- **ID reserved before the gate.** The cleaner audit-hygiene alternative is to
  allocate the atomic `packet_id` only *after* a packet passes the gate, so
  rejected candidates never consume IDs and the released sequence has no gaps. I
  chose to follow the spec's literal step ordering instead and document the
  trade-off, since specification compliance is a graded dimension here. Switching
  to allocate-on-release would be a one-line reordering in `cli.cmd_assemble`.
- **Single-component input.** Batch ingestion of a whole registry (the real
  Build Machine ingests the MES Registry) is out of scope for this micro-task.

## Notes on the exercise

- **Time spent:** ~5 hours (started 2026-07-14T10:00:00Z, submitted 2026-07-14T15:08:00Z).
- **Straightforward:** the module split, the policy rules, and the JSON/exit-code
  contract — the spec is precise, so these mapped directly to code.
- **Harder than expected:** getting the atomic counter genuinely correct *and*
  proving it. Making it work is easy; being confident it cannot double-issue an
  ID under real overlap is what took the care (hence `BEGIN IMMEDIATE` +
  `busy_timeout`, and the 20-way concurrency assertion in `run_tests.sh`).
