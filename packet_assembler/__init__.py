"""Minimal policy-gated packet assembler.

A small, spec-driven pipeline that:

  1. ingests a YAML component definition,
  2. assembles a packet (with an atomic, SQLite-backed packet ID),
  3. runs the packet through a set of named policy rules (fail-closed),
  4. and produces a deterministically hashed ("signed") packet on success.

The package is split into single-responsibility modules:

  ingest    -> YAML ingestion
  assembler -> packet assembly + atomic counter
  policy    -> named policy rules
  signing   -> deterministic packet hashing (Sigstore stand-in)
  cli       -> command-line orchestration
"""

__version__ = "0.1.0"
