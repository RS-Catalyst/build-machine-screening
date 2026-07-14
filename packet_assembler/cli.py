"""Command-line orchestration for the policy-gated packet assembler.

Wires the stages together:

    ingest -> assemble -> policy gate -> sign

and defines the process contract:

    * valid packet   -> signed packet JSON on stdout, exit code 0
    * rejected packet -> structured JSON error on stdout, exit code 1
    * ingestion error -> structured JSON error on stdout, exit code 2
"""

from __future__ import annotations

import argparse
import json
import sys

from .assembler import assemble_packet
from .ingest import IngestError, load_component
from .policy import evaluate
from .signing import sign, verify

DEFAULT_DB = "packet_counter.db"


def _emit(payload):
    """Print a JSON payload to stdout with stable, human-readable formatting."""
    print(json.dumps(payload, indent=2))


def cmd_assemble(args):
    """Assemble, gate and (on success) sign a packet from a YAML component."""
    try:
        component = load_component(args.input)
    except IngestError as exc:
        _emit({"status": "ingest_error", "reason": str(exc)})
        return 2

    packet = assemble_packet(component, args.db)
    results = evaluate(packet)
    failures = [
        {"rule": r["rule"], "reason": r["reason"]}
        for r in results
        if not r["passed"]
    ]

    if failures:
        # Fail-closed: no packet is released. We still surface the reserved
        # packet_id and assembly time so the rejection is itself auditable.
        _emit(
            {
                "status": "rejected",
                "packet_id": packet["packet_id"],
                "assembled_at": packet["assembled_at"],
                "failed_rules": failures,
            }
        )
        return 1

    _emit(sign(packet))
    return 0


def cmd_verify(args):
    """Verify the integrity hash of a previously produced signed packet."""
    try:
        with open(args.packet, "r", encoding="utf-8") as handle:
            signed_packet = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        _emit({"status": "verify_error", "reason": str(exc)})
        return 2

    is_valid, claimed, recomputed = verify(signed_packet)
    _emit(
        {
            "status": "valid" if is_valid else "tampered",
            "claimed_hash": claimed,
            "recomputed_hash": recomputed,
        }
    )
    return 0 if is_valid else 1


def build_parser():
    """Construct the argument parser and its subcommands."""
    parser = argparse.ArgumentParser(
        prog="packet_assembler",
        description="Minimal policy-gated packet assembler (screening task).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    assemble_parser = subparsers.add_parser(
        "assemble", help="assemble, policy-gate and sign a packet from a YAML component"
    )
    assemble_parser.add_argument("input", help="path to the YAML component definition")
    assemble_parser.add_argument(
        "--db",
        default=DEFAULT_DB,
        help=f"SQLite counter database path (default: {DEFAULT_DB})",
    )
    assemble_parser.set_defaults(func=cmd_assemble)

    verify_parser = subparsers.add_parser(
        "verify", help="verify the packet_hash of a signed packet JSON file"
    )
    verify_parser.add_argument("packet", help="path to a signed packet JSON file")
    verify_parser.set_defaults(func=cmd_verify)

    return parser


def main(argv=None):
    """Program entry point. Returns the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
