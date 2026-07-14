"""Packet assembly and the atomic, SQLite-backed packet-ID counter.

The packet ID must be unique even when several assembler processes run at the
same time. We guarantee that with a SQLite ``BEGIN IMMEDIATE`` transaction:
overlapping processes serialise on the database write lock, so no two of them
can ever read-then-write the same sequence value. A ``busy_timeout`` makes
contending writers wait for the lock rather than fail.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

ASSEMBLER_VERSION = "test-assembler-v0.1"

# How long a contending writer will wait for the database lock (milliseconds).
_BUSY_TIMEOUT_MS = 30_000


def utc_now():
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def iso_utc(moment):
    """Format a datetime as an ISO 8601 UTC timestamp ending in ``Z``."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def next_sequence(db_path, date_key):
    """Atomically reserve and return the next sequence number for ``date_key``.

    The counter is scoped per day so the ``NNN`` portion of a packet ID always
    reflects the number of packets assembled on that (UTC) date.

    Parameters
    ----------
    db_path : str
        Path to the SQLite counter database (created on first use).
    date_key : str
        The ``YYYYMMDD`` day the sequence belongs to.

    Returns
    -------
    int
        A sequence number that is unique for the given ``date_key``, even under
        concurrent execution.
    """
    connection = sqlite3.connect(db_path, timeout=30.0, isolation_level=None)
    try:
        connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS packet_counter ("
            "  date_key TEXT PRIMARY KEY,"
            "  seq      INTEGER NOT NULL"
            ")"
        )

        # BEGIN IMMEDIATE takes the write lock up front, so the read below and
        # the write that follows are one indivisible critical section.
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT seq FROM packet_counter WHERE date_key = ?", (date_key,)
        ).fetchone()

        if row is None:
            sequence = 1
            connection.execute(
                "INSERT INTO packet_counter (date_key, seq) VALUES (?, ?)",
                (date_key, sequence),
            )
        else:
            sequence = row[0] + 1
            connection.execute(
                "UPDATE packet_counter SET seq = ? WHERE date_key = ?",
                (sequence, date_key),
            )

        connection.execute("COMMIT")
        return sequence
    finally:
        connection.close()


def assemble_packet(component, db_path, moment=None):
    """Assemble a packet dict from a parsed component mapping.

    A fresh, atomic packet ID is reserved as part of assembly (Step 2 of the
    spec). ``assembled_at`` is stamped here so that policy RULE-007 validates a
    real assembly timestamp.

    Parameters
    ----------
    component : dict
        The component mapping returned by :func:`ingest.load_component`.
    db_path : str
        Path to the SQLite counter database.
    moment : datetime, optional
        Assembly time; defaults to :func:`utc_now`. Injectable for testing.

    Returns
    -------
    dict
        The assembled packet (not yet policy-checked or signed).
    """
    moment = moment or utc_now()
    date_key = moment.strftime("%Y%m%d")
    sequence = next_sequence(db_path, date_key)
    packet_id = f"BAP-{date_key}-{sequence:03d}"

    # Explicit field-by-field mapping keeps the packet schema obvious and means
    # unexpected extra YAML keys are never silently carried into a packet.
    return {
        "packet_id": packet_id,
        "component_id": component.get("id"),
        "component_name": component.get("name"),
        "release": component.get("release"),
        "owns": component.get("owns"),
        "does_not_own": component.get("does_not_own"),
        "fail_closed_behaviour": component.get("fail_closed_behaviour"),
        "cr_authority": component.get("cr_authority"),
        "zones": component.get("zones"),
        "acceptance_tests": component.get("acceptance_tests"),
        "assembled_at": iso_utc(moment),
        "assembler_version": ASSEMBLER_VERSION,
    }
