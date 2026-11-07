#!/usr/bin/env python3
"""Stop one malformed TDS header from wedging dionaea's event loop (#3658).

mssql/mssql.py's handle_io_in() walks the receive buffer with

    while len(data) > l:
        p = TDS_Header(data[l:l+8])
        if p.Length == 0: return l
        ...
        chunk = data[l:l+p.Length]
        p = TDS_Header(chunk)        # re-parsed from the *truncated* chunk
        l += p.Length

A TDS packet's Length counts its own 8-byte header, so anything below 8 is
invalid, but only 0 is rejected. With a declared Length of 1 or 2, `chunk`
is too short to hold the Length field, the re-parse falls back to the
field's default of 0, `l` never advances and the loop never ends.

Observed live on 2026-10-12 19:43:06Z: one connection to 1433 put the main
thread into this loop (py-spy: handle_io_in (mssql.py:48) -> show()), at
100% CPU for 90 hours. Because dionaea runs every protocol on that one
thread, SMB on 445 stopped accepting (accept queue full, healthcheck
timing out), and no dionaea event was indexed until a restart.

This patch rejects every Length below the header size the same way upstream
already rejects 0, so `l` advances by at least 8 on every pass.
"""
from pathlib import Path

MARKER = "honeypot-stack: TDS header length guard (#3658)"
TARGET = Path("/opt/dionaea/lib/dionaea/python/dionaea/mssql/mssql.py")

OLD = """                if p.Length == 0:
                    logger.warning("Bad TDS Header, Length = 0")
                    return l"""

NEW = """                # --- {marker} ---
                # Length includes the 8-byte header. A value of 1 or 2 made
                # the re-parse below read Length=0 and spin here forever.
                if p.Length < 8:
                    logger.warning("Bad TDS Header, Length = %d", p.Length)
                    return l
                # --- end {marker} ---""".format(marker=MARKER)


def apply_patch(target=TARGET):
    """Patch mssql.py in place. Returns the message describing what happened."""
    text = target.read_text()
    if MARKER in text:
        return f"mssql_patch: {target} already patched, skipping"
    if text.count(OLD) != 1:
        raise SystemExit(
            "mssql_patch: expected exactly one occurrence of the Length == 0 "
            "TDS header check, refusing to patch blind"
        )
    target.write_text(text.replace(OLD, NEW, 1))
    return f"mssql_patch: TDS headers with Length < 8 are now rejected in {target}"


if __name__ == "__main__":
    print(apply_patch())
