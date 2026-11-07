#!/usr/bin/env python3
"""Test dionaea/mssql_patch.py (#3658).

Runs the TDS receive loop from upstream mssql.py, before and after the patch,
against a stand-in TDS_Header that parses a short buffer the way dionaea's
packet layer does: a buffer too short for the Length field leaves Length at
its default of 0 (verified against the deployed image: declared Length 1 and
2 re-parse to 0, 3 raises).

The stand-in counts parses. After a bound far beyond what any real buffer
needs it records a runaway and returns a valid header, so an unpatched loop
ends instead of hanging the test run.

Usage: dionaea/tests/test_mssql_patch.py
"""
import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent / "mssql_patch.py"
SPEC = importlib.util.spec_from_file_location("mssql_patch", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

TDS_STATUS_EOM = 0x01
RUNAWAY_BOUND = 10000

# The receive loop as upstream ships it, up to the point where a complete
# message is handed on. The patch's OLD block sits inside it verbatim.
UPSTREAM_LOOP = '''
class Handler:
    def __init__(self):
        self.buf = b''
        self.pendingPacketType = None

    def handle_io_in(self, data):
        l = 0
        chunk = b''
        while len(data) > l:
            # logger.warning("len(data) %d l %s", len(data), l)
            p = None
            try:
                if len(data) - l < 8:  # length of TDS_Header
                    logger.warning("Incomplete TDS_Header")
                    return l

                p = TDS_Header(data[l:l+8])
                p.show()

{old}

                if len(data[l:]) < p.Length:
                    return l

                chunk = data[l:l+p.Length]
                p = TDS_Header(chunk)

                l += p.Length
                self.buf += chunk[8:]
                self.pendingPacketType = p.Type

                if p.Status != TDS_STATUS_EOM:
                    # Command spans multiple packets TDS_ things
                    # this is not the last packet
                    continue
            except:
                return l

            return l
        return l
'''.format(old=MODULE.OLD)


class Logger:
    def warning(self, *args):
        pass


class Parser:
    """Builds TDS_Header stand-ins and remembers whether the loop ran away."""

    def __init__(self):
        self.parses = 0
        self.runaway = False

    def header(self, raw):
        parser = self

        class TDSHeader:
            def __init__(self, b):
                parser.parses += 1
                if parser.parses > RUNAWAY_BOUND:
                    parser.runaway = True
                    b = bytes([0x12, TDS_STATUS_EOM, 0, 8, 0, 0, 0, 0])
                self.Type = b[0] if len(b) > 0 else 0x12
                self.Status = b[1] if len(b) > 1 else 0
                if len(b) >= 4:
                    self.Length = struct.unpack(">H", b[2:4])[0]
                elif len(b) == 3:
                    raise struct.error("unpack requires a buffer of 2 bytes")
                else:
                    self.Length = 0

            def show(self):
                pass

        return TDSHeader(raw)


def handler_for(text):
    parser = Parser()
    scope = {"logger": Logger(), "TDS_Header": parser.header, "TDS_STATUS_EOM": TDS_STATUS_EOM}
    exec(compile(text, "<mssql.py>", "exec"), scope)
    return scope["Handler"](), parser


def patched_loop():
    with tempfile.TemporaryDirectory() as d:
        target = Path(d) / "mssql.py"
        target.write_text(UPSTREAM_LOOP)
        MODULE.apply_patch(target)
        return target.read_text()


def header(length, status=0):
    return bytes([0x12, status]) + struct.pack(">H", length) + bytes(4)


class ShortLengthNoLongerSpins(unittest.TestCase):
    def test_upstream_loop_runs_away_on_length_1_and_2(self):
        # Proves the stand-in reproduces the live failure, so the next test
        # means something.
        for length in (1, 2):
            with self.subTest(length=length):
                handler, parser = handler_for(UPSTREAM_LOOP)
                handler.handle_io_in(header(length))
                self.assertTrue(parser.runaway)

    def test_patched_loop_returns_for_every_short_length(self):
        for length in range(0, 8):
            with self.subTest(length=length):
                handler, parser = handler_for(patched_loop())
                consumed = handler.handle_io_in(header(length))
                self.assertFalse(parser.runaway)
                self.assertEqual(consumed, 0)

    def test_patched_loop_still_reads_valid_packets(self):
        # Two packets in one buffer: the first not end-of-message, the second
        # is. Both must be consumed and their payloads joined.
        first = header(12) + b"abcd"
        second = header(10, TDS_STATUS_EOM) + b"ef"
        handler, parser = handler_for(patched_loop())
        consumed = handler.handle_io_in(first + second)
        self.assertFalse(parser.runaway)
        self.assertEqual(consumed, len(first) + len(second))
        self.assertEqual(handler.buf, b"abcdef")

    def test_patched_loop_waits_for_the_rest_of_a_split_packet(self):
        handler, parser = handler_for(patched_loop())
        self.assertEqual(handler.handle_io_in(header(20) + b"partial"), 0)
        self.assertFalse(parser.runaway)


class AppliesCleanly(unittest.TestCase):
    def test_applies_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "mssql.py"
            target.write_text(UPSTREAM_LOOP)
            self.assertIn("now rejected", MODULE.apply_patch(target))
            once = target.read_text()
            self.assertIn("already patched", MODULE.apply_patch(target))
            self.assertEqual(once, target.read_text())

    def test_refuses_to_patch_a_file_it_does_not_recognise(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "mssql.py"
            target.write_text("# an mssql.py this patch was not written against\n")
            with self.assertRaises(SystemExit):
                MODULE.apply_patch(target)


if __name__ == "__main__":
    unittest.main()
