#!/usr/bin/env python3
"""Unit tests for the McTiny stderr parser in mctiny_session_launcher.py.
SAMPLE is cut from a real mctiny-client run (mctiny-20200804). Run:
python3 -m unittest eval/scripts/test_mctiny_stderr.py
"""
import base64
import gzip
import unittest

import mctiny_session_launcher as launcher

SAMPLE = """\
> 1791820295.995696 810 65...400000
< 1791820295.996181 121 86...800100
cookie0
> 1791820295.996222 1226 86...800040
> 1791820295.996252 1226 86...800041
< 1791820296.026395 133 b9...932160
> 1791820296.026405 315 86...80feff
< 1791820296.026458 315 69...d4ffff
client ksession d2...d5
client packets sent 971 received 971
client bytes sent 1188422 received 135977
"""

FIRST_SENT = 1791820295.995696
LAST_RECEIVED = 1791820296.026458


class ParserTest(unittest.TestCase):
    def test_events_keep_packet_lines_only(self):
        kinds = [kind for _, kind in launcher.packet_events(SAMPLE)]
        self.assertEqual(kinds, ["sent", "received", "sent", "sent", "received", "sent", "received"])

    def test_network_seconds_first_sent_to_last_received(self):
        self.assertAlmostEqual(launcher.network_seconds(SAMPLE), LAST_RECEIVED - FIRST_SENT)

    def test_last_received_is_the_latest_timestamp_not_the_last_line(self):
        reordered = SAMPLE + "< 1791820290.000000 10 00...000000\n"
        self.assertAlmostEqual(launcher.network_seconds(reordered), LAST_RECEIVED - FIRST_SENT)

    def test_none_without_both_directions(self):
        self.assertIsNone(launcher.network_seconds("> 1.0 10 00...000000\n> 2.0 10 00...000000\n"))
        self.assertIsNone(launcher.network_seconds("< 1.0 10 00...000000\n"))

    def test_none_for_unknown_format_and_empty(self):
        self.assertIsNone(launcher.network_seconds("no timestamps here\nsent received\n"))
        self.assertIsNone(launcher.network_seconds(""))

    def test_summary_numbers_still_parse(self):
        numbers = launcher.session_numbers(SAMPLE)
        self.assertEqual((numbers["packets_sent"], numbers["packets_received"]), (971, 971))

    def test_compress_round_trip(self):
        packed = launcher.compress_stderr(SAMPLE)
        self.assertEqual(gzip.decompress(base64.b64decode(packed)).decode(), SAMPLE)

    def test_as_text(self):
        self.assertEqual(launcher.as_text(None), "")
        self.assertEqual(launcher.as_text(b"ab"), "ab")


if __name__ == "__main__":
    unittest.main()
