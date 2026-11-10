import sys
import unittest
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2])
)

from tools.metrics import parse_log, summarize

class MetricsTests(unittest.TestCase):

    def test_latency_extraction(self):
        result = parse_log(
            "authorized peer restored in 292 ms", "full"
        )
        self.assertEqual(
            result["durations_ms"]["peer_restoration_ms"],
            [292]
        )

    def test_partial_logs_fail(self):
        self.assertFalse(
            parse_log("CONNECTED", "full")["passed"]
        )

    def test_error_exit_fails(self):
        result = parse_log(
            "SUCCESS: ACTIVE VPN fail-closed validated",
            "active-fail-closed", 1
        )
        self.assertFalse(result["passed"])

    def test_empty_summary(self):
        self.assertIn("0/0", summarize([]))
