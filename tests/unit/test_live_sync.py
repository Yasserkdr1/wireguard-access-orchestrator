
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2] / "src")
)

from wgao.live_sync import NS_PATTERN, parse_set, synchronize


class LiveSyncTests(unittest.TestCase):

    def test_parse_nft_set(self):
        data = {
            "nftables": [
                {"set": {
                    "name": "clients_g1",
                    "elem": ["10.77.0.100", "10.77.0.101"]
                }}
            ]
        }
        self.assertEqual(
            parse_set(json.dumps(data), "1"),
            {"10.77.0.100", "10.77.0.101"}
        )

    def test_empty_set(self):
        data = {"nftables": [
            {"set": {"name": "clients_g2"}}
        ]}
        self.assertEqual(
            parse_set(json.dumps(data), "2"), set()
        )

    def test_reject_invalid_set(self):
        data = {"nftables": [
            {"set": {
                "name": "clients_g1",
                "elem": [{"prefix": "0/0"}]
            }}
        ]}
        with self.assertRaises(RuntimeError):
            parse_set(json.dumps(data), "1")

    def test_reject_host_namespace(self):
        self.assertTrue(
            NS_PATTERN.fullmatch("wgao-gw-12345")
        )
        with self.assertRaises(ValueError):
            synchronize(
                "default", "/tmp/unused",
                "/tmp/unused", "/tmp/unused",
                apply=True
            )

    def test_dry_run_detects_missing_access(self):
        key = "A" * 43 + "="
        desired = (
            {"1": {"10.77.0.100"}},
            {key: "10.77.0.100/32"},
            {
                "vpn_interface": "wg0",
                "resource_interface": "eth1"
            }
        )
        with (
            patch(
                "wgao.live_sync.subprocess.run",
                return_value=SimpleNamespace(
                    stdout="wgao-gw-12345\n"
                )
            ),
            patch(
                "wgao.live_sync.desired_state",
                return_value=desired
            ),
            patch(
                "wgao.live_sync.live_state",
                return_value=({"1": set()}, {})
            ),
            patch("wgao.live_sync.run") as command
        ):
            result = synchronize(
                "wgao-gw-12345",
                "test.db", "roster.json",
                "resources.json", apply=False
            )

            self.assertEqual(result["set_updates"], ["1"])
            self.assertEqual(result["peers_add_or_fix"], 1)
            command.assert_not_called()


    def test_lockdown_rejects_host_namespace(self):
        from wgao.live_sync import emergency_lockdown

        with self.assertRaises(ValueError):
            emergency_lockdown("default")

    def test_lockdown_targets_lab_namespace(self):
        from wgao.live_sync import emergency_lockdown

        with patch("wgao.live_sync.subprocess.run") as command:
            command.return_value = SimpleNamespace(
                stdout="wgao-gw-12345\n"
            )

            emergency_lockdown("wgao-gw-12345")

            self.assertEqual(command.call_count, 2)
            self.assertEqual(
                command.call_args_list[1].args[0],
                [
                    "ip", "-n", "wgao-gw-12345",
                    "link", "set", "dev", "wg0", "down"
                ]
            )

if __name__ == "__main__":
    unittest.main()
