
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2] / "src")
)

from wgao.policy_integrity import signature, render_current, repair


def example():
    return {"nftables": [
        {"metainfo": {"version": "1.1"}},
        {"table": {
            "family": "inet", "name": "wgao_demo", "handle": 1
        }},
        {"set": {
            "family": "inet", "table": "wgao_demo",
            "name": "clients_g1", "type": "ipv4_addr",
            "elem": ["10.77.0.100"], "handle": 2
        }},
        {"chain": {
            "family": "inet", "table": "wgao_demo",
            "name": "forward", "type": "filter",
            "hook": "forward", "prio": 0,
            "policy": "drop", "handle": 3
        }},
        {"rule": {
            "family": "inet", "table": "wgao_demo",
            "chain": "forward",
            "expr": [{"drop": None}], "handle": 4
        }}
    ]}


class PolicyIntegrityTests(unittest.TestCase):

    def test_ignores_dynamic_elements(self):
        a, b = example(), example()
        b["nftables"][2]["set"]["elem"] = ["10.77.0.101"]
        b["nftables"][3]["chain"]["handle"] = 99
        self.assertEqual(
            signature(json.dumps(a)),
            signature(json.dumps(b))
        )

    def test_detects_injected_rule(self):
        a, b = example(), example()
        b["nftables"].append({"rule": {
            "family": "inet", "table": "wgao_demo",
            "chain": "forward", "expr": [{"accept": None}]
        }})
        self.assertNotEqual(
            signature(json.dumps(a)),
            signature(json.dumps(b))
        )

    def test_policy_default_deny(self):
        config = {
            "vpn_interface": "wg0",
            "resource_interface": "eth1",
            "groups": {"1": [("10.200.1.10", 443)]}
        }
        policy = render_current(
            config, {"1": {"10.77.0.100"}}
        )
        self.assertIn("policy drop", policy)
        self.assertIn("tcp dport 443", policy)
        self.assertNotIn("tcp dport 444", policy)

    def test_atomic_repair_scope(self):
        config = {
            "vpn_interface": "wg0",
            "resource_interface": "eth1",
            "groups": {"1": [("10.200.1.10", 443)]}
        }
        runner = Mock()
        repair(
            "wgao-gw-12345", config,
            {"1": {"10.77.0.100"}}, runner
        )
        self.assertEqual(runner.call_count, 2)
        batch = runner.call_args.kwargs["stdin"]
        self.assertTrue(
            batch.startswith("delete table inet wgao_demo")
        )
        self.assertNotIn("flush ruleset", batch)


if __name__ == "__main__":
    unittest.main()
