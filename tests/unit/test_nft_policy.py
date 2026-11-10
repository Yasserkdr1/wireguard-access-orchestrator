import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from wgao.broker import register_device, revoke_device, reconcile_local
from wgao.nft_policy import load_resources, render_policy


class NftPolicyTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.db = self.root / "peers.sqlite3"
        self.roster = self.root / "roster.json"
        self.resources = self.root / "resources.json"
        self.set_roster([{"user_id": 7, "group_id": 1}, {"user_id": 12, "group_id": 2}])
        self.set_resources({
            "vpn_interface": "wg0", "resource_interface": "eth1",
            "groups": {"1": [{"address": "10.200.1.10", "port": 443}],
                       "2": [{"address": "10.200.2.10", "port": 22}]},
        })

    def set_roster(self, members):
        self.roster.write_text(json.dumps({"members": members}))

    def set_resources(self, data):
        self.resources.write_text(json.dumps(data))

    def register(self, user=7, key_num=1):
        pub = base64.b64encode(bytes([key_num]) * 32).decode("ascii")
        return register_device(self.db, self.roster, user, "laptop", pub)

    def render(self):
        return render_policy(self.db, self.roster, self.resources)

    def test_render_group_set_and_default_drop(self):
        self.register()
        script = self.render()
        self.assertIn("table inet wgao_demo", script)
        self.assertIn("set clients_g1", script)
        self.assertIn("elements = { 10.77.0.100 };", script)
        self.assertIn("policy drop", script)
        self.assertIn('ip saddr @clients_g1 ip daddr 10.200.1.10 tcp dport 443', script)
        self.assertIn('ip daddr @clients_g1 ct state established accept', script)
        self.assertNotIn('ct state established,related accept', script)
        self.assertNotIn('flush ruleset', script)
        self.assertNotIn('nft add', script)

    def test_revocation_removes_group_ip_from_preview(self):
        dev = self.register()
        self.assertIn("10.77.0.100", self.render())
        revoke_device(self.db, dev["device_id"])
        self.assertNotIn("10.77.0.100", self.render())
        self.assertIn("set clients_g1", self.render())

    def test_stale_roster_fails_closed_until_reconcile(self):
        self.register()
        self.set_roster([{"user_id": 7, "group_id": 2}])
        with self.assertRaisesRegex(ValueError, "Stale device membership"):
            self.render()
        reconcile_local(self.db, self.roster)
        self.assertNotIn("10.77.0.100", self.render())

    def test_unknown_active_group_fails_closed(self):
        self.set_roster([{"user_id": 7, "group_id": 3}])
        self.register()
        with self.assertRaisesRegex(ValueError, "No resource policy"):
            self.render()

    def test_group2_separated_from_group1(self):
        self.register(key_num=1)
        self.register(user=12, key_num=2)
        script = self.render()
        self.assertIn("elements = { 10.77.0.101 };", script)
        self.assertIn("ip saddr @clients_g2 ip daddr 10.200.2.10", script)
        self.assertNotIn("ip saddr @clients_g1 ip daddr 10.200.2.10", script)

    def test_invalid_interface_injection_rejected(self):
        r = json.loads(self.resources.read_text())
        r["vpn_interface"] = 'wg0"; flush ruleset'
        self.set_resources(r)
        with self.assertRaisesRegex(ValueError, "Interface names"):
            load_resources(self.resources)

    def test_public_address_rejected_for_demo(self):
        r = json.loads(self.resources.read_text())
        r["groups"]["1"] = [{"address": "8.8.8.8", "port": 443}]
        self.set_resources(r)
        with self.assertRaisesRegex(ValueError, "RFC1918"):
            self.render()

    def test_bad_group_port_and_missing_fields_rejected(self):
        original = json.loads(self.resources.read_text())
        for resource in ({"address": "10.200.1.10", "port": True},
                         {"address": "10.200.1.10", "port": 65536},
                         {"address": "10.200.1.10"}):
            with self.subTest(resource=resource):
                r = json.loads(json.dumps(original))
                r["groups"]["1"] = [resource]
                self.set_resources(r)
                with self.assertRaises(ValueError):
                    self.render()
        self.set_resources(original)

if __name__ == "__main__":
    unittest.main()
