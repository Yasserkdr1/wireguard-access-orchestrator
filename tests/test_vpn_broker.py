import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

path = Path(__file__).resolve().parents[1] / "legacy/appsclub_vpn_broker.py"
spec = importlib.util.spec_from_file_location("vpn_broker", path)
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)

class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        p = Path(self.temp.name)
        self.patches = [patch.object(b, "DB_PATH", p / "devices.sqlite3"),
                        patch.object(b, "DYNAMIC", p / "dynamic-peers.json")]
        for x in self.patches:
            x.start()
            self.addCleanup(x.stop)

    def test_public_key_validation(self):
        self.assertFalse(b.valid_public_key("abc"))
        self.assertTrue(b.valid_public_key("gROnxTFxvIOFT52uJAl2wr0M7uNecCSCI+b5L3PsxHM="))

    def test_registry_contains_only_public_ip_metadata(self):
        conn = b.connect()
        with conn:
            conn.execute("INSERT INTO devices VALUES (?,?,?,?,?,?,?)", (
                "a" * 32, 7, 2, "10.77.0.100/32", "dummy-public-key", "Laptop", 10))
        b.publish_dynamic(conn)
        data = json.loads(b.DYNAMIC.read_text())
        self.assertEqual(data, {"2": {"peers": ["10.77.0.100/32"]}})
        self.assertNotIn("PrivateKey", b.DYNAMIC.read_text())
        conn.close()

    def test_team_change_revokes_existing_device(self):
        conn = b.connect()
        with conn:
            conn.execute("INSERT INTO devices VALUES (?,?,?,?,?,?,?)", (
                "b" * 32, 7, 2, "10.77.0.100/32", "oldpub", "Laptop", 10))
        self.assertEqual(b.revoke_invalid(conn, {7: 3}), 1)
        self.assertEqual(conn.execute("SELECT count(*) FROM devices").fetchone()[0], 0)
        self.assertEqual(conn.execute("SELECT public_key FROM retired_keys").fetchone()[0], "oldpub")
        conn.close()

    def test_banned_user_has_no_eligible_roster(self):
        with patch.object(b, "get_roster", return_value={12: 3}):
            with self.assertRaises(PermissionError):
                b.fetch_valid_user({"user_id": 7})

    def test_alloc_does_not_reuse_static_wireguard_ip(self):
        conn = b.connect()
        with patch.object(b, "current_gateway_ips", return_value={"10.77.0.100/32"}):
            self.assertEqual(b.allocate_ip(conn), "10.77.0.101/32")
        conn.close()

    def test_private_key_never_saved_to_db(self):
        with patch.object(b, "get_roster", return_value={7: 2}), \
             patch.object(b, "current_gateway_ips", return_value=set()), \
             patch.object(b, "generate_pair", return_value=("SECRET-DO-NOT-STORE", "gROnxTFxvIOFT52uJAl2wr0M7uNecCSCI+b5L3PsxHM=")), \
             patch.object(b, "command", return_value="tXkjO+7JUjST7U4QgZ9VVC0CFcuhoRB3DOG0vPM+4Qo="), \
             patch.object(b, "exclusive", return_value=__import__('contextlib').nullcontext()):
            result = b.issue({"user_id": 7, "label": "Laptop"})
        self.assertIn("SECRET-DO-NOT-STORE", result["config"])
        self.assertNotIn(b"SECRET-DO-NOT-STORE", b.DB_PATH.read_bytes())
        self.assertEqual(json.loads(b.DYNAMIC.read_text()), {"2": {"peers": ["10.77.0.100/32"]}})

if __name__ == "__main__":
    unittest.main()

# Tests for revocation / cleanup semantics are intentionally at the bottom so
# they can run without a CTFd import or an actual WireGuard interface.
class RevocationTests(BrokerTests):
    def test_revoke_only_own_device(self):
        conn = b.connect()
        with conn:
            conn.execute("INSERT INTO devices VALUES (?,?,?,?,?,?,?)", (
                "c" * 32, 71, 2, "10.77.0.100/32", "pub-71", "Laptop", 10))
            conn.execute("INSERT INTO devices VALUES (?,?,?,?,?,?,?)", (
                "d" * 32, 72, 2, "10.77.0.101/32", "pub-72", "Laptop", 10))
        conn.close()
        with patch.object(b, "get_roster", return_value={71: 2, 72: 2}), \
             patch.object(b, "sync_wg", return_value=None), \
             patch.object(b, "exclusive", return_value=__import__('contextlib').nullcontext()):
            with self.assertRaises(ValueError):
                b.revoke({"user_id": 71, "device_id": "d" * 32})
            self.assertTrue(b.revoke({"user_id": 71, "device_id": "c" * 32})["revoked"])
        conn = b.connect()
        self.assertEqual(conn.execute("SELECT user_id FROM devices").fetchone()[0], 72)
        conn.close()

    def test_unknown_dynamic_key_is_removed(self):
        with patch.object(b, "command") as mock:
            mock.side_effect = ["KEY 10.77.0.101/32\nSTATIC 10.77.0.10/32", ""]
            b.remove_unknown_dynamic(set())
            self.assertEqual(mock.call_count, 2)
            self.assertEqual(mock.call_args_list[1].args[0][-2:], ["KEY", "remove"])
