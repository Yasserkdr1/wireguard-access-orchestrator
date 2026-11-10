import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from wgao.broker import (
    register_device, list_devices, revoke_device, reconcile_local,
    desired_access_by_group, open_db, validate_public_key,
)


def pubkey(i: int) -> str:
    return base64.b64encode(bytes([i]) * 32).decode("ascii")


class LocalBrokerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "data" / "peers.sqlite3"
        self.roster = Path(self.tmp.name) / "roster.json"
        self.write_roster([{ "user_id": 7, "group_id": 1 }, { "user_id": 12, "group_id": 2 }])

    def write_roster(self, members):
        self.roster.write_text(json.dumps({"members": members}), encoding="utf-8")

    def register(self, uid=7, label="Laptop", k=1):
        return register_device(self.db, self.roster, uid, label, pubkey(k))

    def test_registration_and_registry_no_private_keys(self):
        d = self.register()
        self.assertEqual(d["ip"], "10.77.0.100/32")
        self.assertEqual(d["group_id"], 1)
        self.assertEqual(len(list_devices(self.db)), 1)
        self.assertEqual(desired_access_by_group(self.db), {"1": ["10.77.0.100/32"]})
        self.assertNotIn("private_key", self.db.read_bytes().decode("latin1").lower())

    def test_requires_eligible_user(self):
        with self.assertRaises(PermissionError):
            self.register(uid=99)

    def test_public_key_validation_and_duplicates(self):
        self.assertFalse(validate_public_key("test"))
        self.assertTrue(validate_public_key(pubkey(3)))
        self.register()
        with self.assertRaises(ValueError):
            self.register(k=1)

    def test_device_limit(self):
        self.register(k=1)
        self.register(k=2)
        with self.assertRaises(ValueError):
            self.register(k=3)

    def test_group_change_revokes_but_does_not_affect_other_user(self):
        a = self.register(k=1)
        b = self.register(uid=12, k=2)
        self.write_roster([{ "user_id": 7, "group_id": 3 }, { "user_id": 12, "group_id": 2 }])
        result = reconcile_local(self.db, self.roster)
        self.assertEqual(result["removed_from_local_registry"], 1)
        self.assertEqual([d["device_id"] for d in list_devices(self.db)], [b["device_id"]])
        self.assertNotEqual(a["device_id"], b["device_id"])
        with self.assertRaises(ValueError):
            self.register(k=1)  # Old public key retired, never reuse it

    def test_revocation(self):
        a = self.register()
        self.assertEqual(revoke_device(self.db, a["device_id"]), {"revoked": a["device_id"]})
        self.assertEqual(list_devices(self.db), [])
        with self.assertRaises(ValueError):
            self.register(k=1)

    def test_invalid_roster_does_not_destroy_registry(self):
        self.register()
        self.write_roster([{ "user_id": 7, "group_id": True }])
        with self.assertRaises(ValueError):
            reconcile_local(self.db, self.roster)
        self.assertEqual(len(list_devices(self.db)), 1)

    def test_db_permissions(self):
        conn = open_db(self.db)
        conn.close()
        self.assertEqual(self.db.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
