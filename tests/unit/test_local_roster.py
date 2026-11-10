import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from wgao.roster import load_roster

class LocalRosterTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "roster.json"

    def write(self, members):
        self.path.write_text(json.dumps({"members": members}))

    def test_valid_groups(self):
        self.write([{"user_id": 7, "group_id": 1}, {"user_id": 8, "group_id": 2}])
        self.assertEqual(load_roster(self.path), {7: 1, 8: 2})

    def test_duplicate_user_fail_closed(self):
        self.write([{"user_id": 7, "group_id": 1}, {"user_id": 7, "group_id": 2}])
        with self.assertRaises(ValueError):
            load_roster(self.path)

    def test_bool_id_rejected(self):
        self.write([{"user_id": True, "group_id": 1}])
        with self.assertRaises(ValueError):
            load_roster(self.path)

    def test_invalid_group_rejected(self):
        self.write([{"user_id": 7, "group_id": 400}])
        with self.assertRaises(ValueError):
            load_roster(self.path)

if __name__ == '__main__':
    unittest.main()
