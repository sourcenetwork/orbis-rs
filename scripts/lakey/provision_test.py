import json
from pathlib import Path
import unittest

import node_test as fixtures
import provision


class ProvisionTest(unittest.TestCase):
    setUp = fixtures.LocalStateTest.setUp
    tearDown = fixtures.LocalStateTest.tearDown
    write = fixtures.LocalStateTest.write
    binary = fixtures.LocalStateTest.binary
    def prepare(self):
        self.state.unlink()
        self.config.pop("master_digest")
        self.config.update(chain="chain", ring="ring", epoch=1)
        self.write("Programs/Schedules/lakey_init_node.sch", "1\n1\nlakey_init_node-0:1\n1 0\n0\n")
        self.write("Programs/Bytecode/lakey_init_node-0.bc", "synthetic init")
        self.path = self.root / "config.json"

    def save(self):
        self.path.write_text(json.dumps(self.config)); self.path.chmod(0o600)

    def test_initialize_pins_one_local_master(self):
        self.prepare()
        self.binary("from pathlib import Path\np=Path('Persistence/Transactions-P0.data')\np.write_bytes(bytes(8+512*32)); p.chmod(0o600)\n")
        self.save()
        result = provision.initialize(self.path, "12" * 32)
        self.assertTrue(result["initialized"])
        self.assertIn("master_digest", json.loads(self.path.read_text()))
        self.assertFalse((self.root / "lakey.initializing").exists())
        with self.assertRaisesRegex(ValueError, "already exists"):
            provision.initialize(self.path, "13" * 32)

    def test_failed_initialization_cannot_be_blindly_retried(self):
        self.prepare()
        self.binary("raise SystemExit(1)\n")
        self.save()
        with self.assertRaises(Exception): provision.initialize(self.path, "12" * 32)
        self.assertTrue((self.root / "lakey.initializing").exists())
        self.assertNotIn("master_digest", json.loads(self.path.read_text()))
        with self.assertRaisesRegex(ValueError, "operator recovery"):
            provision.initialize(self.path, "13" * 32)

    def test_incomplete_master_never_marks_initialized(self):
        self.prepare()
        self.binary("from pathlib import Path\np=Path('Persistence/Transactions-P0.data')\np.write_bytes(bytes(8)); p.chmod(0o600)\n")
        self.save()
        with self.assertRaisesRegex(ValueError, "invalid initialized"):
            provision.initialize(self.path, "12" * 32)
        self.assertNotIn("master_digest", json.loads(self.path.read_text()))

if __name__ == '__main__': unittest.main()
