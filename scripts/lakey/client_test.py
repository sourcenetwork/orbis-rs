"""Exercise the private executable interface without printing keys or witnesses."""
import json
import os
import subprocess
import unittest


@unittest.skipUnless(os.environ.get("ORBIS_AUDIT_TEST_BINARY"), "set ORBIS_AUDIT_TEST_BINARY")
class AuditClientTest(unittest.TestCase):
    def call(self, operation, version=1):
        return subprocess.run(
            [os.environ["ORBIS_AUDIT_TEST_BINARY"]],
            input=json.dumps({"version": version, "operation": operation}).encode(),
            capture_output=True, timeout=10,
        )

    def test_capabilities_and_private_reader_registration(self):
        result = self.call({"kind": "capabilities"})
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), {"protocol": 1, "lakey": 1, "shieldd_selection": 2})
        first = self.call({"kind": "generate_reader"})
        second = self.call({"kind": "generate_reader"})
        self.assertEqual(first.returncode, 0)
        self.assertEqual(second.returncode, 0)
        one, two = json.loads(first.stdout), json.loads(second.stdout)
        self.assertNotEqual(one["reader"], two["reader"])
        self.assertEqual(len(one["secret"]), 32)
        self.assertEqual(first.stderr, b"")
        verified = self.call({"kind": "verify_reader", "reader": one["reader"], "proof": one["proof"]})
        self.assertEqual(verified.returncode, 0)
        self.assertTrue(json.loads(verified.stdout)["verified"])
        changed = self.call({"kind": "verify_reader", "reader": two["reader"], "proof": one["proof"]})
        self.assertNotEqual(changed.returncode, 0)
        self.assertEqual(changed.stdout, b"")
        self.assertEqual(changed.stderr, b"audit operation failed\n")

    def test_invalid_version_and_fields_do_not_echo_input(self):
        for operation, version in [({"kind": "capabilities"}, 2),
                                   ({"kind": "capabilities", "secret": "do-not-log"}, 1)]:
            result = self.call(operation, version)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"" if version == 2 else b'{"status":"rejected"}')
            self.assertEqual(result.stderr, b"audit operation failed\n")

    def test_authentication_identity_does_not_export_seed(self):
        operation = {"kind": "authentication_identity", "authentication_seed": [7] * 32}
        first, second = self.call(operation), self.call(operation)
        self.assertEqual(first.returncode, 0)
        self.assertEqual(first.stdout, second.stdout)
        value = json.loads(first.stdout)
        self.assertEqual(set(value), {"did"})
        self.assertTrue(value["did"].startswith("did:key:"))
        self.assertEqual(first.stderr, b"")


if __name__ == "__main__":
    unittest.main()
