import hashlib
import importlib.util
import os
import json
import subprocess
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("lakey_node", Path(__file__).with_name("node.py"))
node = importlib.util.module_from_spec(spec)
spec.loader.exec_module(node)

class LocalStateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for name in ["Persistence", "Player-Data", "Programs/Schedules", "Programs/Bytecode"]:
            (self.root/name).mkdir(parents=True,mode=0o700,exist_ok=True)
        self.state = self.root/"Persistence/Transactions-P0.data"
        self.state.write_bytes(bytes(8+512*32)); self.state.chmod(0o600)
        key = self.root/"Player-Data/P0.key"; key.write_text("synthetic"); key.chmod(0o600)
        self.artifacts = {}
        for peer in range(5): self.write(f"Player-Data/P{peer}.pem", "synthetic certificate")
        self.write("peers", "127.0.0.1\n"*5)
        self.write("Programs/Schedules/lakey_derive_node.sch", "1\n1\nlakey_derive_node-0:1\n1 0\n0\n")
        self.write("Programs/Bytecode/lakey_derive_node-0.bc", "synthetic")
        self.config = dict(node=0,nodes=5,threshold=3,root=str(self.root),timeout_seconds=1,artifacts=self.artifacts,master_digest=hashlib.sha256(self.state.read_bytes()).hexdigest())
    def tearDown(self): self.tmp.cleanup()
    def write(self,name,text):
        path = self.root/name; path.write_text(text); path.chmod(0o700)
        self.artifacts[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    def binary(self,body): self.write("malicious-shamir-party.x", "#!/usr/bin/env python3\n"+body)
    def derive(self): return node.derive(self.config,[1]*(16*512),"01"*32)
    def test_failed_execution_marks_changed_master(self):
        self.binary("from pathlib import Path\np=Path('Persistence/Transactions-P0.data')\nb=bytearray(p.read_bytes()); b[8]=1; p.write_bytes(b); raise SystemExit(1)\n")
        with self.assertRaises(Exception): self.derive()
        self.assertTrue((self.root/"lakey.recovery-required").exists())
    def test_timeout_removes_transient_slot(self):
        self.binary("import time\nwith open('Persistence/Transactions-P0.data','ab') as f: f.write(bytes(32))\ntime.sleep(5)\n")
        with self.assertRaises(Exception): self.derive()
        self.assertEqual(self.state.stat().st_size,8+512*32)
    def test_foreign_node_state_is_rejected(self):
        self.binary("raise SystemExit(0)\n")
        (self.root/"Persistence/Transactions-P1.data").write_bytes(b"synthetic")
        with self.assertRaisesRegex(ValueError,"another node"): self.derive()
    def test_idle_master_replacement_is_rejected(self):
        changed = bytearray(self.state.read_bytes()); changed[8] = 1; self.state.write_bytes(changed)
        self.binary("with open('Persistence/Transactions-P0.data','ab') as f: f.write(bytes(32))\n")
        with self.assertRaisesRegex(ValueError, "configured master digest"): self.derive()

    def test_unpinned_peer_certificates_are_rejected(self):
        del self.artifacts["Player-Data/P1.pem"]
        self.binary("with open('Persistence/Transactions-P0.data','ab') as f: f.write(bytes(32))\n")
        with self.assertRaisesRegex(ValueError, "peer certificate must be pinned"): self.derive()

    def test_additional_trust_entry_must_be_pinned(self):
        self.binary("raise AssertionError('must not execute')\n")
        (self.root/"Player-Data/01234567.0").write_text("unconfigured trust")
        with self.assertRaisesRegex(ValueError, "trust entry must be pinned"): self.derive()

    def test_changed_artifact_is_rejected(self):
        self.binary("raise SystemExit(0)\n")
        (self.root/"peers").write_text("changed")
        with self.assertRaisesRegex(ValueError,"digest mismatch"): self.derive()

    def test_schedule_cannot_load_an_unpinned_tape(self):
        self.binary("raise SystemExit(0)\n")
        self.write("Programs/Schedules/lakey_derive_node.sch", "1\n1\nother-0:1\n1 0\n0\n")
        with self.assertRaisesRegex(ValueError,"bytecode must be pinned"): self.derive()

    def test_interrupted_slot_is_removed_before_retry(self):
        master = self.state.read_bytes()
        node.persist(self.root/"lakey.in-progress", {"master_size":len(master), "master_digest":hashlib.sha256(master).hexdigest()})
        self.state.write_bytes(master + b"secret transient slot"*2)
        self.binary("from pathlib import Path\np=Path('Persistence/Transactions-P0.data')\nassert p.stat().st_size == 8+512*32\nwith p.open('ab') as f: f.write(bytes(32))\n")
        self.assertEqual(self.derive(), "00"*32)
        self.assertEqual(self.state.read_bytes(), master)
        self.assertFalse((self.root/"lakey.in-progress").exists())

    def test_interrupted_master_mutation_is_quarantined(self):
        master = self.state.read_bytes()
        node.persist(self.root/"lakey.in-progress", {"master_size":len(master), "master_digest":hashlib.sha256(master).hexdigest()})
        changed = bytearray(master); changed[8] = 1; self.state.write_bytes(changed)
        self.binary("raise AssertionError('must not execute')\n")
        with self.assertRaisesRegex(ValueError,"recovery required"): self.derive()
        self.assertTrue((self.root/"lakey.recovery-required").exists())

@unittest.skipUnless(os.environ.get("LAKEY_WORKER_TEST_BINARY"), "requires built LaKey worker")
class WorkerFramingTest(unittest.TestCase):
    def test_complete_request_does_not_wait_for_stdin_eof(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory)/"config.json"
            config.write_text(json.dumps(dict(chain="chain",ring="ring",epoch=1,node=0)))
            child = subprocess.Popen([os.environ["LAKEY_WORKER_TEST_BINARY"], str(config)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                child.stdin.write(b"{}\n"); child.stdin.flush()
                self.assertNotEqual(child.wait(timeout=2), 0)
                self.assertIn(b"phase 2", child.stderr.read())
            finally:
                if child.poll() is None: child.kill()
                child.communicate()

if __name__ == '__main__': unittest.main()
