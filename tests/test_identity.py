from __future__ import annotations
import tempfile
import unittest
from pathlib import Path

from common.identity import NodeIdentity, verify_signature


class TestIdentity(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _path(self, name: str) -> str:
        return str(Path(self._tmp.name) / name)

    def test_generate_sign_verify(self):
        identity = NodeIdentity(self._path("key.pem"), passphrase="secret")
        data = b"payload"
        signature = identity.sign_payload(data)
        self.assertTrue(verify_signature(data, signature, identity.get_public_key_pem()))

    def test_tampered_data_rejected(self):
        identity = NodeIdentity(self._path("key2.pem"), passphrase=None)
        data = b"payload"
        signature = identity.sign_payload(data)
        self.assertFalse(verify_signature(b"tampered", signature, identity.get_public_key_pem()))

    def test_persistence_roundtrip(self):
        path = self._path("key3.pem")
        identity = NodeIdentity(path, passphrase="secret")
        pub = identity.get_public_key_pem()
        signature = identity.sign_payload(b"x")
        # Reload from disk; must use the same passphrase and produce the same signature.
        reloaded = NodeIdentity(path, passphrase="secret")
        self.assertEqual(pub, reloaded.get_public_key_pem())
        self.assertEqual(signature, reloaded.sign_payload(b"x"))

    def test_wrong_passphrase_falls_back_to_new_key(self):
        path = self._path("key4.pem")
        first = NodeIdentity(path, passphrase="correct")
        pub1 = first.get_public_key_pem()
        # Wrong passphrase -> cannot load -> regenerates a new key (and overwrites).
        second = NodeIdentity(path, passphrase="wrong")
        self.assertNotEqual(pub1, second.get_public_key_pem())

    def test_verify_with_wrong_key_fails(self):
        a = NodeIdentity(self._path("a.pem"))
        b = NodeIdentity(self._path("b.pem"))
        signature = a.sign_payload(b"data")
        self.assertFalse(verify_signature(b"data", signature, b.get_public_key_pem()))


if __name__ == "__main__":
    unittest.main()