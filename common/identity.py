from __future__ import annotations
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def verify_signature(data: bytes, signature: bytes, public_key_pem: str) -> bool:
    """Verify an RSA-PKCS1v15-SHA256 signature against a PEM public key."""
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except (InvalidSignature, ValueError, TypeError, Exception):
        return False


class NodeIdentity:
    """File-backed RSA identity used when no TPM is available.

    The private key never leaves the configured key path and is optionally
    encrypted with a passphrase derived from the cluster password (PBKDF2 via
    BestAvailableEncryption).
    """

    def __init__(self, key_path: str, passphrase: Optional[str] = None):
        self.key_path = Path(key_path)
        self.passphrase = passphrase
        self._private_key = self._load_or_generate()

    def _load_or_generate(self):
        if self.key_path.exists():
            try:
                return self._load()
            except Exception:
                print(f"[identity] corrupt key at {self.key_path}; regenerating")
        return self._generate_and_save()

    def _load(self):
        data = self.key_path.read_bytes()
        return serialization.load_pem_private_key(data, password=self._password_bytes())

    def _generate_and_save(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        if self._password_bytes() is not None:
            encryption = serialization.BestAvailableEncryption(self._password_bytes())
        else:
            encryption = serialization.NoEncryption()
        self.key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                encryption,
            )
        )
        return key

    def _password_bytes(self) -> Optional[bytes]:
        return self.passphrase.encode("utf-8") if self.passphrase else None

    def sign_payload(self, data: bytes) -> bytes:
        return self._private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    def get_public_key_pem(self) -> str:
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def save_public_key(self, path: str):
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(self.get_public_key_pem())
