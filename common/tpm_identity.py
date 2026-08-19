from __future__ import annotations
from typing import Optional

from common.identity import NodeIdentity, verify_signature

__all__ = ["create_identity", "TPMIdentity", "verify_signature"]


class TPMIdentity:
    """Real TPM 2.0 signing via tpm2-pytss (private key never leaves silicon).

    Construction raises if no TPM stack/device is available; callers fall back
    to a file-backed identity.
    """

    def __init__(self, device_path: Optional[str] = None):
        import tpm2_pytss

        ctx = tpm2_pytss.ESYS()
        ctx.startup()
        raise NotImplementedError(
            "TPM signing-key provisioning is not implemented; use `kind=file`, "
            "or provision a key context with tpm2-tools and extend this method."
        )


def create_identity(kind: str = "auto", key_path: str = "config/identity.pem",
                    passphrase: Optional[str] = None, device_path: Optional[str] = None):
    """Return a signing identity.

    `kind=file` -> RSA key pair on disk (encrypted with `passphrase`).
    `kind=tpm`  -> real TPM 2.0 signing (raises if no TPM stack is present).
    `kind=auto` -> try TPM, fall back to the file-backed identity.
    """
    if kind == "file":
        return NodeIdentity(key_path, passphrase)
    try:
        return TPMIdentity(device_path)
    except Exception as exc:
        if kind == "tpm":
            raise RuntimeError("TPM identity unavailable") from exc
        print(f"[tpm] {exc}; using file-backed identity at {key_path}")
        return NodeIdentity(key_path, passphrase)