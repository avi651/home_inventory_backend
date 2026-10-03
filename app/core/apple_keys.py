"""The Sign in with Apple signing key (.p8): shared by settings validation and the client."""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def load_apple_private_key(pem: str) -> ec.EllipticCurvePrivateKey:
    """The .p8 key as an ES256 (P-256) signing key. Accepts `\\n`-escaped newlines (env vars).

    Raises ValueError with a fixed message: never echoes key material.
    """
    try:
        key = load_pem_private_key(pem.replace("\\n", "\n").encode(), password=None)
    except ValueError, TypeError:
        raise ValueError("not a PEM private key") from None
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("not a P-256 (ES256) key")
    return key
