"""
API for generating key fingerprints.
"""


from cryptography.hazmat.primitives import serialization

from chaum.crypto import hashing


FINGERPRINT_LENGTH = 8


def public_key_fingerprint(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashing.sha256(pem)[:FINGERPRINT_LENGTH]
