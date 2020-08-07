"""
API for generating key fingerprints.
"""


from chaum.crypto import hashing
from chaum.crypto import keys


FINGERPRINT_LENGTH = 8


def public_key_fingerprint(public_key):
    return hashing.sha256(keys.public_key_bytes(public_key))[:FINGERPRINT_LENGTH]
