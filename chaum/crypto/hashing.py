"""
API for hashing data.
"""

import hashlib


def sha256(bytez):
    """
    Hashes the given bytes with SHA256.
    Returns a hex digest (0-9a-f) of the hash.
    """
    sha = hashlib.sha256()
    sha.update(bytez)
    return sha.hexdigest()
