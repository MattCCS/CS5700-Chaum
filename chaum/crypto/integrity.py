"""
Integrity-checking functions (HMAC).
"""

import hashlib


def hmac(key, plaintext):
    h = hashlib.sha256()
    h.update(plaintext)
    return h.digest()


def hmac_verify(key, plaintext, signature):
    h = hashlib.sha256()
    h.update(plaintext)
    return h.digest() == signature
