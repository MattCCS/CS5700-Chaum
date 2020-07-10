"""
API for encrypting and decrypting data with symmetric encryption,
as well as generating AES keys and initialization vectors.
"""

import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from chaum.common import packing
from chaum.crypto import constants
from chaum.crypto import exceptions
from chaum.crypto import integrity


def encrypt_hmac(aes_key, aes_iv, plaintext):
    """Returns packed_ciphertext."""
    ciphertext = encrypt(aes_key, aes_iv, plaintext)
    hmac_sig = integrity.hmac(aes_key, plaintext)
    return packing.pack([aes_iv, ciphertext, hmac_sig])


def decrypt_hmac(aes_key, packed_ciphertext):
    """Returns plaintext."""
    (aes_iv, ciphertext, hmac_sig) = packing.unpack(packed_ciphertext)
    plaintext = decrypt(aes_key, aes_iv, ciphertext)
    if not integrity.hmac_verify(aes_key, plaintext, hmac_sig):
        raise exceptions.IntegrityVerificationFailedException()
    return plaintext


def generate_key_and_iv(key_length=constants.AES_KEY_BYTES, iv_length=constants.AES_IV_BYTES):
    """
    Generates a random AES key and initialization vector
    using the os.urandom method (recommended for cryptographic use).

    + produces AES key and IV (private!)
    """

    aes_key = os.urandom(key_length)
    aes_iv = os.urandom(iv_length)

    return (aes_key, aes_iv)


def encrypt(aes_key, aes_iv, plaintext):
    """
    Encrypts the given plaintext with the given
    key and initialization vector using
    AES-256 in Counter (CTR) mode.

    + produces ciphertext (public)
    """

    assert type(plaintext) is bytes

    backend = default_backend()

    try:
        # AES-256 in CTR mode
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(aes_iv), backend=backend)
        encryptor = cipher.encryptor()

        return encryptor.update(plaintext) + encryptor.finalize()

    except ValueError as err:
        raise exceptions.SymmetricEncryptionException(err)


def decrypt(aes_key, aes_iv, ciphertext):
    """
    Decrypts the given ciphertext with the given
    key and initialization vector using
    AES-256 in Counter (CTR) mode.

    + produces plaintext (private!)
    """

    backend = default_backend()

    try:
        # AES-256 in CTR mode
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(aes_iv), backend=backend)
        decryptor = cipher.decryptor()

        return decryptor.update(ciphertext)

    except ValueError as err:
        raise exceptions.SymmetricEncryptionException(err)
