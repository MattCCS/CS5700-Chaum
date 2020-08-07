"""
Hybrid cryptography functions.
"""

from chaum.common import packing
from chaum.crypto import asymmetric
from chaum.crypto import symmetric
from chaum.crypto import exceptions


def hybrid_encrypt(plaintext, public_key):
    (key, iv) = symmetric.generate_key_and_iv()

    # Symmetric encryption of data
    e_msg = symmetric.encrypt(key, iv, plaintext)

    # Asymmetric encryption of key/IV
    k_msg = packing.pack([key, iv])
    ek_msg = asymmetric.public_key_encrypt(k_msg, public_key)

    return packing.pack([ek_msg, e_msg])


def hybrid_decrypt(ciphertext, private_key):
    try:
        (ek_msg, e_msg) = packing.unpack(ciphertext)

        # Asymmetric decryption of key/IV
        k_msg = asymmetric.private_key_decrypt(ek_msg, private_key)
        (key, iv) = packing.unpack(k_msg)

        # Symmetric decryption of data
        plaintext = symmetric.decrypt(key, iv, e_msg)

        return plaintext
    except (TypeError, ValueError, exceptions.AsymmetricEncryptionException) as exc:
        raise exceptions.HybridEncryptionException from exc
