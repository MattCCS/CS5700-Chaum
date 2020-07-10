"""
API for encrypting and decrypting data with asymmetric encryption.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from chaum.crypto import exceptions


def public_key_encrypt(plaintext, public_key):
    """
    Encrypts the given plaintext with the given
    public key using SHA1 and OAEP padding.

    + produces ciphertext (public)
    """

    # not expected to error, since it is
    # always given a string, which it will pad.
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )


def private_key_decrypt(ciphertext, private_key):
    """
    Decrypts the given ciphertext with the given
    private key using SHA1 and OAEP padding.

    + produces plaintext (private!)
    """

    try:
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
    except ValueError as err:
        raise exceptions.AsymmetricEncryptionException(err)
