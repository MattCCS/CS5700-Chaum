"""
API for signing data and verifying signatures with asymmetric cryptography.
"""

import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from chaum.crypto import exceptions


def sign(data, private_key):
    """
    Signs the given data with the given
    private key, ensuring the integrity
    and authenticity of the message.

    + produces signature (public)
    """

    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA1()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA1()
    )


def verify(data, signature, public_key):
    """
    Verifies the given data under the given
    signature and public key, confirming the
    integrity and authenticity of the message.

    ! raises error if verification failed
    """

    try:
        return public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA1()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA1()
        )
    except cryptography.exceptions.InvalidSignature as err:
        raise exceptions.SignatureVerificationFailedException(err)
