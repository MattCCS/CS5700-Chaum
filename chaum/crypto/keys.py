"""
API for loading public and private key files by relative or absolute path.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from chaum.crypto import exceptions


def load_private_key(priv_key_path):
    """
    Loads the private key from the given path.

    + produces private key (private!)
    """
    with open(priv_key_path, 'rb') as infile:
        return load_private_key_bytes(infile.read())


def load_public_key(pub_key_path):
    """
    Loads the public key from the given path.

    + produces public key (public)
    """
    with open(pub_key_path, 'rb') as infile:
        return load_public_key_bytes(infile.read())


def load_private_key_bytes(priv_key_bytes):
    """
    Loads the private key from the given bytes.

    + produces private key (private!)
    """

    try:
        private_key = serialization.load_pem_private_key(
            priv_key_bytes,
            password=None,
            backend=default_backend()
        )

        return private_key

    except ValueError as err:
        raise exceptions.PrivateKeyParseException(err)
    except IOError as err:
        raise exceptions.PrivateKeyNotFoundException(err)


def load_public_key_bytes(pub_key_bytes):
    """
    Loads the public key from the given bytes.

    + produces public key (public)
    """

    try:
        public_key = serialization.load_pem_public_key(
            pub_key_bytes,
            backend=default_backend()
        )

        return public_key

    except ValueError as err:
        raise exceptions.PublicKeyParseException(err)
    except IOError as err:
        raise exceptions.PublicKeyNotFoundException(err)


def public_key_bytes(public_key):
    """
    Returns the raw bytes of the given public key.

    + produces public key (public)
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
