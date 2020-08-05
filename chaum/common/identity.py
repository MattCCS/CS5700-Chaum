"""
Identity storage and management.
"""

import os
import pathlib

from chaum import config
from chaum.crypto import keys

KEYS_PATH = config.ROOT.parent / "keys"
PUBLIC_KEYS_PATH = (KEYS_PATH / "public")
PRIVATE_KEYS_PATH = KEYS_PATH


class Identity(object):
    """docstring for Identity"""

    def __init__(self, identifier, address, port, public_key=None):
        super(Identity, self).__init__()
        self.identifier = identifier
        self.address = address
        self.port = port
        self.public_key = public_key

    def __repr__(self):
        return f"<{self.__class__.__name__} {vars(self)}>"


def load_public_identities():
    public_keys_path = (KEYS_PATH / "public")
    public_filenames = os.listdir(public_keys_path)
    identifiers = [pathlib.Path(f).stem for f in public_filenames if f.endswith(".pub")]

    for identifier in identifiers:
        print(f"Loading identifier: {identifier}")
        identity_data = config.load("nodes")[identifier]
        (address, port) = (identity_data["address"], identity_data["port"])
        yield Identity(identifier, address, port, public_key=load_public_key(identifier))


def load_public_key(identifier):
    return keys.load_public_key((PUBLIC_KEYS_PATH / identifier).with_suffix(".pub"))


def load_public_key_abs(abs_path):
    raise NotImplementedError()


def load_private_key(identifier):
    return keys.load_private_key(PRIVATE_KEYS_PATH / identifier / f"{identifier}.priv")


NODES = list(load_public_identities())
