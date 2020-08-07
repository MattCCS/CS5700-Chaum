"""
Identity storage and management.
"""

from chaum import config
from chaum.common import logtools
from chaum.crypto import fingerprint
from chaum.crypto import keys

logger = logtools.new_logger(__loader__.name)
KEYS_PATH = config.ROOT.parent / "keys"
PRIVATE_KEYS_PATH = (KEYS_PATH / "private")

PUBLIC_NODES = None


class Identity(object):
    """docstring for Identity"""

    def __init__(self, identifier, address, port, public_key=None):
        super(Identity, self).__init__()
        self.identifier = identifier
        self.address = address
        self.port = port
        self.public_key = public_key
        self.private_key = None
        self.fingerprint = fingerprint.public_key_fingerprint(public_key)

    def __repr__(self):
        return f"<{self.__class__.__name__} {vars(self)}>"


def load_node_identities():
    identifiers = config.load_safe("nodes").keys()
    for identifier in identifiers:
        yield load_node_identity(identifier)


def load_node_identity(identifier):
    logger.info(f"Loading identifier: {identifier}")
    node_identities = config.load_safe("nodes")
    try:
        identity_data = node_identities[identifier]
    except KeyError:
        logger.critical(f"[!] Configuration for node {repr(identifier)} not found!\nChoose from: {list(node_identities.keys())}\n")
        config.exit_with_generic_warning()
    (address, port) = (identity_data["address"], identity_data["port"])
    return Identity(identifier, address, port, public_key=load_public_key(identifier, identity_data))


def load_client_identities():
    identifiers = config.load_safe("clients").keys()
    for identifier in identifiers:
        yield load_client_identity(identifier)


def load_client_identity(identifier):
    logger.info(f"[ ] Loading client: {identifier}")
    client_identities = config.load_safe("clients")
    try:
        identity_data = client_identities[identifier]
    except KeyError:
        logger.critical(f"[!] Configuration for client {repr(identifier)} not found!\nChoose from: {list(client_identities.keys())}\n")
        config.exit_with_generic_warning()
    public_key_path = identity_data["public_key"]
    return Identity(identifier, None, None, load_public_key_rel(public_key_path))


def load_public_key(identifier, identity_data):
    return keys.load_public_key(KEYS_PATH / identity_data["public_key"])


def load_public_key_rel(rel_path):
    return keys.load_public_key(KEYS_PATH / rel_path)


def load_private_key(identifier):
    return keys.load_private_key(PRIVATE_KEYS_PATH / identifier / f"{identifier}.priv")


def get_public_nodes():
    global PUBLIC_NODES
    if PUBLIC_NODES is None:
        PUBLIC_NODES = {e.identifier: e for e in load_node_identities()}
    return PUBLIC_NODES
