"""
API for constructing Chaum-routed payloads.
"""

import random

from chaum.common import identity as identity_module
from chaum.common import packing
from chaum.crypto import hybrid


def random_route(destination, identities=identity_module.NODES, length=3):
    return random.sample(identities, k=length) + [destination]


def encapsulate(data, identity):
    # Encrypt and address.
    e_msg = hybrid.hybrid_encrypt(data, identity.public_key) if identity.public_key else data
    next_hop = [identity.identifier, identity.address, identity.port]
    return packing.pack([next_hop, e_msg])


def encapsulate_route(data, identities):
    for identity in reversed(identities):
        data = encapsulate(data, identity)
    return data


def encapsulate_route_e2e(data, identities, sender):
    sender_info = [sender.identifier, sender.address, sender.port]
    p_msg = packing.pack([sender_info, data])
    return encapsulate_route(p_msg, identities)
