"""
API for constructing Chaum-routed payloads.
"""

import random

from chaum.common import packing
from chaum.crypto import hybrid


def random_route(identities, destination, length=3):
    available = set(identities) - set([destination])
    route = random.sample(list(available), k=length) + [destination]
    return reversed(route)


def encapsulate(data, identity):
    e_msg = hybrid.hybrid_encrypt(data, identity.public_key)
    return packing.pack([identity.identifier, e_msg])


def deencapsulate(data, private_key):
    # TODO: this must perform an identity lookup.
    (identifier, e_msg) = packing.unpack(data)
    # TODO: must discard packets not intended for us...?
    print(identifier)
    data = hybrid.hybrid_decrypt(e_msg, private_key)
    if identifier == "Server C":
        return (True, data)
    return (False, data)


def encapsulate_route(data, identities):
    for identity in identities:
        data = encapsulate(data, identity)
    return data


def deencapsulate_route(data, private_key):
    # TODO: this must perform an identity lookup.
    while True:
        (us, data) = deencapsulate(data, private_key)
        if us:
            return data
