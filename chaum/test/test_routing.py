
from chaum import config
from chaum import routing
from chaum.crypto import key_loading


class Identity(object):
    """docstring for Identity"""

    def __init__(self, identifier, public_key):
        super(Identity, self).__init__()
        self.identifier = identifier
        self.public_key = public_key


def test():
    public_key = key_loading.load_public_key((config.ROOT / "../nodes/s1/keys/s1pubkey").resolve())
    print(public_key)

    private_key = key_loading.load_private_key((config.ROOT / "../nodes/s1/keys/s1privkey.pem").resolve())
    print(private_key)

    identities = [
        Identity("Server A", public_key),
        Identity("Server B", public_key),
        Identity("Server C", public_key),
        Identity("Server D", public_key),
    ]

    route = routing.random_route(identities, identities[2], length=3)
    print(route)

    packet = routing.encapsulate_route(b"WE ATTACK AT DAWN", route)
    print(packet)

    newtext = routing.deencapsulate_route(packet, private_key)
    print(newtext)
