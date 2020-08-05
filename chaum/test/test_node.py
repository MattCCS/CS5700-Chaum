
from chaum import config
from chaum.client import routing as client_routing
from chaum.common import identity
from chaum.crypto import exceptions
from chaum.crypto import keys
from chaum.node import main


def test():
    # Server activity
    private_key = keys.load_private_key((config.ROOT / "../test-keys/test.priv").resolve())
    print(private_key)

    node = main.Node(private_key)

    test_valid(node)
    test_malformed(node)


def test_valid(node):
    public_key = keys.load_public_key((config.ROOT / "../test-keys/test.pub").resolve())
    print(public_key)

    node_identity = identity.Identity("Next Hop", public_key)

    valid_packet = client_routing.encapsulate_route(b"WE ATTACK AT DAWN", [node_identity])
    print(valid_packet)

    print(node.route(valid_packet))


def test_malformed(node):
    malformed_packet = b"malformed!"
    print(malformed_packet)

    try:
        print(node._route(malformed_packet))
    except exceptions.HybridEncryptionException as exc:
        print(f"Got expected error: {type(exc)}")
