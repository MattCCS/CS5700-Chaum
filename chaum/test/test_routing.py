
from chaum.client import routing as client_routing
from chaum.common import identity
from chaum.node import routing as node_routing


def deencapsulate_route(data, private_keys):
    for private_key in private_keys:
        (next_hop, data) = node_routing.deencapsulate(data, private_key)
        print(f"Next hop: {next_hop}")
    return data


def test():
    # Shared activity
    node_identities = identity.NODES
    print(node_identities)

    # Client activity
    route = client_routing.random_route(node_identities, node_identities[2], length=3)
    print(route)

    packet = client_routing.encapsulate_route(b"WE ATTACK AT DAWN", route)
    print(packet)

    # Server(s) activity
    _private_keys = [
        identity.load_private_key(i.identifier)
        for i in route
    ]
    newtext = deencapsulate_route(packet, _private_keys)
    print(newtext)
