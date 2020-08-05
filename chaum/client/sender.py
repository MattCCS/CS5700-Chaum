"""
Start a single client.
"""


from chaum.client import routing
from chaum.common import identity
from chaum.common import tcp
from chaum.common import packing
from chaum.crypto import hybrid


def forward(addressed_packet):
    (next_hop, packet) = packing.unpack(addressed_packet)
    (_, next_address, next_port) = next_hop
    print(f"Next hop: {repr(next_hop)}")

    client_socket = tcp.connect_socket(next_address, next_port)
    client_socket.send(packet)
    client_socket.close()


def main():
    msg = b"Hello, world!"
    source = identity.Identity("alice", "localhost", 9999)
    destination = identity.Identity("bob", "localhost", 1025)

    if destination.public_key:
        msg = hybrid.hybrid_encrypt(msg, destination.public_key)

    route = routing.random_route(destination, length=1)
    print(repr(route))

    addressed_packet = routing.encapsulate_route_e2e(msg, route, source)
    print(repr(addressed_packet))

    forward(addressed_packet)


if __name__ == '__main__':
    main()
