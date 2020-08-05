"""
Start a single Mix node.
"""

import argparse
import traceback

from chaum import config
from chaum.node import routing
from chaum.common import exceptions
from chaum.common import identity
from chaum.common import tcp


class Node:
    def __init__(self, private_key):
        self.private_key = private_key

    def _route(self, packet):
        return routing.deencapsulate(packet, self.private_key)

    def route(self, packet):
        try:
            (next_hop, next_packet) = self._route(packet)
        except Exception as exc:
            print(f"Unexpected exception while routing: {exc}")
            traceback.print_exc()
            return None
        return (next_hop, next_packet)

    def __repr__(self):
        return f"<{self.__class__.__name__} {vars(self)}>"


def forward(next_hop, next_packet):
    (next_name, next_ip, next_port) = next_hop
    print(f"Next: {next_name}/{next_ip}/{next_port} | {next_packet}")

    try:
        client_socket = tcp.connect_socket(next_ip, next_port)
        print("[Server] Sending response...")
        client_socket.send(next_packet)
        client_socket.close()
    except (exceptions.ClientSocketException, TypeError) as exc:
        print(exc)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("identifier", type=str, help="(Example: 'server1')")
    return parser.parse_args()


def main():
    args = parse_args()

    nodes = config.load_safe("nodes")
    print(nodes)
    node_config = nodes[args.identifier]
    print(node_config)
    node = Node(identity.load_private_key(args.identifier))

    server_socket = tcp.bind_socket(node_config["port"])

    try:
        while True:
            print(f"[Server: {args.identifier}] Waiting for input...")
            (client_socket, address) = server_socket.accept()

            input_bytes = client_socket.recv(tcp.DEFAULT_READ_SIZE)

            unpacked = node.route(input_bytes)
            print(f"Unpacked: {repr(unpacked)}")
            if unpacked is None:
                print(f"NO OUTPUT DATA!")
                continue  # TODO: log

            (next_hop, next_packet) = unpacked
            forward(next_hop, next_packet)

    except KeyboardInterrupt:
        print("[Server] User cancelling...")

    server_socket.close()
    print("[Server] Done.")


if __name__ == '__main__':
    main()
