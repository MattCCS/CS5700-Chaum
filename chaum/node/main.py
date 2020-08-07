"""
Start a single Mix node.
"""

import argparse
import traceback

from chaum.node import routing
from chaum.common import exceptions
from chaum.common import identity
from chaum.common import logtools
from chaum.common import tcp


logger = logtools.new_logger(__loader__.name)


class Node:
    def __init__(self, private_key):
        self.private_key = private_key

    def _route(self, packet):
        return routing.deencapsulate(packet, self.private_key)

    def route(self, packet):
        try:
            (next_hop, next_packet) = self._route(packet)
        except Exception as exc:
            logger.error(f"[!] Unexpected exception while routing: {exc}")
            traceback.print_exc()
            logger.debug(traceback.format_exc())
            return None
        return (next_hop, next_packet)

    def __repr__(self):
        return f"<{self.__class__.__name__} {vars(self)}>"


def forward(next_hop, next_packet):
    (next_ip, next_port) = next_hop
    print(f"[Server] Next hop: {next_ip}/{next_port}")
    logger.debug(f"Next packet: {next_packet}")

    try:
        client_socket = tcp.connect_socket(next_ip, next_port)
        print("[Server] Sending response...")
        client_socket.send(next_packet)
        client_socket.close()
    except (exceptions.ClientSocketException, TypeError) as exc:
        logger.error(f"[!] Error connecting or sending: {exc}")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("identifier", type=str, help="(Example: 'server1')")
    logtools.add_log_parser(parser)
    return parser.parse_args()


def main():
    args = parse_args()

    node_identity = identity.get_public_nodes()[args.identifier]
    node = Node(identity.load_private_key(args.identifier))

    server_socket = tcp.bind_socket(node_identity.port)

    try:
        while True:
            print(f"\n[Server: {args.identifier}] Waiting for input...")
            (client_socket, address) = server_socket.accept()

            input_bytes = tcp.recv(client_socket)
            logger.debug(f"input_bytes: {input_bytes}")

            unpacked = node.route(input_bytes)
            logger.debug(f"Unpacked: {repr(unpacked)}")
            if unpacked is None:
                logger.error(f"[!] No output data!  Ignoring...")
                continue

            (next_hop, next_packet) = unpacked
            forward(next_hop, next_packet)

    except KeyboardInterrupt:
        print("[Server] User cancelling...")

    server_socket.close()
    print("[Server] Done.")


if __name__ == '__main__':
    main()
