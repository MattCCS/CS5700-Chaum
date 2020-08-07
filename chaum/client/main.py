"""
Start a single client.
"""

import argparse
import socket
import threading
import time

from chaum.client import routing
from chaum.common import colors
from chaum.common import identity
from chaum.common import ip
from chaum.common import logtools
from chaum.common import packing
from chaum.common import tcp
from chaum.crypto import exceptions
from chaum.crypto import hybrid
from chaum.crypto import signing


logger = logtools.new_logger(__loader__.name)
RUN = True


class SendError(Exception): pass  # noqa


def listen(port, self_identity):
    server_socket = tcp.bind_socket(port)
    server_socket.settimeout(0.25)
    print(f"[*] Awaiting incoming messages on port {port}...")

    while True:
        try:
            (client_socket, address) = server_socket.accept()
        except socket.timeout:
            if not RUN:
                logger.debug("[.] Client listen thread ending.")
                return
            continue

        try:
            input_bytes = client_socket.recv(tcp.DEFAULT_READ_SIZE)
            logger.debug(f"\tRaw bytes: {repr(input_bytes)}")
        except ConnectionResetError as exc:
            logger.debug(exc)
            continue

        # try to decrypt
        try:
            plaintext_bytes = hybrid.hybrid_decrypt(input_bytes, self_identity.private_key)
            logger.debug(f"\tPlaintext bytes: {repr(plaintext_bytes)}")
        except exceptions.HybridEncryptionException as exc:
            logger.debug(exc)
            logger.warning(f"\n[-] An incoming message failed to decrypt.")
            continue

        (sender_info, msg) = packing.unpack(plaintext_bytes)
        logger.debug(f"sender_info: {sender_info}")

        (sid, saddr, sport) = sender_info
        (msg, fingerprint, signature) = packing.unpack(msg)

        verified = False
        try:
            sender_identity = self_identity.fingerprints[fingerprint]
            try:
                signing.verify(msg, signature, sender_identity.public_key)
                logger.info(f"[+] Sender verified as: {sender_identity.identifier} ({sender_identity.fingerprint})")
                verified = True
            except exceptions.SignatureVerificationFailedException as exc:
                logger.debug(exc)
                logger.error("\n[!] Sender signature verification failed!  This could be an attack!")
        except KeyError:
            logger.error("\n[!] Sender fingerprint not found!  Identity cannot be verified!")

        msg = msg.decode("utf-8")
        line = f"[{sid}@{saddr}:{sport}] {sid} says: \"{msg}\""

        if verified:
            print(line)
        else:
            print(colors.error(line))

        self_identity.seen[sid] = (sid, saddr, sport)

        # print("\n[+] New message!")
        # print(f"\tFrom: {sid}@{saddr}:{sport}")
        # print(f"\tMessage: {msg}")
        logger.info(f"\t(Raw socket: {address})")


def stop_thread():
    global RUN
    RUN = False


def forward(addressed_packet):
    (next_hop, packet) = packing.unpack(addressed_packet)
    (_, next_address, next_port) = next_hop
    logger.debug(f"Next hop: {repr(next_hop)}")

    client_socket = tcp.connect_socket(next_address, next_port)
    client_socket.send(packet)
    client_socket.close()


def form_message(msg, sender, destination, dest_addr, dest_port):
    destination.address = dest_addr
    destination.port = dest_port

    msg = msg.encode("utf-8")

    # sign msg
    signature = signing.sign(msg, sender.private_key)
    logger.debug(f"msg fingerprint: {repr(sender.fingerprint)}")
    logger.debug(f"msg signature: {repr(signature)}")
    msg = packing.pack([msg, sender.fingerprint, signature])

    # decide on route
    route = routing.random_route(destination)
    logger.debug(f"route: {repr(route)}")

    # encrypt msg for route
    addressed_packet = routing.encapsulate_route_e2e(msg, route, sender)
    logger.debug(f"addressed_packet: {repr(addressed_packet)}")

    forward(addressed_packet)


def handle_send(inp, sender, last=None):
    try:
        (head, msg) = inp.strip().split(maxsplit=1)
    except ValueError:
        print("\n[-] send: Couldn't parse fields.")
        raise SendError()

    try:
        (_, ident, addr, port) = head.split(":")
        to = (ident, addr, port)
    except ValueError:
        if not last:
            print("\t[-] send: Couldn't parse ident/addr/port and no prior recipient!\n\tCheck help for `send` syntax.")
            raise SendError()
        to = last

    (ident, addr, port) = to

    try:
        dest = sender.peers[ident]
    except KeyError:
        print(f"\t[!] send: Couldn't find peer: {repr(ident)}")
        raise SendError()

    try:
        port = int(port)
    except ValueError:
        print("\t[!] send: Port must be a number!")
        raise SendError()

    form_message(msg, sender, dest, addr, port)
    print(f"\t[+] Message sent to {ident}@{addr}:{port}.")

    return (ident, addr, port)


def cli_loop(sender):
    last = None

    try:
        while True:
            # to = "(Choose a recipient)"
            inp = input(f"[{sender.identifier}]> ")
            if not inp:
                continue
            elif inp == "last":
                print(f"\t(Last recipient: {repr(last)})")
            elif inp in ('quit', 'exit', 'stop'):
                print(f"\n[.] Exiting...")
                break
            elif inp in ('peer', 'peers', 'friend', 'friends', 'keys'):
                print(f"\n[*] Listing keys...")
                print(f"You:")
                print(f"\t{sender.identifier}@{sender.address}:{sender.port} ({sender.fingerprint})")
                print(f"Your peers:")
                for peer in sender.peers:
                    print(f"\t{peer.identifier}@{peer.address}:{peer.port} ({peer.fingerprint})")
            elif inp.startswith("send"):
                try:
                    (ident, addr, port) = handle_send(inp, sender, last=last)
                    if last != (ident, addr, port):
                        last = (ident, addr, port)
                        print(f"\t[*] (Caching new recipient: {ident}:{addr}:{port}.")
                except SendError as exc:
                    logger.debug(exc)
            # elif inp in ('?', 'help'):
            #     print(f"\n\tCommand format: send <message> ")
            else:
                print(f"\n\tCommand: last")
                print(f"\tCommand: peers")
                print(f"\tCommand format: send[:ident:addr:port] <message>")
    except KeyboardInterrupt:
        print(f"\n[.] User cancelled.")


def load_self_identity(args):
    sender = identity.load_client_identity(args.identifier)
    sender.address = ip.get_lan_ip()
    sender.port = args.port
    sender.private_key = identity.load_private_key(args.identifier)

    # special to clients
    sender.peers = {i.identifier: i for i in identity.load_client_identities()}
    sender.fingerprints = {i.fingerprint: i for i in sender.peers.values()}
    sender.seen = {}
    return sender


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("identifier", type=str)
    parser.add_argument("-p", "--port", type=int, required=True)
    logtools.add_log_parser(parser)
    return parser.parse_args()


def main():
    args = parse_args()

    sender = load_self_identity(args)

    threading.Thread(target=listen, args=(args.port, sender)).start()

    time.sleep(0.2)
    cli_loop(sender)

    stop_thread()


if __name__ == '__main__':
    main()
