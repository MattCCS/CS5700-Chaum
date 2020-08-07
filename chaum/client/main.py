"""
Start a single Mix client.
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
from chaum.crypto import keys
from chaum.crypto import signing


logger = logtools.new_logger(__loader__.name)
RUN = True


class CommandError(Exception): pass  # noqa


def listen(port, self_identity):
    server_socket = tcp.bind_socket(port)
    server_socket.settimeout(0.25)
    port = server_socket.getsockname()[1]
    self_identity.port = port
    print(f"[*] Awaiting incoming messages on port {port}...")

    while True:
        try:
            (client_socket, address) = server_socket.accept()
        except socket.timeout:
            if not RUN:
                logger.info("[.] Client listen thread ending.")
                return
            continue

        logger.info(f"\t(Raw socket: {address})")

        try:
            input_bytes = tcp.recv(client_socket)
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
        logger.info(f"sender_info: {sender_info}")

        (sid, saddr, sport) = sender_info
        (msg, fingerprint, signature, spk_bytes) = packing.unpack(msg)

        if sid in self_identity.blocked:
            logger.info(f"\n[-] An unwanted message was blocked.")
            continue

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
            print(colors.red("\n[!] Sender fingerprint not found!  Identity cannot be verified!"))

        msg = msg.decode("utf-8")
        line = f"[{sid}@{saddr}:{sport}] {sid} says: \"{msg}\""

        if verified:
            if sid in self_identity.seen:
                print(colors.yellow(line))
            else:
                print(colors.green(line))
        else:
            print(colors.yellow(line))
            self_identity.seen[sid] = (saddr, sport, spk_bytes)

        if verified:
            sender_identity.address = saddr
            sender_identity.port = sport


def stop_thread():
    global RUN
    RUN = False


def forward(addressed_packet):
    (next_hop, packet) = packing.unpack(addressed_packet)
    (next_address, next_port) = next_hop
    logger.info(f"Next hop: {repr(next_hop)}")

    client_socket = tcp.connect_socket(next_address, next_port)
    client_socket.send(packet)
    client_socket.close()


def send_message(msg, sender, destination, dest_addr, dest_port):
    destination.address = dest_addr
    destination.port = dest_port

    msg = msg.encode("utf-8")

    # sign msg
    signature = signing.sign(msg, sender.private_key)
    pkbytes = keys.public_key_bytes(sender.public_key)
    logger.debug(f"msg fingerprint: {repr(sender.fingerprint)}")
    logger.debug(f"msg signature: {repr(signature)}")
    msg = packing.pack([msg, sender.fingerprint, signature, pkbytes])

    # decide on route
    route = routing.random_route(destination)
    logger.info(f"route: {repr([i.identifier for i in route])}")

    # encrypt msg for route
    addressed_packet = routing.encapsulate_route_e2e(msg, route, sender)
    logger.debug(f"addressed_packet: {repr(addressed_packet)}")

    forward(addressed_packet)


def handle_set(inp, sender):
    try:
        (_, ident, addr, port) = inp.strip().split(maxsplit=3)
    except ValueError:
        print("\n[-] set: Couldn't parse ident/addr/port.\n\tCheck help for `set` syntax.")
        raise CommandError()

    if ident not in sender.peers:
        print(f"\n[-] set: Peer unknown: {ident}")
        raise CommandError()

    try:
        port = int(port)
    except ValueError:
        print(f"\n[-] set: Port must be an int, got: {port}")
        raise CommandError()

    sender.peers[ident].address = addr
    sender.peers[ident].port = port
    print(colors.green(f"\t[+] Updated info for {ident}."))


def handle_send(inp, sender, last=None):
    try:
        (head, msg) = inp.strip().split(maxsplit=1)
    except ValueError:
        print("\n[-] send: Couldn't parse fields.")
        raise CommandError()

    try:
        (_, ident) = head.split(":", 1)
    except ValueError:
        if not last:
            print("\t[-] send: Couldn't parse identifier and no prior recipient!\n\tCheck help for `send` syntax.")
            raise CommandError()
        ident = last

    try:
        dest = sender.peers[ident]
    except KeyError:
        print(f"\t[!] send: Couldn't find peer: {repr(ident)}")
        raise CommandError()

    addr = dest.address
    port = dest.port

    if None in (port, addr):
        print(colors.yellow(f"\t[!] Contact info for {ident} is unknown!\n\tUpdate it with the `set` command."))
        raise CommandError()

    try:
        port = int(port)
    except Exception:
        print("\t[!] send: Port must be a number!")
        raise CommandError()

    try:
        send_message(msg, sender, dest, addr, port)
        print(f"\t[+] Message sent to {ident}@{addr}:{port}.")
    except Exception as exc:
        print(f"\t[!] Message failed to send!  Maybe the first node is down?")
        logger.error(exc)
        raise CommandError(exc)

    return ident


def handle_remember(inp, sender):
    try:
        (_, ident) = inp.strip().split(maxsplit=1)
    except ValueError:
        print("\n[-] remember: Couldn't parse identifier.\n\tCheck help for `remember` syntax.")
        raise CommandError()

    if ident in sender.peers:
        print(f"\n[-] remember: Peer already known: {ident}")
        raise CommandError()

    try:
        (addr, port, pk_bytes) = sender.seen[ident]
    except KeyError:
        print(f"\t[!] remember: Couldn't find contact: {repr(ident)}")
        raise CommandError()

    public_key = keys.load_public_key_bytes(pk_bytes)

    cached_ident = identity.Identity(ident, addr, port, public_key=public_key)
    sender.peers[ident] = cached_ident
    sender.fingerprints[cached_ident.fingerprint] = cached_ident

    print(colors.yellow(f"\t[+] Cached info for {ident}."))


def handle_block(inp, sender):
    try:
        (_, ident) = inp.strip().split(maxsplit=1)
    except ValueError:
        print("\n[-] block: Couldn't parse identifier.\n\tCheck help for `block` syntax.")
        raise CommandError()

    if ident in sender.blocked:
        print(colors.green(f"\t[+] {ident} is already blocked."))
        return

    if ident in sender.peers:
        consent = input(colors.yellow(f"[?] {ident} is in your trusted peers list.\nAre you sure you want to block them? [Y/n] "))
        if consent != 'Y':
            print("\t[.] Cancelled block.")
            return

    sender.blocked.add(ident)
    print(colors.green(f"\t[+] {ident} has been blocked.  You will no longer see their messages."))


def handle_unblock(inp, sender):
    try:
        (_, ident) = inp.strip().split(maxsplit=1)
    except ValueError:
        print("\n[-] unblock: Couldn't parse identifier.\n\tCheck help for `unblock` syntax.")
        raise CommandError()

    if ident not in sender.blocked:
        print(colors.green(f"\t[+] {ident} was already unblocked."))
        return

    sender.blocked.discard(ident)
    print(colors.green(f"\t[+] {ident} has been unblocked."))


def peer_line(sender, peer):
    line = f"{peer.identifier}@{peer.address}:{peer.port} ({peer.fingerprint})"

    if peer.identifier in sender.blocked:
        color = colors.red
        line += " (BLOCKED)"
    elif peer.identifier == sender.identifier:
        color = colors.white
    elif peer.identifier in sender.seen:
        color = colors.yellow
    else:
        color = colors.green

    return color(line)


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
                print(peer_line(sender, sender))
                print(f"Your peers:")
                for peer in sender.peers.values():
                    if peer.identifier == sender.identifier:
                        continue
                    print(f"\t{peer_line(sender, peer)}")
            elif inp.startswith("set"):
                try:
                    handle_set(inp, sender)
                except CommandError as exc:
                    logger.debug(exc)
            elif inp.startswith("remember"):
                try:
                    handle_remember(inp, sender)
                except CommandError as exc:
                    logger.debug(exc)
            elif inp.startswith("block"):
                try:
                    handle_block(inp, sender)
                except CommandError as exc:
                    logger.debug(exc)
            elif inp.startswith("unblock"):
                try:
                    handle_unblock(inp, sender)
                except CommandError as exc:
                    logger.debug(exc)
            elif inp.startswith("send"):
                try:
                    identifier = handle_send(inp, sender, last=last)
                    if last != identifier:
                        last = identifier
                        print(f"\t[*] (Caching new recipient: {last}.)")
                except CommandError as exc:
                    logger.debug(exc)
            else:
                print()
                print("--- COMMANDS ---")
                print(f"- peers")
                print(f"\tShows the contact info of yourself and others.")
                print(f"\t(Updates automatically when you get a message.)")
                print(f"\tColor code:")
                print(f"\t\t- {colors.white('you')}")
                print(f"\t\t- {colors.green('trusted peer')}")
                print(f"\t\t- {colors.yellow('untrusted peer')}")
                print(f"\t\t- {colors.red('(blocked)')}")

                print(f"- set <identifier> <address> <port>")
                print(f"\tUpdates the contact information for the identifier.")

                print(f"- send[:identifier] <message>")
                print(f"\tSend a message to the given contact.")
                print(f"\t`send` will remember the last person you spoke to.")
                print(f"\t(Requires the recipient's info to be set with `peers`.)")

                print(f"- remember <identifier>")
                print(f"\tAdds the given identifier to your peers list.")
                print(f"\t(Allows you to securely talk to new people.)")

                print(f"- last")
                print(f"\tShows the last person you spoke to.")

                print(f"- block/unblock <identifier>")
                print(f"\tBlock/unblock the given contact.")

    except KeyboardInterrupt:
        print(f"\n[.] User cancelled.")


def load_self_identity(args):
    sender = identity.load_client_identity(args.identifier)
    sender.address = ip.get_lan_ip()
    sender.port = args.port
    sender.private_key = identity.load_private_key(args.identifier)

    # special to clients
    sender.peers = {i.identifier: i for i in identity.load_client_identities()}
    sender.peers[sender.identifier] = sender  # set pointer
    sender.fingerprints = {i.fingerprint: i for i in sender.peers.values()}
    sender.seen = {}
    sender.blocked = set()
    return sender


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("identifier", type=str)
    parser.add_argument("-p", "--port", type=int, default=0)
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
