"""
Start a single client.
"""

import argparse
import socket
import threading
import time

from chaum.client import routing
from chaum.common import identity
from chaum.common import packing
from chaum.common import tcp
from chaum.crypto import hybrid


RUN = True


def listen(port):
    server_socket = tcp.bind_socket(port)
    server_socket.settimeout(0.25)
    print(f"[*] Awaiting incoming messages on port {port}...")

    while True:
        try:
            (client_socket, address) = server_socket.accept()
        except socket.timeout:
            if not RUN:
                return
            continue

        input_bytes = client_socket.recv(tcp.DEFAULT_READ_SIZE)

        # print(input_bytes)
        (sender_info, msg) = packing.unpack(input_bytes)
        (sid, saddr, sport) = sender_info

        print(f"\n[--> {sid}@{saddr}:{sport}] {msg}")
        # print("\n[+] New message!")
        # print(f"\tFrom: {sid}@{saddr}:{sport}")
        # print(f"\tMessage: {msg}")
        # print(f"\t(Raw socket: {address})")


def stop_thread():
    global RUN
    RUN = False


def forward(addressed_packet):
    (next_hop, packet) = packing.unpack(addressed_packet)
    (_, next_address, next_port) = next_hop
    # print(f"Next hop: {repr(next_hop)}")

    client_socket = tcp.connect_socket(next_address, next_port)
    client_socket.send(packet)
    client_socket.close()


def form_message(msg, dest_addr, dest_port):
    source = identity.Identity("GenericSender", "localhost", 9999)
    destination = identity.Identity("GenericReceiver", dest_addr, dest_port)

    if destination.public_key:
        msg = hybrid.hybrid_encrypt(msg, destination.public_key)

    route = routing.random_route(destination, length=4)
    print(repr(route))

    addressed_packet = routing.encapsulate_route_e2e(msg, route, source)
    # print(repr(addressed_packet))

    forward(addressed_packet)


def handle_send(inp, last=None):
    try:
        (head, msg) = inp.strip().split(maxsplit=1)
    except ValueError:
        print("\n[-] Couldn't parse fields.")
        return

    try:
        (_, addr, port) = head.split(":")
        to = (addr, port)
    except ValueError:
        if not last:
            print("\t[-] Couldn't parse addr/port and no prior recipient!")
            print("\t[-] Check help for `send` syntax.")
            return
        to = last

    (addr, port) = to

    try:
        port = int(port)
        form_message(msg, addr, port)
        print(f"\t[+] Message sent to {addr}@{port}.")
    except ValueError:
        print("\t[!] Port must be a number!")
        return

    return (addr, port)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", type=int)
    return parser.parse_args()


def main():
    args = parse_args()
    threading.Thread(target=listen, args=(args.port,)).start()

    last = None

    time.sleep(0.2)
    try:
        while True:
            inp = input("[Send a message]> ")
            if not inp:
                continue
            elif inp == "last":
                print(f"\t(Last recipient: {repr(last)})")
            elif inp in ('quit', 'exit', 'stop'):
                print(f"\n[.] Exiting...")
                break
            elif inp.startswith("send"):
                try:
                    (addr, port) = handle_send(inp, last=last)
                    if last != (addr, port):
                        last = (addr, port)
                        print(f"\t[*] (Caching new recipient: {addr}:{port}.")
                except TypeError:
                    pass
            # elif inp in ('?', 'help'):
            #     print(f"\n\tCommand format: send <message> ")
            else:
                print(f"\n\tCommand format: send[:addr:port] <message>")
                print(f"\n\tCommand format: last")
    except KeyboardInterrupt:
        print(f"\n[.] User cancelled.")

    stop_thread()


if __name__ == '__main__':
    main()
