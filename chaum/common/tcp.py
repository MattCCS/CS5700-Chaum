
import socket

from chaum.common import exceptions


DEFAULT_READ_SIZE = 8192


def bind_socket(port):
    """
    Server function.
    Bind a socket to given port.  Handle errors gracefully.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind(('', port))
        server_socket.listen(1)
    except (PermissionError, OverflowError):
        text = "[!] Please choose a port between 1024 and 65535."
        raise exceptions.ServerSocketException(text)

    return server_socket


def connect_socket(address, port):
    """
    Client function.
    Create socket connection to given address and port.  Handle errors gracefully.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((address, port))
    except socket.gaierror:
        text = "[!] Please choose a valid IPv4 or IPv6 address."
        raise exceptions.ClientSocketException(text)
    except ConnectionRefusedError:
        text = "[!] Connection to port {} was refused!".format(port)
        text += "\n[!] Please make sure the server really is running at that address and port."
        raise exceptions.ClientSocketException(text)
    except TimeoutError:
        text = "[!] Connection timed out!"
        text += "\n[!] Please make sure the server really is running at that address and port."
        raise exceptions.ClientSocketException(text)
    except (OSError, OverflowError):
        text = "[!] Please choose a port between 1024 and 65535."
        raise exceptions.ClientSocketException(text)

    return client_socket
