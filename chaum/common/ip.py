
import socket


def get_lan_ip():
    """
    Source: https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        sock.connect(('10.255.255.255', 1))
        ip = sock.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        sock.close()
    return ip
