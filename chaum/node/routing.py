"""
API for routing Chaum-routed payloads.
"""

from chaum.common import packing
from chaum.crypto import hybrid


def deencapsulate(data, private_key):
    p_msg = hybrid.hybrid_decrypt(data, private_key)
    (next_hop, next_data) = packing.unpack(p_msg)
    return (next_hop, next_data)
