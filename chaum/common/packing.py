
import base64
import struct

import umsgpack


DELIMITER = b":"


def pack_slow(parts):
    return DELIMITER.join(base64.b64encode(e) for e in parts)


def unpack_slow(packed):
    return (base64.b64decode(e) for e in packed.split(DELIMITER))


def pack_fast(parts):
    count = len(parts)
    lengths = (len(p) for p in parts)
    return b''.join((bytes([count]), *(struct.pack('>H', length) for length in lengths), *parts))


def unpack_fast(packed):
    # TODO: in Python3.8, use the assignment operator...
    count = packed[0]
    lengths = (struct.unpack('>H', packed[i * 2 + 1: i * 2 + 3])[0] for i in range(count))
    offset = count * 2 + 1
    for length in lengths:
        yield packed[offset: offset + length]
        offset += length


def pack(parts):
    return umsgpack.packb(parts)


def unpack(packed):
    return umsgpack.unpackb(packed)
