
from chaum import config
from chaum.crypto import hybrid
from chaum.crypto import keys


def test():
    public_key = keys.load_public_key((config.ROOT / "../test-keys/test.pub").resolve())
    print(public_key)

    private_key = keys.load_private_key((config.ROOT / "../test-keys/test.priv").resolve())
    print(private_key)

    plaintext = b"268"
    ciphertext = hybrid.hybrid_encrypt(plaintext, public_key)
    print(len(ciphertext))

    newtext = hybrid.hybrid_decrypt(ciphertext, private_key)
    print(newtext)
