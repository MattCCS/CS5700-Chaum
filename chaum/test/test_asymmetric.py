
from chaum import config
from chaum.crypto import asymmetric
from chaum.crypto import keys


def test():
    public_key = keys.load_public_key((config.ROOT / "../test-keys/test.pub").resolve())
    print(public_key)

    private_key = keys.load_private_key((config.ROOT / "../test-keys/test.priv").resolve())
    print(private_key)

    plaintext = b"secret"

    ciphertext = asymmetric.public_key_encrypt(plaintext, public_key)
    print(ciphertext)

    newtext = asymmetric.private_key_decrypt(ciphertext, private_key)
    print(newtext)
