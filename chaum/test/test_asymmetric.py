
from chaum import config
from chaum.crypto import asymmetric
from chaum.crypto import key_loading


def test():
    print("\tTesting: asymmetric")
    public_key = key_loading.load_public_key((config.ROOT / "../nodes/s1/keys/s1pubkey").resolve())
    print(public_key)

    private_key = key_loading.load_private_key((config.ROOT / "../nodes/s1/keys/s1privkey.pem").resolve())
    print(private_key)

    plaintext = b"secret"

    ciphertext = asymmetric.public_key_encrypt(plaintext, public_key)
    print(ciphertext)

    newtext = asymmetric.private_key_decrypt(ciphertext, private_key)
    print(newtext)
