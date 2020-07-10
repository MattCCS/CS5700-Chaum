
from chaum import config
from chaum.crypto import hybrid
from chaum.crypto import key_loading


def test():
    print("\tTesting: hybrid")
    public_key = key_loading.load_public_key((config.ROOT / "../nodes/s1/keys/s1pubkey").resolve())
    print(public_key)

    private_key = key_loading.load_private_key((config.ROOT / "../nodes/s1/keys/s1privkey.pem").resolve())
    print(private_key)

    plaintext = b"268"
    ciphertext = hybrid.hybrid_encrypt(plaintext, public_key)
    print(len(ciphertext))

    newtext = hybrid.hybrid_decrypt(ciphertext, private_key)
    print(newtext)
