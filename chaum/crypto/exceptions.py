"""
Custom exceptions.
"""

# key errors
class PublicKeyNotFoundException            (Exception): pass  # noqa
class PublicKeyParseException               (Exception): pass  # noqa

class PrivateKeyNotFoundException           (Exception): pass  # noqa
class PrivateKeyParseException              (Exception): pass  # noqa

# signature/integrity errors
class SignatureVerificationFailedException  (Exception): pass  # noqa
class IntegrityVerificationFailedException  (Exception): pass  # noqa

# encryption errors
class SymmetricEncryptionException          (Exception): pass  # noqa
class AsymmetricEncryptionException         (Exception): pass  # noqa

# parsing errors
class PacketParseException                  (Exception): pass  # noqa
