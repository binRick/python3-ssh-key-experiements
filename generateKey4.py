#!/usr/bin/env python3

from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend

KEY_SIZE = 1024
KEY_PASSPHRASE = b'12341234'

key = rsa.generate_private_key(
    backend=crypto_default_backend(),
    public_exponent=65537,
    key_size=KEY_SIZE
)

PRIVATE_KEY = key.private_bytes(
    encoding=crypto_serialization.Encoding.PEM,
    format=crypto_serialization.PrivateFormat.PKCS8,
    encryption_algorithm=crypto_serialization.BestAvailableEncryption(KEY_PASSPHRASE),
).decode()

PUBLIC_KEY = key.public_key().public_bytes(
    crypto_serialization.Encoding.OpenSSH,
    crypto_serialization.PublicFormat.OpenSSH
).decode()

print("PRIVATE_KEY={}".format(PRIVATE_KEY))
print("PUBLIC_KEY={}".format(PUBLIC_KEY))
