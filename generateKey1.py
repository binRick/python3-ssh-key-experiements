#!/usr/bin/env python3
import paramiko, io, base64, sys
from Crypto.PublicKey import RSA

KEY_SIZE = 1024
KEY_PASSPHRASE = b'12341234'

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key

PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=KEY_SIZE,
    backend=default_backend()
)
PUBLIC_KEY = PRIVATE_KEY.public_key()

"""
pem = PRIVATE_KEY.private_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PrivateFormat.PKCS8,
   encryption_algorithm=serialization.BestAvailableEncryption(KEY_PASSPHRASE)
)
"""

print("PRIVATE_KEY={}".format(PRIVATE_KEY))
print("PUBLIC_KEY={}".format(PUBLIC_KEY))


"""
print("PUBLIC_KEY={}".format(
    serialization.load_ssh_public_key(PUBLIC_KEY, backend=default_backend()),
))
"""


pem = PUBLIC_KEY.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print(pem)

print(base64.b64encode(pem))



key = load_pem_public_key(pem, backend=default_backend())

print(key)
