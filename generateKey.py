#!/usr/bin/env python3
import paramiko, io, base64, sys
from Crypto.PublicKey import RSA

KEY_SIZE = 1024
KEY_PASSPHRASE = None


key = paramiko.RSAKey.generate(KEY_SIZE)
keyio = io.StringIO()
key.write_private_key(keyio, KEY_PASSPHRASE)


PRIVATE_KEY = keyio.getvalue()
PUBLIC_KEY = RSA.importKey(keyio.getvalue()).publickey().exportKey('PEM').decode()

print("PRIVATE_KEY={}".format(PRIVATE_KEY))
print("PUBLIC_KEY={}".format(PUBLIC_KEY))

