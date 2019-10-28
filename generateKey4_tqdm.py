#!/usr/bin/env python3
import time, sys, os
from tqdm import tqdm, trange
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend

NUM_COLS = 80
QTY_ROWS = 10
CONCURRENT_THREADS = 2
KEY_SIZE = 8192
KEY_PASSPHRASE = b'12341234'

L = list(range(QTY_ROWS))[::-1]



def generateKey(n):
    pbar = tqdm(total=3, position=None)
    pbar.set_description("Generating Private Key")
    key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=65537,
        key_size=KEY_SIZE
    )
    pbar.update()

    pbar.set_description("Extracting Private Key")
    pbar.update()
    PRIVATE_KEY = key.private_bytes(
        encoding=crypto_serialization.Encoding.PEM,
        format=crypto_serialization.PrivateFormat.PKCS8,
        encryption_algorithm=crypto_serialization.BestAvailableEncryption(KEY_PASSPHRASE),
    ).decode()

    pbar.set_description("Extracting Public Key")
    pbar.update()
    PUBLIC_KEY = key.public_key().public_bytes(
        crypto_serialization.Encoding.OpenSSH,
        crypto_serialization.PublicFormat.OpenSSH
    ).decode()

    #tqdm.write("PRIVATE_KEY={}".format(PRIVATE_KEY))
    #tqdm.write("PUBLIC_KEY={}".format(PUBLIC_KEY))
    tqdm.write("{} is complete. Generated {} bytes of key data.".format(n, len(PUBLIC_KEY) + len(PUBLIC_KEY)))


if __name__ == '__main__':
    start = int(time.time() * 1000)
    print(("{msg:<{ncols}}").format(msg="Multi-threaded Key Generator", ncols=NUM_COLS))
    with ThreadPoolExecutor(max_workers=CONCURRENT_THREADS) as p:
        p.map(generateKey, L)
        #p.map(progresser, L)
    end = int(time.time() * 1000)
    duration = end - start
    print("Finished in {}ms".format(duration))
