import base64

from hurry.filesize import size
import sys
import os
from functools import reduce
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging

logging.basicConfig(level=logging.DEBUG)
logging.debug('initialized')

def decompose_encrypt_file(file_path, fernet_obj, size_chunk):
    # open file and read as binary
    with open(file_path, 'rb') as f:
        file_binary = f.read()
        logging.debug('read file')

        binary_splits = [file_binary[i:i + size_chunk * 1000000] for i in
                         range(0, len(file_binary), size_chunk * 1000000)]
        logging.debug('split file')

    for i, split in enumerate(binary_splits):
        with open(f'tmp/{i}.bin', 'wb') as f:
            f.write(fernet_obj.encrypt(split))
            logging.debug(f'encrypted {i}')


def decrypt_compose_files(file_paths, fernet_obj):
    sorted_file_paths = sorted(list(map(Path, file_paths)), key=lambda file: file.name)
    logging.debug(sorted_file_paths)

    parts = [fernet_obj.decrypt(open(file, 'rb').read()) for file in sorted_file_paths]
    logging.debug('decrypted')

    with open('example/new.mp4', 'wb') as f:
        f.write(reduce(lambda x, y: x + y, parts))
        logging.debug('file written')


def create_fernet_password(password, salt):
    logging.debug('called create fernet password')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    logging.debug('created kdf')
    key = base64.urlsafe_b64encode(kdf.derive(bytes(password, 'utf-8')))
    logging.debug('key created')

    return Fernet(key)


def generate_salt():
    if Path('salt.bin').exists():
        with open('salt', 'rb') as f:
            salt = f.read()
    else:
        salt = os.urandom(16)
        with open('salt', 'wb') as f:
            f.write(salt)

    return salt


def main():
    pass


if __name__ == '__main__':
    main()
