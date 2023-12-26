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
import hashlib

logFormat = logging.Formatter('%(levelname)s:%(name)s:%(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

fileHandler = logging.FileHandler('discordge.log')
fileHandler.setFormatter(logFormat)
logger.addHandler(fileHandler)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormat)
logger.addHandler(consoleHandler)

logger.debug('initialized')


def calculate_hash(data: bytes):
    h = hashlib.new('sha256')
    h.update(data)
    return h.hexdigest()


def decompose_to_parts(file_path: Path, size_chunk: int, write_to_disk: bool = False, directory_to_save: str = 'tmp/'):
    logger.info('decompose_to_parts(%s, %s, %s, %s)', file_path, size_chunk, write_to_disk, directory_to_save)

    with open(file_path, 'rb') as f:
        logger.debug('reading file')
        file_binary = f.read()
        logger.debug('memory space of file_binary: %s', size(sys.getsizeof(file_binary)))

        h = hashlib.new('sha256')
        h.update(file_binary)
        logger.debug('sha256: %s', h.hexdigest())

        logger.debug('splitting file into chunks')
        parts = [file_binary[i:i + size_chunk * 1000000] for i in
                 range(0, len(file_binary), size_chunk * 1000000)]
        logger.debug('number of parts generated: %s', len(parts))
        logger.debug('memory space of parts: %s', size(sys.getsizeof(parts)))

        logger.debug(
          '\n'.join(map(calculate_hash, parts))
        )

    if write_to_disk:
        logger.debug('writing parts to disk')
        for i, split in enumerate(parts):
            with open(f'{directory_to_save}/{i}.part', 'wb') as f:
                logger.debug('writing (%s).part', i)
                f.write(split)

    return parts


def encrypt_parts(parts: list[bytes], fernet_obj: Fernet):
    logger.info('encrypt_parts()')

    for i, split in enumerate(parts):
        with open(f'tmp/{i}.bin', 'wb') as f:
            logger.debug('writing (%s).bin', i)
            f.write(fernet_obj.encrypt(split))


def decrypt_parts(file_paths: list[str], fernet_obj: Fernet):
    logger.info('decrypt_parts()')
    sorted_file_paths = sorted(list(map(Path, file_paths)), key=lambda file: int(file.stem))
    logger.debug('sorted parts: %s', sorted_file_paths)

    logger.debug('decrypting parts')
    parts = list(map(lambda x: fernet_obj.decrypt(open(x, 'rb').read()), sorted_file_paths))

    logger.debug(
      '\n'.join(map(calculate_hash, parts))
    )

    return parts


def compose_to_file(parts: list[bytes]):
    logger.info('compose_to_file()')

    with open('example/new.mp4', 'wb') as f:
        logger.debug('writing to file')
        f.write(reduce(lambda x, y: x + y, parts))


def create_fernet_password(password, salt):
    logger.info('create_fernet_password()')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    logger.debug('encoding password')
    key = base64.urlsafe_b64encode(kdf.derive(bytes(password, 'utf-8')))

    logger.debug('creating fernet key')
    return Fernet(key)


def generate_salt():
    logger.info('generate_salt()')

    if Path('discordge-workdir/salt.bin').exists():
        logger.debug('salt exists')
        with open('discordge-workdir/salt.bin', 'rb') as f:
            salt = f.read()
    else:
        logger.debug('salt does not exist')
        salt = os.urandom(16)
        with open('discordge-workdir/salt.bin', 'wb') as f:
            f.write(salt)

    return salt


def main():
    pass


if __name__ == '__main__':
    main()
