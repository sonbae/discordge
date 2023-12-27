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
import math

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


def decompose(file_bytes: bytes, size_chunk: int) -> list[bytes]:
    logger.info('decompose()')

    logger.debug('decomposing...')
    chunks = [file_bytes[i:i + size_chunk * 1000000] for i in range(0, len(file_bytes), size_chunk * 1000000)]
    logger.debug('number of chunks generated: %s', len(chunks))

    return chunks


def compose(chunks: list[bytes]) -> bytes:
    logger.info('compose()')

    logger.debug('composing...')
    file_bytes = reduce(lambda x, y: x + y, chunks)

    return file_bytes


def encrypt(chunks: list[bytes], fernet_obj: Fernet) -> list[bytes]:
    logger.info('encrypt()')

    logger.debug('encrypting chunks...')
    encrypted_chunks = list(map(lambda x: fernet_obj.encrypt(x), chunks))

    return encrypted_chunks


def decrypt(chunks: list[bytes], fernet_obj: Fernet) -> list[bytes]:
    logger.info('decrypt()')

    logger.debug('decrypting chunks...')
    decrypted_chunks = list(map(lambda x: fernet_obj.decrypt(x), chunks))

    return decrypted_chunks


def file_to_parts(file_path: Path, size_chunk: int, directory: str = 'tmp/', is_encrypt: bool = False, fernet_obj: Fernet = None) -> list[Path]:
    logger.info('generate_parts()')

    file_name = file_path.name

    # read in file
    with open(file_path, 'rb') as f:
        file_bytes = f.read()
    
    # generate chunk bytes
    if is_encrypt:
        new_size_chunk = size_chunk / 1.35 // 1
        chunks = decompose(file_bytes, new_size_chunk)
        chunks = encrypt(chunks, fernet_obj)
    else:
        chunks = decompose(file_bytes, size_chunk)
    
    # write to file
    files_paths = list()
    for i, chunk in enumerate(chunks):
        chunk_path = f'{directory}/{file_name}.{i}.bin'
        files_paths = files_paths.append(chunk_path)
        open(chunk_path, 'wb').write(chunk)

    return files_paths


def parts_to_file(file_paths: list[Path], directory: str = 'tmp/', is_encrypt: bool = False, fernet_obj: Fernet = None) -> Path:
    logger.info('generate_file()')

    file_name = str(file_paths[0].name.split('.')[:-2])

    # sort parts
    sorted_file_paths = sorted(list(file_paths), key=lambda file: int(file.suffixes[-2]))

    # read files
    files_bytes = list(map(lambda x: open(x, 'rb').read(), sorted_file_paths))

    # generate file bytes
    if is_encrypt:
        files_bytes = decrypt(files_bytes, fernet_obj)
    file_bytes = compose(files_bytes)

    # write to file
    file_path = f'{directory}/{file_name}'
    open(file_path, 'wb').write(file_bytes)

    return Path(file_path)


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

    if Path('tmp/salt.bin').exists():
        logger.debug('salt exists')
        with open('tmp/salt.bin', 'rb') as f:
            salt = f.read()
    else:
        logger.debug('salt does not exist')
        salt = os.urandom(16)
        with open('tmp/salt.bin', 'wb') as f:
            f.write(salt)

    return salt


def main():
    pass


if __name__ == '__main__':
    main()
