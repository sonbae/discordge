from hurry.filesize import size
import sys
from functools import reduce
from pathlib import Path
from cryptography.fernet import Fernet

MAX_UPLOAD_SIZE = 500  # MB


def decompose_file(file_path, fer):
    # open file and read as binary
    with open(file_path, 'rb') as f:
        file_binary = f.read()
        print(size(sys.getsizeof(file_binary)))

        binary_splits = [file_binary[i:i + MAX_UPLOAD_SIZE * 1000000] for i in
                         range(0, len(file_binary), MAX_UPLOAD_SIZE * 1000000)]
        print(size(sys.getsizeof(binary_splits)))

    for i, split in enumerate(binary_splits):
        print(i)
        with open(f'tmp/{i}.bin', 'wb') as f:
            f.write(fer.encrypt(split))


def compose_file_from_parts(parts):
    with open('example/new.mp4', 'wb') as f:
        f.write(reduce(lambda x, y: x + y, parts))


def main():
    key = Fernet.generate_key().decode('ascii')
    print(f'Save the key: {key}')

    f = Fernet(key)

    decompose_file('example/csgo.mp4', f)
    yur = input('whats your key you fuck: ')

    fhelp = Fernet(yur.encode('ascii'))

    path_obj = Path('tmp/')
    items = path_obj.glob('*')
    sorted_items = sorted(items, key=lambda item: item.name)
    parts = [fhelp.decrypt(open(f'tmp/{item.name}', 'rb').read()) for item in sorted_items]

    compose_file_from_parts(parts)


if __name__ == '__main__':
    main()
