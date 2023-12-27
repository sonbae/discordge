from pathlib import Path
import hashlib

def calculate_hash(data: bytes):
    h = hashlib.new('sha256')
    h.update(data)
    return h.hexdigest()

def pretty_paths(paths: list[Path]) -> str:
    paths_str = '\n'.join(list(map(lambda x: str(x), paths)))
    return paths_str