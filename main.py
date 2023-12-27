from crypto import *
from utilities import *
from pathlib import Path

movie_path = Path('example/csgo.mp4')

files = file_to_parts(
    file_path=movie_path,
    size_chunk=400,
)

print(pretty_paths(files))
