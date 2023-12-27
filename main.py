from crypto import *
from utilities import *
from pathlib import Path

movie_path = Path('example/csgo.mp4')
password = 'helloWorld'
salt = generate_salt()

# files = file_to_parts(
#     file_path=movie_path,
#     size_chunk=400,
# )

# print(pretty_paths(files))

# file = parts_to_file(
#     file_paths=files,
# )

fernet_object = create_fernet_password(password, salt)

files = file_to_parts(
    file_path=movie_path,
    size_chunk=400,
    is_encrypt=True,
    fernet_obj=fernet_object,
)

file = parts_to_file(
    file_paths=files,
    is_encrypt=True,
    fernet_obj=fernet_object,
)