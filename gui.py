from PyQt5.QtWidgets import QMainWindow, QApplication, QPushButton, QLabel, QVBoxLayout, QWidget, QSpinBox
import sys
import logging
from crypto import *
from pathlib import Path

work_dir_path = Path('discordge-workdir')
if not work_dir_path.exists():
    work_dir_path.mkdir()

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


class MainWidget(QMainWindow):
    def __init__(self):
        super().__init__()
        self.file_paths = None
        self.work_dir_path = None
        self.salt = generate_salt()
        self.chunk_value = 400

        self.file_paths_label = QLabel("EMPTY WORDS")

        self.encrypt_button = QPushButton('Encrypt')
        self.encrypt_button.clicked.connect(self.encrypt)

        self.decrypt_button = QPushButton('Decrypt')
        self.decrypt_button.clicked.connect(self.decrypt)

        self.reset_button = QPushButton("Reset")
        self.reset_button.clicked.connect(self.reset_list)

        self.chunk_size = QSpinBox()
        self.chunk_size.setRange(10, 500)
        self.chunk_size.setSuffix('MB')
        self.chunk_size.setSingleStep(10)
        self.chunk_size.setValue(self.chunk_value)
        self.chunk_size.valueChanged.connect(self.chunk_changed)

        layout = QVBoxLayout()
        layout.addWidget(self.file_paths_label)
        layout.addWidget(self.reset_button)
        layout.addWidget(self.encrypt_button)
        layout.addWidget(self.decrypt_button)
        layout.addWidget(self.chunk_size)

        widget = QWidget()
        widget.setLayout(layout)

        self.setCentralWidget(widget)

        self.setWindowTitle("discordge")
        self.resize(720, 480)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def reset_list(self):
        logger.info('reset_list()')
        self.file_paths_label.setText('')

    def encrypt(self):
        logger.info('encrypt()')
        print('hello')
        password = 'helloWorld'

        logger.debug('creating fernet object')
        fernet_obj = create_fernet_password(password, self.salt)

        logger.debug('decomposing to parts')
        parts = decompose_to_parts(file_path=self.file_paths[0], size_chunk=self.chunk_value, write_to_disk=False)

        logger.debug('encrypting parts')
        encrypt_parts(parts, fernet_obj)

    def decrypt(self):
        logger.info('decrypt()')
        password = 'helloWorld'

        logger.debug('creating fernet object')
        fernet_obj = create_fernet_password(password, self.salt)

        logger.debug('decrypting parts')
        parts = decrypt_parts(self.file_paths, fernet_obj)

        compose_to_file(parts)

    def chunk_changed(self, i):
        self.chunk_value = i

    def dropEvent(self, event):
        self.file_paths = list(map(lambda x: x.toLocalFile(), event.mimeData().urls()))
        logger.debug(self.file_paths)
        print('\n'.join(self.file_paths))
        self.file_paths_label.setText('\n'.join(self.file_paths))


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ui = MainWidget()
    ui.show()
    sys.exit(app.exec_())
