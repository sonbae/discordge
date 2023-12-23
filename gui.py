from PyQt5.QtWidgets import QMainWindow, QApplication, QPushButton, QLabel, QVBoxLayout, QWidget, QSpinBox
import sys
import logging
from crypto import *

class MainWidget(QMainWindow):
    def __init__(self):
        super().__init__()
        self.file_paths = None
        self.salt = generate_salt()
        self.chunk_value = 50

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
        print('reset')
        self.file_paths_label.setText('')

    def encrypt(self):
        logging.debug('encrypt func')
        password = 'helloWorld'

        fernet_obj = create_fernet_password(password, self.salt)
        logging.debug('fernet object created')

        decompose_encrypt_file(self.file_paths[0], fernet_obj, self.chunk_value)
        logging.debug('decomposed')

    def decrypt(self):
        logging.debug('decrypt func')
        password = 'helloWorld'

        fernet_obj = create_fernet_password(password, self.salt)
        logging.debug('fernet object created')

        decrypt_compose_files(self.file_paths, fernet_obj)
        logging.debug('composed')

    def chunk_changed(self, i):
        self.chunk_value = i

    def dropEvent(self, event):
        self.file_paths = list(map(lambda x: x.toLocalFile(), event.mimeData().urls()))
        logging.debug(self.file_paths)
        print('\n'.join(self.file_paths))
        self.file_paths_label.setText('\n'.join(self.file_paths))


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ui = MainWidget()
    ui.show()
    sys.exit(app.exec_())
