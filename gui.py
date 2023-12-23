from PyQt5.QtWidgets import QMainWindow, QApplication, QPushButton, QLabel, QVBoxLayout, QWidget
import sys


class MainWidget(QMainWindow):
    def __init__(self):
        super().__init__()
        self.file_paths = None

        self.file_paths_label = QLabel("EMPTY WORDS")

        self.reset_button = QPushButton("Reset")
        self.reset_button.clicked.connect(self.reset_list)

        layout = QVBoxLayout()
        layout.addWidget(self.file_paths_label)
        layout.addWidget(self.reset_button)

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

    def dropEvent(self, event):
        self.file_paths = list(map(lambda x: x.toLocalFile(), event.mimeData().urls()))
        print('\n'.join(self.file_paths))
        self.file_paths_label.setText('\n'.join(self.file_paths))


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ui = MainWidget()
    ui.show()
    sys.exit(app.exec_())
