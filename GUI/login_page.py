import sys
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QMessageBox
)
import socket

sys.path.append('D:\\Prs\\24-04\\Python\\Network\\')
from terminal_based.client import log_in, sign_in

host = '127.0.0.1'
port = 15000


class LoginPage(QWidget):
    def __init__(self):
        super().__init__()
        self.password_input = None
        self.username_input = None
        self.chatroom_window = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Login / Sign Up")
        self.setGeometry(100, 100, 400, 200)

        username_label = QLabel("Username:")
        password_label = QLabel("Password:")
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        login_button = QPushButton("Login")
        login_button.clicked.connect(self.attempt_login)

        signup_button = QPushButton("Sign Up")
        signup_button.clicked.connect(self.attempt_signup)

        layout = QVBoxLayout()
        layout.addWidget(username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(login_button)
        layout.addWidget(signup_button)

        self.setLayout(layout)

    def attempt_login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        if not username or not password:
            QMessageBox.critical(self, "Error", "Please enter both username and password.")
            return

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client_socket.connect((host, port))
            auth_key, salt, welcome_msg = log_in(client_socket, username, password)
            if auth_key and salt:
                # Successful login, open chatroom window
                self.open_chatroom(client_socket, auth_key, salt, welcome_msg)
            else:
                QMessageBox.critical(self, "Error", welcome_msg)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error connecting to server: {e}")

    def attempt_signup(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        if not username or not password:
            QMessageBox.critical(self, "Error", "Please enter both username and password.")
            return

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client_socket.connect((host, port))
            sign_in(client_socket, username, password)
            QMessageBox.information(self, "Success", "Sign up successful. You can now login.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error connecting to server: {e}")

    def open_chatroom(self, client_socket, auth_key, salt, welcome_msg):
        from chatroom_window import ChatRoomWindow
        self.chatroom_window = ChatRoomWindow(client_socket, auth_key, salt, welcome_msg,
                                              self.username_input.text().strip())
        self.chatroom_window.show()
        self.close()


def main():
    app = QApplication(sys.argv)
    login_page = LoginPage()
    login_page.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
