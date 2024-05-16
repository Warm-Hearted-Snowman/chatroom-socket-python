import sys
from PyQt5.QtWidgets import QApplication

sys.path.append('D:\\Prs\\24-04\\Python\\Network\\')
from login_page import LoginPage
from chatroom_window import ChatRoomWindow  # Import your existing ChatRoomWindow


def main():
    app = QApplication(sys.argv)

    # Create and show the login page
    login_page = LoginPage()
    login_page.show()

    # Start the application event loop
    sys.exit(app.exec_())

    # After the event loop exits (e.g., when the login page is closed),
    # check if the login was successful and open the chatroom window
    # if login_page.authenticated:
    #     auth_key, salt = login_page.auth_data
    #     chatroom_window = ChatRoomWindow(auth_key, salt)
    #     chatroom_window.show()


if __name__ == "__main__":
    main()
