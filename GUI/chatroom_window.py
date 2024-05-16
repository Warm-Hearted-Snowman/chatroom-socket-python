import mimetypes
import os
import sys
from time import sleep

from PyQt5.QtCore import QThread, pyqtSignal
import socket

from PyQt5.QtGui import QTextDocument
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit, QPushButton, QMessageBox, QTabWidget, QDialog, QListWidget,
    QListWidgetItem, QLabel, QFileDialog, QPlainTextEdit
)
from PyQt5.QtCore import Qt

sys.path.append('D:\\Prs\\24-04\\Python\\Network\\')
from terminal_based.client import (
    send_public_msg,
    receive_enc_msg,
    parse_send_private_msg,
    send_private_msg,
    get_attendance,
    left_chatroom
)
import ast

host = '127.0.0.1'
port = 15000

MSG_SIZE_HEADER_LENGTH = 10
AUTH_KEY, SALT = None, None
SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


class MessageReceiver(QThread):
    message_received = pyqtSignal(tuple)
    error_occurred = pyqtSignal(str)

    def __init__(self, socket, auth_key, parent=None):
        super().__init__(parent)
        self.socket = socket
        self.auth_key = auth_key
        self.running = True

    def run(self):
        while self.running:
            try:
                # Receive message from the server
                message = receive_enc_msg(self.socket, self.auth_key)
                if message:
                    self.message_received.emit(message)
            except ConnectionError as e:
                self.error_occurred.emit(f"ConnectionError: {e}")
                break
            except Exception as e:
                self.error_occurred.emit(f"An error occurred: {e}")

    def stop(self):
        self.running = False


class ChatRoomWindow(QWidget):
    def __init__(self, socket, auth_key, salt, welcome_msg, username):
        super().__init__()
        self.setWindowTitle(username)
        self.username = username
        self.attendees = []
        self.show_in_chat_flag = True
        self.socket = socket
        self.auth_key = auth_key
        self.salt = salt
        self.welcome_msg = welcome_msg
        self.init_ui()
        # Add a close button for each tab
        self.tab_widget.tabBar().setTabsClosable(True)
        self.tab_widget.tabBar().tabCloseRequested.connect(self.close_tab)

    def init_ui(self):
        # Create a tab widget to manage different chat sections
        self.tab_widget = QTabWidget()

        # Public chat tab
        self.public_chat_display = QTextEdit()
        self.public_chat_display.setReadOnly(True)
        self.tab_widget.addTab(self.public_chat_display, "Public Chat")

        # Private chat tabs (for each contact)
        self.private_chat_tabs = {}

        # Input field for typing messages
        self.message_input = QPlainTextEdit()
        self.message_input.setMaximumHeight(100)  # Set maximum height to limit expansion
        self.message_input.setPlaceholderText("Type your message here...")
        # self.message_input.returnPressed.connect(self.send_message)  # Trigger send on Enter press

        # Button for sending messages
        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        # Button to fetch and display attendance
        self.attendance_button = QPushButton("Fetch Attendees")
        self.attendance_button.clicked.connect(self.show_attendees)

        # Button for selecting files to send
        self.select_file_button = QPushButton("Select File")
        self.select_file_button.clicked.connect(self.select_file)

        # Button for sending selected file
        self.send_file_button = QPushButton("Send File")
        self.send_file_button.clicked.connect(self.send_file)

        # Label to display file transfer status
        self.file_transfer_status_label = QLabel("")

        # Main layout for the widget
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tab_widget)
        main_layout.addWidget(self.message_input)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(self.send_button)
        buttons_layout.addWidget(self.select_file_button)
        buttons_layout.addWidget(self.send_file_button)
        buttons_layout.addWidget(self.attendance_button)

        main_layout.addLayout(buttons_layout)
        main_layout.addWidget(self.file_transfer_status_label)

        self.setLayout(main_layout)

        # Initialize the welcome message and attendance list
        self.handle_system_message(self.welcome_msg)
        get_attendance(self.socket, self.auth_key, self.salt)

        # Start message receiver thread
        self.message_receiver = MessageReceiver(self.socket, self.auth_key)
        self.message_receiver.message_received.connect(self.process_received_message)
        self.message_receiver.error_occurred.connect(self.display_error)
        self.message_receiver.start()

        # Focus message_input when first tab (Public Chat) is selected
        self.tab_widget.currentChanged.connect(self.tab_changed)
        self.tab_changed(0)  # Trigger initial focus

    def select_file(self):
        # Open a file dialog to allow the user to select a file
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)")
        if file_path:
            # Update UI to display the selected file name
            file_name = os.path.basename(file_path)
            self.selected_file_path = file_path
            self.file_transfer_status_label.setText(f"Selected File: {file_name}")

    def send_file(self):
        if not hasattr(self, 'selected_file_path') or not self.selected_file_path:
            self.file_transfer_status_label.setText("No file selected.")
            return

        try:
            # Read the file content
            with open(self.selected_file_path, 'rb') as file:
                file_content = file.read()

            # Get the file extension
            file_extension = os.path.splitext(self.selected_file_path)[1]

            # Determine the Content-Type based on the file extension
            content_type, _ = mimetypes.guess_type(file_extension)

            # If the Content-Type is not recognized, default to 'application/octet-stream'
            if not content_type:
                content_type = 'application/octet-stream'

            # Prepare file metadata
            file_metadata = {
                'File-Name': os.path.basename(self.selected_file_path),
                'Content-Type': content_type
            }

            # Get the currently selected tab index
            current_tab_index = self.tab_widget.currentIndex()

            # Check if the current tab is a private chat tab
            current_tab_widget = self.tab_widget.widget(current_tab_index)
            if current_tab_widget in self.private_chat_tabs.values():
                # Find the contacts associated with the current private chat tab
                contacts = None
                for key, value in self.private_chat_tabs.items():
                    if value == current_tab_widget:
                        contacts = key.split(', ')
                        break

                if contacts:
                    # Send the file as a private message
                    send_private_msg(self.socket, file_content, contacts, self.auth_key, self.salt, file=file_metadata)
                    self.file_transfer_status_label.setText("File sent successfully.")
                    return

            # If the current tab is not a private chat tab or no contacts are associated, send as public message
            send_public_msg(self.socket, file_content, self.auth_key, self.salt, file=file_metadata)
            self.file_transfer_status_label.setText("File sent successfully.")

        except Exception as e:
            self.file_transfer_status_label.setText(f"Error sending file: {str(e)}")

    def tab_changed(self, index):
        current_widget = self.tab_widget.widget(index)
        if current_widget == self.public_chat_display:
            self.message_input.setFocus()

    def add_private_chat_tab(self, contacts):
        if contacts not in self.private_chat_tabs:
            private_chat_display = QTextEdit()
            private_chat_display.setReadOnly(True)
            self.private_chat_tabs[contacts] = private_chat_display
            self.tab_widget.addTab(private_chat_display, f"Private Chat: {contacts}")
            # Select the newly added private chat tab
            self.tab_widget.setCurrentWidget(private_chat_display)

    def send_message(self):
        message_text = self.message_input.toPlainText().strip()
        if not message_text:
            return

        # Get the currently selected tab index
        current_tab_index = self.tab_widget.currentIndex()

        # Check if the current tab is a private chat tab
        current_tab_widget = self.tab_widget.widget(current_tab_index)
        if current_tab_widget in self.private_chat_tabs.values():
            # Find the contacts associated with the current private chat tab
            contacts = None
            for key, value in self.private_chat_tabs.items():
                if value == current_tab_widget:
                    contacts = key.split(', ')
                    break

            if contacts:
                # Send the message as a private message
                if message_text == "Bye.":
                    left_chatroom(self.socket)
                    self.closeEvent()
                self.send_private_message(contacts, message_text)
                self.display_message(current_tab_widget, f"[You]: {message_text}")

        else:
            # Send the message in public message section
            if message_text[:2].lower() == 'to':
                _, contacts, body = parse_send_private_msg(message_text)
                self.send_private_message(contacts, body)
                self.display_message(current_tab_widget, f"[You]: {message_text}")
            elif message_text == "attendance":
                self.show_in_chat_flag = True
                get_attendance(self.socket, self.auth_key, self.salt)
            elif message_text == "Bye.":
                left_chatroom(self.socket)
                self.closeEvent()
            else:
                self.send_public_message(message_text)
                self.display_message(current_tab_widget, f"[You]: {message_text}")

        self.message_input.clear()
        self.message_input.setFocus()

    def send_public_message(self, message):
        send_public_msg(self.socket, message, self.auth_key, self.salt)

    def send_private_message(self, contacts, message):
        send_private_msg(self.socket, message, contacts, self.auth_key, self.salt)

    def process_received_message(self, message):
        method, headers, body = message

        if method == 'Public Message':
            self.handle_public_message(headers, body)
        elif method == 'Private Message':
            self.handle_private_message(headers, body)
        elif method == 'Attendance List':
            self.handle_attendance_list(headers)
        elif method == 'System Message':
            self.handle_system_message(body)
        else:
            self.display_received_message(f"Unhandled message: {message}")

    def handle_public_message(self, headers, body):
        sender = headers['Sender']
        self.display_message(self.public_chat_display, f"[Public] [{sender}]: {body}")

    def handle_private_message(self, headers, body):
        sender = headers['Sender']
        contacts = ", ".join(sorted(headers.get("Contacts").split(',')))
        self.add_private_chat_tab(contacts)
        private_chat_display = self.private_chat_tabs[contacts]
        self.display_message(private_chat_display, f"[Private] From [{sender}] to [{contacts}]: {body}")

    def handle_attendance_list(self, headers):
        attendance_list = ast.literal_eval(headers["Attendance-List"])
        if self.show_in_chat_flag:
            list_for_show = ", ".join(attendance_list)
            self.attendees = attendance_list
            self.display_received_message(f"Online Users: {list_for_show}")
        else:
            self.attendees = attendance_list

    def show_attendees(self):
        self.show_in_chat_flag = False
        get_attendance(self.socket, self.auth_key, self.salt)
        # Create a dialog to display attendees
        dialog = QDialog(self)
        dialog.setWindowTitle("Select Attendees")

        layout = QVBoxLayout()
        attendee_list_widget = QListWidget()

        for attendee in self.attendees:
            item = QListWidgetItem(attendee)
            item.setCheckState(Qt.Unchecked)
            attendee_list_widget.addItem(item)

        layout.addWidget(attendee_list_widget)

        confirm_button = QPushButton("Send Private Message")
        confirm_button.clicked.connect(lambda: self.handle_confirm_button_clicked(dialog, attendee_list_widget))

        layout.addWidget(confirm_button)
        dialog.setLayout(layout)

        dialog.exec_()

    def handle_confirm_button_clicked(self, dialog, attendee_list_widget):
        self.prepare_private_chat(attendee_list_widget)
        dialog.accept()

    def prepare_private_chat(self, attendee_list_widget):
        selected_attendees = []
        for index in range(attendee_list_widget.count()):
            item = attendee_list_widget.item(index)
            if item.checkState() == Qt.Checked:
                selected_attendees.append(item.text())

        if selected_attendees:
            # Check if the current user is selected
            current_user = self.get_current_user()
            if current_user not in selected_attendees:
                selected_attendees.append(current_user)

            contacts = ", ".join(sorted(selected_attendees))
            # Create private chat tab immediately
            self.add_private_chat_tab(contacts)
        else:
            QMessageBox.warning(self, "No Attendees Selected", "Please select at least one attendee.")

    def get_current_user(self):
        return self.username

    def send_private_message_to_selected(self, attendee_list_widget):
        selected_attendees = []
        for index in range(attendee_list_widget.count()):
            item = attendee_list_widget.item(index)
            if item.checkState() == Qt.Checked:
                selected_attendees.append(item.text())

        if selected_attendees:
            contacts = ",".join(selected_attendees)
            message_text = self.message_input.toPlainText().strip()
            if message_text:
                self.send_private_message(contacts, message_text)
                self.message_input.clear()

    def display_message(self, display_widget, message):
        # Get existing document or create a new one if it doesn't exist
        document = display_widget.document()
        if not document:
            document = QTextDocument()

        # Append a newline before the new message
        if not document.isEmpty():
            message = "<br>" + message

        # Append HTML to existing document
        cursor = display_widget.textCursor()
        cursor.movePosition(cursor.End)
        cursor.insertHtml(message)

        # Scroll to the end
        display_widget.ensureCursorVisible()

    def handle_system_message(self, body):
        self.display_received_message(f"[System] {body}")

    def display_received_message(self, message):
        current_tab_index = self.tab_widget.currentIndex()
        current_tab_widget = self.tab_widget.widget(current_tab_index)
        self.display_message(current_tab_widget, message)

    def display_error(self, error_message):
        QMessageBox.critical(self, "Error", error_message)

    def close_tab(self, index):
        widget = self.tab_widget.widget(index)
        if widget in self.private_chat_tabs.values():
            # Remove the private chat tab from the dictionary
            for key, value in self.private_chat_tabs.items():
                if value == widget:
                    del self.private_chat_tabs[key]
                    break
        self.tab_widget.removeTab(index)

    def closeEvent(self, event):
        self.message_receiver.stop()
        self.message_receiver.wait()
        event.accept()
