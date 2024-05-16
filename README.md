# PyQt5 Chat Application

This is a PyQt5-based chat application that supports public and private messaging, file transfer, and displaying HTML-formatted messages. It includes both client and server components to facilitate communication between multiple users in a chatroom environment.

## Features

- **Public and Private Messaging**: Users can send messages in public chatrooms or privately to selected attendees.
- **File Transfer**: Users can select and send files to other users.
- **HTML Message Support**: Messages can include HTML tags for rich text formatting, including bold text, colored text, and clickable links.
- **Attendee List**: Users can view the list of attendees currently online in the chatroom.

## Requirements

- Python 3.x
- PyQt5
- socket

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/Warm-Hearted-Snowman/chatroom-socket-python
    cd chatroom-socket-python
    ```

## Usage

### Server

1. Run the server:

    ```bash
    python server.py
    ```

### Client

1. Run the client:

    ```bash
    python client.py
    ```

2. Enter your username and connect to the server.

## File Transfer

1. Select a file using the `Select File` button.
2. Click the `Send File` button to send the selected file to the server.

## HTML Message Formatting

You can include HTML tags in your messages to apply rich text formatting. For example:
- `<b>Bold Text</b>`
- `<span style="color: red;">Red Text</span>`
- `<a href="http://example.com">Clickable Link</a>`

## Code Overview

### Client-Side

- **`ChatRoomWindow`**: Main UI class for the chat application. Manages public and private chat tabs, message input, and file transfer.
- **`MessageReceiver`**: Thread class to receive and process messages from the server.

### Server-Side

- **`server.py`**: Main server script. Manages client connections, message broadcasting, and file transfer.

### Utilities

- **`client.py`**: Client-side functions for sending and receiving encrypted messages.
- **`server.py`**: Server-side functions for handling client requests, managing the chatroom, and broadcasting messages.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request if you have any suggestions or improvements.

## License

This project is licensed under the MIT License.

## Contact

For any questions or support, please contact `amirhtpt.a@gmail.com`.
