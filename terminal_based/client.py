import socket
import sys
import threading
import re
import ast
from base64 import b64decode, b64encode

sys.path.append('D:\\Prs\\24-04\\Python\\Network\\terminal_based\\')
from aes_encryption import decrypt, encrypt
import json

host = '127.0.0.1'
port = 15000

MSG_SIZE_HEADER_LENGTH = 10
AUTH_KEY, SALT = None, None

stop_event = threading.Event()


def parse_send_private_msg(text):
    # Define the pattern to match
    pattern = r'(\w+)\s+([a-zA-Z0-9,]*[a-zA-Z0-9])\s+(\S.*)'

    # Match the pattern
    match = re.match(pattern, text)

    if match:
        # Extract the matched groups
        first_part = match.group(1)
        second_part = [part for part in match.group(2).split(',') if part]  # Filter out empty strings
        third_part = match.group(3)

        # Return the parsed parts
        return first_part, second_part, third_part
    else:
        return None


def apply_tag_formatting(message):
    # Define tag patterns and corresponding formatting logic
    tag_patterns = {
        r'<bold>(.*?)</bold>': lambda match: f'<b>{match.group(1)}</b>',
        r'<color:(.*?)>(.*?)</color>': lambda match: f'<font color="{match.group(1)}">{match.group(2)}</font>',
        r'<link:(.*?)>(.*?)</link>': lambda match: f'<a href="{match.group(1)}">{match.group(2)}</a>',
    }
    # Apply formatting for each tag pattern found in the message
    for pattern, formatter in tag_patterns.items():
        message = re.sub(pattern, formatter, message)
    return message


def send_msg(write_socket, msg):
    """
    Send a message through the given socket.

    Args:
        write_socket: The socket to write the message to.
        msg: The message to be sent.
    """
    try:
        message = convert_msg_to_bytes(msg)
        write_socket.send(message)
        write_socket.send(b'<END>')
    except Exception as e:
        if e.errno == 10054:
            print("Socket is closed by the server")
            sys.exit()
        elif e.errno == 10038:
            # It's about socket still had data to recv.
            sys.exit()
        print(f"Error occurred while sending message: {e}")


def send_enc_msg(write_socket, msg, auth_key=None, salt=None):
    """
    Send an encrypted message through the given socket.

    Args:
        write_socket: The socket to write the encrypted message to.
        msg: The message to be encrypted and sent.
        auth_key: Authentication key for encryption.
        salt: Salt for encryption.
    """
    try:
        if auth_key is None and salt is None:
            if isinstance(msg, dict):
                msg = json.dumps(msg)
            encrypted_message = encrypt(AUTH_KEY, SALT, msg.encode('utf-8'))
        else:
            if isinstance(msg, dict):
                msg = json.dumps(msg)
            if not isinstance(msg, bytes):
                encrypted_message = encrypt(auth_key, salt, msg.encode('utf-8'))
            else:
                encrypted_message = encrypt(auth_key, salt, msg)
        message = convert_msg_to_bytes(b64encode(json.dumps(encrypted_message).encode('ascii')))
        write_socket.send(message)
        write_socket.send(b'<END>')
    except Exception as e:
        if e is TypeError:
            print(str(e))
        elif e is AttributeError:
            print(str(e))
        elif e.errno == 10054:
            print("Socket is closed by the server")
            sys.exit()
        elif e.errno == 10038:
            # It's about socket still had data to recv.
            sys.exit()
        print(f"Error occurred while sending encrypted message: {e}")
        send_msg(write_socket, msg)


def receive_msg(read_socket):
    """
    Receive a message from the given socket.

    Args:
        read_socket: The socket to read the message from.

    Returns:
        The received message if successful.
    """
    try:
        received_msg = b''  # Initialize received message as bytes
        while True:
            data = read_socket.recv(1024)  # Receive data from socket
            received_msg += data  # Append received data to the message buffer
            if received_msg[-5:] == b'<END>':  # If no more data is received (connection closed)
                break

        msg = received_msg[:-5].decode('utf-8')
        method, headers, body = parse_msg(msg)
        return method, headers, body
    except Exception as e:
        print(f"Error occurred while receiving message: {e}")
        return None


def process_received_msg(received_msg: bytes) -> bool:
    try:
        index = received_msg.index(b'\r\n\r\n') + 4
        headers = get_headers(received_msg.decode('utf-8'))
        if headers is not None and headers['Content-Length'] != len(received_msg[index:]):
            return False
        return True
    except Exception as e:
        return False


def get_headers(text: str):
    msg_parts = text.split('\r\n\r\n')
    headers = None
    try:
        headers = {item.split()[0].strip(": "): ''.join(item.split()[1:]).strip('"') for item in
                   msg_parts[0].split('\r\n')[1:]}
    except IndexError:
        pass  # Handle potential absence of headers gracefully
    return headers


def parse_msg(text: str) -> tuple[str, dict, str]:
    """
    Parses a formatted message into its constituent parts (method, headers, and body).

    Args:
        text: The received message string.

    Returns:
        A tuple containing the method, headers (as a dictionary), and body.
    """
    msg_parts = text.split('\r\n\r\n')
    method = msg_parts[0].split('\r\n')[:1][0]
    headers = None
    try:
        headers = {item.split()[0].strip(": "): ''.join(item.split()[1:]).strip('"') for item in
                   msg_parts[0].split('\r\n')[1:]}
    except IndexError:
        pass  # Handle potential absence of headers gracefully

    body = msg_parts[1]
    return method, headers, body


def get_private_msg(headers, body):
    sender = headers["Sender"]
    contacts = ", ".join(headers["Contacts"].split())
    msg = body
    return [sender, contacts, msg]


def get_public_msg(headers, body):
    sender = headers["Sender"]
    msg = body
    return [sender, msg]


def get_attendance_list(headers, body):
    attendance_list = ", ".join(ast.literal_eval(headers["Attendance-List"]))
    return [attendance_list, ]


def get_system_message(headers, body):
    return [body, ]


def receive_enc_msg(read_socket, auth_key=None) -> tuple[str, dict, str]:
    """
    Receive an encrypted message from the given socket and decrypt it.

    Args:
        read_socket: The socket to read the message from.
        auth_key: Authentication key for decryption.

    Returns:
        The decrypted message if successful.
    """
    try:
        received_msg = b''  # Initialize received message as bytes
        while True:
            data = read_socket.recv(1024)  # Receive data from socket
            received_msg += data  # Append received data to the message buffer
            if received_msg[-5:] == b'<END>':  # If no more data is received (connection closed)
                break

        encrypted_message = received_msg[:-5].decode('utf-8')
        try:
            encrypted_message = json.loads((b64decode(encrypted_message)).decode('utf-8'))
            if auth_key is None:
                decrypted_message = decrypt(AUTH_KEY, encrypted_message).decode('utf-8')
                method, headers, body = parse_msg(decrypted_message)
                valid_methods = ['Public Message', 'Private Message', 'Attendance List', 'System Message']
                if method in valid_methods:
                    return method, headers, body
                else:
                    print("Get unknown method message")
            else:
                decrypted_message = decrypt(auth_key, encrypted_message).decode('utf-8')
                print(decrypt(auth_key, encrypted_message))
                method, headers, body = parse_msg(decrypted_message)
                valid_methods = ['Public Message', 'Private Message', 'Attendance List', 'System Message']
                if method in valid_methods:
                    return method, headers, body
                else:
                    print(method)
                    print("Get unknown header message")
            return decrypted_message
        except Exception as e:
            if auth_key is None:
                print("Message is not encrypted: " + str(e))
            else:
                print("Message is not encrypted: (not login) " + str(e) + decrypt(auth_key, encrypted_message).decode(
                    'utf-8'))
            return encrypted_message
    except Exception as e:
        if auth_key is None:
            print("Message is Empty: " + str(e))
        else:
            if e.errno == 10053:
                print("Connection aborted by the host machine")
                left_chatroom(read_socket, True)
                # Handle this specific error case appropriately
            if e.errno == 10054:
                print("Another login attempt for your account reached, and you logged out.")
                left_chatroom(read_socket, True)
                # Handle this specific error case appropriately
            else:
                # Handle other socket errors
                print(f"Socket error: {e}")
        return None


def convert_msg_to_bytes(message) -> bytes:
    """
    Formats a message for transmission, handling dictionaries, bytes, and other types.

    Args:
        message: The message to be formatted.

    Returns:
        The formatted message as a bytes object, ready for transmission.
    """
    try:
        if isinstance(message, dict):
            # Serialize dictionaries using JSON
            message = json.dumps(message).encode('utf-8')
        # Ensure bytes representation for consistent length calculation
        if not isinstance(message, bytes):
            message = message.encode('utf-8')

        return message
    except Exception as e:
        print(f"Error occurred while formatting message: {e}")
        return b''


def send_public_msg(write_socket, msg, auth_key=None, salt=None, file=None):
    """
    Send a public message through the given socket.

    Args:
        :param file
        :param write_socket: The socket to write the message to.
        :param msg: The public message to be sent.
        :param salt:
        :param auth_key:
    """
    try:
        if file is not None:
            payload = f'Public Message\r\nContent-Length: "{len(msg)}"\r\nFile-Name: {file['File-Name']}\r\nContent-Type: {file['Content-Type']}\r\n\r\n'
            payload = payload.encode() + msg
        else:
            payload = f'Public Message\r\nContent-Length: "{len(msg.encode("utf-8"))}"\r\n\r\n{msg}'
        send_enc_msg(write_socket, payload, auth_key, salt)
    except Exception as e:
        print(f"Error occurred while sending public message: {e}")


def send_private_msg(write_socket, msg, contacts, auth_key=None, salt=None, file=None):
    """
    Send a private message through the given socket to specified contacts.

    Args:
        write_socket: The socket to write the message to.
        msg: The private message to be sent.
        contacts: List of usernames to whom the message is to be sent.
        auth_key:
        salt:
        file:
    """
    try:
        if contacts is not None:
            if file is not None:
                payload = f'Private Message\r\nContent-Length: "{len(msg)}"\r\nContacts: "{", ".join(contacts)}"\r\nFile-Name: {file['File-Name']}\r\nContent-Type: {file['Content-Type']}\r\n\r\n'
                payload = payload.encode() + msg
            else:
                payload = f'Private Message\r\nContent-Length: "{len(msg.encode("utf-8"))}"\r\nContacts: "{", ".join(contacts)}"\r\n\r\n{msg}'
            send_enc_msg(write_socket, payload, auth_key, salt)
    except Exception as e:
        print(f"Error occurred while sending private message: {e}")


def sign_in(client_socket, passed_username=None, passed_password=None):
    """
    Sign in with a username and password through the given client socket.

    Args:
        :param client_socket: The socket for communication with the server.
        :param passed_password:
        :param passed_username:
    """
    try:
        if not passed_username:
            username = input("Enter your Username:")
            password = input("Enter your Password:")
        else:
            username = passed_username
            password = passed_password
        payload = f'Registration\r\nusername: "{username}"\r\npassword: "{password}"\r\n\r\n'
        send_msg(client_socket, payload)
        _, _, body = receive_msg(client_socket)
        print(body)
        client_socket.close()
    except Exception as e:
        print(f"Error occurred during sign-in process: {e}")


def log_in(client_socket, passed_username=None, passed_password=None):
    """
    Log in with a username and password through the given client socket.

    Args:
        client_socket: The socket for communication with the server.
        passed_username:
        passed_password:

    Returns:
        auth_key and salt if login is successful, otherwise None.
    """
    try:
        if not passed_username:
            username = input("Enter your Username:")
        else:
            username = passed_username
        payload = f'Login\r\nusername: "{username}"\r\n\r\n'
        send_msg(client_socket, payload)
        msg = receive_msg(client_socket)
        method, headers, body = msg
        if method == 'System Message':
            if headers.get('Logged-In-Before', 0) != 0:
                print(body)
                _, _, body = receive_msg(client_socket)
                print(body)
                method, headers, body = receive_msg(client_socket)
            try:
                key = ast.literal_eval(body)
                if not passed_password:
                    password = input("Enter your password: ")
                else:
                    password = passed_password
                try:
                    auth_key = decrypt(password, key)
                    test_msg = encrypt(auth_key, key['salt'].encode('Latin-1'), f'Hello {username}'.encode('utf-8'))
                    send_enc_msg(client_socket, test_msg, auth_key, key['salt'].encode('Latin-1'))
                    _, _, body = receive_enc_msg(client_socket, auth_key)
                    print(body)
                    return auth_key, key['salt'].encode('Latin-1'), body
                except Exception as e:
                    print(e)
                    send_msg(client_socket, b'Password was wrong')
                    _, _, body = receive_msg(client_socket)
                    print(body)
                    client_socket.close()
                    return None, None, body
            except Exception as e:
                client_socket.close()
                return None, None, body
    except Exception as e:
        print(f"Error occurred during login process: {e}")
        return None, None


def get_attendance(client_socket, auth_key=None, salt=None):
    """
    Request attendance list from the server through the given client socket.

    Args:
        client_socket: The socket for communication with the server.
        auth_key:
        salt:
    """
    try:
        payload = 'Attendance List\r\n\r\n\r\n'
        send_enc_msg(client_socket, payload, auth_key, salt)
    except Exception as e:
        print(f"Error occurred while requesting attendance list: {e}")


def receive_messages_from_server(client_socket):
    """
    Receive messages from the server until the stop event is set.

    Args:
        client_socket: The socket for communication with the server.
    """
    try:
        while not stop_event.is_set():
            received_msg = receive_enc_msg(client_socket, AUTH_KEY)
            if received_msg is not None:
                process_received_message(received_msg)  # Process the message
            else:
                # print("Disconnected from server or error occurred")
                break  # Exit the loop if disconnected
    except Exception as e:
        print(f"Error occurred during message reception from server: {e}")


def process_received_message(message):
    method = message[0]
    headers = message[1]
    body = message[2]
    if method == 'Public Message':
        handle_public_message(headers, body)
    elif method == 'Private Message':
        handle_private_message(headers, body)
    elif method == 'System Message':
        handle_system_message(body)
    elif method == 'Attendance List':
        handle_attendance_list(headers)
    else:
        display_received_message(f"Unhandled message: {message}")


def handle_public_message(headers, body):
    sender = headers['Sender']
    print(f"[Public] [{sender}]: {body}")


def handle_private_message(headers=dict, body=str):
    sender = headers['Sender']
    contacts = ", ".join(sorted(headers.get("Contacts").split(',')))
    print(f"[Private] From [{sender}] to [{contacts}]: {body}")


def handle_attendance_list(headers):
    attendance_list = ", ".join(ast.literal_eval(headers["Attendance-List"]))
    print(f"Online Users: {attendance_list}")


def handle_system_message(body):
    print(f"[System] {body}")


def display_received_message(message):
    print(message)


def left_chatroom(client_socket, closed_sock=True):
    if closed_sock:
        try:
            payload = f'Left Chatroom\r\n\r\n\r\n'
            send_enc_msg(client_socket, payload)
            client_socket.close()
            stop_event.set()  # Signal the reception thread to stop
        except Exception as e:
            print(f"Error occurred while sending left chat room message: {e}")
        else:
            stop_event.set()  # Signal the reception thread to stop
    print("Program ending")
    sys.exit()  # Terminate the program


def main():
    global AUTH_KEY
    global SALT

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    print("Welcome to the chat application!")
    print("1. Log in")
    print("2. Sign up")
    choice = input("Enter your choice: ")

    if choice == '1':
        AUTH_KEY, SALT, _ = log_in(s)
    elif choice == '2':
        sign_in(s)
    else:
        print("Invalid choice. Exiting...")
        s.close()
        return

    if AUTH_KEY is not None:
        threading.Thread(target=receive_messages_from_server, args=(s,)).start()
        get_attendance(s)

    while True and AUTH_KEY is not None:
        message = input()
        if message[:2].lower() == 'to':
            _, contacts, body = parse_send_private_msg(message)
            send_private_msg(s, body, contacts)
        elif message == "attendance":
            get_attendance(s)
        elif message == "Bye.":
            left_chatroom(s)
        else:
            send_public_msg(s, message)

    s.close()


if __name__ == "__main__":
    main()
