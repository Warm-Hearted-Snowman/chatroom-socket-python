import logging
import socket
import threading
from typing import Tuple, Dict

from db_utils import *
from aes_encryption import *
import json

IP = '127.0.0.1'
PORT = 15000
MSG_SIZE_HEADER_LENGTH = 10
DB = "server_db.db"

clients = {}

logger = logging.getLogger(__name__)


def send_msg(write_socket, msg, headers=None):
    """
    Send a message through the given socket.

    Args:
        write_socket: The socket to write the message to.
        msg: The message to be sent.
        :param headers:
    """
    message = format_server_message(msg, headers)
    message = convert_msg_to_bytes(message)
    try:
        write_socket.send(message)
        write_socket.send(b'<END>')
    except Exception as e:
        logger.error(f"Error occurred while sending message: {e}")


def dict_to_text(dictionary):
    # Use list comprehension to create a list of formatted strings
    formatted_items = [f'{key}: "{value}"' for key, value in dictionary.items()]

    # Join the formatted strings with newline characters to create the final text
    result_text = '\r\n'.join(formatted_items)

    return result_text


def format_server_message(msg, headers=None):
    if headers is None:
        headers = {}
    if isinstance(msg, dict) or isinstance(msg, list):
        msg = json.dumps(msg)
    payload = f"System Message\r\nContent-Length: '{len(msg.encode('utf-8'))}'\r\n{dict_to_text(headers)}\r\n\r\n{msg}"
    return payload


def send_enc_msg(write_socket, msg):
    """
    Send an encrypted message through the given socket.

    Args:
        write_socket: The socket to write the encrypted message to.
        msg: The message to be encrypted and sent.
    """
    try:
        username, enc_key = get_enckey_by_socket(DB, write_socket)
        _, salt = get_auth_user_info(DB, username)
        encrypted_message = encrypt(enc_key, salt, msg.encode('utf-8'))
        message = convert_msg_to_bytes(b64encode(json.dumps(encrypted_message).encode('utf-8')))
        write_socket.send(message)
        write_socket.send(b'<END>')
    except Exception as e:
        logger.error(f"Error occurred while sending encrypted message: {e}")


def receive_msg(read_socket):
    """
    Receive a message from the given socket.

    Args:
        read_socket: The socket to read the message from.

    Returns:
        The received message if successful, None otherwise.
    """
    try:
        received_data = b''
        while True:
            data = read_socket.recv(1024)  # Receive data from socket
            received_data += data
            if received_data[-5:] == b'<END>':  # If no more data is received (connection closed)
                break

        # Decode the received message
        msg = received_data[:-5].decode('utf-8')

        return msg
    except Exception as e:
        logger.error(f"Error occurred while receiving message: {e}")
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


def receive_encrypted_message(read_socket: socket) -> bytes:
    """
    Receives an encrypted message from a socket, decrypts it, and returns the decrypted message.

    Args:
        read_socket: Socket connection to read from.

    Returns:
        The decrypted message as a string, or None if an error occurs.
    """
    try:
        logger.info(f"Receiving encrypted message from socket {read_socket}")

        received_msg = b''  # Initialize received message as bytes
        while True:
            data = read_socket.recv(1024)  # Receive data from socket
            received_msg += data  # Append received data to the message buffer
            if received_msg[-5:] == b'<END>':  # If no more data is received (connection closed)
                break
        # Decode the received message
        encrypted_data = received_msg[:-5].decode('utf-8')

        # Decrypt message
        try:
            encrypted_data = (b64decode(encrypted_data))
            if encrypted_data.find(b'File-Name: ') == -1:
                encrypted_data = encrypted_data.decode('utf-8')
            encrypted_data = json.loads(encrypted_data)
            _, enc_key = get_enckey_by_socket(DB, read_socket)
            decrypted_data = decrypt(enc_key, encrypted_data)  # Assuming a decrypt_message function
            logger.info(f"Decrypted message successfully: {decrypted_data}")
            return decrypted_data
        except Exception as e:
            logger.error(f"Decryption error on socket {read_socket}: {e}")
            end_connection(read_socket, True)
            return None  # Indicate decryption failure
    except (ConnectionError, OSError) as e:  # Catch potential socket errors
        logger.error(f"Socket error on {read_socket}: {e}")
        end_connection(read_socket, True)
        return None  # Indicate socket communication error
    except Exception as e:  # Catch unexpected errors
        logger.exception(f"Unexpected error receiving message on socket {read_socket}: {e}")
        end_connection(read_socket, True)
        return None  # Indicate general error


def convert_msg_to_bytes(message):
    """
    Formats a message for transmission, handling dictionaries, bytes, and other types.

    Args:
        message: The message to be formatted.

    Returns:
        The formatted message as a bytes object, ready for transmission.
    """

    if isinstance(message, dict):
        # Serialize dictionaries using pickle
        message = json.dumps(message).encode('utf-8')
    # Ensure bytes representation for consistent length calculation
    if not isinstance(message, bytes):
        message = message.encode('utf-8')

    return message


def end_connection(client_socket, authed_client=False):
    """
    End the connection with the client socket.

    Args:
        client_socket: The client socket to end the connection with.
        authed_client: Boolean indicating whether the client is authenticated.
    """
    try:
        username = "Not Authenticated User"
        if authed_client:
            username = get_username_by_socket(DB, client_socket)
            delete_enc_key(DB, client_socket)
            delete_socketcluster_key(DB, client_socket)
            del clients[client_socket]
            send_public_message(client_socket, {}, f"( {username} ) left the chat room.", True)
        logger.info(f'Connection with client socket " {client_socket} : {username} " closed.')
        client_socket.close()
    except Exception as e:
        logger.error(f"Error occurred while ending connection with client socket {client_socket}: {e}")


def send_private_message(client_socket, headers, body):
    """
    Send a private message to specified clients.

    Args:
        client_socket: The client socket sending the message.
        headers: Headers of the message.
        body: Body of the message.
    """
    try:
        username = get_username_by_socket(DB, client_socket)
        target_clients = headers.get('Contacts', '').split(',')
        save_message(DB, username, target_clients, body)
        if username not in target_clients:
            target_clients.insert(0, username)
        for client_sock, sock_username in clients.items():
            if sock_username in target_clients:
                payload = f'Private Message\r\nContent-Length: "{len(body.encode("utf-8"))}"\r\nContacts: "{", ".join(target_clients)}"\r\nSender: {username}\r\n\r\n{body}'
                send_enc_msg(client_sock, payload)
        logger.info(f"Private message sent from {username} to {target_clients}: {body}")
    except Exception as e:
        logger.error(f"Error occurred while sending private message from {username}: {e}")


def send_attendance_list(client_socket, headers):
    """
    Send the list of online users to the client.

    Args:
        client_socket: The client socket to send the list to.
        headers: Headers of the message.
    """
    try:
        payload = f'Attendance List\r\nAttendance-List: "{list(clients.values())}"\r\n\r\n'
        send_enc_msg(client_socket, payload)
        logger.info("Attendance list sent to client.")
    except Exception as e:
        logger.error(f"Error occurred while sending attendance list to client: {e}")


def start_connection(client_socket: socket) -> None:
    """
    Establishes a connection with a client, handles message receiving, parsing, and routing.

    Args:
        client_socket: Socket connection to manage.
    """
    logger.info(f"Client socket {client_socket} connected")

    try:
        # Receive initial message
        msg = receive_msg(client_socket)
        if msg == '':
            logger.info(f"Client {client_socket} disconnected (empty initial message)")
            end_connection(client_socket)
            return
        # Parse initial message
        method, headers, body = parse_msg(msg)
        logger.debug(f"Received initial message from {client_socket}: {method}, {headers}, {body}")

        # Handle initial login/registration
        if method == 'Login':
            log_in(client_socket, headers)
        elif method == 'Registration':
            sign_in(client_socket, headers)
        else:
            logger.error(f"Invalid initial method received from {client_socket}: {method}")

        # Continuous message processing loop
        while True:
            # Receive and decrypt message
            msg = receive_encrypted_message(client_socket)
            if msg is None:
                logger.info(f"Client {client_socket} disconnected (empty encrypted message)")
                end_connection(client_socket, True)
                break
            # Parse decrypted message
            method, headers, body = parse_msg(msg)
            logger.debug(f"Received decrypted message from {client_socket}: {method}, {headers}")

            try:
                # Handle different message types
                if method == 'Public Message':
                    if 'File-Name' in headers:
                        handle_file_transfer(client_socket, headers, body)
                    else:
                        send_public_message(client_socket, headers, body.decode('utf-8'))
                elif method == 'Private Message':
                    if 'File-Name' in headers:
                        # Handle file transfer request
                        handle_file_transfer(client_socket, headers, body, True)
                    else:
                        send_private_message(client_socket, headers, body.decode('utf-8'))
                elif method == 'Attendance List':
                    send_attendance_list(client_socket, headers)
                elif method == 'Left Chatroom':
                    end_connection(client_socket, True)
                else:
                    logger.error(f"Invalid method received from {client_socket}: {method}")
                    raise ValueError("Wrong Entry")  # More specific exception
            except Exception as e:
                logger.exception(f"Error processing message from {client_socket}: {e}")
                raise  # Re-raise to disconnect client

    except (ConnectionError, OSError) as e:
        logger.error(f"Socket error on {client_socket}: {e}")
    except Exception as e:  # Catch unexpected errors
        logger.exception(f"Unexpected error handling client {client_socket}: {e}")
    finally:
        end_connection(client_socket, authed_client=True)  # Assuming cleanup for authenticated clients


def handle_file_transfer(client_socket, headers, body, is_private=False):
    try:
        file_name = headers.get('File-Name')
        content_type = headers.get('Content-Type')
        contacts = headers.get('Contacts')

        if is_private:
            directory = f'./files/private/{contacts}'
        else:
            directory = './files/public/'

        # Check if directory exists, if not, create it
        if not os.path.exists(directory):
            os.makedirs(directory)

        # Construct the file path
        file_path = os.path.join(directory, file_name)

        # Write the file content received from the client
        with open(file_path, 'wb') as file:
            file.write(body)
        # Send a confirmation message to the client
        confirmation_msg = f"File '{file_name}' has been received and saved successfully."
        send_public_message(client_socket, {}, confirmation_msg, True)
    except Exception as e:
        error_msg = f"Error occurred while handling file transfer: {e}"
        send_public_message(client_socket, {}, error_msg, True)


def send_public_message(client_socket: socket, headers: dict, body: str, system_is_sender: bool = False) -> None:
    """
    Broadcasts a public message to all connected clients.

    Args:
        client_socket: Socket of the sending client.
        headers: Message headers (unused in this function).
        body: Message body to broadcast.
        system_is_sender: Whether the message originates from the server.
    """
    username = 'Server' if system_is_sender else get_username_by_socket(DB, client_socket)
    logger.info(f"Public message sent from {username}: {body}")
    save_message(DB, username, 'PUBLIC', body)
    for client_sock in clients:
        try:
            payload = f'Public Message\r\nContent-Length: "{len(body.encode("utf-8"))}"\r\nSender: {username}\r\n\r\n{body}'
            send_enc_msg(client_sock, payload)
            logger.info(f"Public message sent to client {client_sock.getpeername()}")
        except socket.error as e:
            logger.error(f"Error sending public message to {client_sock}: {e}")
    # Consider removing the print statement as logging provides a record


def get_socket_adr(client_socket):
    """
    Retrieves the IP address and port of the connected client socket.

    Args:
        client_socket: Socket connection

    Returns:
        2 object containing the IP address and port number.
    """
    return client_socket.getpeername()[0], client_socket.getpeername()[1]


def find_key_by_value(dictionary, search_value):
    # Use a dictionary comprehension to find the key for the given value
    try:
        key = next(key for key, value in dictionary.items() if value == search_value)
        validation = True
    except:
        key = ''
        validation = False
    return validation, key


def log_in(client_socket: socket, auth_headers: dict) -> None:
    """
    Handles user login process, including authentication, encryption key exchange,
    and potentially updating user socket information in the database.

    Args:
        client_socket: Socket connection to the client.
        auth_headers: Dictionary containing username and password for authentication.
    """
    username = auth_headers.get("username")

    if not username:
        logger.error(f"Missing username in login request from {client_socket.getpeername()}")
        send_msg(client_socket, "Invalid credentials provided")
        end_connection(client_socket)
        return None

    try:
        # Check for username existence
        if not username_exists(DB, username):
            logger.info(f"Login attempt for non-existent user: {username}")
            send_msg(client_socket, "Username not found")
            end_connection(client_socket)
            return None

        if username in clients.values():
            logger.info(f"Login attempt for logged in user: {username}")
            send_msg(client_socket, f"The {username} user has logged in before, logging him out...",
                     {'Logged-In-Before': True})
            validation, logged_socket = find_key_by_value(clients, username)
            if validation:
                end_connection(logged_socket, True)
                logger.info(f"Previous ( {username} ) logged out successfully.")
                send_msg(client_socket, f"Previous {username} logged out successfully.")

        # Retrieve user authentication information
        stored_password, salt = get_auth_user_info(DB, username)

        # Generate and exchange encryption key
        random_enc_key = generate_random_key(16)
        encrypted_key = encrypt(stored_password, salt, random_enc_key)
        send_msg(client_socket, encrypted_key)
        add_enc_key(DB, username, random_enc_key)
        socket_ip, socket_port = get_socket_adr(client_socket)
        add_user_socket_info(DB, username, socket_ip, socket_port,
                             threading.current_thread().ident)

        # Receive and validate client authentication message
        received_msg = receive_encrypted_message(client_socket).decode('utf-8')
        if received_msg is None:
            logger.error(
                f"Failed to receive encrypted message from ( {client_socket.getpeername()} : {username} ), password was wrong")
            send_msg(client_socket, "Authentication failed: Password was wrong!")
            return None
        try:
            user_auth_key = json.loads(received_msg)
            test_msg = decrypt(random_enc_key, user_auth_key).decode('utf-8')
            if test_msg != f'Hello {username}':
                logger.info(f"Failed login attempt for user: ( {username} ), protocol usage wrong.")
                send_msg(client_socket, "Authentication failed: wrong protocol usage")
                end_connection(client_socket)
                return None
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(f"Error decoding JSON: {e}")
            send_msg(client_socket, "Invalid authentication request")
            end_connection(client_socket)
            return None

        # Login successful - send welcome message and update user info
        logger.info(f"User {username} logged in successfully")
        payload = format_server_message(f"Hi {username}, welcome to the chat room.")
        send_enc_msg(client_socket, payload)
        send_public_message(client_socket, {}, f"( {username} ) joined the chat room.", True)
        clients[client_socket] = username

    except Exception as e:
        logger.exception(f"Unexpected error during login for {username}: {e}")
        send_msg(client_socket, "Internal server error")
        end_connection(client_socket)
        raise  # Re-raise for potential further handling


def generate_message_with_tags(text, tags):
    # Generate message content with specified tags
    formatted_text = text
    for tag, params in tags.items():
        formatted_text = f'<{tag}:{":".join(params)}>{formatted_text}</{tag}>'
    return formatted_text


def sign_in(client_socket: socket, auth_headers: dict) -> None:
    """
    Handles user sign-in process based on provided credentials and sends feedback to the client.

    Args:
        client_socket: Socket connection to the client.
        auth_headers: Dictionary containing username and password for authentication.
    """
    username = auth_headers.get("username")
    password = auth_headers.get("password")

    if not username or not password:
        logger.error(f"Missing username or password in sign-in request from {client_socket.getpeername()}")
        error_message = "Invalid credentials provided"
        send_msg(client_socket, error_message)
        return

    if username_exists(DB, username):
        logger.info(f"Sign-in attempt with existing username: {username}")
        error_message = "Username already exists"
        send_msg(client_socket, error_message)
        return

    # Attempt user creation
    if add_user(DB, username, password):
        success_message = "User created successfully"
        logger.info(f"User {username} created successfully")
    else:
        success_message = "User creation failed"
        logger.error(f"Failed to create user {username}")

    send_msg(client_socket, success_message)


def parse_msg(text: bytes) -> tuple[str, dict, bytes]:
    """
    Parses a formatted message into its constituent parts (method, headers, and body).

    Args:
        text: The received message string.

    Returns:
        A tuple containing the method, headers (as a dictionary), and body.
    """
    if isinstance(text, str):
        text = text.encode()
    msg_parts = text.find(b'\r\n\r\n')
    method = text[:msg_parts].decode('utf-8').split('\r\n')[:1][0]
    headers = None
    try:
        headers = {item.split()[0].strip(": "): ''.join(item.split()[1:]).strip('"') for item in
                   text[:msg_parts].decode('utf-8').split('\r\n')[1:]}
    except IndexError:
        pass  # Handle potential absence of headers gracefully

    body = text[msg_parts + 4:]
    return method, headers, body


def get_headers(text: str):
    msg_parts = text.split('\r\n\r\n')
    headers = None
    try:
        headers = {item.split()[0].strip(": "): ''.join(item.split()[1:]).strip('"') for item in
                   msg_parts[0].split('\r\n')[1:]}
    except IndexError:
        pass  # Handle potential absence of headers gracefully
    return headers


def main():
    """
    Entry point for the chat server application.
    """

    logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Clean up any existing sessions/sockets
    delete_sessions_sockets(DB)

    # Create server socket
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((IP, PORT))
        server_socket.listen()
        logging.info(f"Server listening on {IP}:{PORT}")
    except OSError as e:
        logging.error(f"Failed to start server: {e}")
        exit(1)

    # Main server loop
    while True:
        try:
            new_client_socket, client_address = server_socket.accept()
            logging.info(f"New client connected from {client_address}")
            # Start a new thread for each client connection
            threading.Thread(target=start_connection, args=(new_client_socket,)).start()
        except Exception as e:
            logging.exception(f"Unexpected error while accepting connection: {e}")


if __name__ == '__main__':
    main()
