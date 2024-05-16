import logging
import socket
import sqlite3
import os
from Crypto.Random import get_random_bytes

db_file = "server_db.db"

# Setting up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def is_db_exist(db_file_path):
    """
    Creates a new SQLite database file if it doesn't exist.

    Args:
        db_file_path (str): The path to the database file.
    """
    if not os.path.isfile(db_file_path):
        conn = sqlite3.connect(db_file_path)
        conn.close()
        logger.info(f"Database file '{db_file_path}' created.")


def create_db(db_file):
    """
    Create database tables if they don't exist.

    Args:
        db_file (str): The path to the database file.
    """
    try:
        is_db_exist(db_file)
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS User (
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          username TEXT UNIQUE,
                          password TEXT
                        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS UserSalt (
                          user_id INTEGER PRIMARY KEY REFERENCES User(id),
                          salt TEXT
                        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS UsersSession (
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          username TEXT UNIQUE,
                          enc_key TEXT
                        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS UsersSockets (
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          username TEXT UNIQUE,
                          socket_ip TEXT,
                          socket_port TEXT,
                          thread_id INTEGER
                        )''')
        # Create Messages table
        cursor.execute('''CREATE TABLE IF NOT EXISTS Messages (
                          id INTEGER PRIMARY KEY,
                          sender_id INTEGER,
                          recipients_id TEXT,
                          message TEXT,
                          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                          FOREIGN KEY (sender_id) REFERENCES User(id)
                      )''')
        conn.commit()
        logger.info("Database tables created with improved design!")
    except sqlite3.Error as err:
        logger.error(f"Error creating database tables: {err}")
    finally:
        conn.close()


def save_message(db_file, sender_username, recipients_username, message):
    """
    Save a message to the database.

    Args:
        db_file (str): Path to the SQLite database file.
        sender_username (str): Username of the message sender.
        recipients_username (str): Username of the message recipient.
        message (str): Content of the message.
    """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Get sender and recipient IDs
        cursor.execute("SELECT id FROM User WHERE username=?", (sender_username,))
        sender_row = cursor.fetchone()
        if not sender_row:
            raise ValueError(f"Sender '{sender_username}' not found in the database.")
        sender_id = sender_row[0]

        # Insert message into Messages table
        cursor.execute('''INSERT INTO Messages (sender_id, recipients_id, message)
                          VALUES (?, ?, ?)''', (sender_id, recipients_username, message))
        conn.commit()
        logger.info("Message saved successfully.")

    except sqlite3.Error as e:
        logger.error(f"Database error occurred: {e}")
    except ValueError as ve:
        logger.error(f"Error in save_message(): {ve}")
    finally:
        if conn:
            conn.close()


def username_exists(db_file, username):
    """
    Checks if a username exists in the User table.

    Args:
        db_file (str): The path to the database file.
        username (str): The username to check.

    Returns:
        bool: True if the username exists, False otherwise.
    """
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM User WHERE username = ?", (username,))
        result = cursor.fetchone()
        return result is not None
    except sqlite3.Error as err:
        logger.error(f"Error checking username existence: {err}")
        return False
    finally:
        conn.close()


def add_user(db_file_path, username, password):
    """
    Adds a new user to the User table with hashed password and random salt.

    Args:
        db_file_path (str): The path to the database file.
        username (str): The username for the new user.
        password (str): The raw password for the new user.

    Returns:
        bool: True if the user was added successfully, False otherwise.
    """
    try:
        conn = sqlite3.connect(db_file_path)
        cursor = conn.cursor()
        salt = get_random_bytes(16)
        cursor.execute("""
            INSERT INTO User (username, password)
            VALUES (?, ?)
        """, (username, password))
        cursor.execute("""
            INSERT INTO UserSalt (user_id, salt)
            VALUES (?, ?)
        """, (cursor.lastrowid, salt))
        conn.commit()
        return True
    except sqlite3.Error as err:
        logger.error(f"Error adding user: {err}")
        return False
    finally:
        conn.close()


def get_auth_user_info(db_file, username):
    """
    Get user authentication information from the database.

    Args:
        db_file (str): The path to the database file.
        username (str): The username to fetch information for.

    Returns:
        tuple: A tuple containing the user's password and salt.
    """
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        cursor.execute("SELECT id, password FROM User WHERE username = ?", (username,))
        result = cursor.fetchone()
        id, password = result[0], result[1]
        cursor.execute("SELECT salt FROM UserSalt WHERE user_id = ?", (id,))
        salt = cursor.fetchone()[0]
        return password, salt
    except sqlite3.Error as err:
        logger.error(f"Error retrieving user information: {err}")
        return None, None
    finally:
        conn.close()


def add_enc_key(db_file, username, enc_key):
    """
    Add encryption key to the UsersSession table in the database.

    Args:
        db_file (str): The path to the database file.
        username (str): The username to associate with the encryption key.
        enc_key (str): The encryption key to add.
    """
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        cursor.execute("INSERT INTO UsersSession (username, enc_key) VALUES (?, ?)", (username, enc_key))
        conn.commit()
        logger.info("Encryption key added successfully.")
    except sqlite3.Error as err:
        logger.error(f"Error adding encryption key: {err}")
    finally:
        conn.close()


def delete_enc_key(db_file, client_socket):
    """
    Delete encryption key associated with a client socket from the UsersSession table.

    Args:
        db_file (str): The path to the database file.
        client_socket (socket.socket): The client socket whose encryption key is to be deleted.
    """
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        username = get_username_by_socket(db_file, client_socket)
        cursor.execute("DELETE FROM UsersSession WHERE username = ?", (username,))
        conn.commit()
        logger.info("Encryption key deleted successfully.")
    except sqlite3.Error as err:
        logger.error(f"Error deleting encryption key: {err}")
    finally:
        conn.close()


def delete_socketcluster_key(db_file, client_socket):
    """
    Delete socket cluster key associated with a client socket from the UsersSockets table.

    Args:
        db_file (str): The path to the database file.
        client_socket (socket.socket): The client socket whose socket cluster key is to be deleted.
    """
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        username = get_username_by_socket(db_file, client_socket)
        cursor.execute("DELETE FROM UsersSockets WHERE username = ?", (username,))
        conn.commit()
        logger.info("Socket cluster key deleted successfully.")
    except sqlite3.Error as err:
        logger.error(f"Error deleting socket cluster key: {err}")
    finally:
        conn.close()


def add_user_socket_info(db_file, username, socket_ip, socket_port, thread_id):
    """
    Add user socket information to the UsersSockets table in the database.

    Args:
        db_file (str): The path to the database file.
        username (str): The username associated with the socket.
        socket_ip (str): The IP address of the socket.
        socket_port (int): The port of the socket.
        thread_id (int): The ID of the thread associated with the socket.
    """
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO UsersSockets (username, socket_ip, socket_port, thread_id) VALUES (?, ?, ?, ?)
        """, (username, socket_ip, socket_port, thread_id))
        conn.commit()
        logger.info("User socket information added successfully.")
    except sqlite3.Error as err:
        logger.error(f"Error adding user socket information: {err}")
    finally:
        conn.close()


def get_username_by_key(db_file, key):
    """
    Retrieve username associated with an encryption key from the UsersSession table.

    Args:
        db_file (str): The path to the database file.
        key (str): The encryption key.

    Returns:
        str: The username associated with the encryption key.
    """
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        cursor.execute("SELECT username FROM UsersSession WHERE enc_key = ?", (key,))
        result = cursor.fetchone()
        return result[0] if result else None
    except sqlite3.Error as err:
        logger.error(f"Error retrieving username by key: {err}")
        return None
    finally:
        conn.close()


def get_username_by_socket(db_file, client_socket: socket.socket):
    """
    Retrieve username associated with a client socket from the UsersSockets table.

    Args:
        db_file (str): The path to the database file.
        client_socket (socket.socket): The client socket.

    Returns:
        str: The username associated with the client socket.
    """
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        socket_ip, socket_port = client_socket.getpeername()
        cursor.execute("SELECT username FROM UsersSockets WHERE socket_ip = ? AND socket_port = ?",
                       (socket_ip, socket_port))
        result = cursor.fetchone()
        return result[0] if result else None
    except sqlite3.Error as err:
        logger.error(f"Error retrieving username by socket: {err}")
        return None
    finally:
        conn.close()


def get_enckey_by_socket(db_file, client_socket: socket.socket):
    """
    Retrieve encryption key associated with a client socket from the UsersSession table.

    Args:
        db_file (str): The path to the database file.
        client_socket (socket.socket): The client socket.

    Returns:
        tuple: A tuple containing the username and encryption key associated with the client socket.
    """
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        username = get_username_by_socket(db_file, client_socket)
        cursor.execute("SELECT enc_key FROM UsersSession WHERE username = ?", (username,))
        enc_key = cursor.fetchone()[0]
        return username, enc_key
    except sqlite3.Error as err:
        logger.error(f"Error retrieving encryption key by socket: {err}")
        return None, None
    finally:
        conn.close()


def get_clients_info(db_file):
    """
    Retrieve information about all connected clients from the UsersSockets table.

    Args:
        db_file (str): The path to the database file.

    Returns:
        list: A list of tuples containing information about each connected client (username, socket_ip, socket_port).
    """
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        cursor.execute("SELECT username, socket_ip, socket_port FROM UsersSockets")
        clients = cursor.fetchall()
        return clients
    except sqlite3.Error as err:
        logger.error(f"Error retrieving clients information: {err}")
        return []
    finally:
        conn.close()


def delete_sessions_sockets(db_file):
    """
    Delete all records from the UsersSockets and UsersSession tables.

    Args:
        db_file (str): The path to the database file.

    Returns:
        bool: True if deletion was successful, False otherwise.
    """
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        cursor.execute("DELETE FROM UsersSockets")
        cursor.execute("DELETE FROM UsersSession")
        conn.commit()
        logger.info("Sessions and sockets deleted successfully.")
        return True
    except sqlite3.Error as err:
        logger.error(f"Error deleting sessions and sockets: {err}")
        return False
    finally:
        conn.close()


def get_all_public_msgs(db_file):
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM Messages WHERE recipients_id = 'PUBLIC'")
        messages = cursor.fetchall()

        return messages
    except sqlite3.Error as err:
        logger.error(f"Error deleting sessions and sockets: {err}")
        return False
    finally:
        conn.close()


def get_username_by_userid(db_file, user_id):
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        cursor.execute("SELECT username FROM User WHERE id = ?",
                       (user_id,))
        result = cursor.fetchone()
        return result[0] if result else None
    except sqlite3.Error as err:
        logger.error(f"Error retrieving username by user id: {err}")
        return None
    finally:
        conn.close()
