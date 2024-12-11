import socket
import threading
import rsa
import os
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.modes import CFB
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from backend.crypto import (
    generate_rsa_keys,
    generate_iv,
    calculate_checksum,
)
import hashlib
from pyDH import DiffieHellman
import json

BUFFER_SIZE = 1024 * 1024  # 1MB
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


class FileTransfer:
    def __init__(self, is_server, ip, port):
        """
        Initialize the FileTransfer instance.

        :param is_server: Boolean indicating if this is a server instance
        :param ip: IP address to bind/connect to
        :param port: Port number to use
        """
        self.is_server = is_server
        self.ip = ip
        self.port = port
        self.conn = None
        self.server_socket = None
        self.shared_key = None
        self._handshake_complete = threading.Event()

        # Generate RSA key pair
        try:
            self.rsa_public_key, self.rsa_private_key = generate_rsa_keys()
        except Exception as e:
            logging.error(f"Failed to generate RSA keys: {e}")
            raise

    def start(self):
        """
        Start the file transfer process in a separate thread.
        """
        try:
            thread = threading.Thread(target=self._run)
            thread.start()
            return thread
        except Exception as e:
            logging.error(f"Failed to start file transfer: {e}")
            raise

    def wait_for_handshake(self, timeout=30):
        """
        Wait for the handshake to complete.

        :param timeout: Maximum time to wait for handshake (in seconds)
        :return: True if handshake completed, False otherwise
        """
        return self._handshake_complete.wait(timeout)

    def _run(self):
        """
        Main method to run either server or client logic.
        """
        try:
            if self.is_server:
                self._start_server()
            else:
                self._start_client()
        except Exception as e:
            logging.error(f"Error in file transfer process: {e}")
        finally:
            # Ensure handshake event is set in case of early termination
            self._handshake_complete.set()

    def _start_server(self):
        """Start the server and wait for a client connection."""
        try:
            # Create server socket
            self.server_socket = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.ip, self.port))
            self.server_socket.listen(1)

            logging.info(f"Server listening on {self.ip}:{self.port}")

            # Accept connection
            self.conn, client_address = self.server_socket.accept()
            logging.info(f"Connection from {client_address}")

            # Perform crypto handshake
            self._crypto_handshake()

            # Signal handshake completion
            self._handshake_complete.set()

            # Wait for file transfer
            self._receive_file()
        except Exception as e:
            logging.error(f"Server error: {e}")
        finally:
            self.close()

    def _start_client(self):
        """Connect to the server and perform file transfer."""
        try:
            # Create client socket
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.connect((self.ip, self.port))
            logging.info(f"Connected to {self.ip}:{self.port}")

            # Perform crypto handshake
            self._crypto_handshake()

            # Signal handshake completion
            self._handshake_complete.set()
        except Exception as e:
            logging.error(f"Client error: {e}")
            self.close()

    def _crypto_handshake(self):
        """
        Perform the cryptographic handshake using Diffie-Hellman for public key exchange 
        and shared key generation, and RSA for authentication.
        """
        try:
            logging.info("Starting Crypto Handshake")
            logging.info(f"Role: {'Server' if self.is_server else 'Client'}")

            # Log RSA key details for debugging
            logging.info("RSA Key Details:")
            logging.info(f"Public Key Size: {
                         len(self.rsa_public_key.save_pkcs1())} bytes")
            logging.info(f"Public Key Fingerprint: {hashlib.sha256(
                self.rsa_public_key.save_pkcs1()).hexdigest()}")

            # Step 1: Public Key Exchange using RSA
            if self.is_server:
                # Server sends its RSA public key
                self._send_public_key()
                logging.info("Server sent its public key")

                # Server receives peer's public key
                peer_public_key = self._receive_public_key()
                logging.info("Server received peer's public key")
            else:
                # Client receives server's public key
                peer_public_key = self._receive_public_key()
                logging.info("Client received server's public key")

                # Client sends its RSA public key
                self._send_public_key()
                logging.info("Client sent its public key")

            # Log peer public key details
            logging.info("Peer Public Key Details:")
            logging.info(f"Peer Public Key Size: {
                         len(peer_public_key.save_pkcs1())} bytes")
            logging.info(f"Peer Public Key Fingerprint: {
                         hashlib.sha256(peer_public_key.save_pkcs1()).hexdigest()}")

            # Step 2: Diffie-Hellman Key Exchange
            logging.info("Generating Diffie-Hellman key pair...")

            # Initialize DH for both server and client
            dh = DiffieHellman()

            # Generate DH public/private keys for both server and client
            public_key_dh = dh.gen_public_key()
            private_key_dh = dh.get_private_key()

            # Serialize Diffie-Hellman public key as bytes
            public_key_dh_bytes = str(public_key_dh).encode()

            # Encrypt and send Diffie-Hellman public key
            self.conn.sendall(public_key_dh_bytes)
            logging.info("Sent DH public key.")

            # Receive the encrypted DH public key from the peer
            encrypted_peer_dh_key = self.conn.recv(BUFFER_SIZE)
            peer_public_key_dh = encrypted_peer_dh_key.decode()

            # Calculate shared secret using Diffie-Hellman
            shared_secret = dh.gen_shared_key(int(peer_public_key_dh))
            self.shared_key = hashlib.sha256(shared_secret.encode()).digest()
            logging.info(f"Shared Key derived from DH: {
                         hashlib.sha256(self.shared_key).hexdigest()}")

            logging.info("Crypto handshake completed successfully")

        except Exception as e:
            logging.error(f"Crypto handshake failed: {e}")
            raise

    def _send_public_key(self):
        """Send the RSA public key to the peer."""
        try:
            public_key_data = self.rsa_public_key.save_pkcs1()
            key_length = len(public_key_data)
            self.conn.sendall(key_length.to_bytes(
                4, byteorder='big'))  # Send the key length
            self.conn.sendall(public_key_data)  # Send the public key data
            logging.info("Public key sent successfully")
        except Exception as e:
            logging.error(f"Error sending public key: {e}")
            raise

    def _receive_public_key(self):
        """Receive the RSA public key from the peer."""
        try:
            # Receive the length of the public key
            key_length_bytes = self.conn.recv(4)
            key_length = int.from_bytes(key_length_bytes, byteorder='big')

            # Receive the actual public key data
            public_key_data = self.conn.recv(key_length)
            peer_public_key = rsa.PublicKey.load_pkcs1(public_key_data)
            logging.info("Public key received successfully")
            return peer_public_key
        except Exception as e:
            logging.error(f"Error receiving public key: {e}")
            raise

    def _encrypt_data(self, data):
        """
        Encrypt data using the shared key.

        :param data: Bytes to encrypt
        :return: Encrypted bytes with prepended IV
        """
        try:
            # Generate a new IV for each encryption
            iv = generate_iv()

            # Create AES cipher using CFB mode
            cipher = Cipher(AES(self.shared_key), CFB(iv),
                            backend=default_backend())
            encryptor = cipher.encryptor()

            # Encrypt data
            encrypted_data = encryptor.update(data) + encryptor.finalize()

            # Prepend IV to the encrypted data
            return iv + encrypted_data
        except Exception as e:
            logging.error(f"Encryption error: {e}")
            raise

    def _decrypt_data(self, encrypted_data):
        """
        Decrypt data using the shared key.

        :param encrypted_data: Bytes to decrypt (includes IV)
        :return: Decrypted bytes
        """
        try:
            # Extract IV (first 16 bytes)
            iv = encrypted_data[:16]
            data = encrypted_data[16:]

            # Create AES cipher using CFB mode
            cipher = Cipher(AES(self.shared_key), CFB(iv),
                            backend=default_backend())
            decryptor = cipher.decryptor()

            # Decrypt data
            decrypted_data = decryptor.update(data) + decryptor.finalize()

            return decrypted_data
        except Exception as e:
            logging.error(f"Decryption error: {e}")
            raise

    def send_file(self, file_path):
        """
        Send a file with its name, type, and checksum.
        """
        if not self.wait_for_handshake():
            raise ValueError("Handshake not completed within timeout")

        try:
            # Validate file exists
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")

            # Prepare file metadata
            checksum = calculate_checksum(file_path)
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)  # Get the file size

            # Create and encrypt control message
            control_message = {
                "type": "control",
                "file_name": file_name,
                "checksum": checksum,
                "size": file_size  # Add the size to the control message
            }

            encrypted_control_msg = self._encrypt_data(
                json.dumps(control_message).encode())

            # Send control message
            self.conn.sendall(encrypted_control_msg)

            # Send file chunks
            logging.info(f"Sending file: {file_name}")
            with open(file_path, "rb") as f:
                while chunk := f.read(BUFFER_SIZE):
                    encrypted_chunk = self._encrypt_data(chunk)
                    self.conn.sendall(encrypted_chunk)

            logging.info("File sent successfully")
        except Exception as e:
            logging.error(f"File send error: {e}")
            raise

    def _receive_file(self):
        """
        Receive a file from the network.
        """
        try:
            # Create the 'received_files' directory if it doesn't exist
            if not os.path.exists("received_files"):
                os.makedirs("received_files")

            # Receive control message
            encrypted_control_msg = self.conn.recv(BUFFER_SIZE)
            if not encrypted_control_msg:
                raise Exception("No control message received")

            control_message = json.loads(
                self._decrypt_data(encrypted_control_msg).decode())

            file_name = control_message["file_name"]
            expected_checksum = control_message["checksum"]
            # Use .get() to avoid KeyError
            file_size = control_message.get("size")

            if file_size is None:
                raise ValueError(
                    "File size not provided in the control message")

            # Prepare to receive the file
            logging.info(f"Receiving file: {file_name}")

            # Path to save the received file in the "received_files" directory
            received_file_path = os.path.join("received_files", file_name)

            with open(received_file_path, "wb") as f:
                total_received = 0
                while True:
                    # Receive encrypted chunk
                    encrypted_chunk = self.conn.recv(BUFFER_SIZE + 16)

                    if not encrypted_chunk:
                        logging.info(
                            f"Connection closed by peer, finished receiving file {file_name}")
                        break  # End of file transmission

                    # Decrypt chunk
                    decrypted_chunk = self._decrypt_data(encrypted_chunk)
                    f.write(decrypted_chunk)
                    total_received += len(decrypted_chunk)

                    logging.debug(f"Received chunk of size {
                                  len(decrypted_chunk)} bytes, total: {total_received} bytes")

                    # If the file is fully received, break the loop
                    if total_received >= file_size:
                        logging.info(f"File {file_name} received successfully")
                        break

            # Verify checksum
            received_checksum = calculate_checksum(received_file_path)
            if received_checksum != expected_checksum:
                os.remove(received_file_path)
                raise ValueError("File transfer checksum mismatch")

            logging.info(f"File received and saved successfully: {
                         received_file_path}")
        except Exception as e:
            logging.error(f"File receive error: {e}")
            raise

    def close(self):
        """
        Close all network connections.
        """
        try:
            # Close client connection
            if self.conn:
                self.conn.close()
                self.conn = None
                logging.info("Client connection closed")

            # Close server socket if it exists
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None
                logging.info("Server socket closed")

            # Ensure handshake event is set
            self._handshake_complete.set()
        except Exception as e:
            logging.error(f"Error during connection closure: {e}")
