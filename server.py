# secure_server.py
import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Generate and save RSA keys for the server if not already present
def initialize_server_keys():
    private_key_path = "server_private_key.pem"
    public_key_path = "server_public_key.pem"

    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        with open(private_key_path, "wb") as private_file:
            private_file.write(private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))

        public_key = private_key.public_key()
        with open(public_key_path, "wb") as public_file:
            public_file.write(public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("Server keys generated.")

# Load server's private key
def load_server_private_key():
    with open("server_private_key.pem", "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

# Decrypt the session key using RSA
def rsa_decrypt_session_key(encrypted_key, private_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Decrypt the message using AES
def aes_decrypt_message(encrypted_data, session_key):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    from cryptography.hazmat.primitives import padding as sym_padding
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(plaintext_padded) + unpadder.finalize()

# Handle client communication
def handle_client(client_socket):
    private_key = load_server_private_key()

    try:
        # Receive the encrypted session key
        encrypted_session_key = client_socket.recv(256)  # RSA-encrypted key

        # Decrypt session key
        session_key = rsa_decrypt_session_key(encrypted_session_key, private_key)
        print(f"Decrypted session key: {session_key}")

        # Receive and decrypt the encrypted message
        encrypted_message = client_socket.recv(4096)
        message = aes_decrypt_message(encrypted_message, session_key)

        print(f"Decrypted message: {message.decode('utf-8')}")

    except Exception as e:
        print(f"Error handling client: {e}")

    finally:
        client_socket.close()

# Main server setup
def start_server():
    initialize_server_keys()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 12345))
    server_socket.listen(5)
    print("Server listening on port 12345...")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")
        handle_client(client_socket)

if __name__ == "__main__":
    start_server()
