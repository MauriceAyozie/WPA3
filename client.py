# secure_client.py
import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from cryptography.hazmat.primitives import padding as sym_padding

def initialize_client_keys():
    private_key_path = "client_private_key.pem"
    public_key_path = "client_public_key.pem"

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
        print("Client keys generated.")

def load_server_public_key():
    with open("server_public_key.pem", "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

def generate_session_key():
    return os.urandom(32)  # 256-bit AES key

def rsa_encrypt_session_key(session_key, public_key):
    return public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def aes_encrypt_message(message, session_key):
    # Generate IV
    iv = os.urandom(16)  # 128-bit IV

    # Apply PKCS7 padding
    padder = sym_padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode("utf-8")) + padder.finalize()

    # Encrypt with AES-CBC
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    return iv + ciphertext

def main():
    initialize_client_keys()

    server_public_key = load_server_public_key()
    session_key = generate_session_key()

    encrypted_session_key = rsa_encrypt_session_key(session_key, server_public_key)

    message = "This is a confidential message."
    encrypted_message = aes_encrypt_message(message, session_key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(("127.0.0.1", 12345))

        # Send encrypted session key
        client_socket.sendall(encrypted_session_key)
        print("Encrypted session key sent.")

        # Send encrypted message
        client_socket.sendall(encrypted_message)
        print("Encrypted message sent.")

if __name__ == "__main__":
    main()
