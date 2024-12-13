import socket
import base64
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# Load the server's public key
def load_server_public_key():
    try:
        with open("public_key_server.pem", "rb") as file:
            return serialization.load_pem_public_key(file.read())
    except FileNotFoundError:
        print("public_key_server.pem not found. Ensure the server's public key is available.")
        raise

# Generate a random session key (AES-512, 64 bytes)
def generate_session_key():
    return os.urandom(64)

# Setup the client socket and connect to the server
def setup_client_connection(host='127.0.0.1', port=9876):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"Connected to {host}:{port}")
    return client_socket

def main():
    try:
        # Load the server's public key
        server_public_key = load_server_public_key()

        # Generate a random session key
        session_key = generate_session_key()
        print(f"Generated session key: {session_key} (Length: {len(session_key)})")

        # Encrypt the session key using the server's public key
        encrypted_session_key = server_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )
        print(f"Encrypted session key: {encrypted_session_key}")

        # Base64 encode the encrypted session key before sending
        encrypted_session_key_b64 = base64.b64encode(encrypted_session_key)
        print(f"Base64-encoded encrypted session key: {encrypted_session_key_b64}")

        # Setup client connection and send the encrypted session key
        client_socket = setup_client_connection()
        client_socket.send(encrypted_session_key_b64)

    except Exception as e:
        print(f"Client encountered an error: {e}")
    finally:
        if 'client_socket' in locals():
            client_socket.close()
            print("Client connection closed.")

if __name__ == "__main__":
    main()


