import socket
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Load server's private key
def load_private_key():
    try:
        with open("server_private.pem", "rb") as key_file:
            return serialization.load_pem_private_key(key_file.read(), password=None)
    except FileNotFoundError:
        print("server_private.pem not found. Ensure the server's private key is available.")
        raise

# Decrypt the session key
def decrypt_session_key(encrypted_session_key, private_key):
    try:
        decrypted_key = private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )
        print(f"Decrypted session key: {decrypted_key} (Length: {len(decrypted_key)})")
        return decrypted_key
    except Exception as e:
        print(f"Error during decryption: {e}")
        raise

# Server setup
def start_server(host='127.0.0.1', port=9876):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server listening on {host}:{port}...")
    return server_socket

def main():
    try:
        # Start the server and wait for a connection
        server_socket = start_server()
        client_socket, client_address = server_socket.accept()
        print(f"Connection established with {client_address}")

        # Load private key
        private_key = load_private_key()

        # Receive encrypted session key from the client
        encrypted_session_key_b64 = client_socket.recv(4096)
        print(f"Received Base64-encoded encrypted session key: {encrypted_session_key_b64}")

        # Base64 decode the encrypted session key
        encrypted_session_key = base64.b64decode(encrypted_session_key_b64)
        print(f"Base64-decoded encrypted session key: {encrypted_session_key}")

        # Decrypt the session key
        session_key = decrypt_session_key(encrypted_session_key, private_key)
    except Exception as e:
        print(f"Server encountered an error: {e}")
    finally:
        if 'client_socket' in locals():
            client_socket.close()
            print("Client connection closed.")
        if 'server_socket' in locals():
            server_socket.close()
            print("Server socket closed.")

if __name__ == "__main__":
    main()


