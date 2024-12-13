from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_server_keys():
    # Generate the server's private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Save the private key to a PEM file
    with open("server_private.pem", "wb") as private_key_file:
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_file.write(private_key_bytes)

    print("Server private key saved as 'server_private.pem'")

    # Generate the corresponding public key
    public_key = private_key.public_key()

    # Save the public key to a PEM file
    with open("public_key_server.pem", "wb") as public_key_file:
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_file.write(public_key_bytes)

    print("Server public key saved as 'public_key_server.pem'")

if __name__ == "__main__":
    generate_server_keys()