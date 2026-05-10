import socket
import os
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

PUBLIC_KEY_PATH = os.path.join(CURRENT_DIR, "public.pem")

CLIENT_PRIVATE_KEY_PATH = os.path.join(
    CURRENT_DIR,
    "client_private.pem"
)

CLIENT_PUBLIC_KEY_PATH = os.path.join(
    CURRENT_DIR,
    "client_public.pem"
)

SERVER_IP = "127.0.0.1"   
SERVER_PORT = 12345

def start_client():

    # Generate client RSA keys if they don't exist
    if not os.path.exists(CLIENT_PRIVATE_KEY_PATH):

        client_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        client_public_key = client_private_key.public_key()

        with open(CLIENT_PRIVATE_KEY_PATH, "wb") as f:
            f.write(
                client_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        with open(CLIENT_PUBLIC_KEY_PATH, "wb") as f:
            f.write(
                client_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

    else:

        with open(CLIENT_PRIVATE_KEY_PATH, "rb") as f:
            client_private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )

    # Load server public key
    with open(PUBLIC_KEY_PATH, "rb") as key_file:
        server_public_key = serialization.load_pem_public_key(
            key_file.read()
        )

    # Generate DES key
    des_key = get_random_bytes(8)

    # Encrypt DES key with server RSA public key
    enc_des_key = server_public_key.encrypt(
        des_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Create socket connection
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client.connect((SERVER_IP, SERVER_PORT))

    print(f"Connected to server {SERVER_IP}:{SERVER_PORT}")

    # Send client public key
    with open(CLIENT_PUBLIC_KEY_PATH, "rb") as f:
        client_pub_key_bytes = f.read()

    client.send(
        len(client_pub_key_bytes).to_bytes(
            4,
            byteorder='big'
        )
    )

    client.send(client_pub_key_bytes)

    print("Client public key sent.")

    # Send encrypted DES key
    client.send(enc_des_key)

    print("Encrypted DES key sent securely.")

    while True:

        message = input(
            "\nEnter message ('quit' to exit): "
        ).strip()

        if message.lower() == "quit":
            break

        # Generate IV
        iv = get_random_bytes(8)

        # Encrypt message with DES-CBC
        cipher_des = DES.new(
            des_key,
            DES.MODE_CBC,
            iv
        )

        ciphertext = cipher_des.encrypt(
            pad(
                message.encode('utf-8'),
                DES.block_size
            )
        )

        # Sign encrypted message
        signature = client_private_key.sign(
            ciphertext,
            padding.PSS(
                mgf=padding.MGF1(
                    hashes.SHA256()
                ),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Send IV
        client.send(iv)

        # Send ciphertext
        client.send(
            len(ciphertext).to_bytes(
                4,
                byteorder='big'
            )
        )

        client.send(ciphertext)

        # Send signature
        client.send(
            len(signature).to_bytes(
                4,
                byteorder='big'
            )
        )

        client.send(signature)

        print("\nEncrypted and signed message sent.")

    client.close()

    print("\nConnection closed.")

if __name__ == "__main__":
    start_client()