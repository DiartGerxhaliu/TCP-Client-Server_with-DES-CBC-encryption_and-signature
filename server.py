import socket
import os
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_KEY_PATH = os.path.join(CURRENT_DIR, "public.pem")

# Generate RSA keys for server
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

# Save public key
with open(PUBLIC_KEY_PATH, "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

def recv_exact(conn, size):
    data = b''

    while len(data) < size:
        packet = conn.recv(size - len(data))

        if not packet:
            return None

        data += packet

    return data

def start_server():

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Allow wireless/LAN connections
    server.bind(('0.0.0.0', 12345))

    server.listen(1)

    hostname = socket.gethostname()
    server_ip = socket.gethostbyname(hostname)

    print(f"\nServer running on IP: {server_ip}")
    print("Waiting for client connection...\n")

    conn, addr = server.accept()

    print(f"Client connected from: {addr}")

    # Receive client public key
    client_pub_key_size = int.from_bytes(
        recv_exact(conn, 4),
        byteorder='big'
    )

    client_pub_key_bytes = recv_exact(conn, client_pub_key_size)

    client_public_key = serialization.load_pem_public_key(
        client_pub_key_bytes
    )

    print("Client public key received.")

    # Receive encrypted DES key
    enc_des_key = recv_exact(conn, 256)

    # Decrypt DES key using server private RSA key
    des_key = private_key.decrypt(
        enc_des_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("DES secret key established securely.\n")

    while True:

        iv = recv_exact(conn, 8)

        if not iv:
            break

        msg_len = int.from_bytes(
            recv_exact(conn, 4),
            byteorder='big'
        )

        ciphertext = recv_exact(conn, msg_len)

        sig_len = int.from_bytes(
            recv_exact(conn, 4),
            byteorder='big'
        )

        signature = recv_exact(conn, sig_len)

        print(f"\nEncrypted Message (HEX):")
        print(ciphertext.hex())

        print(f"\nSignature (HEX):")
        print(signature.hex())

        # Verify signature
        try:

            client_public_key.verify(
                signature,
                ciphertext,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            print("\nSignature VERIFIED.")

        except Exception as e:

            print(f"\nSignature verification FAILED: {e}")
            continue

        # DES-CBC Decryption
        cipher_des = DES.new(
            des_key,
            DES.MODE_CBC,
            iv
        )

        decrypted_message = unpad(
            cipher_des.decrypt(ciphertext),
            DES.block_size
        )

        print("\nDecrypted Message:")
        print(decrypted_message.decode('utf-8'))

    print("\nConnection closed.")

    conn.close()
    server.close()

if __name__ == "__main__":
    start_server()