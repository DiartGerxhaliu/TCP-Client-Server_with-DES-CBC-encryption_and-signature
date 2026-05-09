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
CLIENT_PUBLIC_KEY_PATH = os.path.join(CURRENT_DIR, "client_public.pem")

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

with open(PUBLIC_KEY_PATH, "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 12345))
    server.listen(1)
    print("Server waiting for communication...")

    conn, addr = server.accept()
    print(f"Client connected from {addr}")

    client_pub_key_size = int.from_bytes(conn.recv(4), byteorder='big')
    client_pub_key_bytes = b''
    while len(client_pub_key_bytes) < client_pub_key_size:
        chunk = conn.recv(min(1024, client_pub_key_size - len(client_pub_key_bytes)))
        if not chunk:
            break
        client_pub_key_bytes += chunk

    client_public_key = serialization.load_pem_public_key(client_pub_key_bytes)
    print("Client public key received for signature verification.")

    enc_des_key = conn.recv(256)

    des_key = private_key.decrypt(
        enc_des_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("DES key established securely.")

    while True:
        iv = conn.recv(8)
        if not iv:
            break

        msg_len_bytes = conn.recv(4)
        if not msg_len_bytes:
            break

        msg_len = int.from_bytes(msg_len_bytes, byteorder='big')

        ciphertext = b''
        while len(ciphertext) < msg_len:
            chunk = conn.recv(min(1024, msg_len - len(ciphertext)))
            if not chunk:
                break
            ciphertext += chunk

        sig_len_bytes = conn.recv(4)
        sig_len = int.from_bytes(sig_len_bytes, byteorder='big')

        signature = b''
        while len(signature) < sig_len:
            chunk = conn.recv(min(1024, sig_len - len(signature)))
            if not chunk:
                break
            signature += chunk

        # Show signature
        print(f"Signature (hex): {signature.hex()}")

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
            print("Signature verified successfully.")
        except Exception as e:
            print(f"Signature verification failed: {e}")
            continue

        # Show encrypted message
        print(f"Encrypted message (hex): {ciphertext.hex()}")

        # Decrypt message with DES-CBC
        cipher_des = DES.new(des_key, DES.MODE_CBC, iv)
        decrypted_msg = unpad(cipher_des.decrypt(ciphertext), DES.block_size)

        print(f"Decrypted message: {decrypted_msg.decode('utf-8')}")

    print("Connection closed.")
    conn.close()

if __name__ == "__main__":
    start_server()