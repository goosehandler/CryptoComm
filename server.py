import socket
import os
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography import x509

with open("certificate_Dima.pem", "rb") as f:
    server_cert = f.read()

with open("private_key_Dima.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

HOST = "0.0.0.0"
PORT = 8989

private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print(f"Server's Public key: {public_key.hex()}")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))

while True:

    server_socket.listen(1)
    print(f"[*] Server started on {HOST}:{PORT}, waiting for connection...")

    conn, addr = server_socket.accept()
    print(f"[+] Connection established with {addr}")

    conn.sendall(server_cert)
    client_cert = conn.recv(4096)
    
    try:
        x509.load_pem_x509_certificate(client_cert)
        print("[*] Client's certificate verified.")
    except Exception as e:
        print(f"[-] Certificate verification failed: {e}")
        conn.close()
        exit()

    conn.sendall(public_key)
    alice_public_key_der = conn.recv(1024)

    alice_public_key = serialization.load_der_public_key(alice_public_key_der)

    shared_secret = private_key.exchange(ec.ECDH(), alice_public_key)

    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"secure_chat_session"
    ).derive(shared_secret)

    print(f"[*] Shared secret established: {shared_secret.hex()}")

    nonce = conn.recv(12)
    ciphertext_len = int.from_bytes(conn.recv(4), 'big')
    ciphertext = conn.recv(ciphertext_len)
    mac = conn.recv(32)

    print(f'Cipher text: {ciphertext.hex()}')

    expected_mac = hmac.new(session_key, nonce + ciphertext, hashlib.sha256).digest()

    if not hmac.compare_digest(mac, expected_mac):
        print("[-] Message integrity verification failed!")
    else:
        aesgcm = AESGCM(session_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        print(f"[+] Received message: {plaintext.decode()}")

