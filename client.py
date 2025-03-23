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

with open("certificate_Alex.pem", "rb") as f:
    client_cert = f.read()

with open("private_key_Alex.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

SERVER_IP = "10.16.116.124"
PORT = 8989

private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

for i in range(1):

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, PORT))
    print(f"[*] Connected to server at {SERVER_IP}:{PORT}")

    server_cert = client_socket.recv(4096)
    client_socket.sendall(client_cert)
    
    try:
        x509.load_pem_x509_certificate(server_cert)
        print("[*] Server's certificate verified.")
    except Exception as e:
        print(f"[-] Certificate verification failed: {e}")
        client_socket.close()
        exit()

    server_public_key_der = client_socket.recv(1024)
    client_socket.sendall(public_key)
    print("Client's public key:", public_key.hex())

    server_public_key = serialization.load_der_public_key(server_public_key_der)

    shared_secret = private_key.exchange(ec.ECDH(), server_public_key)

    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"secure_chat_session"
    ).derive(shared_secret)

    print(f"[*] Shared secret established: {shared_secret.hex()}")

    message = f"Hello Dima! This is Alex. {i}"
    nonce = os.urandom(12)
    aesgcm = AESGCM(session_key)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)

    print("Chiper text:", ciphertext.hex())

    mac = hmac.new(session_key, nonce + ciphertext, hashlib.sha256).digest()

    client_socket.sendall(nonce)
    client_socket.sendall(len(ciphertext).to_bytes(4, 'big'))
    client_socket.sendall(ciphertext)
    client_socket.sendall(mac)

    print("[+] Message sent securely.")

    client_socket.close()
