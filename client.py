import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

# Key derivation
password = b"password"
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(password)

def encrypt(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()
    return iv + ct

def decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

def receive_messages():
    while True:
        try:
            message = client_socket.recv(1024)
            if message:
                decrypted_message = decrypt(message, key)
                print(f"Received: {decrypted_message.decode('utf-8')}")
        except Exception as e:
            print(f"Error: {e}")
            client_socket.close()
            break

server_ip = ''
server_port = 12345

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((server_ip, server_port))

thread = threading.Thread(target=receive_messages)
thread.start()

print("Connected to the server")
while True:
    message = input("")
    if message:
        encrypted_message = encrypt(message.encode('utf-8'), key)
        client_socket.send(encrypted_message)
