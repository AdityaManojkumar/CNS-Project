from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import socket

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_file_with_aes(file_path, aes_key):
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)
    return cipher_aes.nonce, tag, ciphertext

def encrypt_aes_key_with_rsa(aes_key, rsa_public_key):
    key = RSA.import_key(rsa_public_key)
    cipher_rsa = PKCS1_OAEP.new(key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key

def client_program(file_path, server_ip, server_port, server_public_key_file):
    # Read the server's public key
    with open(server_public_key_file, 'rb') as f:
        server_public_key = f.read()

    # Generate RSA keys (not needed for this scenario)
    private_rsa, public_rsa = generate_rsa_keys()

    # Create AES key
    aes_key = get_random_bytes(16)  # AES key of 16 bytes

    # Encrypt the file with AES
    nonce, tag, ciphertext = encrypt_file_with_aes(file_path, aes_key)

    # Encrypt the AES key with RSA using the server's public key
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, server_public_key)

    # Send encrypted AES key and file to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((server_ip, server_port))

        # Send RSA-encrypted AES key
        client_socket.sendall(encrypted_aes_key)

        # Send nonce, tag, and ciphertext
        client_socket.sendall(nonce)
        client_socket.sendall(tag)
        client_socket.sendall(ciphertext)

if _name_ == "_main_":
    file_path = 'example.txt'  # Path to file to be sent
    server_ip = '127.0.0.1'
    server_port = 65435
    server_public_key_file = 'server_public_key.pem'  # Ensure this file exists and is correct
    client_program(file_path, server_ip, server_port, server_public_key_file)
