from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import socket

def decrypt_aes_key_with_rsa(encrypted_aes_key, private_rsa_key):
    try:
        private_key = RSA.import_key(private_rsa_key)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        return aes_key
    except Exception as e:
        print(f"Error decrypting AES key: {e}")
        return None

def decrypt_file_with_aes(nonce, tag, ciphertext, aes_key):
    try:
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        decrypted_file = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return decrypted_file
    except Exception as e:
        print(f"Error decrypting file: {e}")
        return None

def server_program(port, private_rsa_key):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        try:
            server_socket.bind(('127.0.0.1', port))  # Corrected IP address
            server_socket.listen(1)
            print("Server waiting for connection...")
            conn, addr = server_socket.accept()
            with conn:
                print(f"Connected by {addr}")

                # Receive encrypted AES key, nonce, tag, and ciphertext
                encrypted_aes_key = conn.recv(256)
                print(f"Received encrypted AES key of length: {len(encrypted_aes_key)}")

                nonce = conn.recv(16)
                print(f"Received nonce of length: {len(nonce)}")

                tag = conn.recv(16)
                print(f"Received tag of length: {len(tag)}")

                ciphertext = bytearray()
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    ciphertext.extend(data)
                print(f"Received ciphertext of length: {len(ciphertext)}")

                if len(ciphertext) == 0:
                    print("No data received for ciphertext.")
                    return

                # Decrypt AES key
                aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_rsa_key)
                if aes_key is None:
                    return

                # Decrypt file
                decrypted_file = decrypt_file_with_aes(nonce, tag, bytes(ciphertext), aes_key)
                if decrypted_file is None:
                    return

                # Save decrypted file
                with open('decrypted_output.txt', 'wb') as f:
                    f.write(decrypted_file)
                print("File decrypted and saved.")
        except Exception as e:
            print(f"Server error: {e}")

if _name_ == "_main_":
    try:
        private_rsa_key = open('server_private_key.pem', 'rb').read()
        server_program(65434, private_rsa_key)
    except Exception as e:
        print(f"Error reading private key: {e}")
