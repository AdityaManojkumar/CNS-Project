import socket
import threading

# Configurations
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65434
MITM_HOST = '127.0.0.1'
MITM_PORT = 65435

def handle_client(client_socket, server_socket):
    try:
        # Relay data from client to server
        encrypted_aes_key = client_socket.recv(256)  # Receive the RSA-encrypted AES key
        print(f"[MITM] Intercepted AES key of length: {len(encrypted_aes_key)}")
        server_socket.sendall(encrypted_aes_key)  # Forward to server

        nonce = client_socket.recv(16)  # Receive the nonce
        print(f"[MITM] Intercepted nonce of length: {len(nonce)}")
        server_socket.sendall(nonce)  # Forward to server

        tag = client_socket.recv(16)  # Receive the tag
        print(f"[MITM] Intercepted tag of length: {len(tag)}")
        server_socket.sendall(tag)  # Forward to server

        ciphertext = bytearray()
        while True:
            chunk = client_socket.recv(4096)
            if not chunk:
                break
            ciphertext.extend(chunk)
            server_socket.sendall(chunk)  # Forward to server
        print(f"[MITM] Intercepted ciphertext of length: {len(ciphertext)}")

        # Save intercepted data to file (for the attacker)
        with open('intercepted_encrypted_file.bin', 'wb') as f:
            f.write(encrypted_aes_key + nonce + tag + ciphertext)
        print("[MITM] Encrypted file intercepted and saved.")
    finally:
        client_socket.close()
        server_socket.close()

def mitm_program():
    # Create MITM socket to listen for the client
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as mitm_socket:
        mitm_socket.bind((MITM_HOST, MITM_PORT))
        mitm_socket.listen(1)
        print(f"[MITM] Listening for client on {MITM_HOST}:{MITM_PORT}...")

        while True:
            client_socket, client_addr = mitm_socket.accept()
            print(f"[MITM] Connection from client: {client_addr}")

            # Create a connection to the real server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((SERVER_HOST, SERVER_PORT))
            print(f"[MITM] Connected to server at {SERVER_HOST}:{SERVER_PORT}")

            # Start handling the client-server communication
            threading.Thread(target=handle_client, args=(client_socket, server_socket)).start()

if _name_ == "_main_":
    mitm_program()
