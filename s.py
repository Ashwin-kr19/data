################GENERATE_KEYS#######################

import subprocess

# Command to generate a private key with AES-256-CBC encryption
# openssl genrsa -aes-256-cbc -out myprivate.key
generate_private_key = [
    "openssl", "genrsa", "-aes-256-cbc", "-out", "myprivate.key"
]

# Command to generate a public key from the private key
# openssl rsa -in myprivate.key -pubout > mypublic.keys
generate_public_key = [
    "openssl", "rsa", "-in", "myprivate.key", "-pubout", "-out", "mypublic.key"
]

try:
    # Run the command to generate the private key
    subprocess.run(generate_private_key, check=True)
    print("Private key saved as 'myprivate.key'.")
    
    # Run the command to generate the public key
    subprocess.run(generate_public_key, check=True)
    print("Public key saved as 'mypublic.key'.")
except subprocess.CalledProcessError as e:
    print(f"An error occurred during key generation: {e}")












###########RSA##########################

#####SERVER.PY##########

import socket
import subprocess

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 65431))
    server_socket.listen()

    print("Server is listening on port 65431...")

    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    # Open a file to store the received content (received_file.enc)
    with open("received_file.enc", 'wb') as file:
        while True:
            data = conn.recv(1024)
            if data == b'END':  # Check for the end-of-file marker
                break
            if not data:
                break  # No more data, break out of the loop
            file.write(data)  # Write data to file in chunks

    print("File received and saved as 'received_file.enc'")
    
    # Send a confirmation message to the client
    conn.sendall(b"File received successfully")

    # Decrypt the received file (received_file.enc) into decrypt.txt
    command = [
        "openssl", "pkeyutl", "-decrypt", "-in", "received_file.enc", 
        "-inkey", "myprivate.key", "-out", "decrypt.txt"
    ]
    subprocess.run(command, check=True)

    print("File decrypted and saved as 'decrypt.txt'")

    conn.close()

if __name__ == "__main__":
    start_server()



###########CLIENT.PY############

import socket
import subprocess

def send_file():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 65431))

    # Run OpenSSL command to encrypt message.txt into encrypt.enc
    command = [
        "openssl", "pkeyutl", "-encrypt", "-in", "message.txt", 
        "-pubin", "-inkey", "mypublic.key", "-out", "encrypt.enc"
    ]
    subprocess.run(command, check=True)

    # Send the encrypted file content (encrypt.enc)
    with open("encrypt.enc", 'rb') as file:
        chunk = file.read(1024)
        while chunk:
            client_socket.sendall(chunk)
            chunk = file.read(1024)
    
    # Send an end-of-file marker to indicate the end of transmission
    client_socket.sendall(b'END')

    # Receive the server's confirmation
    data = client_socket.recv(1024)
    print(f"Received from server: {data.decode('utf-8')}")

    client_socket.close()

if __name__ == "__main__":
    send_file()



















#####################SIGNATURE#################################


################SERVER.PY##################

import socket
import subprocess

# Function to sign a message using the private key
def sign_message():
    command = [
        "openssl", "dgst", "-sha256", "-sign", "myprivate.key", "-out", "signature.bin", "message.txt"
    ]
    
    try:
        subprocess.run(command, check=True)
        with open("signature.bin", "rb") as f:
            signature_data = f.read()
        return signature_data
    except subprocess.CalledProcessError as e:
        return f"Error during signing: {e}".encode()

# Function to verify the digital signature using the public key
def verify_signature():
    command = [
        "openssl", "dgst", "-sha256", "-verify", "mypublic.key", "-signature", "signature.bin", "message.txt"
    ]
    
    try:
        subprocess.run(command, check=True)
        return b"Signature verification successful."
    except subprocess.CalledProcessError as e:
        return f"Signature verification failed: {e}".encode()

# Set up the server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('localhost', 8080))
server.listen(1)

print("Server is listening on port 8080...")

while True:
    client_socket, client_address = server.accept()
    print(f"Connection from {client_address} established.")

    client_data = client_socket.recv(1024).decode()

    if client_data.startswith("SIGN"):
        message = client_data.split("SIGN ")[1]
        with open("message.txt", "w") as f:
            f.write(message)
        signature = sign_message()
        client_socket.send(signature)

    elif client_data == "VERIFY":
        verification_result = verify_signature()
        client_socket.send(verification_result)

    client_socket.close()



##############CLIENT.PY###############

import socket

# Read the message to be signed from a file
with open("message.txt", "r") as f:
    message_to_sign = f.read()

# Connect to the server to sign the message
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('localhost', 8080))

# Send the message to be signed
client.send(f"SIGN {message_to_sign}".encode())

# Receive the signature from the server
signature = client.recv(1024)
with open("signature.bin", "wb") as f:
    f.write(signature)
print(f"Signature received and saved to 'signature.bin'")

client.close()

# Connect again to request signature verification
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('localhost', 8080))

# Request signature verification
client.send("VERIFY".encode())

# Receive the verification result from the server
verification_result = client.recv(1024).decode()
print(f"Verification result: {verification_result}")

client.close()














###################SYMMETRIC##############################


######################SERVER.PY####################

import socket
import subprocess
import os

# Function to encrypt the message using AES-256-CBC
def encrypt_message():
    command = [
        "openssl", "enc", "-aes-256-cbc", "-md", "sha512", "-pbkdf2", "-iter", "1000", "-salt",
        "-in", "message.txt", "-out", "encrypt_1.enc"
    ]

    try:
        subprocess.run(command, check=True)
        return "File encrypted and saved to 'encrypt_1.enc'."
    except subprocess.CalledProcessError as e:
        return f"An error occurred during encryption: {e}"

# Function to decrypt the encrypted file
def decrypt_message():
    if not os.path.exists("encrypt_1.enc"):
        return "Error: Encrypted file 'encrypt_1.enc' not found."

    command = [
        "openssl", "enc", "-aes-256-cbc", "-md", "sha512", "-pbkdf2", "-iter", "1000", "-d",
        "-in", "encrypt_1.enc", "-out", "decrypt_1.txt"
    ]

    try:
        subprocess.run(command, check=True)
        return "File decrypted and saved to 'decrypt_1.txt'."
    except subprocess.CalledProcessError as e:
        return f"An error occurred during decryption: {e}"

# Set up the server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('localhost', 8080))
server.listen(1)

print("Server is listening on port 8080...")

while True:
    client_socket, client_address = server.accept()
    print(f"Connection from {client_address} established.")

    client_data = client_socket.recv(1024).decode()

    if client_data.startswith("ENCRYPT"):
        message = client_data.split("ENCRYPT ")[1]
        with open("message.txt", "w") as f:
            f.write(message)
        result = encrypt_message()
        client_socket.send(result.encode())

    elif client_data.startswith("DECRYPT"):
        result = decrypt_message()
        client_socket.send(result.encode())

    client_socket.close()



#######################CLIENT.PY#######################

import socket

def send_message(command, message):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 8080))

    client.send(f"{command} {message}".encode())

    response = client.recv(1024).decode()
    client.close()
    return response

# Encrypt the message.txt file
with open("message.txt", "r") as f:
    message_to_encrypt = f.read()

encryption_result = send_message("ENCRYPT", message_to_encrypt)
print(f"Encryption result: {encryption_result}")

# Decrypt the message.txt file
decryption_result = send_message("DECRYPT", "")
print(f"Decryption result: {decryption_result}")










