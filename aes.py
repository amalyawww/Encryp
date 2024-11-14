from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

def generate_key(password: str, salt: bytes) -> bytes:
    # Generate a 32-byte key using PBKDF2HMAC with SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path: str, password: str):
    # Generate a random 16-byte IV and salt
    iv = os.urandom(16)
    salt = os.urandom(16)
    key = generate_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Read the file content
    with open(file_path, 'rb') as file:
        file_data = file.read()

    # Pad data to be multiple of block size (16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    # Encrypt data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Save the encrypted file with salt, iv, and encrypted data
    with open(file_path + '.enc', 'wb') as encrypted_file:
        encrypted_file.write(salt + iv + encrypted_data)

    print(f"File encrypted successfully: {file_path}.enc")

def decrypt_file(file_path: str, password: str):
    # Read the encrypted file
    with open(file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()

    # Extract salt, IV, and encrypted data
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    encrypted_data = encrypted_data[32:]

    # Generate the key from the password and salt
    key = generate_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    original_data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Save the decrypted file
    with open(file_path.replace('.enc', '.dec'), 'wb') as decrypted_file:
        decrypted_file.write(original_data)

    print(f"File decrypted successfully: {file_path.replace('.enc', '.dec')}")

if __name__ == "__main__":
    file_path = input("Enter the file path: ")
    password = input("Enter the password: ")

    action = input("Do you want to (E)ncrypt or (D)ecrypt? ").lower()

    if action == 'e':
        encrypt_file(file_path, password)
    elif action == 'd':
        decrypt_file(file_path, password)
    else:
        print("Invalid choice! Please enter 'E' to encrypt or 'D' to decrypt.")
