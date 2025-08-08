def main():
    import argparse, os, getpass
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
    import os
    from getpass import getpass
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.exceptions import InvalidTag

    '''def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())'''
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**16,  # CPU/memory cost (e.g., 2^15 = 32,768)
            r=8,
            p=1,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_file(input_path, password):
        with open(input_path, 'rb') as f:
            plaintext = f.read()
        salt, nonce = os.urandom(16), os.urandom(12)
        key = derive_key(password, salt)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
        with open(input_path + ".enc", 'wb') as f:
            f.write(salt + nonce + ciphertext)
        print(f"[+] Encrypted file: {input_path}.enc")

    def decrypt_file(input_path):
        if not input_path.endswith(".enc"):
            print("Error: File must have a .enc extension.")
            return

        # Read encrypted data once (salt + nonce + ciphertext)
        with open(input_path, 'rb') as f:
            data = f.read()

        salt = data[:16]
        nonce = data[16:28]
        ciphertext = data[28:]

        for attempt in range(1, 4):  # 3 attempts max
            password = getpass(f"Attempt {attempt}/3 - Enter password: ")
            try:
                key = derive_key(password, salt)
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                aesgcm = AESGCM(key)
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)

                # Success: write decrypted file
                out_path = input_path[:-4] + ".dec"
                with open(out_path, 'wb') as f:
                    f.write(plaintext)

                print(f"✅ Decryption successful: {out_path}")
                return  # exit after success

            except (InvalidTag, Exception):
                print("❌ Invalid password or corrupted file.")

        # If all attempts fail, delete the encrypted file
        print("🚨 Maximum password attempts exceeded.")
        print(f"🧨 Deleting encrypted file: {input_path}")
        os.remove(input_path)

    parser = argparse.ArgumentParser(description="AES-256 File Encryptor")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode")
    parser.add_argument("file", help="Path to file")
    parser.add_argument("-p", "--password", help="Password")
    args = parser.parse_args()
    if args.mode == "encrypt":
        if not args.password:
            args.password = getpass("Enter password: ")
        encrypt_file(args.file, args.password)
    else:
        decrypt_file(args.file)  # No password argument here
