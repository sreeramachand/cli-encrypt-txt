# cli-encrypt-txt — Quantum-ready File Encryption

---

A minimal CLI to encrypt/decrypt files with:

- **AES-256-GCM** for confidentiality + integrity
- **Password mode** using **Argon2id** (memory-hard, replaces PBKDF2)
- **Opaque/steganographic headers** to thwart foreign decryption scripts
- **Memory, Iteration, and Parallelism** modification support for hardware customization

> AES-256 remains safe vs. Grover’s algorithm. 

---

## Purpose

The goal is to ensure security of personal data on cloud platforms instead of a dedicated password manager. This allows those who do not wish to depend on others for their security to take it into their own hands. Additionally, once the file is encrypted, it can be saved on the cloud. Decryption even with Quantum Technology should not be possible, even with people who can access this software and inspect the code. Your data will always be safe and secured even when saved insecurely (email, google drive/OneDrive, dropbox). Additionally, those with powerful processors can make those with limited powerful compute access from being able to decrypt the file, since this is stored in the headers. Furthermore, headers are opaque to further complicate decryption. 

---

## Install

Python 3.9+ recommended.

**Password mode only**
```bash
#Windows
python -m venv .venv
.venv/scripts/activate 
pip install cli-encrypt-txt==3.1.0

# Encrypt
cli-encrypt-txt encrypt secret.pdf -p "strong pass" \
  --m-kib 524288 --t-cost 3 --parallelism 4

# Decrypt
cli-encrypt-txt decrypt secret.pdf.enc

# Encrypt with extreme Argon2id settings into a JPEG cover:
python -m cli_encrypt_txt encrypt secret.txt \
  --m-kib 1048576 \
  --t-cost 6 \
  --parallelism 8 \
  --cover cover.jpg
# -> outputs: secret.txt.enc.jpg

# Decrypt (prompts for password; writes secret.txt.enc.dec or strips .enc if present):
python -m cli_encrypt_txt decrypt secret.txt.enc.jpg
```

> No need to keep file name or file extension consistent after encryption. This adds to the security!! The only thing that must be consistent is the password which will be prompted. 


## Links

Please view the project at PyPI: https://pypi.org/project/cli-encrypt-txt/


## Table

| Customizations  | Purpose |
| ------------- |:-------------:|
|  `--m-kib`      | Sets the memory cost in KiB (used in Argon2id hashing). Higher values increase resistance to brute-force attacks but require more RAM.     |
| `--t-cost`      | Sets the time cost (number of iterations) in Argon2id. More iterations = slower password hashing = harder for attackers.     |
| `--parallelism`      | Number of threads/lanes to use in Argon2id. Improves performance on multicore CPUs while maintaining security.     |
| `--cover`      | Enables steganographic mode, hiding encrypted text inside a cover file (like an image) so the ciphertext doesn’t look suspicious.      |


# Acknowledgements

Thank you to the users!!! I really hope this tool can help improve your system's security and keep unwanted nosy actors out of your personal data! If this project helped please share the repository and let me know what you think! Cheers!

# License
MIT License © 2025 Adityakrishna SreeRamachandrarao


