# 🔐 cli-encrypt-txt

A simple and secure CLI tool to **encrypt** and **decrypt** text files with a password. Ideal for protecting sensitive information, storing credentials, or creating your own minimal password manager.

---

## ✨ Features

- 🔐 Encrypt text files into `.enc` format using a password
- 🔓 Decrypt `.enc` files with up to **3 password attempts**
- 📦 Lightweight & easy to use
- 🧠 Great for storing private notes or credentials securely

---

## 🚀 Installation

```bash
pip install cli-encrypt-txt
```

---

## 🧑‍💻 Usage

### 🔐 Encrypt a file

```bash
cli-encrypt-txt encrypt test.txt
```

- You'll be prompted to enter a password.
- Output: `test.txt.enc`

### 🔓 Decrypt a file

```bash
cli-encrypt-txt decrypt test.txt.enc
```

- Enter the same password to decrypt.
- You have **3 attempts** to get it right.
- Output: `test.txt`

---

## 💡 Use Case

Use `cli-encrypt-txt` as a **local password manager** or secret storage system. Simply encrypt a `.txt` file containing your credentials, secrets, or notes, and store the `.enc` file safely. Only those with the password can decrypt it.

---

## 🔧 Example

```bash
$ cli-encrypt-txt encrypt secrets.txt
Enter password: ******
Successfully encrypted to: secrets.txt.enc

$ cli-encrypt-txt decrypt secrets.txt.enc
Enter password: ******
Decryption successful! File saved as: secrets.txt
```

---

## 🛠️ Developer Notes

- Requires Python 3.7+
- Designed with simplicity and file-level encryption in mind
- No external dependencies (pure Python, unless otherwise noted)

---

## 📝 License

MIT License © 2025 Adityakrishna SreeRamachandrarao

---
