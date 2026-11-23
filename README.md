# 🛡️ SecureCrypt-Pro

> **Next-Generation Authenticated File & Folder Encryption Suite with Military-Grade Cryptography and Modern GUI**

[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Cryptography](https://img.shields.io/badge/Cipher-AES--256--GCM-green.svg)]()
[![KDF](https://img.shields.io/badge/KDF-Argon2id-purple.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://img.shields.io/badge/CI-Passing-brightgreen.svg)]()

SecureCrypt-Pro is a high-security cryptography utility crafted in Python. It offers authenticated data confidentiality, tamper-proof integrity, folder-level packaging, DoD-standard file shredding, and a responsive dark-themed Graphical User Interface (GUI).

---

## 🌟 Key Highlights

- **Authenticated Encryption (AES-256-GCM)**: Authenticates headers and payload together, thwarting bit-flipping and chosen-ciphertext attacks.
- **Argon2id Key Derivation**: Employs memory-hard parameters (64 MB memory cost) protecting passwords against GPU and ASIC cluster attacks.
- **Tamper Detection**: Instant rejection if even a single byte or header metadata bit is altered.
- **Folder / Directory Encryption**: Packages entire nested directory trees into a single authenticated `.scrypt` archive.
- **DoD 5220.22-M File Shredder**: Secure 3-pass physical disk overwrite (zeroes, ones, cryptographic random bytes) to prevent forensics recovery of unencrypted data.
- **Dual Interface**: Includes both a color-coded CLI with ASCII art and a modern CustomTkinter Desktop GUI.
- **Shannon Entropy Engine**: Evaluates password resilience and computes bit-level entropy in real time.

---

## 🏗️ Architecture & Security Model

```
[ User Input (File / Folder) ]
              │
              ▼
   [ Zlib Stream Compression ]
              │
              ▼
 [ Header (Magic + Version + Salt + Nonce + AAD) ]
              │
              ▼
[ Argon2id KDF: Password + Salt -> 256-bit Key ]
              │
              ▼
  [ AES-256-GCM Authenticated Encryption ]
              │
              ▼
    [ Output: .scrypt Container ]
```

---

## 🚀 Quick Start

### 1. Installation

Clone your repository and install dependencies:

```bash
git clone https://github.com/abdorashad21a-del/SecureCrypt-Pro.git
cd SecureCrypt-Pro
pip install -r requirements.txt
```

### 2. Graphical Interface (GUI)

Launch the visual application with dark theme:

```bash
python -m securecrypt gui
```

### 3. Command Line Interface (CLI)

#### Encrypt a File or Entire Folder
```bash
# Encrypt file
python -m securecrypt encrypt secret.pdf

# Encrypt and shred the original unencrypted file
python -m securecrypt encrypt sensitive.docx --shred

# Encrypt an entire directory
python -m securecrypt encrypt ./my_project_folder
```

#### Decrypt Files / Folders
```bash
# Decrypt file
python -m securecrypt decrypt secret.pdf.scrypt

# Decrypt folder
python -m securecrypt decrypt my_project_folder.folder.scrypt
```

#### Secure DoD Shredding
```bash
python -m securecrypt shred confidential_notes.txt
```

#### Generate High-Entropy Passphrase
```bash
python -m securecrypt genpass --length 32
```

---

## 🧪 Testing & Verification

Run the automated test suite with pytest:

```bash
pytest tests -v
```

All 7 test modules cover:
1. Exact file content integrity roundtrip.
2. 1-bit tampering detection and rejection.
3. Incorrect password denial.
4. Recursive folder tree encryption & restoration.
5. Multi-pass file shredding forensics elimination.
6. Entropy calculation and strong key generation.

---

## 👤 Author

Developed with care by **Abdelrahman Rashad** ([@abdorashad21a-del](https://github.com/abdorashad21a-del)).
Licensed under the [MIT License](LICENSE).
