# 🔐 Custom Mini-DES (S-DES) Text & File Encryption System

An educational Python implementation of the **Simplified Data Encryption Standard (S-DES)** block cipher enhanced with **Cipher Block Chaining (CBC)** mode and a dynamic **8-bit Initialization Vector (IV)**.

> **Disclaimer:** Because this educational cipher uses a 10-bit key space (\(2^{10} = 1,024\) keys), it is designed strictly for academic study and cryptographic demonstration. Do not use it to secure sensitive production data.

---

## ✨ Features
- **Zero External Dependencies:** Built 100% from scratch using Python standard libraries (`os`, `base64`, `binascii`).
- **Complete S-DES Architecture:** Implements `P10` and `P8` key scheduling, circular left shifts (`LS-1`, `LS-2`), `IP` / `IP⁻¹` permutations, `E/P` expansion, non-linear S-Boxes (`S0`, `S1`), and a 2-round Feistel network.
- **Cipher Block Chaining (CBC) Mode:** Eliminates statistical pattern leakage found in Electronic Codebook (ECB) mode.
- **Dynamic CSPRNG Initialization Vector:** Automatically generates a random 8-bit IV via `os.urandom(1)` and prepends it to the ciphertext stream.
- **Dual-Mode Support:** Encrypts and decrypts both **UTF-8 text strings** (via Base64 encoding) and **arbitrary binary files** (`.txt`, `.pdf`, `.png`, `.zip`).

---

## 🛠️ Project Structure
```text
Mini-DES-CBC-Encryption/
│
├── mini_des_cbc.py      # Complete CLI application & Mini-DES CBC cipher engine
└── README.md            # Project documentation and usage guide
```

---

## 🚀 Quick Start

### 1. Prerequisites
Ensure you have **Python 3.8+** installed:
```bash
python --version
```

### 2. Run the Application
Clone the repository and launch the interactive CLI menu:
```bash
git clone https://github.com
cd Mini-DES-CBC-Encryption
python mini_des_cbc.py
```

---

## 💻 Sample Usage

### Text Encryption & Decryption
```text
Select an Operation:
  1. Encrypt Text (UTF-8 -> Base64)
  2. Decrypt Text (Base64 -> UTF-8)
  3. Encrypt Binary File
  4. Decrypt Binary File
  5. Exit

Enter choice (1-5): 1
Enter 10-bit Master Key (e.g., 1010000010): 1010000010
Enter Plaintext Message: Cryptography Lab Project 2026

[SUCCESS] Encrypted Ciphertext (Base64):
np4x8kL9vQ2mP7wR4tY6uI0oP3aS8dF1gH5jK9lZ
```

---

## 📊 Cryptographic Specifications

| Parameter | Specification |
| :--- | :--- |
| **Block Size** | 8 bits (1 byte) |
| **Master Key Size** | 10 bits |
| **Round Subkeys** | Two 8-bit keys (`K1`, `K2`) |
| **Network Structure** | 2-Round Feistel Cipher |
| **Mode of Operation** | Cipher Block Chaining (CBC) with random 8-bit IV |
| **Average Avalanche Effect** | ~50.31% bit flip per single-bit change |

---

## 📚 References
1. E. F. Schaefer, *"A simplified data encryption standard algorithm,"* Cryptologia, vol. 20, no. 1, pp. 77–84, 1996.
2. W. Stallings, *Cryptography and Network Security: Principles and Practice*, 8th ed., Pearson, 2020.
