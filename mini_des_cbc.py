"""
Project Title : Secure Text and File Encryption Using Custom Mini-DES (S-DES)
Mode          : Cipher Block Chaining (CBC) with Dynamic 8-Bit Random IV
Purpose       : Educational Implementation of Symmetric Block Cipher Mechanics
"""

import os
import base64
import binascii

# ==============================================================================
# 1. CRYPTOGRAPHIC PERMUTATION & SUBSTITUTION TABLES (1-Based Indexing)
# ==============================================================================
P10    = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8     = (6, 3, 7, 4, 8, 5, 10, 9)
P4     = (2, 4, 3, 1)
IP     = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INV = (4, 1, 3, 5, 7, 2, 8, 6)
EP     = (4, 1, 2, 3, 2, 3, 4, 1)

# Non-Linear Substitution Boxes (S0 and S1)
S0 = (
    (1, 0, 3, 2),
    (3, 2, 1, 0),
    (0, 2, 1, 3),
    (3, 1, 3, 2)
)

S1 = (
    (0, 1, 2, 3),
    (2, 0, 1, 3),
    (3, 0, 1, 0),
    (2, 1, 0, 3)
)


# ==============================================================================
# 2. CORE BITWISE & KEY SCHEDULE FUNCTIONS
# ==============================================================================
def permute(bits: str, table: tuple) -> str:
    """Rearranges a bit string according to a 1-based permutation table."""
    return ''.join(bits[i - 1] for i in table)


def left_shift(bits: str, n: int) -> str:
    """Performs a circular left shift by n positions."""
    return bits[n:] + bits[:n]


def xor_bits(b1: str, b2: str) -> str:
    """Performs bitwise XOR on two equal-length binary strings."""
    return ''.join('1' if x != y else '0' for x, y in zip(b1, b2))


def sbox_lookup(bits: str, sbox: tuple) -> str:
    """Maps a 4-bit input to a 2-bit output using a 4x4 S-Box matrix."""
    row = int(bits[0:1] + bits[3:4], 2)
    col = int(bits[1:2] + bits[2:3], 2)
    return format(sbox[row][col], '02b')


def validate_key(key10: str) -> None:
    """Ensures the master key is an exact 10-bit binary string."""
    if len(key10) != 10 or any(bit not in ('0', '1') for bit in key10):
        raise ValueError("Invalid Key: Master key must be exactly 10 binary digits (0 or 1).")


def generate_keys(key10: str) -> tuple:
    """Derives two 8-bit round subkeys (K1, K2) from a 10-bit master key."""
    validate_key(key10)
    p10_key = permute(key10, P10)
    
    # Split into two 5-bit halves and apply LS-1
    left, right = left_shift(p10_key[:5], 1), left_shift(p10_key[5:], 1)
    k1 = permute(left + right, P8)
    
    # Apply LS-2 (2 additional left shifts) for K2
    left, right = left_shift(left, 2), left_shift(right, 2)
    k2 = permute(left + right, P8)
    return k1, k2


# ==============================================================================
# 3. FEISTEL ROUND & SINGLE-BYTE MINI-DES ENGINE
# ==============================================================================
def fk(bits: str, subkey: str) -> str:
    """Executes one Feistel round function f_K on an 8-bit block."""
    left, right = bits[:4], bits[4:]
    expanded = permute(right, EP)
    xored = xor_bits(expanded, subkey)
    
    # Non-linear S-Box substitution and P4 permutation
    s_out = sbox_lookup(xored[:4], S0) + sbox_lookup(xored[4:], S1)
    p4_out = permute(s_out, P4)
    
    return xor_bits(left, p4_out) + right


def sdes_byte(byte_val: int, k1: str, k2: str, decrypt: bool = False) -> int:
    """Encrypts or decrypts a single byte (0-255) using 2-round Mini-DES."""
    bits = permute(format(byte_val, '08b'), IP)
    
    if not decrypt:
        bits = fk(bits, k1)
        bits = bits[4:] + bits[:4]  # Switch (SW)
        bits = fk(bits, k2)
    else:
        bits = fk(bits, k2)
        bits = bits[4:] + bits[:4]  # Switch (SW)
        bits = fk(bits, k1)
        
    return int(permute(bits, IP_INV), 2)


# ==============================================================================
# 4. CIPHER BLOCK CHAINING (CBC) STREAM PROCESSOR
# ==============================================================================
def process_data_cbc(data: bytes, key10: str, decrypt: bool = False) -> bytes:
    """
    Encrypts or decrypts a byte stream in CBC mode.
    Prepends a random 8-bit IV during encryption and extracts it during decryption.
    """
    k1, k2 = generate_keys(key10)
    output = bytearray()
    
    if not decrypt:
        iv = int.from_bytes(os.urandom(1), 'big')
        output.append(iv)
        prev = iv
        for plain_byte in data:
            cipher_byte = sdes_byte(plain_byte ^ prev, k1, k2, decrypt=False)
            output.append(cipher_byte)
            prev = cipher_byte
    else:
        if len(data) < 1:
            raise ValueError("Corrupted Ciphertext: Missing Initialization Vector (IV).")
        prev = int.from_bytes(data[0:1], 'big')
        for cipher_byte in data[1:]:
            plain_byte = sdes_byte(cipher_byte, k1, k2, decrypt=True) ^ prev
            output.append(plain_byte)
            prev = cipher_byte
            
    return bytes(output)


# ==============================================================================
# 5. HIGH-LEVEL TEXT & FILE WRAPPERS + INTERACTIVE CLI MENU
# ==============================================================================
def encrypt_text(plaintext: str, key10: str) -> str:
    raw_bytes = plaintext.encode('utf-8')
    encrypted_bytes = process_data_cbc(raw_bytes, key10, decrypt=False)
    return base64.b64encode(encrypted_bytes).decode('ascii')


def decrypt_text(cipher_b64: str, key10: str) -> str:
    encrypted_bytes = base64.b64decode(cipher_b64.encode('ascii'))
    decrypted_bytes = process_data_cbc(encrypted_bytes, key10, decrypt=True)
    return decrypted_bytes.decode('utf-8')


def encrypt_file(input_path: str, output_path: str, key10: str) -> None:
    with open(input_path, 'rb') as f_in:
        file_bytes = f_in.read()
    encrypted_bytes = process_data_cbc(file_bytes, key10, decrypt=False)
    with open(output_path, 'wb') as f_out:
        f_out.write(encrypted_bytes)


def decrypt_file(input_path: str, output_path: str, key10: str) -> None:
    with open(input_path, 'rb') as f_in:
        encrypted_bytes = f_in.read()
    decrypted_bytes = process_data_cbc(encrypted_bytes, key10, decrypt=True)
    with open(output_path, 'wb') as f_out:
        f_out.write(decrypted_bytes)


def main():
    print("=" * 65)
    print("      CUSTOM MINI-DES (S-DES) CBC ENCRYPTION & DECRYPTION")
    print("=" * 65)
    
    while True:
        print("\nSelect an Operation:")
        print("  1. Encrypt Text (UTF-8 -> Base64)")
        print("  2. Decrypt Text (Base64 -> UTF-8)")
        print("  3. Encrypt Binary File")
        print("  4. Decrypt Binary File")
        print("  5. Exit")
        
        choice = input("\nEnter choice (1-5): ").strip()
        if choice == '5':
            print("Exiting Mini-DES Utility.")
            break
            
        try:
            if choice == '1':
                key = input("Enter 10-bit Master Key (e.g., 1010000010): ").strip()
                msg = input("Enter Plaintext Message: ")
                cipher = encrypt_text(msg, key)
                print(f"\n[SUCCESS] Encrypted Ciphertext (Base64):\n{cipher}")
                
            elif choice == '2':
                key = input("Enter 10-bit Master Key: ").strip()
                cipher = input("Enter Base64 Ciphertext: ").strip()
                plain = decrypt_text(cipher, key)
                print(f"\n[SUCCESS] Decrypted Plaintext:\n{plain}")
                
            elif choice == '3':
                key = input("Enter 10-bit Master Key: ").strip()
                in_file = input("Enter Source File Path (e.g., report.pdf): ").strip()
                out_file = in_file + ".enc"
                encrypt_file(in_file, out_file, key)
                print(f"\n[SUCCESS] Encrypted file saved as: {out_file}")
                
            elif choice == '4':
                key = input("Enter 10-bit Master Key: ").strip()
                in_file = input("Enter Encrypted File Path (e.g., report.pdf.enc): ").strip()
                out_file = input("Enter Restored Output File Path (e.g., restored.pdf): ").strip()
                decrypt_file(in_file, out_file, key)
                print(f"\n[SUCCESS] Decrypted file restored to: {out_file}")
                
            else:
                print("[ERROR] Invalid menu selection. Please choose 1 to 5.")
                
        except FileNotFoundError:
            print("[ERROR] File not found. Please verify the file path.")
        except (binascii.Error, UnicodeDecodeError):
            print("[ERROR] Decryption failed: Invalid key or corrupted ciphertext.")
        except ValueError as ve:
            print(f"[ERROR] {ve}")


if __name__ == "__main__":
    main()
