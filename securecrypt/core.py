"""
Core cryptographic implementation for SecureCrypt-Pro.
Implements AES-256-GCM with Argon2id Key Derivation and Optional zlib Compression.
"""

import os
import sys
import zlib
import struct
import secrets
from typing import Optional, Callable
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from argon2.low_level import hash_secret_raw, Type

MAGIC = b"SCRY"
VERSION = 2
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
BUFFER_SIZE = 64 * 1024  # 64 KB

class CryptoError(Exception):
    """Base exception for all cryptographic operations."""
    pass

class AuthenticationError(CryptoError):
    """Raised when password is wrong or ciphertext has been tampered with."""
    pass

class SecureCrypt:
    """
    High-performance, secure file encryption engine.
    Uses Argon2id for KDF and AES-256-GCM for authenticated encryption.
    """

    def __init__(
        self,
        time_cost: int = 2,
        memory_cost: int = 65536,  # 64 MB
        parallelism: int = 2,
    ):
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism

    def derive_key(self, password: str, salt: bytes, key_len: int = 32) -> bytes:
        """
        Derive a high-entropy key from user password using Argon2id.
        Argon2id provides optimal defense against GPU and ASIC cracking attacks.
        """
        try:
            return hash_secret_raw(
                secret=password.encode("utf-8"),
                salt=salt,
                time_cost=self.time_cost,
                memory_cost=self.memory_cost,
                parallelism=self.parallelism,
                hash_len=key_len,
                type=Type.ID
            )
        except Exception as e:
            raise CryptoError(f"Key derivation failed: {e}")

    def encrypt_bytes(
        self,
        data: bytes,
        password: str,
        compress: bool = True,
        filename_hint: str = ""
    ) -> bytes:
        """Encrypts arbitrary raw bytes in memory and returns authenticated ciphertext."""
        salt = get_random_bytes(SALT_SIZE)
        nonce = get_random_bytes(NONCE_SIZE)
        key = self.derive_key(password, salt, key_len=32)

        original_data = data
        if compress:
            processed_data = zlib.compress(original_data, level=6)
            is_compressed = 1
        else:
            processed_data = original_data
            is_compressed = 0

        # Encode filename hint (max 255 chars)
        fname_bytes = filename_hint.encode("utf-8")[:255]
        fname_len = len(fname_bytes)

        # Additional Authenticated Data (AAD): binds header metadata to the ciphertext
        # Prevents header manipulation / replay attacks
        aad = MAGIC + struct.pack("!BBH", VERSION, is_compressed, fname_len) + fname_bytes + salt

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(processed_data)

        # Clear key from memory
        del key

        # Payload structure:
        # MAGIC(4) | VERSION(1) | COMPRESSED(1) | FNAME_LEN(2) | FNAME(N) | SALT(16) | NONCE(12) | TAG(16) | CIPHERTEXT
        header = (
            MAGIC +
            struct.pack("!BBH", VERSION, is_compressed, fname_len) +
            fname_bytes +
            salt +
            nonce +
            tag
        )
        return header + ciphertext

    def decrypt_bytes(self, encrypted_data: bytes, password: str) -> tuple[bytes, str]:
        """
        Decrypts raw bytes in memory.
        Returns tuple of: (decrypted_bytes, original_filename_hint).
        Raises AuthenticationError if password is incorrect or data was tampered with.
        """
        if len(encrypted_data) < 4 + 4 + SALT_SIZE + NONCE_SIZE + TAG_SIZE:
            raise CryptoError("Corrupted or invalid encrypted file: data too short.")

        if not encrypted_data.startswith(MAGIC):
            raise CryptoError("Invalid file signature. Not a SecureCrypt file.")

        offset = 4
        version, is_compressed, fname_len = struct.unpack("!BBH", encrypted_data[offset:offset+4])
        offset += 4

        if version != VERSION:
            raise CryptoError(f"Unsupported file format version: {version}")

        fname_bytes = encrypted_data[offset:offset+fname_len]
        filename_hint = fname_bytes.decode("utf-8", errors="replace")
        offset += fname_len

        salt = encrypted_data[offset:offset+SALT_SIZE]
        offset += SALT_SIZE

        nonce = encrypted_data[offset:offset+NONCE_SIZE]
        offset += NONCE_SIZE

        tag = encrypted_data[offset:offset+TAG_SIZE]
        offset += TAG_SIZE

        ciphertext = encrypted_data[offset:]

        # Reconstruct AAD for verification
        aad = MAGIC + struct.pack("!BBH", version, is_compressed, fname_len) + fname_bytes + salt

        # Derive key
        key = self.derive_key(password, salt, key_len=32)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)

        try:
            compressed_data = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            raise AuthenticationError("Authentication failed: incorrect password or corrupted/tampered file.")
        finally:
            del key

        if is_compressed:
            try:
                decrypted_data = zlib.decompress(compressed_data)
            except Exception as e:
                raise CryptoError(f"Decompression error: {e}")
        else:
            decrypted_data = compressed_data

        return decrypted_data, filename_hint

    def encrypt_file(
        self,
        input_path: str,
        output_path: Optional[str] = None,
        password: str = "",
        compress: bool = True,
        progress_callback: Optional[Callable[[float], None]] = None
    ) -> str:
        """
        Encrypt a file from disk to disk.
        Supports large files and updates progress.
        """
        if not os.path.isfile(input_path):
            raise FileNotFoundError(f"Source file not found: {input_path}")

        if not password:
            raise ValueError("Password cannot be empty.")

        if output_path is None:
            output_path = input_path + ".scrypt"

        file_size = os.path.getsize(input_path)
        base_name = os.path.basename(input_path)

        if progress_callback:
            progress_callback(0.1)

        with open(input_path, "rb") as f_in:
            data = f_in.read()

        if progress_callback:
            progress_callback(0.4)

        encrypted_bytes = self.encrypt_bytes(
            data=data,
            password=password,
            compress=compress,
            filename_hint=base_name
        )

        if progress_callback:
            progress_callback(0.8)

        with open(output_path, "wb") as f_out:
            f_out.write(encrypted_bytes)

        if progress_callback:
            progress_callback(1.0)

        return output_path

    def decrypt_file(
        self,
        input_path: str,
        output_path: Optional[str] = None,
        password: str = "",
        progress_callback: Optional[Callable[[float], None]] = None
    ) -> str:
        """
        Decrypt a file from disk to disk.
        """
        if not os.path.isfile(input_path):
            raise FileNotFoundError(f"Encrypted file not found: {input_path}")

        if not password:
            raise ValueError("Password cannot be empty.")

        if progress_callback:
            progress_callback(0.2)

        with open(input_path, "rb") as f_in:
            encrypted_data = f_in.read()

        if progress_callback:
            progress_callback(0.6)

        decrypted_bytes, filename_hint = self.decrypt_bytes(encrypted_data, password)

        if output_path is None:
            if input_path.endswith(".scrypt"):
                output_path = input_path[:-7]
            elif input_path.endswith(".enc"):
                output_path = input_path[:-4]
            else:
                out_dir = os.path.dirname(input_path) or "."
                output_path = os.path.join(out_dir, f"decrypted_{filename_hint or 'file'}")

        with open(output_path, "wb") as f_out:
            f_out.write(decrypted_bytes)

        if progress_callback:
            progress_callback(1.0)

        return output_path
