"""
Comprehensive unit test suite for SecureCrypt-Pro.
"""

import os
import pytest
import tempfile
import secrets
from securecrypt.core import SecureCrypt, CryptoError, AuthenticationError
from securecrypt.shredder import shred_file
from securecrypt.archive import encrypt_directory, decrypt_to_directory
from securecrypt.password_tools import assess_password_strength, generate_strong_password

def test_encrypt_decrypt_bytes():
    crypto = SecureCrypt()
    test_data = b"Hello, Cybersecurity World! Confidential Payload 123456789."
    password = "SuperSecretSecurePassword!2026"

    encrypted = crypto.encrypt_bytes(test_data, password=password, compress=True)
    assert len(encrypted) > len(test_data)

    decrypted, fname = crypto.decrypt_bytes(encrypted, password=password)
    assert decrypted == test_data

def test_tampering_detection():
    crypto = SecureCrypt()
    test_data = b"Sensitive Financial Records and Hashes."
    password = "CorrectHorseBatteryStaple!"

    encrypted = bytearray(crypto.encrypt_bytes(test_data, password=password))

    # Flip one single bit in the ciphertext payload
    encrypted[-1] ^= 0x01

    with pytest.raises(AuthenticationError):
        crypto.decrypt_bytes(bytes(encrypted), password=password)

def test_invalid_password_rejection():
    crypto = SecureCrypt()
    test_data = b"Top Secret Intelligence Data"
    correct_pwd = "MyStrongPassword#99"
    wrong_pwd = "WrongPassword#00"

    encrypted = crypto.encrypt_bytes(test_data, password=correct_pwd)

    with pytest.raises(AuthenticationError):
        crypto.decrypt_bytes(encrypted, password=wrong_pwd)

def test_file_encryption_and_decryption(tmp_path):
    crypto = SecureCrypt()
    src_file = tmp_path / "test_document.txt"
    src_file.write_bytes(secrets.token_bytes(1024 * 64))  # 64 KB test file
    password = "DocumentPassword#2026"

    enc_file = tmp_path / "test_document.txt.scrypt"
    crypto.encrypt_file(str(src_file), output_path=str(enc_file), password=password)
    assert enc_file.exists()

    dec_file = tmp_path / "restored_document.txt"
    crypto.decrypt_file(str(enc_file), output_path=str(dec_file), password=password)
    assert dec_file.exists()
    assert dec_file.read_bytes() == src_file.read_bytes()

def test_directory_archive_encryption(tmp_path):
    project_dir = tmp_path / "my_project"
    project_dir.mkdir()
    (project_dir / "file1.txt").write_text("Hello from file 1")
    (project_dir / "subdir").mkdir()
    (project_dir / "subdir" / "file2.txt").write_text("Hello from subdir file 2")

    password = "FolderSecretPassword@44"
    archive_out = tmp_path / "my_project.folder.scrypt"

    encrypt_directory(str(project_dir), output_path=str(archive_out), password=password)
    assert archive_out.exists()

    restore_dir = tmp_path / "restored"
    restore_dir.mkdir()
    decrypt_to_directory(str(archive_out), destination_dir=str(restore_dir), password=password)

    restored_proj = restore_dir / "my_project"
    assert restored_proj.exists()
    assert (restored_proj / "file1.txt").read_text() == "Hello from file 1"
    assert (restored_proj / "subdir" / "file2.txt").read_text() == "Hello from subdir file 2"

def test_file_shredder(tmp_path):
    file_to_kill = tmp_path / "killme.txt"
    file_to_kill.write_text("This text must be permanently eradicated.")
    assert file_to_kill.exists()

    shred_file(str(file_to_kill), passes=3)
    assert not file_to_kill.exists()

def test_password_tools():
    pwd = generate_strong_password(length=30)
    assert len(pwd) == 30
    label, color, entropy = assess_password_strength(pwd)
    assert entropy >= 80
    assert label in ["Strong", "Military-Grade"]
