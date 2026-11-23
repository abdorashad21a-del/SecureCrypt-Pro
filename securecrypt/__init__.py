"""
SecureCrypt-Pro: Advanced Authenticated File & Folder Encryption Suite
Author: Abdelrahman Rashad (@abdorashad21a-del)
License: MIT
"""

__version__ = "2.0.0"
__author__ = "Abdelrahman Rashad"

from .core import SecureCrypt, CryptoError
from .shredder import shred_file
from .archive import encrypt_directory, decrypt_to_directory
from .password_tools import assess_password_strength, generate_strong_password

__all__ = [
    "SecureCrypt",
    "CryptoError",
    "shred_file",
    "encrypt_directory",
    "decrypt_to_directory",
    "assess_password_strength",
    "generate_strong_password",
]
