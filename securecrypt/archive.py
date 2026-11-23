"""
Directory / Folder Encryption and Decryption module.
Packs directory into a compressed archive before applying authenticated encryption.
"""

import os
import tarfile
import io
import shutil
from typing import Optional, Callable
from .core import SecureCrypt, CryptoError

def encrypt_directory(
    dir_path: str,
    output_path: Optional[str] = None,
    password: str = "",
    compress: bool = True,
    progress_callback: Optional[Callable[[float], None]] = None
) -> str:
    """
    Recursively packages a directory and securely encrypts it into a single .scrypt file.
    """
    if not os.path.isdir(dir_path):
        raise NotADirectoryError(f"Directory not found: {dir_path}")

    dir_path = os.path.abspath(dir_path)
    base_name = os.path.basename(dir_path)

    if output_path is None:
        output_path = dir_path + ".folder.scrypt"

    if progress_callback:
        progress_callback(0.1)

    # Pack directory into tar buffer
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w:gz" if compress else "w") as tar:
        tar.add(dir_path, arcname=base_name)

    tar_bytes = tar_buffer.getvalue()

    if progress_callback:
        progress_callback(0.5)

    crypto = SecureCrypt()
    encrypted_bytes = crypto.encrypt_bytes(
        data=tar_bytes,
        password=password,
        compress=False,  # Already compressed by tarfile if chosen
        filename_hint=f"{base_name}.tar"
    )

    if progress_callback:
        progress_callback(0.8)

    with open(output_path, "wb") as f_out:
        f_out.write(encrypted_bytes)

    if progress_callback:
        progress_callback(1.0)

    return output_path

def decrypt_to_directory(
    input_path: str,
    destination_dir: Optional[str] = None,
    password: str = "",
    progress_callback: Optional[Callable[[float], None]] = None
) -> str:
    """
    Decrypts a directory archive file and extracts its full structure.
    """
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Archive file not found: {input_path}")

    if progress_callback:
        progress_callback(0.2)

    with open(input_path, "rb") as f_in:
        encrypted_data = f_in.read()

    crypto = SecureCrypt()
    decrypted_bytes, filename_hint = crypto.decrypt_bytes(encrypted_data, password)

    if progress_callback:
        progress_callback(0.6)

    if destination_dir is None:
        destination_dir = os.path.dirname(os.path.abspath(input_path))

    tar_buffer = io.BytesIO(decrypted_bytes)
    with tarfile.open(fileobj=tar_buffer, mode="r:*") as tar:
        try:
            tar.extractall(path=destination_dir, filter="data")
        except TypeError:
            tar.extractall(path=destination_dir)

    if progress_callback:
        progress_callback(1.0)

    return destination_dir
