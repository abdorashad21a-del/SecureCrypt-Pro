"""
Secure File Shredder implementing DoD 5220.22-M 3-pass sanitization standard.
Ensures irreversible data destruction preventing forensic recovery.
"""

import os
import secrets
from typing import Callable, Optional

def shred_file(
    file_path: str,
    passes: int = 3,
    progress_callback: Optional[Callable[[int, int], None]] = None
) -> bool:
    """
    Overwrites a target file multiple times with random & patterned bytes,
    syncs to storage medium, and permanently unlinks it.
    
    Args:
        file_path: Target file path to sanitize.
        passes: Number of overwrite passes (default 3 for DoD 5220.22-M).
        progress_callback: Optional callback(current_pass, total_passes).
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    file_size = os.path.getsize(file_path)
    if file_size == 0:
        os.remove(file_path)
        return True

    chunk_size = 64 * 1024

    with open(file_path, "r+b") as f:
        for p in range(1, passes + 1):
            f.seek(0)
            if progress_callback:
                progress_callback(p, passes)

            # Pass pattern selection
            if p == 1:
                pattern = b"\x00" * chunk_size
            elif p == 2:
                pattern = b"\xFF" * chunk_size
            else:
                pattern = None  # Random bytes

            bytes_written = 0
            while bytes_written < file_size:
                to_write = min(chunk_size, file_size - bytes_written)
                if pattern:
                    f.write(pattern[:to_write])
                else:
                    f.write(secrets.token_bytes(to_write))
                bytes_written += to_write

            f.flush()
            os.fsync(f.fileno())

    # Obfuscate file name before unlinking to eliminate metadata traces
    dir_name = os.path.dirname(file_path)
    random_name = os.path.join(dir_name, secrets.token_hex(16) + ".tmp")
    try:
        os.rename(file_path, random_name)
        os.remove(random_name)
    except Exception:
        if os.path.exists(file_path):
            os.remove(file_path)

    return True
