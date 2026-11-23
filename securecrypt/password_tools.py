"""
Password analysis and generation tools.
Calculates Shannon entropy, scores password strength, and generates secure passphrases.
"""

import math
import string
import secrets
from typing import Tuple

def calculate_entropy(password: str) -> float:
    """Calculates Shannon entropy in bits for a given password string."""
    if not password:
        return 0.0

    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += len(string.punctuation)
    if any(c.isspace() for c in password):
        charset_size += 1

    if charset_size == 0:
        charset_size = 1

    entropy = len(password) * math.log2(charset_size)
    return round(entropy, 2)

def assess_password_strength(password: str) -> Tuple[str, str, float]:
    """
    Evaluates password quality based on entropy, length, and character diversity.
    Returns: (rating_label, color_code, entropy_bits)
    """
    if not password:
        return "Empty", "#888888", 0.0

    entropy = calculate_entropy(password)
    length = len(password)

    if length < 8 or entropy < 30:
        return "Very Weak", "#ef4444", entropy
    elif length < 10 or entropy < 50:
        return "Weak", "#f97316", entropy
    elif length < 14 or entropy < 75:
        return "Moderate", "#eab308", entropy
    elif length < 18 or entropy < 100:
        return "Strong", "#22c55e", entropy
    else:
        return "Military-Grade", "#10b981", entropy

def generate_strong_password(
    length: int = 24,
    include_uppercase: bool = True,
    include_numbers: bool = True,
    include_symbols: bool = True
) -> str:
    """Generates a cryptographically strong random password using secrets module."""
    charset = list(string.ascii_lowercase)
    guaranteed = [secrets.choice(string.ascii_lowercase)]

    if include_uppercase:
        charset.extend(string.ascii_uppercase)
        guaranteed.append(secrets.choice(string.ascii_uppercase))
    if include_numbers:
        charset.extend(string.digits)
        guaranteed.append(secrets.choice(string.digits))
    if include_symbols:
        symbols = "!@#$%^&*()-_=+[]{}<>?"
        charset.extend(symbols)
        guaranteed.append(secrets.choice(symbols))

    remaining = length - len(guaranteed)
    password_chars = guaranteed + [secrets.choice(charset) for _ in range(remaining)]
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)
