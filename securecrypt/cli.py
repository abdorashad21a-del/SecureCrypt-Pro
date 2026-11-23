"""
Command Line Interface for SecureCrypt-Pro.
Provides intuitive terminal commands, formatted progress, and safety confirmations.
"""

import os
import sys
import getpass
import argparse
from .core import SecureCrypt, CryptoError, AuthenticationError
from .shredder import shred_file
from .archive import encrypt_directory, decrypt_to_directory
from .password_tools import assess_password_strength, generate_strong_password

# Simple ANSI color helpers
GREEN = "\033[92m"
BLUE = "\033[94m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

BANNER = f"""{CYAN}{BOLD}
   ____                             ____                  _          ____            
  / ___|  ___  ___ _   _ _ __ ___  / ___|_ __ _   _ _ __ | |_       |  _ \ _ __ ___  
  \___ \ / _ \/ __| | | | '__/ _ \| |   | '__| | | | '_ \| __|_____| |_) | '__/ _ \ 
   ___) |  __/ (__| |_| | | |  __/| |___| |  | |_| | |_) | |_|_____|  __/| | | (_) |
  |____/ \___|\___|\__,_|_|  \___| \____|_|   \__, | .__/ \__|      |_|   |_|  \___/ 
                                              |___/|_|                               
{RESET}{YELLOW}       Advanced Authenticated File Encryption & Shredding Suite | v2.0.0{RESET}
"""

def print_banner():
    print(BANNER)

def get_secure_password(prompt: str = "Enter password: ", confirm: bool = False) -> str:
    pwd = getpass.getpass(f"{CYAN}{prompt}{RESET}")
    if not pwd:
        print(f"{RED}[-] Error: Password cannot be empty.{RESET}")
        sys.exit(1)

    if confirm:
        pwd2 = getpass.getpass(f"{CYAN}Confirm password: {RESET}")
        if pwd != pwd2:
            print(f"{RED}[-] Error: Passwords do not match!{RESET}")
            sys.exit(1)

    label, _, entropy = assess_password_strength(pwd)
    color = GREEN if entropy >= 60 else (YELLOW if entropy >= 40 else RED)
    print(f"[*] Password Quality: {color}{label}{RESET} (Entropy: {entropy} bits)")
    return pwd

def main():
    parser = argparse.ArgumentParser(
        description="SecureCrypt-Pro: Industry-grade AES-256-GCM & Argon2id encryption tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Encrypt command
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a file or folder")
    enc_parser.add_argument("target", help="File or folder path to encrypt")
    enc_parser.add_argument("-o", "--output", help="Custom output path")
    enc_parser.add_argument("-p", "--password", help="Password (prompted securely if omitted)")
    enc_parser.add_argument("--no-compress", action="store_true", help="Disable zlib compression")
    enc_parser.add_argument("--shred", action="store_true", help="Securely shred the source file after encryption")

    # Decrypt command
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt a .scrypt or folder archive")
    dec_parser.add_argument("target", help="Path to encrypted .scrypt file")
    dec_parser.add_argument("-o", "--output", help="Custom output path or destination directory")
    dec_parser.add_argument("-p", "--password", help="Password (prompted securely if omitted)")

    # Shred command
    shred_parser = subparsers.add_parser("shred", help="Irreversibly sanitize and erase a file (DoD 5220.22-M)")
    shred_parser.add_argument("target", help="Path to file to permanently shred")
    shred_parser.add_argument("-p", "--passes", type=int, default=3, help="Number of overwrite passes (default: 3)")

    # Genpass command
    gen_parser = subparsers.add_parser("genpass", help="Generate a high-entropy secure password")
    gen_parser.add_argument("-l", "--length", type=int, default=24, help="Password length (default: 24)")

    # GUI command
    subparsers.add_parser("gui", help="Launch graphical user interface")

    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        sys.exit(0)

    if args.command == "gui":
        from .gui import launch_gui
        launch_gui()
        return

    print_banner()

    if args.command == "genpass":
        pwd = generate_strong_password(length=args.length)
        label, _, entropy = assess_password_strength(pwd)
        print(f"{GREEN}[+] Generated Password:{RESET} {BOLD}{pwd}{RESET}")
        print(f"[*] Strength: {label} ({entropy} bits entropy)")
        return

    if args.command == "shred":
        target = args.target
        if not os.path.isfile(target):
            print(f"{RED}[-] Error: File not found: {target}{RESET}")
            sys.exit(1)

        confirm = input(f"{YELLOW}[!] WARNING: Are you sure you want to permanently erase '{target}'? [y/N]: {RESET}")
        if confirm.lower() != "y":
            print("[*] Operation cancelled.")
            sys.exit(0)

        print(f"[*] Shredding {target} ({args.passes} passes)...")
        shred_file(target, passes=args.passes)
        print(f"{GREEN}[+] File sanitized and destroyed successfully!{RESET}")
        return

    if args.command == "encrypt":
        target = args.target
        pwd = args.password or get_secure_password("Enter encryption password: ", confirm=True)
        compress = not args.no_compress

        try:
            if os.path.isdir(target):
                print(f"[*] Encrypting directory: {target}...")
                out = encrypt_directory(target, output_path=args.output, password=pwd, compress=compress)
            elif os.path.isfile(target):
                print(f"[*] Encrypting file: {target}...")
                crypto = SecureCrypt()
                out = crypto.encrypt_file(target, output_path=args.output, password=pwd, compress=compress)
            else:
                print(f"{RED}[-] Target not found: {target}{RESET}")
                sys.exit(1)

            print(f"{GREEN}[+] Encrypted successfully to: {out}{RESET}")

            if args.shred:
                if os.path.isfile(target):
                    print(f"[*] Shredding original plaintext file: {target}...")
                    shred_file(target)
                    print(f"{GREEN}[+] Original file securely destroyed.{RESET}")
        except Exception as e:
            print(f"{RED}[-] Encryption failed: {e}{RESET}")
            sys.exit(1)

    if args.command == "decrypt":
        target = args.target
        if not os.path.isfile(target):
            print(f"{RED}[-] File not found: {target}{RESET}")
            sys.exit(1)

        pwd = args.password or get_secure_password("Enter decryption password: ")

        try:
            print(f"[*] Decrypting: {target}...")
            if target.endswith(".folder.scrypt"):
                out = decrypt_to_directory(target, destination_dir=args.output, password=pwd)
                print(f"{GREEN}[+] Folder decrypted & extracted successfully to: {out}{RESET}")
            else:
                crypto = SecureCrypt()
                out = crypto.decrypt_file(target, output_path=args.output, password=pwd)
                print(f"{GREEN}[+] Decrypted successfully to: {out}{RESET}")
        except AuthenticationError as e:
            print(f"{RED}[-] Decryption rejected: {e}{RESET}")
            sys.exit(1)
        except Exception as e:
            print(f"{RED}[-] Decryption error: {e}{RESET}")
            sys.exit(1)

if __name__ == "__main__":
    main()
