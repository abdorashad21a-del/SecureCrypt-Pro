"""
Modern Graphical User Interface (GUI) for SecureCrypt-Pro.
Built using CustomTkinter / Tkinter with sleek dark theme and responsive feedback.
"""

import os
import sys
import threading
from typing import Optional

try:
    import customtkinter as ctk
    from tkinter import filedialog, messagebox
    HAS_CTK = True
except ImportError:
    import tkinter as ctk
    from tkinter import filedialog, messagebox, ttk
    HAS_CTK = False

from .core import SecureCrypt, CryptoError, AuthenticationError
from .archive import encrypt_directory, decrypt_to_directory
from .shredder import shred_file
from .password_tools import assess_password_strength, generate_strong_password

def launch_gui():
    if HAS_CTK:
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")
        app = ctk.CTk()
    else:
        app = ctk.Tk()

    app.title("SecureCrypt-Pro | Cybersecurity Vault")
    app.geometry("640x580")
    app.resizable(False, False)

    # Header Title
    title_label = ctk.CTkLabel(
        app,
        text="🔒 SecureCrypt-Pro",
        font=("Segoe UI", 24, "bold") if HAS_CTK else ("Segoe UI", 18, "bold")
    )
    title_label.pack(pady=(20, 5))

    sub_label = ctk.CTkLabel(
        app,
        text="Military-Grade AES-256-GCM & Argon2id File Encryption",
        font=("Segoe UI", 12) if HAS_CTK else ("Segoe UI", 10),
        text_color="#94a3b8" if HAS_CTK else "#666"
    )
    sub_label.pack(pady=(0, 15))

    # Frame for file selection
    file_frame = ctk.CTkFrame(app) if HAS_CTK else ctk.Frame(app)
    file_frame.pack(fill="x", padx=30, pady=5)

    path_var = ctk.StringVar()
    entry_path = ctk.CTkEntry(
        file_frame,
        textvariable=path_var,
        placeholder_text="Select a file or folder...",
        width=380
    ) if HAS_CTK else ctk.Entry(file_frame, textvariable=path_var, width=45)
    entry_path.pack(side="left", padx=10, pady=12, fill="x", expand=True)

    def browse_file():
        p = filedialog.askopenfilename()
        if p:
            path_var.set(p)

    def browse_folder():
        p = filedialog.askdirectory()
        if p:
            path_var.set(p)

    btn_file = ctk.CTkButton(file_frame, text="Browse File", width=95, command=browse_file) if HAS_CTK else ctk.Button(file_frame, text="Browse File", command=browse_file)
    btn_file.pack(side="left", padx=5)

    btn_folder = ctk.CTkButton(file_frame, text="Folder", width=70, command=browse_folder) if HAS_CTK else ctk.Button(file_frame, text="Folder", command=browse_folder)
    btn_folder.pack(side="left", padx=(0, 10))

    # Password Frame
    pwd_frame = ctk.CTkFrame(app) if HAS_CTK else ctk.Frame(app)
    pwd_frame.pack(fill="x", padx=30, pady=10)

    pwd_var = ctk.StringVar()
    show_pwd = ctk.BooleanVar(value=False)

    entry_pwd = ctk.CTkEntry(
        pwd_frame,
        textvariable=pwd_var,
        show="*",
        placeholder_text="Enter strong password...",
        width=380
    ) if HAS_CTK else ctk.Entry(pwd_frame, textvariable=pwd_var, show="*", width=45)
    entry_pwd.pack(side="left", padx=10, pady=12, fill="x", expand=True)

    def toggle_show():
        if show_pwd.get():
            entry_pwd.configure(show="")
        else:
            entry_pwd.configure(show="*")

    chk_show = ctk.CTkCheckBox(pwd_frame, text="Show", variable=show_pwd, command=toggle_show, width=60) if HAS_CTK else ctk.Checkbutton(pwd_frame, text="Show", variable=show_pwd, command=toggle_show)
    chk_show.pack(side="left", padx=5)

    def gen_pwd():
        p = generate_strong_password(24)
        pwd_var.set(p)
        on_pwd_change()

    btn_gen = ctk.CTkButton(pwd_frame, text="Generate", width=80, fg_color="#475569" if HAS_CTK else None, command=gen_pwd) if HAS_CTK else ctk.Button(pwd_frame, text="Generate", command=gen_pwd)
    btn_gen.pack(side="left", padx=(0, 10))

    # Strength indicator
    strength_label = ctk.CTkLabel(app, text="Password Strength: Waiting for input...", font=("Segoe UI", 11)) if HAS_CTK else ctk.Label(app, text="Password Strength: Waiting for input...")
    strength_label.pack(pady=(0, 10))

    def on_pwd_change(*args):
        p = pwd_var.get()
        label, color, entropy = assess_password_strength(p)
        if HAS_CTK:
            strength_label.configure(
                text=f"Password Strength: {label} ({entropy} bits entropy)",
                text_color=color
            )
        else:
            strength_label.config(text=f"Password Strength: {label} ({entropy} bits entropy)")

    pwd_var.trace_add("write", on_pwd_change)

    # Options (Shred, Compression)
    opt_frame = ctk.CTkFrame(app) if HAS_CTK else ctk.Frame(app)
    opt_frame.pack(fill="x", padx=30, pady=5)

    shred_var = ctk.BooleanVar(value=False)
    chk_shred = ctk.CTkCheckBox(opt_frame, text="Shred original file after encryption (DoD 5220.22-M)", variable=shred_var) if HAS_CTK else ctk.Checkbutton(opt_frame, text="Shred original file after encryption", variable=shred_var)
    chk_shred.pack(side="left", padx=15, pady=10)

    # Progress Bar & Status
    status_label = ctk.CTkLabel(app, text="Ready", font=("Segoe UI", 12)) if HAS_CTK else ctk.Label(app, text="Ready")
    status_label.pack(pady=(10, 5))

    progress = ctk.CTkProgressBar(app, width=540) if HAS_CTK else ttk.Progressbar(app, length=540)
    progress.pack(pady=5)
    if HAS_CTK:
        progress.set(0)

    # Action Buttons
    action_frame = ctk.CTkFrame(app, fg_color="transparent") if HAS_CTK else ctk.Frame(app)
    action_frame.pack(pady=15)

    def run_async(func):
        threading.Thread(target=func, daemon=True).start()

    def do_encrypt():
        target = path_var.get().strip()
        pwd = pwd_var.get()
        if not target or not os.path.exists(target):
            messagebox.showerror("Error", "Please select a valid file or folder!")
            return
        if not pwd:
            messagebox.showerror("Error", "Please enter a password!")
            return

        def task():
            try:
                status_label.configure(text="Encrypting in progress...") if HAS_CTK else status_label.config(text="Encrypting...")
                if HAS_CTK: progress.set(0.3)
                if os.path.isdir(target):
                    out = encrypt_directory(target, password=pwd)
                else:
                    crypto = SecureCrypt()
                    out = crypto.encrypt_file(target, password=pwd)

                if HAS_CTK: progress.set(0.8)
                if shred_var.get() and os.path.isfile(target):
                    shred_file(target)

                if HAS_CTK: progress.set(1.0)
                status_label.configure(text=f"Success! Output: {os.path.basename(out)}") if HAS_CTK else status_label.config(text="Encrypted!")
                messagebox.showinfo("Success", f"Encrypted successfully:\n{out}")
            except Exception as e:
                status_label.configure(text="Encryption Failed") if HAS_CTK else status_label.config(text="Failed")
                messagebox.showerror("Encryption Error", str(e))

        run_async(task)

    def do_decrypt():
        target = path_var.get().strip()
        pwd = pwd_var.get()
        if not target or not os.path.isfile(target):
            messagebox.showerror("Error", "Please select a valid encrypted .scrypt file!")
            return
        if not pwd:
            messagebox.showerror("Error", "Please enter the decryption password!")
            return

        def task():
            try:
                status_label.configure(text="Decrypting and verifying...") if HAS_CTK else status_label.config(text="Decrypting...")
                if HAS_CTK: progress.set(0.3)
                if target.endswith(".folder.scrypt"):
                    out = decrypt_to_directory(target, password=pwd)
                else:
                    crypto = SecureCrypt()
                    out = crypto.decrypt_file(target, password=pwd)

                if HAS_CTK: progress.set(1.0)
                status_label.configure(text="Decryption Successful!") if HAS_CTK else status_label.config(text="Decrypted!")
                messagebox.showinfo("Success", f"Decrypted successfully to:\n{out}")
            except AuthenticationError:
                if HAS_CTK: progress.set(0)
                status_label.configure(text="Authentication Failed") if HAS_CTK else status_label.config(text="Auth Failed")
                messagebox.showerror("Security Alert", "Authentication failed: Invalid password or file was tampered with!")
            except Exception as e:
                if HAS_CTK: progress.set(0)
                status_label.configure(text="Decryption Error") if HAS_CTK else status_label.config(text="Error")
                messagebox.showerror("Decryption Error", str(e))

        run_async(task)

    btn_enc = ctk.CTkButton(
        action_frame,
        text="🔒 Encrypt Target",
        fg_color="#059669",
        hover_color="#047857",
        width=170,
        height=40,
        font=("Segoe UI", 13, "bold"),
        command=do_encrypt
    ) if HAS_CTK else ctk.Button(action_frame, text="Encrypt Target", command=do_encrypt)
    btn_enc.pack(side="left", padx=15)

    btn_dec = ctk.CTkButton(
        action_frame,
        text="🔓 Decrypt Target",
        fg_color="#2563eb",
        hover_color="#1d4ed8",
        width=170,
        height=40,
        font=("Segoe UI", 13, "bold"),
        command=do_decrypt
    ) if HAS_CTK else ctk.Button(action_frame, text="Decrypt Target", command=do_decrypt)
    btn_dec.pack(side="left", padx=15)

    # Footer note
    footer = ctk.CTkLabel(
        app,
        text="Developed by Abdelrahman Rashad | SecureCrypt-Pro Suite",
        font=("Segoe UI", 10),
        text_color="#64748b" if HAS_CTK else "#999"
    )
    footer.pack(side="bottom", pady=15)

    app.mainloop()

if __name__ == "__main__":
    launch_gui()
