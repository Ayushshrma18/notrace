#!/usr/bin/env python3
"""
NoTrace v2.0 - Performance Optimized GUI
Fast-loading encryption application with multiple algorithms
"""

import sys
import os
import json
import base64
import threading
from datetime import datetime

# Lazy imports for faster startup
tkinter = None
messagebox = None
filedialog = None
simpledialog = None

def lazy_import_tkinter():
    global tkinter, messagebox, filedialog, simpledialog
    if tkinter is None:
        import tkinter as tk
        from tkinter import messagebox, filedialog, simpledialog
        tkinter = tk

# Fast crypto imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

class FastEncryptionEngine:
    """Optimized encryption engine with caching"""
    
    def __init__(self):
        self._cached_keys = {}
        self._backend = default_backend()
    
    def get_cached_key(self, password, salt):
        """Get cached key or generate new one"""
        cache_key = password + salt.hex()
        if cache_key not in self._cached_keys:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=self._backend
            )
            self._cached_keys[cache_key] = kdf.derive(password.encode())
        return self._cached_keys[cache_key]
    
    def aes_encrypt(self, plaintext, password):
        """Fast AES-256-CBC encryption"""
        salt = os.urandom(16)
        iv = os.urandom(16)
        key = self.get_cached_key(password, salt)
        
        padder = PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self._backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return base64.b64encode(salt + iv + ciphertext).decode()
    
    def aes_decrypt(self, ciphertext, password):
        """Fast AES-256-CBC decryption"""
        data = base64.b64decode(ciphertext)
        salt, iv, encrypted = data[:16], data[16:32], data[32:]
        key = self.get_cached_key(password, salt)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self._backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted) + decryptor.finalize()
        
        unpadder = PKCS7(128).unpadder()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()
    
    def chacha20_encrypt(self, plaintext, password):
        """Fast ChaCha20 encryption"""
        salt = os.urandom(16)
        key = self.get_cached_key(password, salt)
        
        cipher = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, plaintext.encode(), None)
        
        return base64.b64encode(salt + nonce + ciphertext).decode()
    
    def chacha20_decrypt(self, ciphertext, password):
        """Fast ChaCha20 decryption"""
        data = base64.b64decode(ciphertext)
        salt, nonce, encrypted = data[:16], data[16:28], data[28:]
        key = self.get_cached_key(password, salt)
        
        cipher = ChaCha20Poly1305(key)
        return cipher.decrypt(nonce, encrypted, None).decode()

class FastNoTraceGUI:
    """Performance-optimized GUI with lazy loading"""
    
    def __init__(self):
        lazy_import_tkinter()
        self.engine = FastEncryptionEngine()
        self.setup_ui()
    
    def setup_ui(self):
        """Setup UI with minimal initial load"""
        self.root = tkinter.Tk()
        self.root.title("NoTrace v2.0 - Fast Edition")
        self.root.geometry("900x700")
        self.root.configure(bg='#1a1a1a')
        
        # Fast style configuration
        style = {
            'bg': '#1a1a1a',
            'fg': '#ffffff',
            'selectbackground': '#0d7377',
            'font': ('Segoe UI', 10)
        }
        
        # Create main interface quickly
        self.create_quick_interface(style)
    
    def create_quick_interface(self, style):
        """Create interface with minimal components for fast loading"""
        # Header
        header = tkinter.Frame(self.root, bg=style['bg'], height=80)
        header.pack(fill='x', padx=10, pady=5)
        header.pack_propagate(False)
        
        title = tkinter.Label(header, text="🔐 NoTrace v2.0", 
                            font=('Segoe UI', 18, 'bold'), 
                            bg=style['bg'], fg='#00d4aa')
        title.pack(side='left', pady=20)
        
        subtitle = tkinter.Label(header, text="⚡ Performance Optimized", 
                               font=('Segoe UI', 10), 
                               bg=style['bg'], fg='#888888')
        subtitle.pack(side='right', pady=25)
        
        # Quick action frame
        quick_frame = tkinter.Frame(self.root, bg=style['bg'])
        quick_frame.pack(fill='x', padx=10, pady=5)
        
        # Algorithm selection
        algo_frame = tkinter.Frame(quick_frame, bg=style['bg'])
        algo_frame.pack(fill='x', pady=5)
        
        tkinter.Label(algo_frame, text="Algorithm:", font=style['font'], 
                     bg=style['bg'], fg=style['fg']).pack(side='left')
        
        self.algorithm_var = tkinter.StringVar(value="AES-256-CBC")
        algo_menu = tkinter.OptionMenu(algo_frame, self.algorithm_var, 
                                     "AES-256-CBC", "ChaCha20")
        algo_menu.configure(bg='#2d2d2d', fg='white', font=style['font'])
        algo_menu.pack(side='left', padx=10)
        
        # Input area
        input_frame = tkinter.Frame(self.root, bg=style['bg'])
        input_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Text input
        tkinter.Label(input_frame, text="Message:", font=style['font'], 
                     bg=style['bg'], fg=style['fg']).pack(anchor='w')
        
        self.text_input = tkinter.Text(input_frame, height=8, 
                                     font=('Consolas', 11), 
                                     bg='#2d2d2d', fg='white',
                                     insertbackground='white')
        self.text_input.pack(fill='both', expand=True, pady=5)
        
        # Password input
        pass_frame = tkinter.Frame(input_frame, bg=style['bg'])
        pass_frame.pack(fill='x', pady=5)
        
        tkinter.Label(pass_frame, text="Password:", font=style['font'], 
                     bg=style['bg'], fg=style['fg']).pack(side='left')
        
        self.password_entry = tkinter.Entry(pass_frame, show='*', 
                                          font=style['font'], 
                                          bg='#2d2d2d', fg='white')
        self.password_entry.pack(side='right', fill='x', expand=True, padx=10)
        
        # Buttons
        button_frame = tkinter.Frame(self.root, bg=style['bg'])
        button_frame.pack(fill='x', padx=10, pady=10)
        
        encrypt_btn = tkinter.Button(button_frame, text="🔒 ENCRYPT", 
                                   command=self.encrypt_message,
                                   bg='#0d7377', fg='white', 
                                   font=('Segoe UI', 11, 'bold'),
                                   relief='flat', padx=20, pady=5)
        encrypt_btn.pack(side='left', padx=5)
        
        decrypt_btn = tkinter.Button(button_frame, text="🔓 DECRYPT", 
                                   command=self.decrypt_message,
                                   bg='#14a085', fg='white', 
                                   font=('Segoe UI', 11, 'bold'),
                                   relief='flat', padx=20, pady=5)
        decrypt_btn.pack(side='left', padx=5)
        
        # Quick file buttons
        file_encrypt_btn = tkinter.Button(button_frame, text="📁 File Encrypt", 
                                        command=self.encrypt_file,
                                        bg='#1976d2', fg='white', 
                                        font=style['font'],
                                        relief='flat', padx=15, pady=5)
        file_encrypt_btn.pack(side='right', padx=5)
        
        file_decrypt_btn = tkinter.Button(button_frame, text="📂 File Decrypt", 
                                        command=self.decrypt_file,
                                        bg='#388e3c', fg='white', 
                                        font=style['font'],
                                        relief='flat', padx=15, pady=5)
        file_decrypt_btn.pack(side='right', padx=5)
    
    def encrypt_message(self):
        """Fast message encryption"""
        text = self.text_input.get("1.0", tkinter.END).strip()
        password = self.password_entry.get()
        
        if not text or not password:
            messagebox.showerror("Error", "Please enter both message and password")
            return
        
        try:
            algorithm = self.algorithm_var.get()
            if algorithm == "AES-256-CBC":
                result = self.engine.aes_encrypt(text, password)
            else:  # ChaCha20
                result = self.engine.chacha20_encrypt(text, password)
            
            self.text_input.delete("1.0", tkinter.END)
            self.text_input.insert("1.0", result)
            messagebox.showinfo("Success", f"Message encrypted with {algorithm}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt_message(self):
        """Fast message decryption"""
        text = self.text_input.get("1.0", tkinter.END).strip()
        password = self.password_entry.get()
        
        if not text or not password:
            messagebox.showerror("Error", "Please enter both encrypted message and password")
            return
        
        try:
            algorithm = self.algorithm_var.get()
            if algorithm == "AES-256-CBC":
                result = self.engine.aes_decrypt(text, password)
            else:  # ChaCha20
                result = self.engine.chacha20_decrypt(text, password)
            
            self.text_input.delete("1.0", tkinter.END)
            self.text_input.insert("1.0", result)
            messagebox.showinfo("Success", f"Message decrypted with {algorithm}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    
    def encrypt_file(self):
        """Fast file encryption"""
        file_path = filedialog.askopenfilename(title="Select file to encrypt")
        if not file_path:
            return
        
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            algorithm = self.algorithm_var.get()
            if algorithm == "AES-256-CBC":
                encrypted = self.engine.aes_encrypt(base64.b64encode(data).decode(), password)
            else:
                encrypted = self.engine.chacha20_encrypt(base64.b64encode(data).decode(), password)
            
            save_path = filedialog.asksaveasfilename(
                title="Save encrypted file",
                defaultextension=".enc",
                filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
            )
            
            if save_path:
                with open(save_path, 'w') as f:
                    f.write(encrypted)
                messagebox.showinfo("Success", f"File encrypted and saved to {save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"File encryption failed: {str(e)}")
    
    def decrypt_file(self):
        """Fast file decryption"""
        file_path = filedialog.askopenfilename(
            title="Select encrypted file",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        if not file_path:
            return
        
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        try:
            with open(file_path, 'r') as f:
                encrypted_data = f.read()
            
            algorithm = self.algorithm_var.get()
            if algorithm == "AES-256-CBC":
                decrypted = self.engine.aes_decrypt(encrypted_data, password)
            else:
                decrypted = self.engine.chacha20_decrypt(encrypted_data, password)
            
            original_data = base64.b64decode(decrypted)
            
            save_path = filedialog.asksaveasfilename(title="Save decrypted file")
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(original_data)
                messagebox.showinfo("Success", f"File decrypted and saved to {save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"File decryption failed: {str(e)}")
    
    def run(self):
        """Start the application"""
        self.root.mainloop()

def main():
    """Main entry point - optimized for fast startup"""
    try:
        app = FastNoTraceGUI()
        app.run()
    except Exception as e:
        print(f"Error starting NoTrace: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
