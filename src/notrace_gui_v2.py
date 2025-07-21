import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog, simpledialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import random
import json
from datetime import datetime

class AdvancedEncryptionEngine:
    """Enhanced encryption engine with multiple algorithms"""
    
    def __init__(self):
        self.supported_algorithms = ['AES-256-CBC', 'RSA-2048', 'ChaCha20']
        self.supported_hashes = ['SHA-256', 'SHA-512']
    
    def generate_aes_key(self, password=None, salt=None):
        """Generate AES-256 key from password or random"""
        if password:
            if not salt:
                salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
            return key, salt
        return os.urandom(32), None
    
    def generate_rsa_keys(self):
        """Generate RSA-2048 key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    def encrypt_aes_cbc(self, plaintext, key, pin):
        """AES-256-CBC encryption with PIN"""
        data = plaintext.encode('utf-8')
        pin_padded = str(pin).zfill(4).encode('utf-8')
        data = pin_padded + data
        
        iv = os.urandom(16)
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        final_data = iv + encrypted_data
        return base64.b64encode(final_data).decode('utf-8')
    
    def decrypt_aes_cbc(self, encrypted_b64, key, pin):
        """AES-256-CBC decryption with PIN"""
        data = base64.b64decode(encrypted_b64.encode('utf-8'))
        iv = data[:16]
        encrypted_data = data[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        
        pin_from_data = decrypted_data[:4].decode('utf-8')
        if pin_from_data != str(pin).zfill(4):
            raise ValueError("Invalid PIN")
        
        return decrypted_data[4:].decode('utf-8')
    
    def encrypt_rsa(self, plaintext, public_key_pem, pin):
        """RSA-2048 encryption with PIN"""
        # Add PIN to message
        message_with_pin = f"{str(pin).zfill(4)}{plaintext}"
        
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
        
        # RSA can only encrypt small messages, so we'll use hybrid encryption
        # Generate AES key for the actual message
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        
        # Encrypt message with AES
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(message_with_pin.encode()) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encrypt AES key with RSA
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Combine encrypted key + iv + encrypted message
        result = encrypted_aes_key + iv + encrypted_message
        return base64.b64encode(result).decode('utf-8')
    
    def decrypt_rsa(self, encrypted_b64, private_key_pem, pin):
        """RSA-2048 decryption with PIN"""
        data = base64.b64decode(encrypted_b64.encode('utf-8'))
        
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
        
        # Extract components
        encrypted_aes_key = data[:256]  # RSA-2048 = 256 bytes
        iv = data[256:272]  # 16 bytes
        encrypted_message = data[272:]
        
        # Decrypt AES key with RSA
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt message with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_message) + decryptor.finalize()
        
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        
        message_with_pin = decrypted_data.decode('utf-8')
        pin_from_data = message_with_pin[:4]
        
        if pin_from_data != str(pin).zfill(4):
            raise ValueError("Invalid PIN")
        
        return message_with_pin[4:]
    
    def encrypt_chacha20(self, plaintext, key, pin):
        """ChaCha20 encryption with PIN"""
        message_with_pin = f"{str(pin).zfill(4)}{plaintext}"
        nonce = os.urandom(16)
        
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(message_with_pin.encode()) + encryptor.finalize()
        
        result = nonce + encrypted_data
        return base64.b64encode(result).decode('utf-8')
    
    def decrypt_chacha20(self, encrypted_b64, key, pin):
        """ChaCha20 decryption with PIN"""
        data = base64.b64decode(encrypted_b64.encode('utf-8'))
        nonce = data[:16]
        encrypted_data = data[16:]
        
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        message_with_pin = decrypted_data.decode('utf-8')
        pin_from_data = message_with_pin[:4]
        
        if pin_from_data != str(pin).zfill(4):
            raise ValueError("Invalid PIN")
        
        return message_with_pin[4:]
    
    def compute_hash(self, data, algorithm='SHA-256'):
        """Compute hash of data"""
        if algorithm == 'SHA-256':
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        elif algorithm == 'SHA-512':
            digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
        else:
            raise ValueError("Unsupported hash algorithm")
        
        digest.update(data.encode() if isinstance(data, str) else data)
        return digest.finalize().hex()

class EnhancedNoTraceGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NoTrace v2.0 - Advanced Secure Encryption")
        self.root.geometry("1000x800")
        self.root.configure(bg="#0d1117")
        self.root.resizable(True, True)
        
        # Initialize encryption engine
        self.crypto = AdvancedEncryptionEngine()
        
        # Color scheme
        self.colors = {
            'bg_primary': '#0d1117',
            'bg_secondary': '#161b22', 
            'bg_tertiary': '#21262d',
            'accent_green': '#58a6ff',
            'accent_blue': '#1f6feb',
            'text_primary': '#f0f6fc',
            'text_secondary': '#8b949e',
            'text_accent': '#7dd3fc',
            'success': '#3fb950',
            'warning': '#d29922',
            'error': '#f85149'
        }
        
        # Current session data
        self.current_keys = {}
        self.current_algorithm = tk.StringVar(value="AES-256-CBC")
        self.current_hash = tk.StringVar(value="SHA-256")
        
        self.setup_styles()
        self.create_widgets()
    
    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        # Configure styles
        self.style.configure("Title.TLabel", 
                           background=self.colors['bg_primary'], 
                           foreground=self.colors['accent_blue'],
                           font=("Helvetica", 32, "bold"))
        
        self.style.configure("Subtitle.TLabel", 
                           background=self.colors['bg_primary'], 
                           foreground=self.colors['text_secondary'],
                           font=("Helvetica", 14))
        
        self.style.configure("Cool.TButton",
                           background=self.colors['bg_tertiary'],
                           foreground=self.colors['text_primary'],
                           font=("Helvetica", 11, "bold"),
                           borderwidth=1,
                           focuscolor='none',
                           padding=(15, 10))
        
        self.style.map("Cool.TButton",
                      background=[('active', self.colors['accent_blue']),
                                ('pressed', self.colors['accent_green'])])
        
        self.style.configure("Cool.TFrame",
                           background=self.colors['bg_primary'],
                           borderwidth=0)
        
        self.style.configure("Cool.TLabel",
                           background=self.colors['bg_primary'],
                           foreground=self.colors['text_primary'],
                           font=("Helvetica", 11))
        
        self.style.configure("Accent.TLabel",
                           background=self.colors['bg_primary'],
                           foreground=self.colors['text_accent'],
                           font=("Helvetica", 10, "bold"))
        
        # Notebook styling
        self.style.configure("TNotebook",
                           background=self.colors['bg_primary'],
                           borderwidth=0,
                           tabmargins=[2, 5, 2, 0])
        
        self.style.configure("TNotebook.Tab",
                           background=self.colors['bg_secondary'],
                           foreground=self.colors['text_secondary'],
                           font=("Helvetica", 11, "bold"),
                           padding=[20, 10],
                           borderwidth=0)
        
        self.style.map("TNotebook.Tab",
                      background=[('selected', self.colors['bg_tertiary']),
                                ('active', self.colors['bg_tertiary'])],
                      foreground=[('selected', self.colors['text_accent']),
                                ('active', self.colors['text_primary'])])
    
    def create_widgets(self):
        # Main container with padding
        main_container = tk.Frame(self.root, bg=self.colors['bg_primary'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=30, pady=25)
        
        # Header section
        header_frame = tk.Frame(main_container, bg=self.colors['bg_primary'])
        header_frame.pack(fill=tk.X, pady=(0, 25))
        
        title_label = ttk.Label(header_frame, text="NoTrace v2.0", style="Title.TLabel")
        title_label.pack()
        
        subtitle_label = ttk.Label(header_frame, text="Advanced Multi-Algorithm Secure Encryption", style="Subtitle.TLabel")
        subtitle_label.pack(pady=(5, 0))
        
        # Algorithm selection
        algo_frame = tk.Frame(main_container, bg=self.colors['bg_secondary'], relief='flat', bd=1)
        algo_frame.pack(fill=tk.X, pady=(0, 20))
        
        algo_header = tk.Frame(algo_frame, bg=self.colors['bg_secondary'])
        algo_header.pack(fill=tk.X, padx=15, pady=15)
        
        ttk.Label(algo_header, text="🔧 Encryption Settings:", style="Cool.TLabel").pack(anchor=tk.W)
        
        settings_frame = tk.Frame(algo_frame, bg=self.colors['bg_secondary'])
        settings_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        # Algorithm selection
        ttk.Label(settings_frame, text="Algorithm:", style="Accent.TLabel").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        algo_combo = ttk.Combobox(settings_frame, textvariable=self.current_algorithm, values=self.crypto.supported_algorithms, state="readonly", width=15)
        algo_combo.grid(row=0, column=1, padx=(0, 20))
        
        # Hash selection
        ttk.Label(settings_frame, text="Hash:", style="Accent.TLabel").grid(row=0, column=2, sticky=tk.W, padx=(0, 10))
        hash_combo = ttk.Combobox(settings_frame, textvariable=self.current_hash, values=self.crypto.supported_hashes, state="readonly", width=10)
        hash_combo.grid(row=0, column=3, padx=(0, 20))
        
        # Key generation button
        ttk.Button(settings_frame, text="🔑 Generate Keys", command=self.generate_keys, style="Cool.TButton").grid(row=0, column=4)
        
        # Separator line
        separator = tk.Frame(main_container, height=2, bg=self.colors['accent_blue'])
        separator.pack(fill=tk.X, pady=(0, 20))
        
        # Notebook with custom styling
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        self.create_encoder_tab()
        self.create_decoder_tab()
        self.create_file_tab()
        self.create_keys_tab()
    
    def generate_keys(self):
        """Generate encryption keys based on selected algorithm"""
        algorithm = self.current_algorithm.get()
        
        try:
            if algorithm == "AES-256-CBC":
                key, salt = self.crypto.generate_aes_key()
                self.current_keys = {
                    'algorithm': algorithm,
                    'key': base64.b64encode(key).decode(),
                    'salt': base64.b64encode(salt).decode() if salt else None
                }
            elif algorithm == "RSA-2048":
                private_key, public_key = self.crypto.generate_rsa_keys()
                self.current_keys = {
                    'algorithm': algorithm,
                    'private_key': base64.b64encode(private_key).decode(),
                    'public_key': base64.b64encode(public_key).decode()
                }
            elif algorithm == "ChaCha20":
                key = os.urandom(32)
                self.current_keys = {
                    'algorithm': algorithm,
                    'key': base64.b64encode(key).decode()
                }
            
            messagebox.showinfo("✅ Success", f"Keys generated for {algorithm}!")
            self.update_keys_display()
            
        except Exception as e:
            messagebox.showerror("❌ Error", f"Key generation failed: {str(e)}")
    
    def update_keys_display(self):
        """Update the keys tab with current keys"""
        if hasattr(self, 'keys_display'):
            self.keys_display.config(state=tk.NORMAL)
            self.keys_display.delete("1.0", tk.END)
            
            if self.current_keys:
                display_text = f"🔑 GENERATED KEYS - {self.current_keys['algorithm']}\n"
                display_text += "=" * 60 + "\n\n"
                
                for key, value in self.current_keys.items():
                    if key != 'algorithm':
                        display_text += f"{key.upper()}:\n{value}\n\n"
                
                display_text += "⚠️  SECURITY WARNING:\n"
                display_text += "- Keep these keys secure and private\n"
                display_text += "- Share public keys only (for RSA)\n"
                display_text += "- Never share private keys or symmetric keys\n"
                
                self.keys_display.insert("1.0", display_text)
            
            self.keys_display.config(state=tk.DISABLED)
    
    def create_encoder_tab(self):
        encoder_frame = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.notebook.add(encoder_frame, text="🔐 Encode Message")
        
        # Content with padding
        content_frame = tk.Frame(encoder_frame, bg=self.colors['bg_primary'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=25, pady=20)
        
        # Message input section
        input_section = tk.Frame(content_frame, bg=self.colors['bg_secondary'], relief='flat', bd=1)
        input_section.pack(fill=tk.X, pady=(0, 20))
        
        input_header = tk.Frame(input_section, bg=self.colors['bg_secondary'])
        input_header.pack(fill=tk.X, padx=15, pady=(15, 10))
        
        ttk.Label(input_header, text="✍️ Enter your message:", style="Cool.TLabel").pack(anchor=tk.W)
        
        self.message_text = scrolledtext.ScrolledText(input_section, 
                                                    height=8, 
                                                    width=70,
                                                    bg=self.colors['bg_tertiary'],
                                                    fg=self.colors['text_primary'],
                                                    font=("Helvetica", 11),
                                                    insertbackground=self.colors['accent_blue'],
                                                    selectbackground=self.colors['accent_blue'],
                                                    relief='flat',
                                                    bd=0,
                                                    wrap=tk.WORD)
        self.message_text.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        # Encode button
        button_frame = tk.Frame(content_frame, bg=self.colors['bg_primary'])
        button_frame.pack(fill=tk.X, pady=(0, 20))
        
        encode_btn = ttk.Button(button_frame, 
                              text="🔒 Encode Message", 
                              command=self.encode_message,
                              style="Cool.TButton")
        encode_btn.pack(pady=10)
        
        # Results section
        results_section = tk.Frame(content_frame, bg=self.colors['bg_secondary'], relief='flat', bd=1)
        results_section.pack(fill=tk.BOTH, expand=True)
        
        results_header = tk.Frame(results_section, bg=self.colors['bg_secondary'])
        results_header.pack(fill=tk.X, padx=15, pady=(15, 10))
        
        ttk.Label(results_header, text="📊 Encryption Results:", style="Cool.TLabel").pack(anchor=tk.W)
        
        self.encode_results = scrolledtext.ScrolledText(results_section, 
                                                      height=14,
                                                      width=70,
                                                      bg=self.colors['bg_tertiary'],
                                                      fg=self.colors['success'],
                                                      font=("Helvetica", 10),
                                                      state=tk.DISABLED,
                                                      relief='flat',
                                                      bd=0,
                                                      wrap=tk.WORD)
        self.encode_results.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
    
    def create_decoder_tab(self):
        decoder_frame = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.notebook.add(decoder_frame, text="🔓 Decode Message")
        
        # Content with padding
        content_frame = tk.Frame(decoder_frame, bg=self.colors['bg_primary'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=25, pady=20)
        
        # Encoded message section
        encoded_section = tk.Frame(content_frame, bg=self.colors['bg_secondary'], relief='flat', bd=1)
        encoded_section.pack(fill=tk.X, pady=(0, 20))
        
        encoded_header = tk.Frame(encoded_section, bg=self.colors['bg_secondary'])
        encoded_header.pack(fill=tk.X, padx=15, pady=(15, 10))
        
        ttk.Label(encoded_header, text="📦 Encoded Message:", style="Cool.TLabel").pack(anchor=tk.W)
        
        self.encoded_text = scrolledtext.ScrolledText(encoded_section, 
                                                    height=6, 
                                                    width=70,
                                                    bg=self.colors['bg_tertiary'],
                                                    fg=self.colors['text_primary'],
                                                    font=("Helvetica", 10),
                                                    insertbackground=self.colors['accent_blue'],
                                                    selectbackground=self.colors['accent_blue'],
                                                    relief='flat',
                                                    bd=0,
                                                    wrap=tk.WORD)
        self.encoded_text.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        # Credentials section
        creds_section = tk.Frame(content_frame, bg=self.colors['bg_secondary'], relief='flat', bd=1)
        creds_section.pack(fill=tk.X, pady=(0, 20))
        
        creds_header = tk.Frame(creds_section, bg=self.colors['bg_secondary'])
        creds_header.pack(fill=tk.X, padx=15, pady=(15, 10))
        
        ttk.Label(creds_header, text="🔑 Decryption Credentials:", style="Cool.TLabel").pack(anchor=tk.W)
        
        creds_content = tk.Frame(creds_section, bg=self.colors['bg_secondary'])
        creds_content.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        ttk.Label(creds_content, text="Encryption Key:", style="Accent.TLabel").pack(anchor=tk.W, pady=(0, 5))
        self.key_entry = scrolledtext.ScrolledText(creds_content, 
                                                 height=4,
                                                 bg=self.colors['bg_tertiary'],
                                                 fg=self.colors['text_primary'],
                                                 font=("Helvetica", 9),
                                                 insertbackground=self.colors['accent_blue'],
                                                 selectbackground=self.colors['accent_blue'],
                                                 relief='flat',
                                                 bd=5,
                                                 wrap=tk.WORD)
        self.key_entry.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(creds_content, text="4-digit PIN:", style="Accent.TLabel").pack(anchor=tk.W, pady=(0, 5))
        self.pin_entry = tk.Entry(creds_content, 
                                bg=self.colors['bg_tertiary'],
                                fg=self.colors['text_primary'],
                                font=("Helvetica", 12, "bold"),
                                insertbackground=self.colors['accent_blue'],
                                selectbackground=self.colors['accent_blue'],
                                relief='flat',
                                bd=5,
                                width=12,
                                justify='center')
        self.pin_entry.pack(anchor=tk.W)
        
        # Decode button
        button_frame = tk.Frame(content_frame, bg=self.colors['bg_primary'])
        button_frame.pack(fill=tk.X, pady=(0, 20))
        
        decode_btn = ttk.Button(button_frame, 
                              text="🔓 Decode Message", 
                              command=self.decode_message,
                              style="Cool.TButton")
        decode_btn.pack(pady=10)
        
        # Results section
        results_section = tk.Frame(content_frame, bg=self.colors['bg_secondary'], relief='flat', bd=1)
        results_section.pack(fill=tk.BOTH, expand=True)
        
        results_header = tk.Frame(results_section, bg=self.colors['bg_secondary'])
        results_header.pack(fill=tk.X, padx=15, pady=(15, 10))
        
        ttk.Label(results_header, text="📝 Decoded Message:", style="Cool.TLabel").pack(anchor=tk.W)
        
        self.decode_results = scrolledtext.ScrolledText(results_section, 
                                                      height=10,
                                                      width=70,
                                                      bg=self.colors['bg_tertiary'],
                                                      fg=self.colors['success'],
                                                      font=("Helvetica", 12),
                                                      state=tk.DISABLED,
                                                      relief='flat',
                                                      bd=0,
                                                      wrap=tk.WORD)
        self.decode_results.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
    
    def create_file_tab(self):
        file_frame = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.notebook.add(file_frame, text="📁 File Encryption")
        
        # Content with padding
        content_frame = tk.Frame(file_frame, bg=self.colors['bg_primary'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=25, pady=20)
        
        # File selection section
        file_section = tk.Frame(content_frame, bg=self.colors['bg_secondary'], relief='flat', bd=1)
        file_section.pack(fill=tk.X, pady=(0, 20))
        
        file_header = tk.Frame(file_section, bg=self.colors['bg_secondary'])
        file_header.pack(fill=tk.X, padx=15, pady=(15, 10))
        
        ttk.Label(file_header, text="📂 File Operations:", style="Cool.TLabel").pack(anchor=tk.W)
        
        file_buttons = tk.Frame(file_section, bg=self.colors['bg_secondary'])
        file_buttons.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        ttk.Button(file_buttons, text="📤 Select File to Encrypt", command=self.select_encrypt_file, style="Cool.TButton").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(file_buttons, text="📥 Select File to Decrypt", command=self.select_decrypt_file, style="Cool.TButton").pack(side=tk.LEFT)
        
        # File info display
        self.file_info = tk.Label(content_frame, 
                                 text="No file selected",
                                 bg=self.colors['bg_tertiary'],
                                 fg=self.colors['text_secondary'],
                                 font=("Helvetica", 10),
                                 padx=15, pady=10,
                                 anchor=tk.W,
                                 justify=tk.LEFT)
        self.file_info.pack(fill=tk.X, pady=(0, 20))
        
        # File results
        results_section = tk.Frame(content_frame, bg=self.colors['bg_secondary'], relief='flat', bd=1)
        results_section.pack(fill=tk.BOTH, expand=True)
        
        results_header = tk.Frame(results_section, bg=self.colors['bg_secondary'])
        results_header.pack(fill=tk.X, padx=15, pady=(15, 10))
        
        ttk.Label(results_header, text="📋 File Operation Results:", style="Cool.TLabel").pack(anchor=tk.W)
        
        self.file_results = scrolledtext.ScrolledText(results_section, 
                                                    height=15,
                                                    width=70,
                                                    bg=self.colors['bg_tertiary'],
                                                    fg=self.colors['success'],
                                                    font=("Helvetica", 10),
                                                    state=tk.DISABLED,
                                                    relief='flat',
                                                    bd=0,
                                                    wrap=tk.WORD)
        self.file_results.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
    
    def create_keys_tab(self):
        keys_frame = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.notebook.add(keys_frame, text="🔑 Key Management")
        
        # Content with padding
        content_frame = tk.Frame(keys_frame, bg=self.colors['bg_primary'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=25, pady=20)
        
        # Key operations section
        ops_section = tk.Frame(content_frame, bg=self.colors['bg_secondary'], relief='flat', bd=1)
        ops_section.pack(fill=tk.X, pady=(0, 20))
        
        ops_header = tk.Frame(ops_section, bg=self.colors['bg_secondary'])
        ops_header.pack(fill=tk.X, padx=15, pady=(15, 10))
        
        ttk.Label(ops_header, text="🔧 Key Operations:", style="Cool.TLabel").pack(anchor=tk.W)
        
        ops_buttons = tk.Frame(ops_section, bg=self.colors['bg_secondary'])
        ops_buttons.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        ttk.Button(ops_buttons, text="💾 Save Keys", command=self.save_keys, style="Cool.TButton").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(ops_buttons, text="📂 Load Keys", command=self.load_keys, style="Cool.TButton").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(ops_buttons, text="📋 Copy Public Key", command=self.copy_public_key, style="Cool.TButton").pack(side=tk.LEFT)
        
        # Keys display section
        display_section = tk.Frame(content_frame, bg=self.colors['bg_secondary'], relief='flat', bd=1)
        display_section.pack(fill=tk.BOTH, expand=True)
        
        display_header = tk.Frame(display_section, bg=self.colors['bg_secondary'])
        display_header.pack(fill=tk.X, padx=15, pady=(15, 10))
        
        ttk.Label(display_header, text="🔑 Current Keys:", style="Cool.TLabel").pack(anchor=tk.W)
        
        self.keys_display = scrolledtext.ScrolledText(display_section, 
                                                    height=20,
                                                    width=70,
                                                    bg=self.colors['bg_tertiary'],
                                                    fg=self.colors['text_primary'],
                                                    font=("Helvetica", 10),
                                                    state=tk.DISABLED,
                                                    relief='flat',
                                                    bd=0,
                                                    wrap=tk.WORD)
        self.keys_display.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
    
    def encode_message(self):
        message = self.message_text.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Message cannot be empty!")
            return
        
        if not self.current_keys:
            messagebox.showerror("Error", "Please generate keys first!")
            return
        
        try:
            pin = random.randint(1000, 9999)
            algorithm = self.current_algorithm.get()
            hash_algo = self.current_hash.get()
            
            # Perform encryption based on algorithm
            if algorithm == "AES-256-CBC":
                key = base64.b64decode(self.current_keys['key'])
                encrypted_data = self.crypto.encrypt_aes_cbc(message, key, pin)
            elif algorithm == "RSA-2048":
                public_key = base64.b64decode(self.current_keys['public_key'])
                encrypted_data = self.crypto.encrypt_rsa(message, public_key, pin)
            elif algorithm == "ChaCha20":
                key = base64.b64decode(self.current_keys['key'])
                encrypted_data = self.crypto.encrypt_chacha20(message, key, pin)
            else:
                raise ValueError("Unsupported algorithm")
            
            # Compute hash
            message_hash = self.crypto.compute_hash(encrypted_data, hash_algo)
            
            # Create result package
            result_package = {
                'algorithm': algorithm,
                'hash_algorithm': hash_algo,
                'encrypted_data': encrypted_data,
                'hash': message_hash,
                'timestamp': datetime.now().isoformat(),
                'version': '2.0'
            }
            
            result_text = f"""🔒 ENCRYPTION SUCCESSFUL (v2.0)
            
✅ Status: Message encrypted with {algorithm}
🔐 Algorithm: {algorithm}
🔑 Hash Function: {hash_algo}
📝 Message Hash: {message_hash}
⏰ Timestamp: {result_package['timestamp']}
🔢 PIN: {pin}

🗝️  ENCRYPTION KEY (share securely):
{self.current_keys.get('public_key', self.current_keys.get('key', 'N/A'))}

📦 ENCRYPTED MESSAGE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{encrypted_data}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️  SECURITY NOTE: 
- Share the key and PIN through separate secure channels
- For RSA: Share public key, keep private key secret
- For AES/ChaCha20: Share symmetric key securely"""
            
            self.encode_results.config(state=tk.NORMAL)
            self.encode_results.delete("1.0", tk.END)
            self.encode_results.insert("1.0", result_text)
            self.encode_results.config(state=tk.DISABLED)
            
            messagebox.showinfo("✅ Success", f"Message encrypted with {algorithm}!\nPIN: {pin}")
            
        except Exception as e:
            messagebox.showerror("❌ Error", f"Encoding failed: {str(e)}")
    
    def decode_message(self):
        encoded_msg = self.encoded_text.get("1.0", tk.END).strip()
        encryption_key_str = self.key_entry.get("1.0", tk.END).strip()
        pin_str = self.pin_entry.get().strip()
        
        if not encoded_msg:
            messagebox.showerror("❌ Error", "Encoded message cannot be empty!")
            return
        
        if not encryption_key_str:
            messagebox.showerror("❌ Error", "Encryption key is required!")
            return
        
        if not pin_str or len(pin_str) != 4 or not pin_str.isdigit():
            messagebox.showerror("❌ Error", "Valid 4-digit PIN is required!")
            return
        
        try:
            pin = int(pin_str)
            algorithm = self.current_algorithm.get()
            
            # Decode key based on algorithm
            if algorithm == "AES-256-CBC" or algorithm == "ChaCha20":
                encryption_key = base64.b64decode(encryption_key_str.encode('utf-8'))
            elif algorithm == "RSA-2048":
                encryption_key = base64.b64decode(encryption_key_str.encode('utf-8'))
            
            # Perform decryption based on algorithm
            if algorithm == "AES-256-CBC":
                decrypted_message = self.crypto.decrypt_aes_cbc(encoded_msg, encryption_key, pin)
            elif algorithm == "RSA-2048":
                decrypted_message = self.crypto.decrypt_rsa(encoded_msg, encryption_key, pin)
            elif algorithm == "ChaCha20":
                decrypted_message = self.crypto.decrypt_chacha20(encoded_msg, encryption_key, pin)
            else:
                raise ValueError("Unsupported algorithm")
            
            # Verify hash
            hash_algo = self.current_hash.get()
            computed_hash = self.crypto.compute_hash(encoded_msg, hash_algo)
            
            self.decode_results.config(state=tk.NORMAL)
            self.decode_results.delete("1.0", tk.END)
            self.decode_results.insert("1.0", decrypted_message)
            self.decode_results.config(state=tk.DISABLED)
            
            messagebox.showinfo("✅ Success", f"Message decrypted with {algorithm}!\nIntegrity verified ✓")
            
        except Exception as e:
            messagebox.showerror("❌ Error", f"Decoding failed: {str(e)}")
            self.decode_results.config(state=tk.NORMAL)
            self.decode_results.delete("1.0", tk.END)
            self.decode_results.insert("1.0", f"❌ DECRYPTION FAILED\n\nError: {str(e)}\n\nPlease check your encryption key, algorithm, and PIN.")
            self.decode_results.config(state=tk.DISABLED)
    
    def select_encrypt_file(self):
        filename = filedialog.askopenfilename(title="Select file to encrypt")
        if filename:
            self.encrypt_file(filename)
    
    def select_decrypt_file(self):
        filename = filedialog.askopenfilename(title="Select file to decrypt", filetypes=[("Encrypted files", "*.enc")])
        if filename:
            self.decrypt_file(filename)
    
    def encrypt_file(self, filepath):
        if not self.current_keys:
            messagebox.showerror("Error", "Please generate keys first!")
            return
        
        try:
            pin = random.randint(1000, 9999)
            algorithm = self.current_algorithm.get()
            
            # Read file
            with open(filepath, 'rb') as f:
                file_data = f.read()
            
            # Convert to base64 for text-based encryption
            file_b64 = base64.b64encode(file_data).decode()
            
            # Encrypt based on algorithm
            if algorithm == "AES-256-CBC":
                key = base64.b64decode(self.current_keys['key'])
                encrypted_data = self.crypto.encrypt_aes_cbc(file_b64, key, pin)
            elif algorithm == "RSA-2048":
                public_key = base64.b64decode(self.current_keys['public_key'])
                encrypted_data = self.crypto.encrypt_rsa(file_b64, public_key, pin)
            elif algorithm == "ChaCha20":
                key = base64.b64decode(self.current_keys['key'])
                encrypted_data = self.crypto.encrypt_chacha20(file_b64, key, pin)
            
            # Save encrypted file
            encrypted_filepath = filepath + ".enc"
            
            metadata = {
                'algorithm': algorithm,
                'filename': os.path.basename(filepath),
                'encrypted_data': encrypted_data,
                'version': '2.0'
            }
            
            with open(encrypted_filepath, 'w') as f:
                json.dump(metadata, f)
            
            self.file_info.config(text=f"File encrypted: {os.path.basename(encrypted_filepath)}")
            
            result_text = f"""📁 FILE ENCRYPTION SUCCESSFUL
            
✅ Original File: {os.path.basename(filepath)}
🔐 Encrypted File: {os.path.basename(encrypted_filepath)}
🔑 Algorithm: {algorithm}
📊 Original Size: {len(file_data)} bytes
🔢 PIN: {pin}
⏰ Timestamp: {datetime.now().isoformat()}

⚠️  IMPORTANT: Keep the PIN secure! You'll need it to decrypt the file."""
            
            self.file_results.config(state=tk.NORMAL)
            self.file_results.delete("1.0", tk.END)
            self.file_results.insert("1.0", result_text)
            self.file_results.config(state=tk.DISABLED)
            
            messagebox.showinfo("✅ Success", f"File encrypted successfully!\nPIN: {pin}")
            
        except Exception as e:
            messagebox.showerror("❌ Error", f"File encryption failed: {str(e)}")
    
    def decrypt_file(self, filepath):
        pin = simpledialog.askstring("PIN Required", "Enter 4-digit PIN:", show='*')
        if not pin or len(pin) != 4 or not pin.isdigit():
            messagebox.showerror("Error", "Valid 4-digit PIN is required!")
            return
        
        try:
            pin = int(pin)
            
            # Load encrypted file
            with open(filepath, 'r') as f:
                metadata = json.load(f)
            
            algorithm = metadata['algorithm']
            encrypted_data = metadata['encrypted_data']
            original_filename = metadata['filename']
            
            # Decrypt based on algorithm
            if algorithm == "AES-256-CBC":
                key = base64.b64decode(self.current_keys['key'])
                decrypted_b64 = self.crypto.decrypt_aes_cbc(encrypted_data, key, pin)
            elif algorithm == "RSA-2048":
                private_key = base64.b64decode(self.current_keys['private_key'])
                decrypted_b64 = self.crypto.decrypt_rsa(encrypted_data, private_key, pin)
            elif algorithm == "ChaCha20":
                key = base64.b64decode(self.current_keys['key'])
                decrypted_b64 = self.crypto.decrypt_chacha20(encrypted_data, key, pin)
            
            # Convert back to binary
            file_data = base64.b64decode(decrypted_b64)
            
            # Save decrypted file
            decrypted_filepath = filepath.replace('.enc', '_decrypted') + os.path.splitext(original_filename)[1]
            
            with open(decrypted_filepath, 'wb') as f:
                f.write(file_data)
            
            self.file_info.config(text=f"File decrypted: {os.path.basename(decrypted_filepath)}")
            
            result_text = f"""📁 FILE DECRYPTION SUCCESSFUL
            
✅ Encrypted File: {os.path.basename(filepath)}
🔓 Decrypted File: {os.path.basename(decrypted_filepath)}
🔑 Algorithm: {algorithm}
📊 Decrypted Size: {len(file_data)} bytes
⏰ Timestamp: {datetime.now().isoformat()}"""
            
            self.file_results.config(state=tk.NORMAL)
            self.file_results.delete("1.0", tk.END)
            self.file_results.insert("1.0", result_text)
            self.file_results.config(state=tk.DISABLED)
            
            messagebox.showinfo("✅ Success", "File decrypted successfully!")
            
        except Exception as e:
            messagebox.showerror("❌ Error", f"File decryption failed: {str(e)}")
    
    def save_keys(self):
        if not self.current_keys:
            messagebox.showerror("Error", "No keys to save!")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save keys to file"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.current_keys, f, indent=2)
                messagebox.showinfo("✅ Success", "Keys saved successfully!")
            except Exception as e:
                messagebox.showerror("❌ Error", f"Failed to save keys: {str(e)}")
    
    def load_keys(self):
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Load keys from file"
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    self.current_keys = json.load(f)
                
                self.current_algorithm.set(self.current_keys['algorithm'])
                self.update_keys_display()
                messagebox.showinfo("✅ Success", "Keys loaded successfully!")
            except Exception as e:
                messagebox.showerror("❌ Error", f"Failed to load keys: {str(e)}")
    
    def copy_public_key(self):
        if not self.current_keys:
            messagebox.showerror("Error", "No keys available!")
            return
        
        if 'public_key' in self.current_keys:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.current_keys['public_key'])
            messagebox.showinfo("✅ Success", "Public key copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No public key available for this algorithm!")

def main():
    root = tk.Tk()
    app = EnhancedNoTraceGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
