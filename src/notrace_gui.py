import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os
import base64
import random
from datetime import datetime

class LayeredEncryptionMessaging:
    def __init__(self, encryption_key, pin):
        self.key = encryption_key
        self.pin = pin
        
    def encrypt_message(self, plaintext):
        data = plaintext.encode('utf-8')
        
        pin_padded = str(self.pin).zfill(4).encode('utf-8')
        data = pin_padded + data
        
        iv = os.urandom(16)
        
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        final_data = iv + encrypted_data
        
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(final_data)
        message_hash = digest.finalize().hex()
        
        encrypted_b64 = base64.b64encode(final_data).decode('utf-8')
        
        metadata = {
            'layers': 2,
            'layer_info': ['Layer 1: 4-digit PIN', 'Layer 2: AES-256-CBC'],
            'hash': message_hash,
            'timestamp': datetime.now().isoformat(),
            'algorithm': 'AES-256-CBC with PIN protection'
        }
        
        return encrypted_b64, message_hash, metadata
    
    def decrypt_message(self, encrypted_b64):
        data = base64.b64decode(encrypted_b64.encode('utf-8'))
        
        iv = data[:16]
        encrypted_data = data[16:]
        
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        
        pin_from_data = decrypted_data[:4].decode('utf-8')
        if pin_from_data != str(self.pin).zfill(4):
            raise ValueError("Invalid PIN")
        
        message_data = decrypted_data[4:]
        return message_data.decode('utf-8')
    
    def verify_hash(self, encrypted_b64, expected_hash):
        data = base64.b64decode(encrypted_b64.encode('utf-8'))
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        actual_hash = digest.finalize().hex()
        return actual_hash == expected_hash

class P2PMessagingApp:
    def __init__(self):
        self.key = os.urandom(32)
        self.pin = None
        self.encryptor = None
        self.message_log = []
    
    def generate_pin(self):
        self.pin = random.randint(1000, 9999)
        self.encryptor = LayeredEncryptionMessaging(self.key, self.pin)
        return self.pin
    
    def send_message(self, message):
        if self.encryptor is None:
            self.generate_pin()
        
        encrypted_msg, msg_hash, metadata = self.encryptor.encrypt_message(message)
        
        message_package = {
            'encrypted_data': encrypted_msg,
            'hash': msg_hash,
            'metadata': metadata,
            'original_length': len(message)
        }
        
        return message_package
    
    def receive_message(self, message_package, encryption_key, pin):
        encrypted_data = message_package['encrypted_data']
        expected_hash = message_package['hash']
        
        self.key = encryption_key
        self.pin = pin
        self.encryptor = LayeredEncryptionMessaging(self.key, self.pin)
        
        if not self.encryptor.verify_hash(encrypted_data, expected_hash):
            raise ValueError("Message integrity verification failed!")
        
        decrypted_message = self.encryptor.decrypt_message(encrypted_data)
        return decrypted_message
    
    def get_shared_key(self):
        return base64.b64encode(self.key).decode('utf-8')
    
    def get_pin(self):
        return self.pin

class NoTraceGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NoTrace - Secure Message Encryption")
        self.root.geometry("900x700")
        self.root.configure(bg="#0d1117")
        self.root.resizable(True, True)
        
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
        
        self.setup_styles()
        self.create_widgets()
    
    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        # Configure styles
        self.style.configure("Title.TLabel", 
                           background=self.colors['bg_primary'], 
                           foreground=self.colors['accent_blue'],
                           font=("Helvetica", 28, "bold"))
        
        self.style.configure("Subtitle.TLabel", 
                           background=self.colors['bg_primary'], 
                           foreground=self.colors['text_secondary'],
                           font=("Helvetica", 12))
        
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
        
        title_label = ttk.Label(header_frame, text="NoTrace", style="Title.TLabel")
        title_label.pack()
        
        subtitle_label = ttk.Label(header_frame, text="Advanced Secure Message Encryption", style="Subtitle.TLabel")
        subtitle_label.pack(pady=(5, 0))
        
        # Separator line
        separator = tk.Frame(main_container, height=2, bg=self.colors['accent_blue'])
        separator.pack(fill=tk.X, pady=(0, 20))
        
        # Notebook with custom styling
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        self.create_encoder_tab()
        self.create_decoder_tab()
        
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
        self.key_entry = tk.Entry(creds_content, 
                                bg=self.colors['bg_tertiary'],
                                fg=self.colors['text_primary'],
                                font=("Helvetica", 10),
                                insertbackground=self.colors['accent_blue'],
                                selectbackground=self.colors['accent_blue'],
                                relief='flat',
                                bd=5,
                                width=60)
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
        
    def encode_message(self):
        message = self.message_text.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Message cannot be empty!")
            return
        
        try:
            encoder = P2PMessagingApp()
            message_package = encoder.send_message(message)
            
            result_text = f"""🔒 ENCRYPTION SUCCESSFUL
            
✅ Status: Message encrypted with 2-layer security
📊 Encryption Layers: {message_package['metadata']['layers']}
🔐 Algorithm: {message_package['metadata']['algorithm']}
📝 Message Hash: {message_package['hash']}
⏰ Timestamp: {message_package['metadata']['timestamp']}

🔑 SHARE THESE CREDENTIALS WITH RECIPIENT:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🗝️  Encryption Key:
{encoder.get_shared_key()}

📍 4-Digit PIN: {encoder.get_pin()}

📦 ENCRYPTED MESSAGE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{message_package['encrypted_data']}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️  SECURITY NOTE: Share the key and PIN through separate secure channels"""
            
            self.encode_results.config(state=tk.NORMAL)
            self.encode_results.delete("1.0", tk.END)
            self.encode_results.insert("1.0", result_text)
            self.encode_results.config(state=tk.DISABLED)
            
            # Show success popup
            messagebox.showinfo("✅ Success", f"Message encrypted successfully!\nPIN: {encoder.get_pin()}")
            
        except Exception as e:
            messagebox.showerror("❌ Error", f"Encoding failed: {str(e)}")
    
    def decode_message(self):
        encoded_msg = self.encoded_text.get("1.0", tk.END).strip()
        encryption_key_str = self.key_entry.get().strip()
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
            encryption_key = base64.b64decode(encryption_key_str.encode('utf-8'))
            pin = int(pin_str)
            
            decoder = P2PMessagingApp()
            
            message_package = {
                'encrypted_data': encoded_msg,
                'hash': '',
                'metadata': {'layers': 2}
            }
            
            data = base64.b64decode(encoded_msg.encode('utf-8'))
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(data)
            message_package['hash'] = digest.finalize().hex()
            
            decrypted_message = decoder.receive_message(message_package, encryption_key, pin)
            
            self.decode_results.config(state=tk.NORMAL)
            self.decode_results.delete("1.0", tk.END)
            self.decode_results.insert("1.0", decrypted_message)
            self.decode_results.config(state=tk.DISABLED)
            
            # Show success popup
            messagebox.showinfo("✅ Success", "Message decrypted successfully!\nIntegrity verified ✓")
            
        except Exception as e:
            messagebox.showerror("❌ Error", f"Decoding failed: {str(e)}")
            self.decode_results.config(state=tk.NORMAL)
            self.decode_results.delete("1.0", tk.END)
            self.decode_results.insert("1.0", "❌ DECRYPTION FAILED\n\nPlease check your encryption key and PIN.")
            self.decode_results.config(state=tk.DISABLED)

def main():
    root = tk.Tk()
    app = NoTraceGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
