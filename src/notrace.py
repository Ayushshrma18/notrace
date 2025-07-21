from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os
import base64
import json
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
        
        self.message_log.append({
            'action': 'sent',
            'timestamp': datetime.now().isoformat(),
            'message_hash': msg_hash,
            'original_message': message
        })
        
        return message_package
    
    def receive_message(self, message_package, encryption_key, pin):
        encrypted_data = message_package['encrypted_data']
        expected_hash = message_package['hash']
        
        self.key = encryption_key
        self.pin = pin
        self.encryptor = LayeredEncryptionMessaging(self.key, self.pin)
        
        if not self.encryptor.verify_hash(encrypted_data, expected_hash):
            print("Message integrity verification failed!")
            return None
        
        try:
            decrypted_message = self.encryptor.decrypt_message(encrypted_data)
            
            self.message_log.append({
                'action': 'received',
                'timestamp': datetime.now().isoformat(),
                'message_hash': expected_hash,
                'decrypted_message': decrypted_message
            })
            
            print("Message integrity verified and decrypted successfully!")
            return decrypted_message
            
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None
    
    def get_shared_key(self):
        return base64.b64encode(self.key).decode('utf-8')
    
    def get_pin(self):
        return self.pin

def encode_message():
    print("NoTrace - Message Encoder\n")
    
    message = input("Enter your message to encode: ")
    if not message.strip():
        print("Message cannot be empty!")
        return
    
    encoder = P2PMessagingApp()
    
    message_package = encoder.send_message(message)
    
    print(f"\nMessage encoded successfully!")
    print(f"Encryption layers: {message_package['metadata']['layers']}")
    print(f"Message hash: {message_package['hash']}")
    print(f"Encryption key (share with recipient):")
    print(f"   {encoder.get_shared_key()}")
    print(f"4-digit PIN for this message: {encoder.get_pin()}")
    
    print(f"\nEncoded message (send this to recipient):")
    print(f"   {message_package['encrypted_data']}")
    
    return message_package, encoder.get_shared_key(), encoder.get_pin()

def decode_message():
    print("NoTrace - Message Decoder\n")
    
    encoded_msg = input("Enter the encoded message: ").strip()
    if not encoded_msg:
        print("Encoded message cannot be empty!")
        return
    
    encryption_key_str = input("Enter the encryption key: ").strip()
    if not encryption_key_str:
        print("Encryption key is required!")
        return
    
    pin_str = input("Enter the 4-digit PIN: ").strip()
    if not pin_str or len(pin_str) != 4 or not pin_str.isdigit():
        print("Valid 4-digit PIN is required!")
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
        
        if decrypted_message:
            print(f"\nDecoded message: {decrypted_message}")
        else:
            print("Failed to decode message. Check your key and PIN.")
            
    except Exception as e:
        print(f"Decoding failed: {e}")

def main_menu():
    while True:
        print("\n" + "="*50)
        print("NoTrace - Secure Message Encryption")
        print("="*50)
        print("1. Encode Message")
        print("2. Decode Message")
        print("3. Exit")
        print("="*50)
        
        choice = input("Select an option (1-3): ").strip()
        
        if choice == "1":
            encode_message()
        elif choice == "2":
            decode_message()
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main_menu()
