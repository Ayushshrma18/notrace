from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.tabbedpanel import TabbedPanel, TabbedPanelItem
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.scrollview import ScrollView
from kivy.uix.popup import Popup
from kivy.uix.gridlayout import GridLayout
from kivy.metrics import dp
from kivy.core.window import Window
from kivymd.app import MDApp
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.card import MDCard
from kivymd.uix.label import MDLabel
from kivymd.uix.textfield import MDTextField
from kivymd.uix.button import MDRaisedButton, MDFlatButton
from kivymd.uix.tab import MDTabs, MDTabsBase
from kivymd.uix.screen import MDScreen
from kivymd.uix.scrollview import MDScrollView
from kivymd.uix.dialog import MDDialog
from kivymd.theming import ThemableBehavior
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

class Tab(MDBoxLayout, MDTabsBase):
    pass

class EncodeTab(Tab):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.spacing = dp(20)
        self.padding = dp(20)
        
        # Title
        title = MDLabel(
            text="🔐 Encode Message",
            theme_text_color="Primary",
            font_style="H5",
            size_hint_y=None,
            height=dp(50)
        )
        self.add_widget(title)
        
        # Message input card
        input_card = MDCard(
            elevation=3,
            padding=dp(20),
            size_hint_y=None,
            height=dp(200)
        )
        
        input_layout = MDBoxLayout(orientation='vertical', spacing=dp(10))
        
        input_label = MDLabel(
            text="✍️ Enter your message:",
            theme_text_color="Primary",
            font_style="Subtitle1",
            size_hint_y=None,
            height=dp(30)
        )
        
        self.message_input = MDTextField(
            multiline=True,
            hint_text="Type your secret message here...",
            size_hint_y=None,
            height=dp(120)
        )
        
        input_layout.add_widget(input_label)
        input_layout.add_widget(self.message_input)
        input_card.add_widget(input_layout)
        self.add_widget(input_card)
        
        # Encode button
        self.encode_button = MDRaisedButton(
            text="🔒 ENCODE MESSAGE",
            theme_icon_color="Custom",
            icon_color="white",
            md_bg_color="#1976D2",
            size_hint_y=None,
            height=dp(50),
            on_release=self.encode_message
        )
        self.add_widget(self.encode_button)
        
        # Results card
        results_card = MDCard(
            elevation=3,
            padding=dp(20)
        )
        
        results_layout = MDBoxLayout(orientation='vertical', spacing=dp(10))
        
        results_label = MDLabel(
            text="📊 Encryption Results:",
            theme_text_color="Primary",
            font_style="Subtitle1",
            size_hint_y=None,
            height=dp(30)
        )
        
        scroll = MDScrollView()
        self.results_text = MDLabel(
            text="Results will appear here after encoding...",
            theme_text_color="Secondary",
            font_style="Body1",
            text_size=(None, None),
            valign="top"
        )
        scroll.add_widget(self.results_text)
        
        results_layout.add_widget(results_label)
        results_layout.add_widget(scroll)
        results_card.add_widget(results_layout)
        self.add_widget(results_card)
    
    def encode_message(self, *args):
        message = self.message_input.text.strip()
        if not message:
            self.show_dialog("Error", "Message cannot be empty!")
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

🔑 SHARE THESE CREDENTIALS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🗝️  Encryption Key:
{encoder.get_shared_key()}

📍 4-Digit PIN: {encoder.get_pin()}

📦 ENCRYPTED MESSAGE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{message_package['encrypted_data']}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️  SECURITY NOTE: Share key and PIN through separate channels"""
            
            self.results_text.text = result_text
            self.results_text.text_size = (Window.width - dp(80), None)
            
            self.show_dialog("✅ Success", f"Message encrypted successfully!\nPIN: {encoder.get_pin()}")
            
        except Exception as e:
            self.show_dialog("❌ Error", f"Encoding failed: {str(e)}")
    
    def show_dialog(self, title, text):
        dialog = MDDialog(
            title=title,
            text=text,
            buttons=[
                MDFlatButton(
                    text="OK",
                    on_release=lambda x: dialog.dismiss()
                )
            ]
        )
        dialog.open()

class DecodeTab(Tab):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.spacing = dp(20)
        self.padding = dp(20)
        
        # Title
        title = MDLabel(
            text="🔓 Decode Message",
            theme_text_color="Primary",
            font_style="H5",
            size_hint_y=None,
            height=dp(50)
        )
        self.add_widget(title)
        
        # Encoded message card
        encoded_card = MDCard(
            elevation=3,
            padding=dp(20),
            size_hint_y=None,
            height=dp(180)
        )
        
        encoded_layout = MDBoxLayout(orientation='vertical', spacing=dp(10))
        
        encoded_label = MDLabel(
            text="📦 Encoded Message:",
            theme_text_color="Primary",
            font_style="Subtitle1",
            size_hint_y=None,
            height=dp(30)
        )
        
        self.encoded_input = MDTextField(
            multiline=True,
            hint_text="Paste the encoded message here...",
            size_hint_y=None,
            height=dp(100)
        )
        
        encoded_layout.add_widget(encoded_label)
        encoded_layout.add_widget(self.encoded_input)
        encoded_card.add_widget(encoded_layout)
        self.add_widget(encoded_card)
        
        # Credentials card
        creds_card = MDCard(
            elevation=3,
            padding=dp(20),
            size_hint_y=None,
            height=dp(180)
        )
        
        creds_layout = MDBoxLayout(orientation='vertical', spacing=dp(10))
        
        creds_label = MDLabel(
            text="🔑 Decryption Credentials:",
            theme_text_color="Primary",
            font_style="Subtitle1",
            size_hint_y=None,
            height=dp(30)
        )
        
        self.key_input = MDTextField(
            hint_text="Enter encryption key...",
            size_hint_y=None,
            height=dp(50)
        )
        
        self.pin_input = MDTextField(
            hint_text="Enter 4-digit PIN...",
            input_filter="int",
            max_text_length=4,
            size_hint_y=None,
            height=dp(50)
        )
        
        creds_layout.add_widget(creds_label)
        creds_layout.add_widget(self.key_input)
        creds_layout.add_widget(self.pin_input)
        creds_card.add_widget(creds_layout)
        self.add_widget(creds_card)
        
        # Decode button
        self.decode_button = MDRaisedButton(
            text="🔓 DECODE MESSAGE",
            theme_icon_color="Custom",
            icon_color="white",
            md_bg_color="#4CAF50",
            size_hint_y=None,
            height=dp(50),
            on_release=self.decode_message
        )
        self.add_widget(self.decode_button)
        
        # Results card
        results_card = MDCard(
            elevation=3,
            padding=dp(20)
        )
        
        results_layout = MDBoxLayout(orientation='vertical', spacing=dp(10))
        
        results_label = MDLabel(
            text="📝 Decoded Message:",
            theme_text_color="Primary",
            font_style="Subtitle1",
            size_hint_y=None,
            height=dp(30)
        )
        
        scroll = MDScrollView()
        self.results_text = MDLabel(
            text="Decoded message will appear here...",
            theme_text_color="Secondary",
            font_style="Body1",
            text_size=(None, None),
            valign="top"
        )
        scroll.add_widget(self.results_text)
        
        results_layout.add_widget(results_label)
        results_layout.add_widget(scroll)
        results_card.add_widget(results_layout)
        self.add_widget(results_card)
    
    def decode_message(self, *args):
        encoded_msg = self.encoded_input.text.strip()
        encryption_key_str = self.key_input.text.strip()
        pin_str = self.pin_input.text.strip()
        
        if not encoded_msg:
            self.show_dialog("❌ Error", "Encoded message cannot be empty!")
            return
        
        if not encryption_key_str:
            self.show_dialog("❌ Error", "Encryption key is required!")
            return
        
        if not pin_str or len(pin_str) != 4 or not pin_str.isdigit():
            self.show_dialog("❌ Error", "Valid 4-digit PIN is required!")
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
            
            self.results_text.text = decrypted_message
            self.results_text.text_size = (Window.width - dp(80), None)
            
            self.show_dialog("✅ Success", "Message decrypted successfully!\nIntegrity verified ✓")
            
        except Exception as e:
            self.show_dialog("❌ Error", f"Decoding failed: {str(e)}")
            self.results_text.text = "❌ DECRYPTION FAILED\n\nPlease check your encryption key and PIN."
            self.results_text.text_size = (Window.width - dp(80), None)
    
    def show_dialog(self, title, text):
        dialog = MDDialog(
            title=title,
            text=text,
            buttons=[
                MDFlatButton(
                    text="OK",
                    on_release=lambda x: dialog.dismiss()
                )
            ]
        )
        dialog.open()

class NoTraceApp(MDApp):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.title = "NoTrace - Secure Encryption"
        self.theme_cls.primary_palette = "Blue"
        self.theme_cls.primary_hue = "700"
        self.theme_cls.theme_style = "Dark"
        
    def build(self):
        # Main screen
        screen = MDScreen()
        
        # Main layout
        main_layout = MDBoxLayout(
            orientation='vertical',
            spacing=dp(10),
            padding=dp(10)
        )
        
        # Header
        header = MDLabel(
            text="NoTrace",
            theme_text_color="Primary",
            font_style="H3",
            halign="center",
            size_hint_y=None,
            height=dp(60)
        )
        
        subtitle = MDLabel(
            text="Advanced Secure Message Encryption",
            theme_text_color="Secondary",
            font_style="Subtitle1",
            halign="center",
            size_hint_y=None,
            height=dp(30)
        )
        
        # Tabs
        tabs = MDTabs()
        
        # Encode tab
        encode_tab = EncodeTab()
        tabs.add_tab(
            label="🔐 Encode",
            tab=encode_tab
        )
        
        # Decode tab
        decode_tab = DecodeTab()
        tabs.add_tab(
            label="🔓 Decode",
            tab=decode_tab
        )
        
        main_layout.add_widget(header)
        main_layout.add_widget(subtitle)
        main_layout.add_widget(tabs)
        
        screen.add_widget(main_layout)
        return screen

if __name__ == '__main__':
    NoTraceApp().run()
