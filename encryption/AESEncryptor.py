from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

encryption_path = os.path.dirname(os.path.abspath(__file__))
project_path = os.path.abspath(os.path.join(encryption_path, os.pardir))

class AESEncryptor:
    def __init__(self, key_size=32):  # AES-256
        self.key_size = key_size
        self.key = None

    def load_key(self, file_path):
        with open(os.path.join(project_path, file_path), "rb") as key_file:
            self.key = key_file.read()
        print(f"Clé AES chargée depuis {file_path}")

    def save_key(self, file_path):
        with open(os.path.join(project_path, file_path), "wb") as key_file:
            key_file.write(self.key)
        print(f"Clé AES sauvegardée dans {file_path}")

    def generate_key(self):
        self.key = get_random_bytes(self.key_size)
        print(f"Clé AES générée: {self.key.hex()}")

    def encrypt_message(self, message):
        if not self.key:
            raise ValueError("La clé AES n'est pas chargée.")
        
        cipher_aes = AES.new(self.key, AES.MODE_CBC)
        message_bytes = message.encode()
        
        # Padding
        padding_length = AES.block_size - len(message_bytes) % AES.block_size
        padded_message = message_bytes + bytes([padding_length]) * padding_length

        iv = cipher_aes.iv
        encrypted_message = cipher_aes.encrypt(padded_message)
        
        return iv + encrypted_message

    def decrypt_message(self, encrypted_message):
        if not self.key:
            raise ValueError("La clé AES n'est pas chargée.")
        
        iv = encrypted_message[:AES.block_size]
        encrypted_message = encrypted_message[AES.block_size:]
        
        cipher_aes = AES.new(self.key, AES.MODE_CBC, iv=iv)
        decrypted_padded_message = cipher_aes.decrypt(encrypted_message)
        
        # Unpadding
        padding_length = decrypted_padded_message[-1]
        decrypted_message = decrypted_padded_message[:-padding_length]
        
        return decrypted_message.decode()

# Exemple d'utilisation (à commenter si non nécessaire pour vos tests)
# aes_encryptor = AESEncryptor()

# Générer et sauvegarder la clé
# aes_encryptor.generate_key()
# aes_encryptor.save_key("aes_key.bin")

# Charger la clé
# aes_encryptor.load_key("aes_key.bin")

# Chiffrer un message
# message = "Hello, this is a secret message!"
# encrypted_message = aes_encryptor.encrypt_message(message)
# print("Message chiffré:", encrypted_message)

# Déchiffrer le message
# decrypted_message = aes_encryptor.decrypt_message(encrypted_message)
# print("Message déchiffré:", decrypted_message)
