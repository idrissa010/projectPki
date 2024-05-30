from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

encryption_path = os.path.dirname(os.path.abspath(__file__))
project_path = os.path.abspath(os.path.join(encryption_path, os.pardir))

class RSAEncryptor:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.private_key = None
        self.public_key = None

    def load_private_key(self, file_path):
        with open(os.path.join(project_path, file_path), "rb") as private_file:
            self.private_key = RSA.import_key(private_file.read())
        print(f"Clé privée chargée depuis {file_path}")

    def load_public_key(self, file_path):
        with open(os.path.join(project_path, file_path), "rb") as public_file:
            self.public_key = RSA.import_key(public_file.read())
        print(f"Clé publique chargée depuis {file_path}")

    def encrypt_message(self, message):
        if not self.public_key:
            raise ValueError("La clé publique n'est pas chargée.")
        
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        message_bytes = message.encode()
        encrypted_message = b''

        chunk_size = self.public_key.size_in_bytes() - 42
        print(f"Taille des chunks pour le chiffrement: {chunk_size}")

        for i in range(0, len(message_bytes), chunk_size):
            chunk = message_bytes[i:i + chunk_size]
            encrypted_chunk = cipher_rsa.encrypt(chunk)
            encrypted_message += encrypted_chunk
        
        return encrypted_message

    def decrypt_message(self, encrypted_message):
        if not self.private_key:
            raise ValueError("La clé privée n'est pas chargée.")
        
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        decrypted_message = b''

        chunk_size = self.private_key.size_in_bytes()
        print(f"Taille des chunks pour le déchiffrement: {chunk_size}")

        for i in range(0, len(encrypted_message), chunk_size):
            chunk = encrypted_message[i:i + chunk_size]
            try:
                decrypted_chunk = cipher_rsa.decrypt(chunk)
                decrypted_message += decrypted_chunk
            except ValueError as e:
                raise ValueError("Déchifrement...")
        
        return decrypted_message.decode()

# Exemple d'utilisation (à commenter si non nécessaire pour vos tests)
# rsa_encryptor = RSAEncryptor()

# Générer et sauvegarder les clés
# rsa_encryptor.generate_keys()

# Charger les clés (si elles ne sont pas générées dans cette session)
# rsa_encryptor.load_private_key("private_key.pem")
# rsa_encryptor.load_public_key("public_key.pem")

# Chiffrer un message
# message = "Hello, this is a secret message!"
# encrypted_message = rsa_encryptor.encrypt_message(message)
# print("Message chiffré:", encrypted_message)

# Déchiffrer le message
# decrypted_message = rsa_encryptor.decrypt_message(encrypted_message)
# print("Message déchiffré:", decrypted_message)
