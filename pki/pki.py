import os
import time
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

class PKI:
    def __init__(self):
        self.certificates = {}  # Dictionnaire pour stocker les certificats émis
        self.load_crl()  # Charger la liste de révocation des certificats

    def load_crl(self):
        # Charger la liste de révocation des certificats depuis le fichier crl.txt s'il existe
        if os.path.exists("crl.txt"):
            with open("crl.txt", "r") as crl_file:
                for line in crl_file:
                    cert_id = line.strip()
                    self.certificates[cert_id] = {"revoked": True}

    def save_crl(self):
        # Enregistrer la liste de révocation des certificats dans le fichier crl.txt
        with open("crl.txt", "w") as crl_file:
            for cert_id, info in self.certificates.items():
                if info["revoked"]:
                    crl_file.write(cert_id + "\n")

    def generate_key_pair(self):
        # Générer une paire de clés RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        return private_key

    def generate_self_signed_certificate(self, private_key):
        # Générer un certificat auto-signé avec la clé privée donnée
        subject = serialization.NoEncryption().load_pem_private_key(
            private_key,
            password=None,
            backend=default_backend()
        ).public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        cert_id = hashlib.sha256(subject).hexdigest()
        cert = {"id": cert_id, "subject": subject, "revoked": False}
        self.certificates[cert_id] = cert
        return cert

    def create_certificate(self, public_key, signature, date):
        # Créer un certificat avec la clé publique donnée et sa signature
        cert_id = hashlib.sha256(public_key).hexdigest()
        cert = {"id": cert_id, "subject": public_key, "signature": signature, "date": date, "revoked": False}
        self.certificates[cert_id] = cert
        return cert

    def sign_certificate(self, cert):
        # Signer un certificat avec la clé privée de la PKI
        private_key = self.generate_key_pair()
        signature = private_key.sign(
            cert["id"].encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def revoke_certificate(self, cert_id):
        # Révoquer un certificat donné
        if cert_id in self.certificates:
            self.certificates[cert_id]["revoked"] = True
            self.save_crl()

    def is_certificate_revoked(self, cert_id):
        # Vérifier si un certificat donné est révoqué
        return cert_id in self.certificates and self.certificates[cert_id]["revoked"]

