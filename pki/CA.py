import os
import hashlib
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class PKI:
    def __init__(self):
        self.setup_directories()  # Créer les répertoires nécessaires
        self.certificates = {}  # Dictionnaire pour stocker les certificats émis
        self.load_crl()  # Charger la liste de révocation des certificats
        self.private_key = self.load_or_generate_private_key()  # Charger ou générer la clé privée de la CA

    def setup_directories(self):
        # Création du dossier 'certs' s'il n'existe pas
        if not os.path.exists("certs"):
            os.makedirs("certs")
        
        # Création du fichier 'crl.txt' s'il n'existe pas sans crée de dossier
        crl_path = "crl.txt"
        if not os.path.exists(crl_path):
            with open(crl_path, "w") as crl_file:
                crl_file.write("")

        print("Dossiers et fichier CRL créés avec succès.")
    
    def load_crl(self):
        # Charger la liste de révocation des certificats depuis le fichier pki/crl.txt s'il existe
        crl_path = os.path.join("pki", "crl.txt")
        if os.path.exists( crl_path):
            with open(crl_path, "r") as crl_file:
                for line in crl_file:
                    cert_id = line.strip()
                    self.certificates[cert_id] = {"revoked": True}

    def save_crl(self):
        # Enregistrer la liste de révocation des certificats dans le fichier pki/crl.txt
        crl_path = os.path.join("pki", "crl.txt")
        with open(crl_path, "w") as crl_file:
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

    def save_private_key(self, private_key, filename):
        # Sauvegarder la clé privée dans un fichier PEM
        with open(filename, "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

    def save_public_key(self, public_key, filename):
        # Sauvegarder la clé publique dans un fichier PEM
        with open(filename, "wb") as key_file:
            key_file.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

    def load_or_generate_private_key(self):
        # Charger ou générer la clé privée de la CA
        private_key_path = "ca_private_key.pem"
        if os.path.exists(private_key_path):
            with open(private_key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
        else:
            private_key = self.generate_key_pair()
            self.save_private_key(private_key, private_key_path)
        return private_key
    
    def generate_self_signed_certificate(self, private_key):
        # Générer un certificat auto-signé avec la clé privée donnée
        public_key = private_key.public_key()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"mycompany.com"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            # Certificat valide pour un an
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).sign(private_key, hashes.SHA256(), default_backend())

        cert_id = hashlib.sha256(cert.public_bytes(serialization.Encoding.PEM)).hexdigest()
        self.certificates[cert_id] = {"certificate": cert, "revoked": False}
        return cert

    def save_certificate(self, cert, filename):
        # Sauvegarder le certificat dans un fichier PEM
        with open(filename, "wb") as cert_file:
            cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

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

    def generate_certificate(self, cert_request):
        cert_id = hashlib.sha256(cert_request).hexdigest()
        if cert_id not in self.certificates:
            # Si le certificat demandé n'existe pas, le créer et le signer
            signature = self.sign_certificate({"id": cert_id})
            cert = self.create_certificate(cert_request, signature, time.time())
        else:
            # Si le certificat existe déjà, utiliser le certificat existant
            cert = self.certificates[cert_id]
        return cert_id
    
    def generate_certificate_for_public_key(self, public_key):
        # Générer un certificat pour une clé publique donnée
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"mycompany.com"),
        ])

        issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"mycompany.com"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).sign(self.private_key, hashes.SHA256(), default_backend())

        cert_id = hashlib.sha256(cert.public_bytes(serialization.Encoding.PEM)).hexdigest()
        self.certificates[cert_id] = {"certificate": cert, "revoked": False}
        return cert
