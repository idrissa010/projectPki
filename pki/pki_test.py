# pki.py

# pip install cryptography

import os
import datetime
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

class PKI:
    def __init__(self):
        self.crl = set()  # Liste de révocation des certificats

    def generate_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def generate_self_signed_certificate(self, private_key, public_key):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'PKI'),
        ])
        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )

        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        return certificate

    def revoke_certificate(self, certificate):
        self.crl.add(certificate.serial_number)

    def is_certificate_revoked(self, certificate):
        return certificate.serial_number in self.crl

if __name__ == "__main__":
    pki = PKI()

    # Génération de la paire de clés
    private_key, public_key = pki.generate_key_pair()

    # Génération du certificat auto-signé
    certificate = pki.generate_self_signed_certificate(private_key, public_key)

    print("Private Key:")
    print(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode())

    print("Public Key:")
    print(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode())

    print("Certificate:")
    print(certificate.public_bytes(
        encoding=serialization.Encoding.PEM
    ).decode())

    # Révocation du certificat
    pki.revoke_certificate(certificate)
