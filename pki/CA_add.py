import os
import OpenSSL.crypto as crypto

# Variables globales
pki_dir = 'pki'
certs_dir = os.path.join(pki_dir, 'certs')
crl_file = os.path.join(pki_dir, 'crl.pem')

# Crée les répertoires et fichiers nécessaires
if not os.path.exists(pki_dir):
    os.mkdir(pki_dir)
if not os.path.exists(certs_dir):
    os.mkdir(certs_dir)
if not os.path.exists(crl_file):
    with open(crl_file, 'w') as f:
        f.write('')

# Crée une paire de clés et un certificat auto-signé
def create_self_signed_cert(cert_dir, cert_file):
    # Génère une clé privée
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # Crée un certificat auto-signé
    cert = crypto.X509()
    cert.get_subject().CN = 'CA'
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(31536000)  # 1 an
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha256')

    # Écrit la clé et le certificat sur disque
    with open(os.path.join(cert_dir, 'ca.key'), 'wb') as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    with open(os.path.join(cert_dir, cert_file), 'wb') as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

create_self_signed_cert(certs_dir, 'ca.crt')

# Ajoute un certificat révoqué à la CRL
def revoke_cert(cert_file):
    # Lire le certificat révoqué
    with open(cert_file, 'r') as f:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

    # Lire la CRL existante
    with open(crl_file, 'rb') as f:
        crl = crypto.load_crl(crypto.FILETYPE_PEM, f.read())

    # Ajouter le certificat à la CRL
    crl.add_revoked(cert)

    # Écrire la nouvelle CRL sur disque
    with open(crl_file, 'wb') as f:
        f.write(crypto.dump_crl(crypto.FILETYPE_PEM, crl))

# Vérifie si un certificat est révoqué
def is_cert_revoked(cert_file):
    # Lire le certificat
    with open(cert_file, 'r') as f:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

    # Lire la CRL
    with open(crl_file, 'rb') as f:
        crl = crypto.load_crl(crypto.FILETYPE_PEM, f.read())

    # Vérifie si le certificat est révoqué
    for revoked in crl.get_revoked():
        if revoked.get_serial() == cert.get_serial_number():
            return True
    return False

# Émettre un certificat pour un client
def issue_cert(client_pub_key_file, client_cert_file):
    # Lire la clé publique du client
    with open(client_pub_key_file, 'r') as f:
        client_pub_key = crypto.load_publickey(crypto.FILETYPE_PEM, f.read())

    # Lire la clé privée et le certificat de l'autorité de certification
    with open(os.path.join(certs_dir, 'ca.key'), 'r') as f:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())
    with open(os.path.join(certs_dir, 'ca.crt'), 'r') as f:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

    # Crée un certificat pour le client
    cert = crypto.X509()
    cert.get_subject().CN = 'Client'
    cert.set_serial_number(crypto.makelong(crypto.random_number(), 64))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(31536000)  # 1 an
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(client_pub_key)
    cert.sign(ca_key, 'sha256')

    # Écrire le certificat du client sur disque
    with open(client_cert_file, 'wb') as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

# Exemples d'utilisation
issue_cert('client_pub.key', 'client_cert.pem')
print(is_cert_revoked('client_cert.pem'))
