import paho.mqtt.client as mqtt
import json
from CA import PKI
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from encryption.RSAEncryptor import RSAEncryptor

# Informations de connexion au broker MQTT
BROKER_ADDRESS = "194.57.103.203"
BROKER_PORT = 1883
TOPIC_PKI = "vehicle/sami/pki"
TOPIC_VENDEUR = "vehicle/sami/vendeur"
TOPIC_CLIENT = "vehicle/sami/client"

NOM = "PKI"
ID = 46


# Génération de la paire de clés RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

# Fonction pour sauvegarder la clé privée
def save_private_key():
    # Sauvegarder la clé privée dans un fichier PEM
    with open(f"pki_private_key.pem", "wb") as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

# Fonction pour sauvegarder la clé publique
def save_public_key():
    # Sauvegarder la clé publique dans un fichier PEM
    with open(f"pki_public_key.pem", "wb") as key_file:
        key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        
save_private_key()
save_public_key()

# Instanciation RSAEncryptor
rsa_encryptor = RSAEncryptor()
rsa_encryptor.load_private_key("pki/pki_private_key.pem")

# Fonction pour créer une structure JSON contenant les informations
def create_message_structure(message, certificat="", public_key=""):
    message_structure = {
        "nom": NOM,
        "id": ID,
        "message": message,
        "type": 0,
        "certificat": certificat,
        "public_key": public_key
    }
    rsa_encryptor.load_private_key(f"pki/pki_private_key.pem")
    encrypted_message = rsa_encryptor.encrypt_message(json.dumps(message_structure))
    # return encrypted_message
    return json.dumps(message_structure)

# Fonction de rappel lors de la connexion au broker MQTT
def on_connect(client, userdata, flags, rc):
    print("Connecté au broker MQTT avec le code de retour :", str(rc))
    client.subscribe(TOPIC_PKI)

# Fonction de rappel lors de la publication d'un message
def on_publish(client, userdata, mid):
    print("["+NOM+"] : Message publié avec succès.")

# Fonction de rappel lors de la réception d'un message
def on_message(client, userdata, message):
    encrypted_message = message.payload
    # print(f"Message chiffré reçu: {encrypted_message}")
    try:
        decrypted_message = rsa_encryptor.decrypt_message(encrypted_message)
        # print(f"Message déchiffré: {decrypted_message}")
    except ValueError as e:
        return
    payload = json.loads(decrypted_message)

    payload = json.loads(message.payload.decode())
    print("Payload JSON:", payload)


    # encrypted_message = message.payload
    # rsa_encryptor.load_private_key("pki/pki_private_key.pem")
    # decrypted_message = rsa_encryptor.decrypt_message(encrypted_message)
    # # print("Message reçu sur le topic", message.topic, ":", decrypted_message)

    # # payload = json.loads(decrypted_message.payload.decode())
    # payload = json.loads(decrypted_message)

    nom = payload.get("nom", "")  # Utiliser NOM comme valeur par défaut si "nom" n'est pas présent
    received_message = payload.get("message", "")
    public_key_pem = payload.get("public_key", "")
    certificat = payload.get("certificat", "")
    id = payload.get("id", "")
    print("["+nom+"] : ", received_message)

    if "Demande de certificat" in received_message and public_key_pem:
        public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
        cert = myPKI.generate_certificate_for_public_key(public_key)
        cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM).decode()
       
        if nom == "VENDEUR1":
            topic_vendeur1 = f"{TOPIC_VENDEUR}/{1}"
            rsa_encryptor.load_public_key(f"vendeur/vendeur_{id}_public_key.pem")
            client.publish(topic_vendeur1, create_message_structure("Certificat signé", certificat=cert_pem))
        elif nom == "VENDEUR2":
            topic_vendeur2 = f"{TOPIC_VENDEUR}/{2}"
            rsa_encryptor.load_public_key(f"vendeur/vendeur_{id}_public_key.pem")
            client.publish(topic_vendeur2, create_message_structure("Certificat signé", certificat=cert_pem))
    elif "Verification Certificat" in received_message and certificat:
        try:
            cert = x509.load_pem_x509_certificate(certificat.encode(), default_backend())
            cert_id = cert.fingerprint(hashes.SHA256()).hex()
            if myPKI.is_certificate_revoked(cert_id):
                response = "Certificat Vendeur Non Valide"
            else:
                response = "Certificat Vendeur Valide"
        except Exception as e:
            print(f"Erreur lors de la vérification du certificat: {e}")
            response = "Certificat Vendeur Non Valide"

        if nom == "CLIENT1":
            topic_client1 = f"{TOPIC_CLIENT}/{1}"
            print(certificat)
            rsa_encryptor.load_public_key(f"client/client_{id}_public_key.pem")
            client.publish(topic_client1, create_message_structure(response))
        elif nom == "CLIENT2":
            topic_client2 = f"{TOPIC_CLIENT}/{2}"
            rsa_encryptor.load_public_key(f"client/client_{id}_public_key.pem")
            client.publish(topic_client2, create_message_structure(response))
        elif nom == "CLIENT3":
            topic_client3 = f"{TOPIC_CLIENT}/{3}"
            rsa_encryptor.load_public_key(f"client/client_{id}_public_key.pem")
            client.publish(topic_client3, create_message_structure(response))

# Création d'une instance du client MQTT
client = mqtt.Client(protocol=mqtt.MQTTv311)

# Attribution des fonctions de rappel
client.on_connect = on_connect
client.on_message = on_message

# Génération de la clé privée et du certificat auto-signé
myPKI = PKI()
# private_key = myPKI.generate_key_pair()
# myPKI.save_private_key(private_key, "private_key.pem")
# myPKI.save_public_key(private_key.public_key(), "public_key.pem")

cert = myPKI.generate_self_signed_certificate(private_key)
myPKI.save_certificate(cert, "certificate.pem")

# Connexion au broker MQTT
client.connect(BROKER_ADDRESS, BROKER_PORT)

client.on_publish = on_publish

print("--------------------- PKI ---------------------")

# Démarrage de la boucle de gestion des messages dans un thread séparé
client.loop_start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("Interruption reçue, arrêt du client MQTT...")
    client.loop_stop()  # Arrêter la boucle MQTT
    client.disconnect()  # Déconnecter le client

print("Arrêt complet.")
