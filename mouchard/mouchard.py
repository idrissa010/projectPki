import paho.mqtt.client as mqtt
import json
from threading import Thread
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
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
TOPIC_MOUCHARD = "vehicle/sami/mouchard"


class MQTTMouchard:
    def __init__(self, mouchard_id, nom, topic_mouchard):
        self.broker_address = BROKER_ADDRESS
        self.broker_port = BROKER_PORT
        self.mouchard_id = mouchard_id
        self.nom = nom
        self.topic_mouchard = f"{topic_mouchard}/{mouchard_id}"
        self.certificate = None

        # Génération de la paire de clés RSA
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()

        # Sauvegarder la clé privée et la clé publique
        self.save_private_key()
        self.save_public_key()

        # Création d'une instance du client MQTT
        self.client = mqtt.Client(protocol=mqtt.MQTTv311)

        # Attribution des fonctions de rappel
        self.client.on_connect = self.on_connect
        self.client.on_publish = self.on_publish
        self.client.on_message = self.on_message

    # Fonction pour sauvegarder la clé privée
    def save_private_key(self):
        with open(f"mouchard_{self.mouchard_id}_private_key.pem", "wb") as key_file:
            key_file.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

    # Fonction pour sauvegarder la clé publique
    def save_public_key(self):
        with open(f"mouchard_{self.mouchard_id}_public_key.pem", "wb") as key_file:
            key_file.write(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

    # Création de la structure du message
    def create_message_structure(self, message, type_message=0, certificat="", public_key=""):
        message_structure = {
            "nom": self.nom,
            "id": self.mouchard_id,
            "message": message,
            "type": type_message,
            "certificat": certificat,
            "public_key": public_key
        }
        return json.dumps(message_structure)

    # Fonction de rappel lors de la connexion
    def on_connect(self, client, userdata, flags, rc):
        print(f"[{self.nom}] Connecté au broker MQTT avec le code de retour : {rc}")
        client.subscribe(self.topic_mouchard)

    # Fonction de rappel lors de la publication
    def on_publish(self, client, userdata, mid):
        print(f"[{self.nom}] Message publié avec succès.")

    # Fonction de rappel lors de la réception de messages
    def on_message(self, client, userdata, message):
        payload = json.loads(message.payload.decode())
        print(f"[{self.nom}] Message reçu sur le topic {message.topic}: {payload}")

        if payload.get("nom") == "PKI" and payload.get("id") == "PKI":
            cert_pem = payload.get("certificat", "")
            with open(f"mouchard_{self.mouchard_id}_certificate.pem", "wb") as cert_file:
                cert_file.write(cert_pem.encode())
            print(f"[{self.nom}] Certificat reçu et sauvegardé.")

    # Demande de certificat à la PKI
    def request_certificate(self):
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        self.client.publish(
            TOPIC_PKI,
            self.create_message_structure("Demande de certificat", 1, public_key=public_key_pem)
        )

    # Démarrage du mouchard
    def start(self):
        self.client.connect(self.broker_address, self.broker_port)
        print(f"--------------------- {self.nom} ---------------------")
        self.client.loop_start()
        self.request_certificate()

    # Arrêt du mouchard
    def stop(self):
        self.client.loop_stop()
        self.client.disconnect()

# Création et démarrage du mouchard
mouchard1 = MQTTMouchard(1, "MOUCHARD1", "vehicle/sami/mouchard")
mouchard1_thread = Thread(target=mouchard1.start)
mouchard1_thread.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("Interruption reçue, arrêt des threads...")
    mouchard1.stop()
    mouchard1_thread.join()
    print("Arrêt complet.")