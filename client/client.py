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

# Instanciation RSAEncryptor
rsa_encryptor = RSAEncryptor()

class MQTTClient:
    def __init__(self, client_id, nom, topic_client):
        self.broker_address = BROKER_ADDRESS
        self.broker_port = BROKER_PORT
        self.client_id = client_id
        self.nom = nom
        self.topic_client = f"{topic_client}/{client_id}"

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

    # Fonction pour créer une structure JSON contenant les informations
    def create_message_structure(self, message, type_message=0, certificat="", public_key=""):
        message_structure = {
            "nom": self.nom,
            "id": self.client_id,
            "message": message,
            "type": type_message,
            "public_key": public_key,
            "certificat": certificat

        }
        rsa_encryptor.load_private_key(f"client/client_{self.client_id}_private_key.pem")
        encrypted_message = json.dumps(message_structure)
        # return encrypted_message
        return json.dumps(message_structure)
    
     # Fonction pour sauvegarder la clé privée
    def save_private_key(self):
        # Sauvegarder la clé privée dans un fichier PEM
        with open(f"client_{self.client_id}_private_key.pem", "wb") as key_file:
            key_file.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

    # Fonction pour sauvegarder la clé publique
    def save_public_key(self):
        # Sauvegarder la clé publique dans un fichier PEM
        with open(f"client_{self.client_id}_public_key.pem", "wb") as key_file:
            key_file.write(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

    # Fonction de rappel lors de la connexion au broker MQTT
    def on_connect(self, client, userdata, flags, rc):
        print("Connecté au broker MQTT avec le code de retour :", str(rc))
        client.subscribe(self.topic_client)

    # Fonction de rappel lors de la publication d'un message
    def on_publish(self, client, userdata, mid):
        print(f"[{self.nom}] : Message publié avec succès.")
        
    # Fonction de rappel lors de la réception d'un message
    def on_message(self, client, userdata, message):
        encrypted_message = message.payload
        # decrypted_message = rsa_encryptor.decrypt_message(encrypted_message)
        # payload = json.loads(decrypted_message)
        # print("Message reçu sur le topic", message.topic, ":", decrypted_message)

        payload = json.loads(message.payload.decode())
        nom = payload.get("nom", "")
        certificat = payload.get("certificat", "")
        received_message = payload.get("message", "")
        id = payload.get("id", "")
        print(f"[{nom}] : {received_message}")
        print(f"Certificat : {certificat}")
        if nom == "VENDEUR1":
            if received_message != "Transaction effectuée":
                # envoyer le certificat du vendeur à la pki pour vérification
                # with open("certs/vendeur1_cert.pem", "r") as cert_file:
                #     certificat = cert_file.read()
                # client.publish(TOPIC_PKI, self.create_message_structure("Verification Certificat", certificat))
                rsa_encryptor.load_public_key(f"pki/pki_public_key.pem")
                client.publish(TOPIC_PKI, self.create_message_structure("Verification Certificat", certificat=certificat))
        elif nom == "VENDEUR2":
            if received_message != "Transaction effectuée":
                # envoyer le certificat du vendeur à la pki pour vérification et vérif CRL
                # with open("certs/vendeur2_cert.pem", "r") as cert_file:
                #     certificat = cert_file.read()
                # client.publish(TOPIC_PKI, self.create_message_structure("Verification Certificat", certificat))
                rsa_encryptor.load_public_key(f"pki/pki_public_key.pem")
                client.publish(TOPIC_PKI, self.create_message_structure("Verification Certificat", certificat=certificat))
        elif nom == "PKI":
            topic_vendeur1 = f"{TOPIC_VENDEUR}/{1}"
            if received_message == "Certificat Vendeur Valide":
                # rsa_encryptor.load_public_key(f"vendeur/vendeur_{id}_public_key.pem")
                client.publish(topic_vendeur1, self.create_message_structure("Achat effectué"))

    # Fonction pour se connecter au broker et démarrer la boucle de gestion des messages
    def start(self):
        topic_vendeur1 = f"{TOPIC_VENDEUR}/{1}"
        topic_vendeur2 = f"{TOPIC_VENDEUR}/{2}"
        self.client.connect(self.broker_address, self.broker_port)
        print(f"--------------------- {self.nom} ---------------------")
        if self.nom == "CLIENT3":
            # rsa_encryptor.load_public_key(f"vendeur/vendeur_{id}_public_key.pem")
            self.client.publish(topic_vendeur2, self.create_message_structure("Demande de certificat"))
        else:
            # rsa_encryptor.load_public_key(f"vendeur/vendeur_{id}_public_key.pem")
            self.client.publish(topic_vendeur1, self.create_message_structure("Demande de certificat"))
        self.client.loop_start()

    def stop(self):
        self.client.loop_stop()
        self.client.disconnect()

# Création de plusieurs instances de clients
client1 = MQTTClient(1, "CLIENT1", TOPIC_CLIENT)
client2 = MQTTClient(2, "CLIENT2", TOPIC_CLIENT)
client3 = MQTTClient(3, "CLIENT3", TOPIC_CLIENT)

# Démarrage des clients (chaque client devra être démarré dans un thread séparé si vous voulez les exécuter simultanément)
client1_thread = Thread(target=client1.start)
client2_thread = Thread(target=client2.start)
client3_thread = Thread(target=client3.start)

client1_thread.start()
client2_thread.start()
client3_thread.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("Interruption reçue, arrêt des clients MQTT...")
    client1.stop()
    client2.stop()
    client3.stop()
    client1_thread.join()
    client2_thread.join()
    client3_thread.join()
    print("Arrêt complet.")
