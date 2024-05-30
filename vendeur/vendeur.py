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

class MQTTVendeur:
    def __init__(self, vendeur_id, nom, topic_vendeur):
        self.broker_address = BROKER_ADDRESS
        self.broker_port = BROKER_PORT
        self.vendeur_id = vendeur_id
        self.nom = nom
        self.topic_vendeur = f"{topic_vendeur}/{vendeur_id}"
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
        # Sauvegarder la clé privée dans un fichier PEM
        with open(f"vendeur_{self.vendeur_id}_private_key.pem", "wb") as key_file:
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
        with open(f"vendeur_{self.vendeur_id}_public_key.pem", "wb") as key_file:
            key_file.write(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
        rsa_encryptor.load_private_key(f"vendeur/vendeur_{self.vendeur_id}_private_key.pem")

    # Fonction pour créer une structure JSON contenant les informations
    def create_message_structure(self, message, type_message=0, certificat="", public_key=""):
        message_structure = {
            "nom": self.nom,
            "id": self.vendeur_id,
            "message": message,
            "type": type_message,
            "certificat": certificat,
            "public_key": public_key
        }
        rsa_encryptor.load_private_key(f"vendeur/vendeur_{self.vendeur_id}_private_key.pem")
        encrypted_message = rsa_encryptor.encrypt_message(json.dumps(message_structure))
        # return encrypted_message
        return json.dumps(message_structure)

    # Fonction de rappel lors de la connexion au broker MQTT
    def on_connect(self, client, userdata, flags, rc):
        print("Connecté au broker MQTT avec le code de retour :", str(rc))
        client.subscribe(self.topic_vendeur)

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
        print(f"The payload is: {payload}")
        nom = payload.get("nom", "")
        id = payload.get("id", "")
        received_message = payload.get("message", "")
        print(f"[{nom}] : {received_message}")

        if nom == "PKI":
            # Sauvegarder le certificat reçu
            cert_pem = payload.get("certificat", "")
            with open(f"vendeur_{self.vendeur_id}_certificate.pem", "wb") as cert_file:
                cert_file.write(cert_pem.encode())
            print("Certificat reçu et sauvegardé.", cert_pem)
            self.certificate = cert_pem
            self.client.publish(TOPIC_CLIENT, self.create_message_structure("Certificat reçu"))
        elif nom == "CLIENT1":
            topic_client1 = f"{TOPIC_CLIENT}/{1}"
            if received_message == "Achat effectué":
                rsa_encryptor.load_public_key(f"client/client_{id}_public_key.pem")
                self.client.publish(topic_client1, self.create_message_structure("Transaction effectuée"))
            else:
                # Message client
                rsa_encryptor.load_public_key(f"client/client_{id}_public_key.pem")
                self.client.publish(topic_client1, self.create_message_structure("Envoi Certificat", certificat=self.certificate))
        elif nom == "CLIENT2":
            topic_client2 = f"{TOPIC_CLIENT}/{2}"
            if received_message == "Achat effectué":
                rsa_encryptor.load_public_key(f"client/client_{id}_public_key.pem")
                self.client.publish(topic_client2, self.create_message_structure("Transaction effectuée"))
            else:
                # Message client
                # rsa_encryptor.load_public_key("public_key.pem")
                rsa_encryptor.load_public_key(f"client/client_{id}_public_key.pem")
                self.client.publish(topic_client2, self.create_message_structure("Envoi Certificat"))
        elif nom == "CLIENT3":
            topic_client3 = f"{TOPIC_CLIENT}/{3}"
            if received_message == "Achat effectué":
                self.client.publish(topic_client3, self.create_message_structure("Transaction effectuée"))
            else:
                # Message client
                # rsa_encryptor.load_public_key("public_key.pem")
                rsa_encryptor.load_public_key(f"client/client_{id}_public_key.pem")
                self.client.publish(topic_client3, self.create_message_structure("Envoi Certificat"))

    def request_certificate(self):
        # Envoyer une demande de certificat à la PKI
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        # message = self.create_message_structure("Demande de certificat", type_message=1)
        rsa_encryptor.load_public_key(f"pki/pki_public_key.pem")
        self.client.publish(TOPIC_PKI, self.create_message_structure("Demande de certificat", type_message=1, public_key=public_key_pem))

    # Fonction pour se connecter au broker et démarrer la boucle de gestion des messages
    def start(self):
        # Connexion au broker MQTT
        self.client.connect(self.broker_address, self.broker_port)
        print(f"--------------------- {self.nom} ---------------------")
       
        # Boucle de gestion des messages
        self.client.loop_start()
        self.request_certificate()

    def stop(self):
        self.client.loop_stop()
        self.client.disconnect()

# Création de plusieurs instances de vendeurs
vendeur1 = MQTTVendeur(1, "VENDEUR1", TOPIC_VENDEUR)
vendeur2 = MQTTVendeur(2, "VENDEUR2", TOPIC_VENDEUR)

# Démarrage des vendeurs
vendeur1_thread = Thread(target=vendeur1.start)
vendeur2_thread = Thread(target=vendeur2.start)

vendeur1_thread.start()
vendeur2_thread.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("Interruption reçue, arrêt des threads...")
    vendeur1.stop()
    vendeur2.stop()
    vendeur1_thread.join()
    vendeur2_thread.join()
    print("Arrêt complet.")
