import paho.mqtt.client as mqtt
import json
from threading import Thread
import time

# Informations de connexion au broker MQTT
BROKER_ADDRESS = "194.57.103.203"
BROKER_PORT = 1883
TOPIC_PKI = "vehicle/sami/pki"
TOPIC_VENDEUR = "vehicle/sami/vendeur"
TOPIC_CLIENT = "vehicle/sami/client"

class MQTTClient:
    def __init__(self, client_id, nom, topic_client):
        self.broker_address = BROKER_ADDRESS
        self.broker_port = BROKER_PORT
        self.client_id = client_id
        self.nom = nom
        self.topic_client = f"{topic_client}/{client_id}"

        # Création d'une instance du client MQTT
        self.client = mqtt.Client(protocol=mqtt.MQTTv311)

        # Attribution des fonctions de rappel
        self.client.on_connect = self.on_connect
        self.client.on_publish = self.on_publish
        self.client.on_message = self.on_message

    # Fonction pour créer une structure JSON contenant les informations
    def create_message_structure(self, message, type_message=0):
        message_structure = {
            "nom": self.nom,
            "id": self.client_id,
            "message": message,
            "type": type_message
        }
        return json.dumps(message_structure)

    # Fonction de rappel lors de la connexion au broker MQTT
    def on_connect(self, client, userdata, flags, rc):
        print("Connecté au broker MQTT avec le code de retour :", str(rc))
        client.subscribe(self.topic_client)

    # Fonction de rappel lors de la publication d'un message
    def on_publish(self, client, userdata, mid):
        print(f"[{self.nom}] : Message publié avec succès.")
        
    # Fonction de rappel lors de la réception d'un message
    def on_message(self, client, userdata, message):
        payload = json.loads(message.payload.decode())
        nom = payload.get("nom", "")
        received_message = payload.get("message", "")
        print(f"[{nom}] : {received_message}")

        if nom == "VENDEUR1":
            if received_message != "Transaction effectuée":
                client.publish(TOPIC_PKI, self.create_message_structure("Verification Certificat"))
        elif nom == "PKI":
            topic_vendeur1 = f"{TOPIC_VENDEUR}/{1}"
            if received_message == "Certificat Vendeur Valide":
                client.publish(topic_vendeur1, self.create_message_structure("Achat effectué"))

    # Fonction pour se connecter au broker et démarrer la boucle de gestion des messages
    def start(self):
        topic_vendeur1 = f"{TOPIC_VENDEUR}/{1}"
        topic_vendeur2 = f"{TOPIC_VENDEUR}/{2}"
        self.client.connect(self.broker_address, self.broker_port)
        print(f"--------------------- {self.nom} ---------------------")
        if self.nom == "CLIENT3" :
            self.client.publish(topic_vendeur2, self.create_message_structure("Demande de certificat"))
        else :
            self.client.publish(topic_vendeur1, self.create_message_structure("Demande de certificat"))
        self.client.loop_forever()


# Création de plusieurs instances de clients
client1 = MQTTClient( 1, "CLIENT1", TOPIC_CLIENT)
client2 = MQTTClient( 2, "CLIENT2", TOPIC_CLIENT)
client3 = MQTTClient( 3, "CLIENT3", TOPIC_CLIENT)

# Démarrage des clients (chaque client devra être démarré dans un thread séparé si vous voulez les exécuter simultanément)
client1_thread = Thread(target=client1.start)
client2_thread = Thread(target=client2.start)
client3_thread = Thread(target=client3.start)

client1_thread.start()
time.sleep(5)
client2_thread.start()
time.sleep(5)
client3_thread.start()
