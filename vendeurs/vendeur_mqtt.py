import paho.mqtt.client as mqtt
import json
from threading import Thread

# Informations de connexion au broker MQTT
BROKER_ADDRESS = "194.57.103.203"
BROKER_PORT = 1883
TOPIC_PKI = "vehicle/sami/pki"
TOPIC_VENDEUR = "vehicle/sami/vendeur"
TOPIC_CLIENT = "vehicle/sami/client"

class MQTTVendeur:
    def __init__(self, vendeur_id, nom , topic_vendeur ):
        self.broker_address = BROKER_ADDRESS
        self.broker_port = BROKER_PORT
        self.vendeur_id = vendeur_id
        self.nom = nom
        self.topic_vendeur = f"{topic_vendeur}/{vendeur_id}"

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
            "id": self.vendeur_id,
            "message": message,
            "type": type_message
        }
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
        
        payload = json.loads(message.payload.decode())
        nom = payload.get("nom", "")
        message = payload.get("message", "")
        print(f"[{nom}] : {message}")
        
        if nom == "PKI":
            self.client.publish(TOPIC_CLIENT, self.create_message_structure("Certificat reçu"))
        elif nom == "CLIENT1":
            topic_client1 = f"{TOPIC_CLIENT}/{1}"
            if message == "Achat effectué":
                self.client.publish(topic_client1, self.create_message_structure("Transaction effectuée"))
            else:
                # Message client
                self.client.publish(topic_client1, self.create_message_structure("Envoi Certificat"))
        elif nom == "CLIENT2":
            topic_client2 = f"{TOPIC_CLIENT}/{2}"
            if message == "Achat effectué":
                self.client.publish(topic_client2, self.create_message_structure("Transaction effectuée"))
            else:
                # Message client
                self.client.publish(topic_client2, self.create_message_structure("Envoi Certificat"))
        elif nom == "CLIENT3":
            topic_client3 = f"{TOPIC_CLIENT}/{3}"
            if message == "Achat effectué":
                self.client.publish(topic_client3, self.create_message_structure("Transaction effectuée"))
            else:
                # Message client
                self.client.publish(topic_client3, self.create_message_structure("Envoi Certificat"))

     # Fonction pour se connecter au broker et démarrer la boucle de gestion des messages
    def start(self):
        # Connexion au broker MQTT
        self.client.connect(self.broker_address, self.broker_port)
        print(f"--------------------- {self.nom} ---------------------")
        # Publication d'un message sur le topic spécifié
        self.client.publish(TOPIC_PKI, self.create_message_structure("Demande de certificat"))
        # self.client.on_message = on_message
        # Boucle de gestion des messages
        self.client.loop_forever()



# Création de plusieurs instances de vendeurs
vendeur1 = MQTTVendeur( 1, "VENDEUR1", TOPIC_VENDEUR)
vendeur2 = MQTTVendeur( 2, "VENDEUR2", TOPIC_VENDEUR)


# Démarrage des vendeurs 
vendeur1_thread = Thread(target=vendeur1.start)
vendeur2_thread = Thread(target=vendeur2.start)

vendeur1_thread.start()
vendeur2_thread.start()
