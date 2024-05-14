import paho.mqtt.client as mqtt
import json

# Informations de connexion au broker MQTT
BROKER_ADDRESS = "194.57.103.203"
BROKER_PORT = 1883
TOPIC_PKI = "vehicle/sami/pki"
TOPIC_VENDEUR = "vehicle/sami/vendeur"
TOPIC_CLIENT = "vehicle/sami/client"

NOM = "VENDEUR"
ID = 1


# Fonction pour créer une structure JSON contenant les informations
def create_message_structure(message):
    message_structure = {
        "nom": NOM,
        "id": ID,
        "message": message,
        "type": 0
    }
    return json.dumps(message_structure)


# Fonction de rappel lors de la connexion au broker MQTT
def on_connect(client, userdata, flags, rc):
    print("Connecté au broker MQTT avec le code de retour :", str(rc))

    client.subscribe(TOPIC_VENDEUR)


# Fonction de rappel lors de la publication d'un message
def on_publish(client, userdata, mid):
    print("["+NOM+"] : Message publié avec succès.")

# Fonction de rappel lors de la réception d'un message
def on_message(client, userdata, message):
    
    payload = json.loads(message.payload.decode())
    nom = payload.get("nom", "")
    message = payload.get("message", "")
    print("["+nom+"] : ", message)
    
    if nom == "PKI":
        client.publish(TOPIC_CLIENT, create_message_structure("Certificat reçu"))
    elif nom == "CLIENT":
        if message == "Achat effectué":
            client.publish(TOPIC_CLIENT, create_message_structure("Transaction effectuée"))
        else:
            # Message client
            client.publish(TOPIC_CLIENT, create_message_structure("Envoi Certificat"))


# Création d'une instance du client MQTT
client = mqtt.Client(protocol=mqtt.MQTTv311)  # Spécifier la version de l'API de rappel

# Attribution des fonctions de rappel
client.on_connect = on_connect
client.on_publish = on_publish

# Connexion au broker MQTT
client.connect(BROKER_ADDRESS, BROKER_PORT)

print("--------------------- VENDEUR ---------------------")

# Publication d'un message sur le topic spécifié
client.publish(TOPIC_PKI, create_message_structure("Demande de certificat"))


client.on_message = on_message

# Boucle de gestion des messages
client.loop_forever()
