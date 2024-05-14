import paho.mqtt.client as mqtt

# Informations de connexion au broker MQTT
BROKER_ADDRESS = "194.57.103.203"
BROKER_PORT = 1883
TOPIC_PKI = "vehicle/sami/pki"
TOPIC_VENDEUR = "vehicle/sami/vendeur"

NOM = "[PKI] : "
# Fonction de rappel lors de la connexion au broker MQTT
def on_connect(client, userdata, flags, rc):
    print("Connecté au broker MQTT avec le code de retour :", str(rc))
    # Souscrire au topic lors de la connexion
    client.subscribe(TOPIC_PKI)

# Fonction de rappel lors de la réception d'un message
def on_message(client, userdata, message):

    print(str(message.payload.decode()))

    client.publish(TOPIC_VENDEUR, NOM"Certificat signé")


# Création d'une instance du client MQTT
client = mqtt.Client(protocol=mqtt.MQTTv311)  # Spécifier la version de l'API de rappel

# Attribution des fonctions de rappel
client.on_connect = on_connect
client.on_message = on_message

# Connexion au broker MQTT
client.connect(BROKER_ADDRESS, BROKER_PORT)

# Boucle de gestion des messages
client.loop_forever()
