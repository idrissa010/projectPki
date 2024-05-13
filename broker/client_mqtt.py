import paho.mqtt.client as mqtt


# Informations de connexion au broker MQTT
BROKER_ADDRESS = "194.57.103.203"
BROKER_PORT = 1883
TOPIC_PKI = "vehicle/sami/pki"
TOPIC_VENDEUR = "vehicle/sami/vendeur"
TOPIC_CLIENT = "vehicle/sami/client"

NOM = "[CLIENT] : "
# Fonction de rappel lors de la connexion au broker MQTT
def on_connect(client, userdata, flags, rc):
    print("Connecté au broker MQTT avec le code de retour :", str(rc))

    print("--------------------- CLIENT ---------------------")

# Fonction de rappel lors de la publication d'un message
def on_publish(client, userdata, mid):
    print("Message publié avec succès.")

# Fonction de rappel lors de la réception d'un message
def on_message(client, userdata, message):
    print(str(message.payload.decode()))

    

# Création d'une instance du client MQTT
client = mqtt.Client(protocol=mqtt.MQTTv311)  # Spécifier la version de l'API de rappel

# Attribution des fonctions de rappel
client.on_connect = on_connect
client.on_publish = on_publish

# Connexion au broker MQTT
client.connect(BROKER_ADDRESS, BROKER_PORT)

# Publication d'un message sur le topic spécifié
message = NOM + "Demande de certificat"  # Message à publier
client.publish(TOPIC_PKI, message)

client.subscribe(TOPIC_VENDEUR)
client.on_message = on_message
# Boucle de gestion des messages
client.loop_forever()
