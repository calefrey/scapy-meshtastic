# %%
import time

import paho.mqtt.client as mqtt

from scapy_meshtastic import (
    DecodeError,
    MeshApp,
    MeshText,
    MQTTPacket,
)

# %%
# setup the mqtt connection parameters and establish a connection
mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
mqttc.username = "meshdev"
mqttc.password = "large4cats"
mqttc.connect("mqtt.meshtastic.org")

# %%
# Setup a callback for making the connection, so it resubscribes after a connection loss


def on_connect(client, userdata, flags, reason_code, properties):
    print(f"Connected with result code {reason_code}")
    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe([("msh/US/2/e/LongFast/#", 0)])


mqttc.on_connect = on_connect

# %%
# Setup a callback to handle the received messages


def on_message(client, userdata, msg):
    try:
        # decode with our scapy MQTTPacket class
        pkt = MQTTPacket(msg.payload)
        # Let's only print text messages or known-decodable apps
        if pkt.haslayer(MeshText) or pkt.haslayer(MeshApp):
            print(msg.topic)
            print(pkt.show())
            # client.disconnect() # disconnect after the first valid packet
    except DecodeError as e:
        # Take a look at the error log
        print(f"Error from {msg.topic}:")
        print(e)


mqttc.on_message = on_message

# %%
# This is a very busy channel, so we'll only subscribe for half a second and then disconnect
mqttc.loop_start()
time.sleep(0.5)
mqttc.loop_stop()
mqttc.disconnect()


