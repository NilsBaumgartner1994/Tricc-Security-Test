import json
import time
import paho.mqtt.client as mqtt
import MessageHandler
import logging
from threading import Thread
from uuid import getnode as get_mac
import protobuf.tricc_pb2 as tricc
import os
import sys
"""
Contains the logic for the MQTT-connection, publishers as well as subscribers. Users should use the class
MqttInterface

All Parameters for the MQTT connection are taken from mqttConfig.json
"""


#TODO Thread scheint nach Pycharm Beendung noch weiter zu laufen

### Functions need to be outside class, because else there's a mandatory "self" parameter enforced, which prevents
### them being used as callbacks

#hacky module wide dictionaries to track "mid" variables
midValues = {}
publishCounter = 0
numberReceivedMessages = 0

def onConnect(client, userdata, flags_dict, rc, ):
    """
    Callback for when the client has connected
    :param client: client that connected
    :param flags_dict: flags
    :param userdata: userdata passed to the client
    :param rc: connection result
    """

    logging.info("Connected to broker")
    for i in userdata.params["topics"]:
        result, mid = client.subscribe(i, qos= userdata.params["qos"])
        midValues[mid] = i
        logging.info("Started subscription attempt to %s", i)

    print "Connected"

def onDisconnect(client, userdata, rc):
    """
    Callback for when the client disconnects
    :param client: Client that disconnected
    :param userdata: userdata passed to the client
    :param rc: connection result
    """
    print "Disconnected"
    logging.warning("Disconnected from broker")

def onSubscribe(client, userdata, mid, granted_qos):
    """
    Callback when the client has subscribed to a topic
    :param client: Client that subscribed
    :param userdata:  Userdata passed to that client
    :param mid: Can be used to track subscribe requests
    :param granted_qos: Qos with which was subscribed (broker may not have granted the qos which was requested)
    """

    if mid in midValues:
        logging.info("Subscribed to topic. mid=%s", midValues[mid])
        print "Subscribed to topic ",
        print midValues[mid]

        #If not server and subscribed to serverInfoResponse, query server for information (registration with server)
        if(not userdata.mqttInterface.server):
                if(midValues[mid] == "serverInfoResponse"):
                    userdata.mqttInterface.sendQueryServerInfo(not userdata.registeredAtServer)
        midValues.pop(mid)
    else:
        print "Subscribed to topic with unknown mid. Likely unitId topic after getting a server info response"

def onMessage(client, userdata, msg):
    """
    Callback for when the client receives a message. Parses the topic and calls the corresponding message
    handler in MessageHandler.py
    :param client: Client that received the message
    :param userdata: Additional userdata of the client
    :param msg: The message received
    """
    global numberReceivedMessages
    numberReceivedMessages += 1
    print "Received",
    print numberReceivedMessages,
    print "total messages so far"

    logging.info("Received a message on topic %s", msg.topic)
    print "Received a message on topic "+ msg.topic
    if msg.topic == "PositionRelay":
        MessageHandler.handlePositionRelayMsg(msg.payload, userdata)
    elif msg.topic == "PositionZero":
        MessageHandler.handlePositionZeroMsg(msg.payload, userdata)
    elif msg.topic == "RelayData":
        MessageHandler.handleRelayMsg(msg.payload, userdata)
    elif msg.topic == "MiscData":
        MessageHandler.handleMiscMsg(msg.payload, userdata)
    elif msg.topic == "allUnits":
        MessageHandler.handleAllCommandMsg(msg.payload, userdata)
    elif msg.topic == "unit" + str(userdata.params["userId"]):
        MessageHandler.handleSpecificCommandMsg(msg.payload, userdata)
    elif msg.topic == "unit" + str(userdata.params["userId"]) + "_timeSynchro":
        MessageHandler.handleServerInfoResponse(msg.payload, userdata)
    elif msg.topic == "serverInfoResponse":
        MessageHandler.handleServerInfoResponse(msg.payload, userdata)
    elif msg.topic == "queryServerInfo":
        MessageHandler.handleQueryServerInfo(msg.payload, userdata)
    elif msg.topic == "ConnectionMessage":
        MessageHandler.handleConnectionMessage(msg.payload, userdata)
    elif msg.topic == "newIp":
        MessageHandler.handleNewIpMessage(msg.payload, userdata)
    else:
        print "Received message on unknown topic",
        print msg.topic


def onPublish(client, userdata, mid):
    """
    Callback called when the client successfully published data
    :param client:  The client that published the data
    :param userdata:  Addtional userdata
    :param mid: Can be used to track publish calls
    """
    print "Published a message: ",
    if mid in midValues:
        print midValues[mid]
        logging.info("Published message successfully. Publish Counter: %d", midValues[mid])
        midValues.pop(mid)
    else:
        print "But mid",
        print mid
        print "was not known"

def onUnsubscribe(client, userdata, mid):
    print "Unsubscribed from a topic. Currently this can only be serverInfoResponse"
    logging.info("Unsubscribed from a topic (currently this can only be serverInfoResponse")



class Mqtt:
    """
    Wrapper class for the paho mqtt client with the desired interface
    """
    def __init__(self, mqttInterface, type, serverInterface = None, threaded = False):
        """
        Creates the wrapper, the paho mqtt client and connects to the broker
        :param mqttInterface: MqttInterface object that called this class
        :param type: String with either "kit", "relay" or "server"
        :param serverInterface: Arbitrary object that is passed through to the server upon receiving a message
            (see MessageHandler.serverInterfaceMethod)
        :param threaded: Boolean whether the connection attempt should be done via a thread or not
        """
        logging.basicConfig(filename='mqtt.log',level=logging.INFO, format='%(asctime)s %(message)s')
        logging.info("Model class created")
        self.type = type
        self.mqttInterface = mqttInterface
        self.params = self.loadParametersFromJson()
        self.registeredAtServer = self.params["gotIpFromServer"]
        self.serverInterface = serverInterface
        self.client = self.setup()
        self.uuid = str(get_mac())
        if(threaded):
            logging.info("Started in thread mode")
            print "Starting in Thread Mode"
            connectThread = Thread(target= self.connect)
            connectThread.start()
        else:
            logging.info("Started in non thread mode")
            print "Starting in non Thread mode"
            self.connect()

    def addConMesHandler(self, handler):
        """Adds conection message handler to MessageHandler script
        Args:
            handler (Callable): Handler function, must handle the following Args: (Relay node OLSR IP, Connected TriccKit IP)"""
        MessageHandler.addConMesHandler(handler)


    def loadParametersFromJson(self):
        """
        Loads the mqtt parameters from json file mqttConfig.json
        """
        file_path = os.path.abspath(sys.argv[0])
        dir_path = os.path.dirname(file_path)
        filename = "mqttConfig.json"
        if self.type == "server":
            filename = "mqttConfig_Server.json"
        elif self.type == "relay":
            filename = "mqttConfig_RelayNode.json"
        elif self.type == "kit":
            filename = "mqttConfig_TriccKit.json"
        else:
            print "Unknown type for MQTT while loading json file"
            logging.info("Unknown type for MQTT while loading json file")
        print filename
        json_path = os.path.join(dir_path, filename)
        print "Loaded json config from " + json_path
        with open(json_path) as configFile:
            return json.load(configFile)

    def setJsonParameters(self):
        """
        Saves the values from the parameters of this mqtt client to mqttConfig.json
        """
        logging.info("Wrote json parameters")
        file_path = os.path.abspath(sys.argv[0])
        dir_path = os.path.dirname(file_path)
        filename = "mqttConfig.json"
        if self.type == "server":
            filename = "mqttConfig_Server.json"
        elif self.type == "relay":
            filename = "mqttConfig_RelayNode.json"
        elif self.type == "kit":
            filename = "mqttConfig_TriccKit.json"
        else:
            print "Unknown type for MQTT while loading json file"
            logging.info("Unknown type for MQTT while loading json file")
        json_path = os.path.join(dir_path, filename)
        with open(json_path, "w") as configFile:
            json.dump(self.params, configFile, sort_keys=True, indent=4, separators=(',', ': ') )


    def setup(self):
        """
        Creates the paho mqtt client and sets all options according to mqttConfig.json
        """
        client = mqtt.Client(userdata= self)
        client.on_connect = onConnect
        client.on_disconnect = onDisconnect
        client.on_message = onMessage
        client.on_subscribe = onSubscribe
        client.on_unsubscribe = onUnsubscribe
        client.on_publish = onPublish
        client.max_inflight_messages_set(self.params["maxNumberInflightMessages"])
        client.max_queued_messages_set(self.params["maxNumberQueuedMessages"])
        client.message_retry_set(self.params["timeToWaitBeforeRetrySendingFailure"])
        client.will_set(self.params["lastWillTopic"], bytes(self.params["lastWillMessage"]), self.params["lastWillQos"], self.params["lastWillRetain"] )
        client.username_pw_set(self.params["username"], self.params["password"])
        return client

    def connect(self):
        """
        Connects to the broker. If no connection is possible, new attempts are undertaken with a frequency
        according to mqttConfig.json
        """
        connected = False
        while not connected:
            try:
                self.client.connect(self.params["brokerAddress"], self.params["brokerPort"], self.params["keepAlive"])
                connected = True
            except:
                print "Failed to connect. Will retry in ",
                print self.params["connectRetryInterval"],
                print " seconds"
                time.sleep(self.params["connectRetryInterval"])
        #starts a background thread that listens on the network interface. Returns immediately. can be stopped
        # with client.loop_stop().
        #Also handles reconnecting TODO at what frequency? after timeout?
        self.client.loop_start()


    def publish(self, topic, payload):
        """
        Publishes a message, direct interface to paho mqtt client
        :param topic: The topic on which the message should be published
        :param payload: The message that should be published
        """

        global publishCounter
        logging.info("Tried to publish message with counter %d", publishCounter)
        result, mid = self.client.publish(topic, payload, qos=self.params["qos"], retain=self.params["useRetainedMessages"])

        midValues[mid] =publishCounter
        print "Tried to publish message with counter ",
        print publishCounter
        publishCounter += 1
        if(publishCounter > 1000000):
            publishCounter = 0






if __name__ == "__main__":
    """
    Just some testing
    """
    print "hello"
    a = Mqtt()
    a.publish("all", "hello")
    while True:
        pass
