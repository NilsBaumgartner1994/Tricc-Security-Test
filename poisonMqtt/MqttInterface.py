import time
import Mqtt
import protobuf.tricc_pb2 as tricc
import gpsParser
import sys

"""
Poison Interface to send/receive data via python, which will make trouble. Create an instance of MqttInterface and send data via the
right send... function.
If you just want to subscribe to topics, simply create an instance of MqttInterface. The topics subscribed to
are defined in mqttConfig.json and will vary on whether this program is executed by a tricc-kitt, by a relay node
or by the backend server

Necessary modules that need to be installed:
pip install protobuf
pip install paho-mqtt

If you want to start your own broker you also need:
apt-get install mosquitto

If you use Ubuntu 14.04 the mosquitto version in the repositories is outdated. Add private repository before
install (source:https://mosquitto.org/download/) :

    sudo apt-add-repository ppa:mosquitto-dev/mosquitto-ppa
    sudo apt-get update
    sudo apt-get install mosquitto

"""

class MqttInterface:
    """
    Interface class to be used by others. Provides the interface to Mqtt.py
    """

    def __init__(self, type, serverInterface=None, connectionMessageHandler = None):
        """
        Just creates a Mqtt object, which contains the actual mqtt logic
        :param type: Type of the caller. String with either "kit", "relay" or "server"
        :param serverInterface: Arbitrary object that is passed to the server upon received message
        """
        self.type = type
        self.server = False
        threaded = False
        if type == "server":
            threaded = True
            self.server = True
        self.mqtt = Mqtt.Mqtt(self, type, serverInterface, threaded)

        if connectionMessageHandler != None:
            self.mqtt.addConMesHandler(connectionMessageHandler)

    def __createTime(self):
        """
        Creates a protobuf time message with the current system time
        """
        timestamp = tricc.Time()
        currentTime = time.time()
        seconds, nanoseconds = long(currentTime), currentTime - long(currentTime)
        timestamp.sec = seconds
        timestamp.nano = long(nanoseconds * pow(10,9))
        return timestamp

    def __createHeader(self, topic):
        """
        Creates a protobuf header with the given topic. Origin is "userId" taken from mqttConfig.json
        :param topic: The topic for which this message is destinated
        """
        header = tricc.Header()
        header.origin = self.mqtt.params["userId"]
        header.topic = topic
        header.time.CopyFrom(self.__createTime())
        return header

    def __createAcceleration(self, accX, accY, accZ):
        """
        Creates an acceleration message
        :param accX: X component of the acceleration (float)
        :param accY: Y component of the acceleration (float)
        :param accZ: Z component of the acceleration (float)
        :return: The acceleration message
        """
        acceleration = tricc.Acceleration()
        acceleration.x = accX
        acceleration.y = accY
        acceleration.z = accZ
        return acceleration

    def __createGyro(self, gyroX, gyroY, gyroZ):
        """
        Creates a gyro message
        :param gyroX: X Component of the gyroscope (float)
        :param gyroY: Y Component of the gyroscope (float)
        :param gyroZ: Z Component of the gyroscope (float)
        :return: The gyro message
        """
        gyro = tricc.Gyro()
        gyro.x = gyroX
        gyro.y = gyroY
        gyro.z = gyroZ
        return gyro

    def __createNode(self, id, name, nodetype, identifier, ip):
        """

        :param id: (int) Id of the node
        :param name:  (String) Name of the node
        :param nodetype: String with nodetype (kit, server, relay)
        :return: The Node message
        """
        node = tricc.Node()
        node.id = id
        node.name = name
        nodetypeInt = 0
        if nodetype == "relay":
            nodetypeInt = 2
        if nodetype == "kit":
            nodetypeInt = 3
        if nodetype == "server":
            nodetypeInt = 4
        node.nodetype = nodetypeInt

        node.identifier = identifier
        node.ipAddress = ip
        return node

    def addConMesHandler(self, handler):
        """Adds a conection handler function to the MessageHandler script
        Args:
            handler (Callable): Function to handle the connection message. Must handle the following args: (Relay Node OLSR IP, Connected tricc kit ip)
        """
        self.mqtt.addConMesHandler(handler)

    def sendConnectionMessage(self, triccKitIp, relayOlsrIp, topic="ConnectionMessage"):
        """Sends a connection message
        args:
            triccKitIp: Connected TriccKit's IP (str)
            relayOlsrIp: Access point's OLSR IP (str)
        """
        conMes = tricc.ConnectionMessage()
        conMes.header.CopyFrom(self.__createHeader(topic))
        conMes.triccKitIp = triccKitIp
        conMes.relayOlsrIp = relayOlsrIp
        self.mqtt.publish(conMes.header.topic, bytearray(conMes.SerializeToString()))



    def sendPositionDataZero(self, longitude, latitude, altitude, heading, accX, accY, accZ, gyroX, gyroY, gyroZ):
        """
        Send gps data for the tricc-kit pi zero
        :param longitude: Longitude of gps stamp (float)
        :param latitude:  Latitude of gps stamp (float)
        :param altitude:  Altitude of gps stamp (float)
        :param heading:  Heading of the gps stamp (float)
        :param accX: X component of the acceleration (float)
        :param accY: Y component of the acceleration (float)
        :param accZ: Z component of the acceleration (float)
        :param gyroX: X Component of the gyroscope (float)
        :param gyroY: Y Component of the gyroscope (float)
        :param gyroZ: Z Component of the gyroscope (float)
        """
        positionData = tricc.PositionData()
        positionData.header.CopyFrom(self.__createHeader("PositionZero"))
        positionData.longitude = longitude
        positionData.latitude = latitude
        positionData.altitude = altitude
        positionData.heading = heading
        positionData.acceleration.CopyFrom(self.__createAcceleration(accX, accY, accZ))
        positionData.gyro.CopyFrom(self.__createGyro(gyroX, gyroY, gyroZ))
        self.mqtt.publish(positionData.header.topic, bytearray(positionData.SerializeToString()))

    def sendPositionDataRelay(self, longitude, latitude):
        """
        Send gps data for a relay node
        :param longitude: Longitude of gps stamp (float)
        :param latitude:  Latitude of gps stamp (float)
        """
        positionData = tricc.PositionData()
        positionData.header.CopyFrom(self.__createHeader("PositionRelay"))
        positionData.longitude = longitude
        positionData.latitude = latitude
        self.mqtt.publish(positionData.header.topic, bytearray(positionData.SerializeToString()))

    def sendRelayData(self, flame, temp, gas):
        """
        Send data of a relay node
        :param flame: Boolean whether a flame has been detected
        :param temp: The temperature measured
        :param gas: Boolean whether gas has been detected
        """
        relayData = tricc.RelayData()
        relayData.header.CopyFrom(self.__createHeader("RelayData"))
        relayData.flame = flame
        relayData.temp = temp
        relayData.gas = gas
        self.mqtt.publish(relayData.header.topic, bytearray(relayData.SerializeToString()))

    def sendCommand(self, command, parameter, targetId):
        """
        Sends a command. If targetId == 0, then the command will be set to all units. For every other value,
        the command will be sent only to the specific unit
        :param command:  The command to be sent
        :param parameter:  The parameters of the command
        :param targetId:  The id of the target of the command
        """
        commandData = tricc.Command()
        topic = "allUnits"
        if(targetId != 0):
            topic ="unit" + str(targetId)
        commandData.header.CopyFrom(self.__createHeader(topic))
        commandData.command = command
        commandData.parameter = parameter
        self.mqtt.publish(commandData.header.topic, bytearray(commandData.SerializeToString()))


    def sendMiscData(self, datastr, databool, dataint, datalong, dataflt, datadbl, topic):
        """
        Sends misc data
        :param datastr: list with strings
        :param databool:  list with bools
        :param dataint: list with ints
        :param datalong: list with longs
        :param dataflt: list with floats
        :param datadbl: list with doubles
        :param topic: The topic the data should be sent on
        """
        miscData = tricc.MiscData()
        miscData.header.CopyFrom(self.__createHeader(topic))
        for i in datastr:
            miscData.datastr.append(i)
        for i in databool:
            miscData.databool.append(i)
        for i in dataint:
            miscData.dataint.append(i)
        for i in datalong:
            miscData.datalong.append(i)
        for i in dataflt:
            miscData.dataflt.append(i)
        for i in datadbl:
            miscData.datadbl.append(i)
        self.mqtt.publish(miscData.header.topic, bytearray(miscData.SerializeToString()))

    def sendQueryServerInfo(self, firstRegistration):
        """
        Emulates request/response mechanism via MQTT
        :param firstRegistration: Boolean whether this is the initial registration
        """
        queryServerInfo = tricc.QueryServerInfo()
        nodeId = 0
        if not firstRegistration:
            nodeId = self.mqtt.params["userId"]

        if firstRegistration:
            identifier = self.mqtt.uuid#self.mqtt.params["uniqueIdentifier"]
        else:
            identifier = str(self.mqtt.params["userId"])

        queryServerInfo.nodeInfo.CopyFrom(self.__createNode(nodeId, self.mqtt.params["nodeName"], self.type, identifier, " " ))

        queryServerInfo.initialRegistration = firstRegistration


        self.mqtt.publish("queryServerInfo", bytearray(queryServerInfo.SerializeToString()))

    def sendServerInfo(self, identifier, responseId, initialRegistration):
        """
        Response part of the emulated request/response with sendRegisterAtServer()
        :param identifier: (string) Identifier that was used in the registration request
        :param responseId: (int) The Id the node should assume from now on
        :param initialRegistration: boolean whether this was the initial registration
        """
        serverInfoResponse = tricc.ServerInfoResponse()
        serverInfoResponse.identifier = identifier
        serverInfoResponse.responseId = responseId
        serverInfoResponse.serverTime.CopyFrom(self.__createTime())
        topic = "serverInfoResponse"
        if(not initialRegistration):
            topic = "unit"+str(responseId) + "_timeSynchro"
        print "Topic " + topic
        self.mqtt.publish(topic, bytearray(serverInfoResponse.SerializeToString()))


if __name__ == "__main__":
    nodetype = sys.argv[1]
    interface = MqttInterface(nodetype)




    """
    Just for testing
    """
    #interface = MqttInterface("relay")
    time.sleep(1)

#    interface.sendPositionDataRelay(1,2)
#    interface.sendPositionDataZero(1,2,3,4,5,6,7,8,9,10)
#    interface.sendRelayData(1,2,3)
 #   interface.sendCommand("camera_on", "for 5 seconds",0)
 #   interface.sendCommand("camera_off", "for 5 seconds",5)
#    interface.sendMiscData(["hallo"], [0], [3] ,[4] ,[5],[6],"MiscData")

#    interface.sendQueryServerInfo(False)
  #  interface.sendServerInfo(interface.mqtt.uuid, 5, False)
#    interface.sendConnectionMessage("1.1.1.1", "2.2.2.2")
    #send entire burger king route
    """
    route = gpsParser.readRoute("gps_burger_king_route.txt")
    for i in route:
        interface.sendPositionDataRelay(i[0], i[1])
        time.sleep(1)
    """

    count = 0
    while True:
	interface.sendRelayData(False, count, False)
	time.sleep(10)
        count += 1
        pass

