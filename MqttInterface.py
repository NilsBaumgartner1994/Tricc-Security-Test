import time
import poisonMqtt.Mqtt as Mqtt
import protobuf.tricc_pb2 as tricc
import sys
import json
import os
import logging.config
import pyshark
import re
import argparse
import socket
import binascii
import poisonMqtt.gpsParser as gpsParser

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

############################################
#                                          #
#                  Constants               #
#                                          #
############################################

reload(sys)
sys.setdefaultencoding('utf8')

logger = None

INTERFACE = 'en0'
PATH_TO_LOGGING_CONFIG = "logs/loggingConfig.json"


###########################
#  Validation Constants   #
###########################
MINPORT_NUMBER = 0
MAXPORT_NUMBER = 65535

###########################
#  Arguments Commands     #
###########################

PARSER_SRCIP = "srcip"
PARSER_DSTIP = "dstip"
PARSER_SRCPORT = "srcport"
PARSER_DSTPORT = "dstport"
PARSER_SRCMAC = "srcmac"
PARSER_DSTMAC = "dstmac"
PARSER_INTERFACE = "interface"

############################################
#                                          #
#            Validading Methods            #
#                                          #
############################################

def check_all_param_requirements(parser,args):
    return
    #if args.prox and args.lport is None and args.rport is None:
    #    parser.error("--prox requires --lport and --rport.")


###########################
#      IP Addresses       #
###########################

# checking if address is a valid ipv4 or ipv6
def is_valid_ipv4_or_ipv6_address(parser,address):
    """Checks if a given Address is a IPv4 or IPv6.
    :param address: The Address which should be checked
    :param parser: The Parser which will raise an error
    """
    if is_valid_ipv4_address(address):
        return True
    if is_valid_ipv6_address(address):
        return True
        parser.error("The Address %s is neither a IPv4 nor a IPv6 Address!" % address)

# checking is addres is a valid ipv4
def is_valid_ipv4_address(address):
    """Checks if a given Address is a IPv4.
    :param address: The Address which should be checked
    """
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True

# checking is a address is a valid ipv6
def is_valid_ipv6_address(address):
    """Checks if a given Address is a IPv6.
    :param address: The Address which should be checked
    """
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True

###########################
#       IP Porsts         #
###########################

def is_valid_port(parser, port):
    """Checks if a given port is valid.
    :param port: The port which should be checked
    :param parser: The Parser which will raise an error
    """
    if port < MINPORT_NUMBER or port > MAXPORT_NUMBER:
        parser.error("The port %s is not valid! Choose port=[%s,%s]" % port, MINPORT_NUMBER, MAXPORT_NUMBER)

###########################
#       Mac Address       #
###########################


def is_valid_mac_address(parser, macaddress):
    """Checks if a given Address is a valid Mac Address.
    :param macaddress: The Address which should be checked
    :param parser: The Parser which will raise an error
    """
    if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", macaddress.lower()):
        return True
    parser.error("The MAC Address %s is not valid!" % macaddress)


############################################
#                                          #
#                  Parser                  #
#                                          #
############################################


# Instantiate the parser
parser = argparse.ArgumentParser(description='This application will either sniff in the network for packets and will '
                                             'try to decompile them, or it will decompile packets in a given pcapFile.')


###########################
#     IP Addresses        #
###########################

# Optional Argument for a filter IP Address for the Source
parser.add_argument('--'+PARSER_SRCIP, type=lambda x: is_valid_ipv4_or_ipv6_address(parser,x),
                    help='Filters all Packages for the Source IP Address.')

# Optional Argument for a filter IP Address for the Destination
parser.add_argument('--'+PARSER_DSTIP, type=lambda x: is_valid_ipv4_or_ipv6_address(parser,x),
                    help='Filters all Packages for the Destination IP Address.')

###########################
#        IP Ports         #
###########################

# Optional Argument for a filter Port for the Source
parser.add_argument('--'+PARSER_SRCPORT, type=lambda x: is_valid_port(parser,x),
                    help='Filters all Packages for the Source Port.')

# Optional Argument for a filter Port for the Destination
parser.add_argument('--'+PARSER_DSTPORT, type=lambda x: is_valid_port(parser,x),
                    help='Filters all Packages for the Destination Port.')

###########################
#     Mac Addresses       #
###########################

# Optional Argument for a filter Mac Address for the Source
parser.add_argument('--'+PARSER_SRCMAC, type=lambda x: is_valid_mac_address(parser,x),
                    help='Filters all Packages for the Source Mac Address.')

# Optional Argument for a filter Mac Address for the Source
parser.add_argument('--'+PARSER_DSTMAC, type=lambda x: is_valid_mac_address(parser,x),
                    help='Filters all Packages for the Destination Mac Address.')


###########################
#     Packet Sources      #
###########################

# Optional Argument for the Interface on which should be listened
parser.add_argument('--'+PARSER_INTERFACE, type=str,
                    help='The Interface on which should be listened')

###########################
#   Argument Logging      #
###########################

# Loggs all arguments to logfile
def logAllAgruments(args):
    global logger
    logger.info('Application started with Arguments: '+str(args))




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



############################################
#                                          #
#                Methods                   #
#                                          #
############################################



###########################
# Logger Setup and Config #
###########################

def load_logging_config(default_path=PATH_TO_LOGGING_CONFIG,default_level=logging.INFO,env_key='LOG_CFG'):
    path = default_path
    value = os.getenv(env_key, None)
    if value:
        path = value
    if os.path.exists(path):
        with open(path, 'rt') as f:
            config = json.load(f)
        logging.config.dictConfig(config)
    else:
        logging.basicConfig(level=default_level)

def setup_logger():
    load_logging_config()

    global logger
    logger = logging.getLogger(__name__)
    logger.info("Global Logger loaded")

    global loggerPackets
    loggerPackets = logging.getLogger("packet_file_handler")

###########################
#         Main            #
###########################

if __name__ == "__main__":
    setup_logger()
    global logger
    logger.propagate = False #Show logs on console

    nodetype = sys.argv[1]
    interface = MqttInterface(nodetype)




    """
    Just for testing
    """
    #interface = MqttInterface("relay")
    time.sleep(1)

    count = 0
    while True:
	interface.sendRelayData(False, count, False)
	time.sleep(10)
        count += 1
        pass

