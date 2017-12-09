import json
import os
import logging.config
import pyshark
import sys
import re
import argparse
import socket
import time
import binascii
import tricc_pb2 as tricc
import poisonMqtt.MqttInterface as MqttInterface


############################################
#                                          #
#                  Constants               #
#                                          #
############################################

reload(sys)
sys.setdefaultencoding('utf8')

logger = None
loggerPackets = None

INTERFACE = 'en0'
PCAPFILE = 'pcapFiles/loggedPcap.pcap'
NPCAPFILE = 'pcapFiles/loggedNCap.pcapng'
PATH_TO_LOGGING_CONFIG = "logs/loggingConfig.json"


###########################
#  Validation Constants   #
###########################
MINPORT_NUMBER = 0
MAXPORT_NUMBER = 65535

###########################
#  Arguments Commands     #
###########################

PARSER_PACKETS = "packets"
PARSER_SRCIP = "srcip"
PARSER_DSTIP = "dstip"
PARSER_SRCPORT = "srcport"
PARSER_DSTPORT = "dstport"
PARSER_SRCMAC = "srcmac"
PARSER_DSTMAC = "dstmac"
PARSER_INTERFACE = "interface"
PARSER_PCAPFILE = "pcapfile"
PARSER_PROTOCOL = "protocol"

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
#     File Validation     #
###########################

# checking if a file is valid
def is_valid_file(parser, arg):
    """Checks if a given file exists.
    :param parser: The parser which will should raise an error
    :param arg: The file that should be checked.
    """
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        #return open(arg, 'r')  # return an open file handle
        return arg


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



# Optional Argument for the amount of packets which will be caught during live sniffing
parser.add_argument('--'+PARSER_PACKETS, type=int,
                    help='Amount packets caught during live sniffing after sniffing will be terminated.')

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

# Optional PcapFile which should be decompiled
parser.add_argument("--"+PARSER_PCAPFILE, dest=PARSER_PCAPFILE, required=False,
                    help="Input pcapfile which should be decompiled.", metavar="FILE",
                    type=lambda x: is_valid_file(parser, x))

# Optional Argument for the Interface on which should be listened
parser.add_argument('--'+PARSER_PROTOCOL, type=str,
                    help='Filters all packages for the given protocols [udp]. Connect multiple with a ","')

###########################
#   Argument Logging      #
###########################

# Loggs all arguments to logfile
def logAllAgruments(args):
    global logger
    logger.info('Application started with Arguments: '+str(args))

############################################
#                                          #
#                Methods                   #
#                                          #
############################################

###########################
#   Package decoding    #
###########################

def startDecoding(args):
    """Decodes packets depending on the arguments given by the parser.
    :param args: the arguments parsed
    """
    global logger
    logger.info('Start Decoding')
    if(args.pcapfile!=None):
        logger.info('Starting decoding from PcapFile')
        decodeFromPcapFile(args)
    if(args.interface!=None):
        logger.info('Starting decoding from Interface')
        decodeFromInterface(args)

# Decode all incomming packets on an interface
def decodeFromInterface(args):
    """Decodes all incomming packets, with given filter, on an interface forever or packet count amount.
    :param interface: the interface on which should be listened
    :param packet_count: the amount of packet should be listened for.
    """
    global logger
    logger.info('Starting Listening to: '+args.interface)

    packet_nr = 0

    capture = pyshark.LiveCapture(interface='en0')
    logger.info('Setup Capture')
    for packet in capture.sniff_continuously(args.packets):
        packet_nr+=1
        #logger.info("Packet Nr. "+str(packet_nr))
        decodePacket(packet,args)


# Decode all packets in a pcap file
def decodeFromPcapFile(args):
    """Decodes all packets in a pcap file with given filters.
    :param macaddress: The Address which should be checked
    :param parser: The Parser which will raise an error
    """

    filepath = args.pcapfile

    cap = getPacketsInPcapFile(filepath)
    for packet in cap:
        decodePacket(packet,args)

# retreiving all packages in a pcapfile
def getPacketsInPcapFile(filepath):
    global logger
    if os.path.exists(filepath):
        cap = pyshark.FileCapture(filepath)
        return cap
    logger.info('File %s does not exsist!' % filepath)
    return None


###########################
#   Package Decompiling   #
###########################

def decodePacket(packet,args):
    # my_layer = packet.layer_name  # or packet['layer name'] or packet[layer_index]
    #logger.info(str(packet))

    protocol = args.protocol
    if protocol == None:
        decodePacketAddresses(packet)
    if protocol != None:
        protocol = protocol.lower()
        if('udp' in protocol):
            decodePacketIfUDP(packet)

def decodePacketAddresses(packet):
    global loggerPackets

    mac_address_src = packet.eth.src
    mac_address_dst = packet.eth.dst
    logMacAddress = "Mac: " + str(mac_address_src) + " ==> " + str(mac_address_dst)

    protocol = packet.transport_layer
    src_addrIP = "Unkown"
    dst_addrIP = "Unkown"
    if hasattr(packet, "ip"):
        src_addrIP = packet.ip.src
        dst_addrIP = packet.ip.dst
    src_addrIPv6 = "Unkown"
    dst_addrIPv6 = "Unkown"
    if hasattr(packet, "ipv6"):
        src_addrIPv6 = packet.ipv6.src
        dst_addrIPv6 = packet.ipv6.dst

    src_port = "Unkown"
    dst_port = "Unkown"
    #if hasattr(packet, "transport_layer"):
        #dst_port = packet[packet.transport_layer].dstport
        #src_port = packet[packet.transport_layer].srcport

    logIPAddress = "IP: " + str(src_addrIP) + ":" + str(src_port) + " ==> " + str(dst_addrIP) + ":" + str(dst_port)
    logIPv6Address = "IPv6: " + str(src_addrIPv6) + " ==> " + str(dst_addrIPv6)

    if 'DATA' in packet:
        data_layer = packet.data
        hexString = data_layer.data
        decoded = decodeDataToHexArray(hexString)
        logData = "Data: " + decoded
        tricc = decodeAsTriccProto(hexString)
        logProto = "Proto: " + str(tricc)
        print "Jaaaa"

    loggerPackets.info(logMacAddress + "\n" + logIPv6Address + "\n" + logIPAddress + "\n")

def decodePacketIfUDP(packet):
    global loggerPackets
    global logger

    if 'UDP' in packet:
        mac_address_src = packet.eth.src
        mac_address_dst = packet.eth.dst
        logMacAddress = "Mac: "+str(mac_address_src)+" ==> "+str(mac_address_dst)

        protocol = packet.transport_layer
        src_addrIP = "Unkown"
        dst_addrIP = "Unkown"
        if hasattr(packet, "ip"):
            src_addrIP = packet.ip.src
            dst_addrIP = packet.ip.dst
        src_addrIPv6 = "Unkown"
        dst_addrIPv6 = "Unkown"
        if hasattr(packet, "ipv6"):
            src_addrIPv6 = packet.ipv6.src
            dst_addrIPv6 = packet.ipv6.dst
        dst_port = packet[packet.transport_layer].dstport
        src_port = packet[packet.transport_layer].srcport

        logIPAddress = "IP: "+str(src_addrIP)+":"+str(src_port)+" ==> "+str(dst_addrIP)+":"+str(dst_port)
        logIPv6Address = "IPv6: " + str(src_addrIPv6) + " ==> " + str(dst_addrIPv6)
        logger.info(logMacAddress + "\n" + logIPv6Address + "\n" + logIPAddress + "\n")
        if 'DATA' in packet:
            data_layer = packet.data
            hexString = data_layer.data
            decoded = decodeDataToHexArray(hexString)
            logData = "Data: " + decoded
            tricc = decodeAsTriccProto(hexString)
            logProto = "Proto: "+str(tricc)

            loggerPackets("Hallo")
            loggerPackets.info(logMacAddress+"\n"+logIPv6Address+"\n"+logIPAddress+"\n"+logData+"\n"+logProto+"\n")


###########################
#     Hex Decompiling     #
###########################

def decodeDataToHexArray(hexString):
    splits = splithexStringToBytes(hexString)
    decoded = ""
    for split in splits:
        decoded += decodeHexToChar(split)
    return decoded

def splithexStringToBytes(hexString):
    splits = re.findall('..', hexString)
    return splits

def decodeHexToChar(hex):
    dezimal = int(hex, 16)
    character = chr(dezimal)
    return character


###########################
#   Proto Decompiling     #
###########################

def decodeAsTriccProto(hexString):
    #global logger
    #logger.info('Decode HexString to ProtoObject: '+str(hexString))
    #logger.info('HexString parsed to String: ' + hexString)

    protoAsBytearray = binascii.unhexlify(hexString)
    protoAsString = str(protoAsBytearray)

    protoBytearray = protoAsString


    if(decodeAsNode(protoBytearray)!=None):
        return decodeAsNode(protoBytearray)
    if(decodeAsPositionData(protoBytearray)!=None):
        return decodeAsPositionData(protoBytearray)
    if(decodeAsRelayData(protoBytearray)!=None):
        return decodeAsRelayData(protoBytearray)
    if(decodeAsCommand(protoBytearray)!=None):
        return decodeAsCommand(protoBytearray)
    if(decodeAsMiscData(protoBytearray)!=None):
        return decodeAsMiscData(protoBytearray)
    if(decodeAsKitData(protoBytearray)!=None):
        return decodeAsKitData(protoBytearray)

    return None

def decodeAsNode(hexString):
    try:
        tricc = tricc.Node()
        tricc.ParseFromString(hexString)
        return tricc
    except:
        return None

def decodeAsPositionData(hexString):
    try:
        tricc = tricc.PositionData()
        tricc.ParseFromString(hexString)
        return tricc
    except:
        return None

def decodeAsRelayData(hexString):
    try:
        tricc = tricc.RelayData()
        tricc.ParseFromString(hexString)
        return tricc
    except:
        return None

def decodeAsCommand(hexString):
    try:
        tricc = tricc.Command()
        tricc.ParseFromString(hexString)
        return tricc
    except:
        return None

def decodeAsMiscData(hexString):
    try:
        tricc = tricc.MiscData()
        tricc.ParseFromString(hexString)
        return tricc
    except:
        return None

def decodeAsKitData(hexString):
    try:
        tricc = tricc.KitData()
        tricc.ParseFromString(hexString)
        return tricc
    except:
        return None




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
    #loggerPackets.propagate = False

###########################
#         Main            #
###########################


def decodeExampleProtobufObject():
    global logger

    timestamp = tricc.Time()
    currentTime = time.time()
    seconds, nanoseconds = long(currentTime), currentTime - long(currentTime)
    timestamp.sec = seconds
    timestamp.nano = long(nanoseconds * pow(10, 9))

    header = tricc.Header()
    header.origin = 4
    header.topic = "FakeTopic"
    header.time.CopyFrom(timestamp)

    positionData = tricc.PositionData()
    positionData.header.CopyFrom(header)
    positionData.longitude = 52.2
    positionData.latitude = 21.1

    protoAsString = positionData.SerializeToString()
    protoAsBytearray = bytearray(protoAsString)
    protoAsHexarray = binascii.hexlify(protoAsBytearray)
    logger.info("" + str(protoAsHexarray))
    protoAsBytearray = binascii.unhexlify(protoAsHexarray)
    protoAsString = str(protoAsBytearray)
    positionData.ParseFromString(protoAsString)

    logger.info(positionData)

def setup_parser_and_get_args(parser):
    global logger
    logger.info('Parsing Arguments')
    args = parser.parse_args()
    logAllAgruments(args)
    logger.info('Check all Requirements')
    check_all_param_requirements(parser,args)
    return args

def main():
    setup_logger()
    global logger
    args = setup_parser_and_get_args(parser)
    #decodeExampleProtobufObject()
    logger.info("Start Loggin")
    startDecoding(args)
    #server #kit #relay
    # interface = MqttInterface("relay")
    #nodetype = "server"
    #interface = MqttInterface.MqttInterface(nodetype)

if __name__ == '__main__':main()