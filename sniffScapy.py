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
import scapy as scapy #on OS X sudo pip install pypcap
from scapy.all import *

'''
Needed to to work
- pip install scapy
- sudo pip install pypcap

'''

############################################
#                                          #
#                  Constants               #
#                                          #
############################################

reload(sys)
sys.setdefaultencoding('utf8')

logger = None
loggerPackets = None
loggerError = None

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
PARSER_CUSTOMFILTER = "customfilter"

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

parser.add_argument('--'+PARSER_CUSTOMFILTER, type=str,
                    help='Custom filter for packets. filter uses Berkeley Packet Filter (BPF) syntax (the same one as '
                         'tcpdump)')



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

def startSniffing(args):
    global logger
    if (args.interface != None):
        logger.info('Starting decoding from Interface '+str(args.interface))
        try:
            sniff(iface=args.interface, prn=packet_handler, filter="udp")
        except:
            pass
    else:
        logger.info('Live sniffing not started. No Interface given!')

'''
['__all_slots__', '__class__', '__contains__', '__delattr__', '__delitem__', '__div__', '__doc__', '__eq__',
'__format__', '__getattr__', '__getattribute__', '__getitem__', '__gt__', '__hash__', '__init__', '__iter__', 
'__len__', '__lt__', '__metaclass__', '__module__', '__mul__', '__ne__', '__new__', '__nonzero__', '__rdiv__',
'__reduce__', '__reduce_ex__', '__repr__', '__rmul__', '__rtruediv__', '__setattr__', '__setitem__', '__sizeof__',
'__slots__', '__str__', '__subclasshook__', '__truediv__', '_answered', '_do_summary', '_name', 
'_overload_fields', '_pkt', '_show_or_dump', 'add_payload', 'add_underlayer', 'aliastypes', 'answers', 'build', 
'build_done', 'build_padding', 'build_ps', 'canvas_dump', 'clone_with', 'command', 'copy', 'copy_field_value',
'copy_fields_dict', 'decode_payload_as', 'default_fields', 'default_payload_class', 'delfieldval', 'direction',
'dispatch_hook', 'display', 'dissect', 'dissection_done', 'do_build', 'do_build_payload', 'do_build_ps',
'do_dissect', 'do_dissect_payload', 'do_init_fields', 'explicit', 'extract_padding', 'fields', 'fields_desc',
'fieldtype', 'firstlayer', 'fragment', 'from_hexcap', 'get_field', 'getfield_and_val', 'getfieldval',
'getlayer', 'guess_payload_class', 'hashret', 'haslayer', 'hide_defaults', 'init_fields', 'lastlayer',
'libnet', 'lower_bonds', 'mysummary', 'name', 'original', 'overload_fields', 'overloaded_fields',
'packetfields', 'payload', 'payload_guess', 'pdfdump', 'post_build', 'post_dissect', 'post_dissection',
'post_transforms', 'pre_dissect', 'psdump', 'raw_packet_cache', 'raw_packet_cache_fields', 
'remove_payload', 'remove_underlayer', 'route', 'self_build', 'sent_time', 'setfieldval', 'show', 'show2',
'show_indent', 'show_summary', 'sniffed_on', 'sprintf', 'summary', 'time', 'underlayer', 'upper_bonds']
'''

def packet_handler(pkt) :
    global loggerPackets
    global logger
    '''
    logger.info("Found a Package")
    #if packet has 802.11 layer
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
    if TCP in pkt:
        tcp_sport = pkt[TCP].sport
        tcp_dport = pkt[TCP].dport

    logIPAddress = "IP: " + str(ip_src) + ":" + str(tcp_sport) + " ==> " + str(ip_dst) + ":" + str(tcp_dport)
    '''
    #loggerPackets.info(logIPAddress + "\n")
    #print(str(pkt))
    
    if pkt[UDP].payload:
        loggerPackets.info(pkt.show())
        #loggerPackets("Source: "+str(ip_src))

def startDecoding(args):
    """Decodes packets depending on the arguments given by the parser.
    :param args: the arguments parsed
    """
    global logger
    #logger.info('Start Decoding')
    if(args.pcapfile!=None):
        logger.info('Starting decoding from PcapFile')
        decodeFromPcapFile(args)

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

    mac_address_src = "Unkown"
    mac_address_dst = "Unkown"    
    if hasattr(packet, "eth"):
        if hasattr(packet.eth,"src"):
            mac_address_src = packet.eth.src
        if hasattr(packet.eth,"dst"):
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

        if 'DATA' in packet:
            data_layer = packet.data
            hexString = data_layer.data
            #decoded = decodeDataToHexArray(hexString)
            #logData = "Data: " + decoded
            tricc = decodeAsTriccProto(hexString)
            logProto = "Proto: "+str(tricc)

            loggerPackets.info(logMacAddress+"\n"+logIPv6Address+"\n"+logIPAddress+"\n"+logProto+"\n")


###########################
#     Hex Decompiling     #
###########################

def decodeDataToHexArray(hexString):
    splits = splithexStringToBytes(hexString)
    decoded = ""
    for split in splits:
        decoded += decodeHexToChar(split)
    return decoded

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

    print (protoAsString)


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
    logger = logging.getLogger("info_file_handler")
    logger.info("Global Logger loaded")

    global loggerPackets
    loggerPackets = logging.getLogger("packet_file_handler")
    logger.info("Packet Logger loaded")

    global loggerError
    loggerError = logging.getLogger("error_file_handler")
    logger.info("Error Logger loaded")

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
    logger.info("Start Loggin")

    #bytis = b'\x00\x00\x84\x00\x00\x00\x00\x08\x00\x00\x00\x05\x0236\x03186\x03173\x03131\x07in-addr\x04arpa\x00\x00\x0c\x80\x01\x00\x00\x00x\x00\x0f\x07Android\x05local\x00\x018\x01B\x01D\x015\x019\x018\x01E\x01F\x01F\x01F\x01E\x010\x012\x019\x016\x012\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x018\x01E\x01F\x03ip6\xc0#\x00\x0c\x80\x01\x00\x00\x00x\x00\x02\xc03\x018\x01B\x01D\x015\x019\x018\x01E\x01F\x01F\x01F\x01E\x010\x012\x019\x016\x012\x010\x018\x01B\x010\x018\x010\x015\x010\x018\x013\x016\x010\x011\x010\x010\x012\xc0\x82\x00\x0c\x80\x01\x00\x00\x00x\x00\x02\xc03\x016\x01E\x012\x017\x019\x01D\x01B\x01A\x012\x017\x012\x019\x01C\x01B\x011\x010\xc0\xb4\x00\x0c\x80\x01\x00\x00\x00x\x00\x02\xc03\xc03\x00\x01\x80\x01\x00\x00\x00x\x00\x04\x83\xad\xba$\xc03\x00\x1c\x80\x01\x00\x00\x00x\x00\x10\xfe\x80\x00\x00\x00\x00\x00\x00&\x92\x0e\xff\xfe\x89]\xb8\xc03\x00\x1c\x80\x01\x00\x00\x00x\x00\x10 \x01\x068\x05\x08\x0b\x80&\x92\x0e\xff\xfe\x89]\xb8\xc03\x00\x1c\x80\x01\x00\x00\x00x\x00\x10 \x01\x068\x05\x08\x0b\x80\x01\xbc\x92r\xab\xd9r\xe6\xc0\x0c\x00/\x80\x01\x00\x00\x00x\x00\x06\xc0\x0c\x00\x02\x00\x08\xc0B\x00/\x80\x01\x00\x00\x00x\x00\x06\xc0B\x00\x02\x00\x08\xc0\x94\x00/\x80\x01\x00\x00\x00x\x00\x06\xc0\x94\x00\x02\x00\x08\xc0\xe2\x00/\x80\x01\x00\x00\x00x\x00\x06\xc0\xe2\x00\x02\x00\x08\xc03\x00/\x80\x01\x00\x00\x00x\x00\x08\xc03\x00\x04@\x00\x00\x08'
    #positionData = decodeTriccProtoHexString("0a1e0805120c506f736974696f6e5a65726f1a0c08f99d9fd10510f89c919a022d98ab004135442551423d0000803f450000803f4a0f0d0000803f150000803f1d0000803f520f0d0000803f150000803f1d0000803f")

    #protoAsBytearray = binascii.unhexlify(bytis)
    #decodeTriccProtoHexString(protoAsBytearray)
    startDecoding(args)
    startSniffing(args)

if __name__ == '__main__':main()