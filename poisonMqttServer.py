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
import poisonMqtt.gpsParser as gpsParser


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


def setup_parser_and_get_args(parser):
    logger.info('Parsing Arguments')
    args = parser.parse_args()
    logAllAgruments(args)
    logger.info('Check all Requirements')
    check_all_param_requirements(parser,args)
    return args


def sendFakeGPSRouteOverMqtt():
    nodetype = "server"
    interface = MqttInterface.MqttInterface(nodetype)
    return interface


def main():
    setup_logger()
    global logger
    logger.propagate = False #Show logs on console


if __name__ == '__main__':main()