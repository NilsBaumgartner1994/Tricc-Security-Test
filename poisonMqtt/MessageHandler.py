import protobuf.tricc_pb2 as tricc
#import streaming.streaming as streaming
from subprocess import Popen, PIPE
#import Setup
import os

"""
Callbacks for when the Mqtt client receives a message
"""

conMesHandler = list()

def serverInterfaceMethod(serverInterfaceInstance, data):
    if(serverInterfaceInstance != None):
        serverInterfaceInstance.update(data)
        return True

def addConMesHandler(handler):
    """Adds a handler, called if a connection message is received"""
    conMesHandler.append(handler)

def handleConnectionMessage(data, mqttClient):
    """Handles a ConnectionMessage
    Args
        data: The binary data received (str)
        mqttClient: Client that received the data
    """
    conMes = tricc.ConnectionMessage()
    conMes.ParseFromString(data)
    for handler in conMesHandler:
        try:
            handler(conMes.relayOlsrIp, conMes.triccKitIp)
        except Exception as e:
            print "Exception in handle connection message"

def handlePositionRelayMsg(data, mqttClient):
    """
    Received a message with gps data
    :param data: The data received
    :param mqttClient: Client that received the data
    """
    posData = tricc.PositionData()
    posData.ParseFromString(data)
    if(mqttClient.serverInterface != None):
        serverInterfaceMethod(mqttClient.serverInterface, posData)
    print "Received position relay data"

def handlePositionZeroMsg(data, mqttClient):
    """
    Received a message with gps data
    :param data: The data received
    :param mqttClient: Client that received the data
    """
    posData = tricc.PositionData()
    posData.ParseFromString(data)
    if(mqttClient.serverInterface != None):
        serverInterfaceMethod(mqttClient.serverInterface, posData)
    print "Received position zero data"

def handleRelayMsg(data, mqttClient):
    """
    Received a message from a relay node with several sensor values
    :param data: The data received
    :param mqttClient: Client that received the data
    """
    relayData = tricc.RelayData()
    relayData.ParseFromString(data)
    if(mqttClient.serverInterface != None):
        serverInterfaceMethod(mqttClient.serverInterface, relayData)
    print "Received Relay data"

def handleMiscMsg(data, mqttClient):
    """
    Received a message of the misc type
    :param data: The data received
    :param mqttClient: Client that received the data
    """
    miscData = tricc.MiscData()
    miscData.ParseFromString(data)
    if(mqttClient.serverInterface != None):
        serverInterfaceMethod(mqttClient.serverInterface, miscData)
    print "Received Misc Data"

def handleAllCommandMsg(data, mqttClient):
    """
    Received a command message meant for all units
    :param data: The command received
    :param mqttClient: Client that received the data
    """
    command = tricc.Command()
    command.ParseFromString(data)
    print "Received command all"
    if(command.command == "camera_on"):
        handleCameraOnCommand(mqttClient)
    elif(command.command == "camera_off"):
        handleCameraOffCommand()

def handleSpecificCommandMsg(data, mqttClient):
    """
    Received a command message destinated for this specific unit
    :param data: The command received
    :param mqttClient: Client that received the data
    """
    try:
        print "Received command specific"
        command = tricc.Command()
        command.ParseFromString(data)
        if(command.command == "camera_on"):
            handleCameraOnCommand(mqttClient)
        elif(command.command == "camera_off"):
            handleCameraOffCommand()
    except:
        #TODO Ugly hack, because currently there would be a exception when not first registration, as serverInfoResponse comes on unitId topic
        print "Ugly hack in handleSpecificCommandMsg, needs to be fixed some time"
        pass

def handleCameraOnCommand(mqttClient):
    print "Received camera on command"
    #TODO Call Svantjes function and push the result back to the server --> Zero/Client muss noch Port auf dem er published an den Server zurueckgeben
    #TODO On my laptop there is no raspivid installed --> set up golgomath properly for streaming
    #streaming.start_streaming(mqttClient.params["brokerAddress"], mqttClient.params["videoStreamPort"])

def handleCameraOffCommand():
    print "Received camera off command"
    streaming.stop_streaming()

def handleNewIpMessage(data, mqttClient):
    conMes = tricc.ConnectionMessage()
    conMes.ParseFromString(data)
    if(mqttClient.serverInterface != None):
        serverInterfaceMethod(mqttClient.serverInterface, conMes)

def handleQueryServerInfo(data, mqttClient):
    queryInfo = tricc.QueryServerInfo()
    queryInfo.ParseFromString(data)

    if(mqttClient.serverInterface != None):
        serverInterfaceMethod(mqttClient.serverInterface, queryInfo)
    print "Received handleQueryServerInfo"
    print "Initial Registration: " + queryInfo.initialRegistration

def handleServerInfoResponse(data, mqttClient):
    """
    Sets the system time, the unit id in the config file, registered at server in mqtt class to True and
    unsubscribes from "serverInfoResponse" and subscribes to the topic for the unit Id that was received
    :param data:
    :param mqttClient:
    :return:
    """
    print "Received server Info Response"
    response = tricc.ServerInfoResponse()
    response.ParseFromString(data)
    #if mqttClient.params["uniqueIdentifier"] == response.identifier:
    if mqttClient.uuid == response.identifier or str(mqttClient.params["userId"]) == response.identifier:
        print "Server Info Response was for me"
        #set system time and id of unit
        setSystemTime(response.serverTime.sec, mqttClient.params["sudoPw"])
        mqttClient.params["userId"] = response.responseId
        mqttClient.client.unsubscribe("serverInfoResponse")
        unitTopic = "unit"+str(response.responseId)
        unitTimeSynchroTopic = "unit" + str(response.responseId) + "_timeSynchro"
        result, mid = mqttClient.client.subscribe(unitTopic, qos= mqttClient.params["qos"])
        result, mid = mqttClient.client.subscribe(unitTimeSynchroTopic, qos=mqttClient.params["qos"])
        if not unitTopic in mqttClient.params["topics"]:
            mqttClient.params["topics"].append(unitTopic)
        if not unitTimeSynchroTopic in mqttClient.params["topics"]:
             mqttClient.params["topics"].append(unitTimeSynchroTopic)


        if(not mqttClient.registeredAtServer):
            print "Was not yet registered at server"
            current_path = os.path.abspath(__file__)
            dir_path = os.path.dirname(os.path.dirname(current_path))
            network_config_path = os.path.join(dir_path, "routing/network_config.py")
            apMode = False
            with open(network_config_path, "r+") as file:
                lines = file.readlines()
                for i in lines:
                    if "AP_Mode = " in i:
                        mode = i.split("=")[1].strip()
                        if mode == "True":
                            apMode = True
            #set IP of unit
            if mqttClient.mqttInterface.type == "relay":
                print "case relay"
                Setup.setOLSRIPAddressinNetworkConfig(mqttClient.params["userId"])
                Setup.setupRouting()
            elif mqttClient.mqttInterface.type == "kit" and not apMode:
                Setup.setOLSRIPAddressinNetworkConfig(mqttClient.params["userId"])
                Setup.setupRouting()
            elif mqttClient.mqttInterface.type == "kit" and apMode:
                #kein extra setup routing etc mehr noetig
                print "hello"



            mqttClient.params["gotIpFromServer"] = True
            mqttClient.registeredAtServer = True

        mqttClient.setJsonParameters()

        #send IP of unit to server
        mqttClient.mqttInterface.sendConnectionMessage(getIp(), "not used", "newIp")
    else:
        print "But server info Response was not for me"

def setSystemTime(seconds, sudoPw):
        date = "@"+str(seconds)+""
        command = []
        command.append("date")
        command.append("--set="+date)
        p = Popen(['sudo', '-S'] + command, stdin=PIPE, stderr=PIPE,
                  universal_newlines=True)
        sudo_prompt = p.communicate(sudoPw + '\n')[1]

def getIp():
    f = os.popen('ifconfig wlx18d6c7080eb7 | grep "inet\ addr" | cut -d: -f2 | cut -d" " -f1')
    return f.read()


