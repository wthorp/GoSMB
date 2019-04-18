//!/usr/bin/env python
// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Author: Alberto Solino (@agsolino)
//
// Description:
//           Minimalistic MQTT implementation, just focused on connecting, subscribing and publishing basic
// messages on topics.
//
// References:
//           https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html
//
// ToDo:
// [ ] Implement all the MQTT Control Packets and operations
// [ ] Implement QoS = QOS_ASSURED_DELIVERY when publishing messages
//
from __future__ import print_function
import logging
import struct
import socket
from impacket.structure import Structure
try:
    from OpenSSL import SSL
except ImportError:
    logging.critical("pyOpenSSL is not installed, can't continue")
    raise

// Packet Types
PACKET_CONNECT = 1 << 4
PACKET_CONNACK = 2 << 4
PACKET_PUBLISH = 3 << 4
PACKET_PUBACK = 4 << 4
PACKET_PUBREC = 5 << 4
PACKET_PUBREL = 6 << 4
PACKET_PUBCOMP = 7 << 4
PACKET_SUBSCRIBE = 8 << 4
PACKET_SUBSCRIBEACK = 9 << 4
PACKET_UNSUBSCRIBE = 10 << 4
PACKET_UNSUBACK = 11 << 4
PACKET_PINGREQ = 12 << 4
PACKET_PINGRESP = 13 << 4
PACKET_DISCONNECT = 14 << 4

// CONNECT Flags
CONNECT_USERNAME = 0x80
CONNECT_PASSWORD = 0x40
CONNECT_CLEAN_SESSION = 0x2

// CONNECT_ACK Return Errors
CONNECT_ACK_ERROR_MSGS = {
    0x00: 'Connection Accepted',
    0x01: 'Connection Refused, unacceptable protocol version',
    0x02: 'Connection Refused, identifier rejected',
    0x03: 'Connection Refused, Server unavailable',
    0x04: 'Connection Refused, bad user name or password',
    0x05: 'Connection Refused, not authorized'
}

// QoS Levels
QOS_FIRE_AND_FORGET = 0
QOS_ACK_DELIVERY    = 1
QOS_ASSURED_DELIVERY= 2

 type MQTT_Packet struct { // Structure:
    commonHdr= (
        ('PacketType','B=0'),
         MessageLength uint32 // =0
    } (
        ('_VariablePart', '_-VariablePart', 'self.MessageLength'),
        ('VariablePart', ':'),
    }
     func (self TYPE) setQoS(QoS interface{}){
        self.PacketType |= (QoS << 1)

     func (self TYPE) fromString(data interface{}){
        if data is not nil and len(data) > 2 {
            // Get the Length
            index = 1
            multiplier = 1
            value = 0
            encodedByte = 128
            packetType = data[0]
            while (encodedByte & 128) != 0:
                encodedByte = ord(data[index])
                value += (encodedByte & 127) * multiplier
                multiplier *= 128
                index += 1
                if multiplier > 128 * 128 * 128 {
                    raise Exception("Malformed Remaining Length")
            data = packetType + struct.pack('<L', value) + data[index:value+index]
            return Structure.fromString(self, data)
        raise Exception("Dont know")

     func (self TYPE) getData(){
        packetType = self.PacketType
        self.commonHdr = ()
        packetLen = len(Structure.getData(self))
        output = ""
        while packetLen > 0:
            encodedByte = packetLen % 128
            packetLen /= 128
            if packetLen > 0 {
                encodedByte |= 128
            output += chr(encodedByte)
        self.commonHdr = ( ('PacketType','B=0'), ('MessageLength',':'), )
        self.PacketType = packetType
        self.MessageLength = output
        if output == '' {
            self.MessageLength = chr(00)

        return Structure.getData(self)


 type MQTT_String struct { // Structure: (
        ('Length','>H-Name'),
        ('Name',':'),
    }

 type MQTT_Connect struct { // MQTT_Packet: (
        ('ProtocolName',':', MQTT_String),
        ('Version','B=3'),
        ('Flags','B=2'),
        ('KeepAlive','>H=60'),
        ('ClientID',':', MQTT_String),
        ('Payload',':=""'),
    }
     func (self TYPE) __init__(data = nil, alignment = 0 interface{}){
        MQTT_Packet.__init__(self, data, alignment)
        if data == nil {
            self.PacketType = PACKET_CONNECT

 type MQTT_ConnectAck struct { // MQTT_Packet: (
        ('ReturnCode', '>H=0'),
    }

 type MQTT_Publish struct { // MQTT_Packet: (
        ('Topic',':', MQTT_String),
        ('Message',':'),
    }
     func (self TYPE) __init__(data = nil, alignment = 0 interface{}){
        MQTT_Packet.__init__(self, data, alignment)
        if data == nil {
            self.PacketType = PACKET_PUBLISH

     func (self TYPE) getData(){
        if self.PacketType & 6 > 0 {
            // We have QoS enabled, we need to have a MessageID field
            self. (
                ('Topic', ':', MQTT_String),
                ('MessageID', '>H=0'),
                ('Message', ':'),
            }
        return MQTT_Packet.getData(self)

 type MQTT_Disconnect struct { // MQTT_Packet: (
    }
     func (self TYPE) __init__(data=nil, alignment=0 interface{}){
        MQTT_Packet.__init__(self, data, alignment)
        if data == nil {
            self.PacketType = PACKET_DISCONNECT

 type MQTT_Subscribe struct { // MQTT_Packet: (
        ('MessageID','>H=1'),
        ('Topic',':', MQTT_String),
        ('Flags','B=0'),
    }
     func (self TYPE) __init__(data = nil, alignment = 0 interface{}){
        MQTT_Packet.__init__(self, data, alignment)
        if data == nil {
            self.PacketType = PACKET_SUBSCRIBE

 type MQTT_SubscribeACK struct { // MQTT_Packet: (
        ('MessageID','>H=0'),
        ('ReturnCode','B=0'),
    }
     func (self TYPE) __init__(data = nil, alignment = 0 interface{}){
        MQTT_Packet.__init__(self, data, alignment)
        if data == nil {
            self.PacketType = PACKET_SUBSCRIBEACK

 type MQTT_UnSubscribe struct { // MQTT_Packet: (
        ('MessageID','>H=1'),
        ('Topics',':'),
    }
     func (self TYPE) __init__(data = nil, alignment = 0 interface{}){
        MQTT_Packet.__init__(self, data, alignment)
        if data == nil {
            self.PacketType = PACKET_UNSUBSCRIBE

 type MQTTSessionError struct { // Exception:
    """
    This is the exception every client should catch
    """

     func (self TYPE) __init__(error=0, packet=0, errorString='' interface{}){
        Exception.__init__(self)
        self.error = error
        self.packet = packet
        self.errorString = errorString

     func (self TYPE) getErrorCode(){
        return self.error

     func (self TYPE) getErrorPacket(){
        return self.packet

     func (self TYPE) getErrorString(){
        return self.errorString

     func (self TYPE) __str__(){
        return self.errorString

 type MQTTConnection: struct {
     func (self TYPE) __init__(host, port, isSSL=false interface{}){
        self._targetHost = host
        self._targetPort = port
        self._isSSL = isSSL
        self._socket = nil
        self._messageId = 1
        self.connectSocket()

     func (self TYPE) getSocket(){
        return self._socket

     func (self TYPE) connectSocket(){
        s = socket.socket()
        s.connect((self._targetHost, int(self._targetPort)))

        if self._isSSL is true {
            ctx = SSL.Context(SSL.TLSv1_METHOD)
            self._socket = SSL.Connection(ctx, s)
            self._socket.set_connect_state()
            self._socket.do_handshake()
        } else  {
            self._socket = s

     func (self TYPE) send(request interface{}){
        return self._socket.sendall(str(request))

     func (self TYPE) sendReceive(request interface{}){
        self.send(request)
        return self.recv()

     func (self TYPE) recv(){
        REQUEST_SIZE = 8192
        data = ""
        done = false
        while not done:
            recvData = self._socket.recv(REQUEST_SIZE)
            if len(recvData) < REQUEST_SIZE {
                done = true
            data += recvData

        response = []
        while len(data) > 0:
            try:
                message = MQTT_Packet(data)
                remaining = data[len(message):]
            except Exception:
                // We need more data
                remaining = data + self._socket.recv(REQUEST_SIZE)
            } else  {
               response.append(message)
            data = remaining

        self._messageId += 1
        return response

     func (self TYPE) connect(clientId = " ", username = nil, password = nil, protocolName = "MQIsdp", version = 3, flags = CONNECT_CLEAN_SESSION, keepAlive = 60 interface{}){
        """

        :param clientId: Whatever cliend Id that represents you
        :param username: if nil, anonymous connection will be attempted
        :param password: if nil, anonymous connection will be attempted
        :param protocolName: specification states default should be 'MQTT' but some brokers might expect 'MQIsdp'
        :param version: Allowed versions are 3 or 4 (some brokers might like 4)
        :param flags:
        :param keepAlive: default 60
        :return: true or MQTTSessionError if something went wrong
        """

        // Let's build the packet
        connectPacket = MQTT_Connect()
        connectPacket["Version"] = version
        connectPacket["Flags"] = flags
        connectPacket["KeepAlive"] = keepAlive
        connectPacket["ProtocolName"] = MQTT_String()
        connectPacket["ProtocolName"]["Name"] = protocolName

        connectPacket["ClientID"] = MQTT_String()
        connectPacket["ClientID"]["Name"] = clientId

        if username is not nil {
            connectPacket["Flags"] |= CONNECT_USERNAME | CONNECT_PASSWORD
        if username == nil {
            user = ""
        } else  {
            user = username
        if password == nil {
            pwd = ""
        } else  {
            pwd = password

        username = MQTT_String()
        username["Name"] = user
        password = MQTT_String()
        password["Name"] = pwd
        connectPacket["Payload"] = str(username) + str(password)

        data= self.sendReceive(connectPacket)[0]

        response = MQTT_ConnectAck(str(data))
        if response["ReturnCode"] != 0 {
            raise MQTTSessionError(error = response["ReturnCode"], errorString = CONNECT_ACK_ERROR_MSGS[response["ReturnCode"]] )

        return true

     func (self TYPE) subscribe(topic, messageID = 1, flags = 0, QoS = 1 interface{}){
        """

        :param topic: Topic name you want to subscribe to
        :param messageID: optional messageId
        :param flags: Message flags
        :param QoS: define the QoS requested
        :return: true or MQTTSessionError if something went wrong
        """
        subscribePacket = MQTT_Subscribe()
        subscribePacket["MessageID"] = messageID
        subscribePacket["Topic"] = MQTT_String()
        subscribePacket["Topic"]["Name"] = topic
        subscribePacket["Flags"] = flags
        subscribePacket.setQoS(QoS)

        try:
            data = self.sendReceive(subscribePacket)[0]
        except Exception as e:
            raise MQTTSessionError(errorString=str(e))

        subAck = MQTT_SubscribeACK(str(data))

        if subAck["ReturnCode"] > 2 {
            raise MQTTSessionError(errorString = "Failure to subscribe")

        return true

     func (self TYPE) unSubscribe(topic, messageID = 1, QoS = 0 interface{}){
        """
        Unsubscribes from a topic

        :param topic:
        :param messageID:
        :param QoS: define the QoS requested
        :return:
        """
        // ToDo: Support more than one topic
        packet = MQTT_UnSubscribe()
        packet["MessageID"] = messageID
        packet["Topics"] = MQTT_String()
        packet["Topics"]["Name"] = topic
        packet.setQoS( QoS )

        return self.sendReceive(packet)

     func (self TYPE) publish(topic, message, messageID = 1, QoS=0 interface{}){

        packet = MQTT_Publish()
        packet["Topic"] = MQTT_String()
        packet["Topic"]["Name"] = topic
        packet["Message"] = message
        packet["MessageID"] = messageID
        packet.setQoS( QoS )

        return self.sendReceive(packet)

     func (self TYPE) disconnect(){
        return self.send(str(MQTT_Disconnect()))

if __name__ == '__main__' {
    HOST = "192.168.45.162"
    USER = "test"
    PASS = "test"

    mqtt = MQTTConnection(HOST, 1883, false)
    mqtt.connect('secure-', username=USER, password=PASS, version = 3)
    //mqtt.connect(protocolName='MQTT', version=4)
    //mqtt.connect()

    //mqtt.subscribe("/test/beto")
    //mqtt.unSubscribe("/test/beto")
    //mqtt.publish('/test/beto', 'Hey There, I"d like to talk to you', QoS=1)
    mqtt.subscribe("$SYS///")


    while true:

        packets = mqtt.recv()
        for packet in packets:
            publish = MQTT_Publish(str(packet))
            print('%s -> %s' % (publish["Topic"]["Name"], publish["Message"]))

    mqtt.disconnect()
