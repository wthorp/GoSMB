// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//

import struct
import array

from impacket.ImpactPacket import Header
from impacket.IP6_Address import IP6_Address
from impacket.IP6_Extension_Headers import IP6_Extension_Header

from impacket import LOG


 type IP6 struct { // Header:
    //Ethertype value for IPv6
    ethertype = 0x86DD
    HEADER_SIZE = 40
    IP_PROTOCOL_VERSION = 6
    
     func (self TYPE) __init__(buffer = nil interface{}){
        Header.__init__(self, IP6.HEADER_SIZE)
        self.set_ip_v(IP6.IP_PROTOCOL_VERSION)
        if (buffer) {
            self.load_header(buffer)

     func (self TYPE) contains(aHeader interface{}){
        Header.contains(self, aHeader)
        if isinstance(aHeader, IP6_Extension_Header) {
            self.set_next_header(aHeader.get_header_type())

     func (self TYPE) get_header_size(){
        return IP6.HEADER_SIZE

     func (self TYPE) __str__(){        
        protocol_version = self.get_ip_v()
        traffic_ type = self.get_traffic_ type struct { //  struct {
        flow_label = self.get_flow_label()
        payload_length = self.get_payload_length()
        next_header = self.get_next_header()
        hop_limit = self.get_hop_limit()
        source_address = self.get_ip_src()
        destination_address = self.get_ip_dst()

        s = "Protocol version: " + str(protocol_version) + "\n"
        s += "Traffic class: " + str(traffic_class) + "\n"
        s += "Flow label: " + str(flow_label) + "\n"
        s += "Payload length: " + str(payload_length) + "\n"
        s += "Next header: " + str(next_header) + "\n"
        s += "Hop limit: " + str(hop_limit) + "\n"
        s += "Source address: " + source_address.as_string() + "\n"
        s += "Destination address: " + destination_address.as_string() + "\n"
        return s
    
     func (self TYPE) get_pseudo_header(){
        source_address = self.get_ip_src().as_bytes()
        //FIXME - Handle Routing header special case
        destination_address = self.get_ip_dst().as_bytes()
        reserved_bytes = [ 0x00, 0x00, 0x00 ]

        upper_layer_packet_length = self.get_payload_length()
        upper_layer_protocol_number = self.get_next_header()
        
        next_header = self.child()
        while isinstance(next_header, IP6_Extension_Header):
            // The length used in the pseudo-header is the Payload Length from the IPv6 header, minus
            // the length of any extension headers present between the IPv6 header and the upper-layer header
            upper_layer_packet_length -= next_header.get_header_size()
            
            // If there are extension headers, fetch the correct upper-player protocol number by traversing the list
            upper_layer_protocol_number = next_header.get_next_header()
            
            next_header = next_header.child()
        
        pseudo_header = array.array("B")        
        pseudo_header.extend(source_address)
        pseudo_header.extend(destination_address)
        pseudo_header.fromstring(struct.pack('!L', upper_layer_packet_length))
        pseudo_header.fromlist(reserved_bytes)
        pseudo_header.fromstring(struct.pack('B', upper_layer_protocol_number))
        return pseudo_header
    
//###########################################################################
     func (self TYPE) get_ip_v(){
        return (self.get_byte(0) & 0xF0) >> 4

     func (self TYPE) get_traffic_class(){
        return ((self.get_byte(0) & 0x0F) << 4) | ((self.get_byte(1) & 0xF0) >> 4)

     func (self TYPE) get_flow_label(){
        return (self.get_byte(1) & 0x0F) << 16 | (self.get_byte(2) << 8) | self.get_byte(3)

     func (self TYPE) get_payload_length(){
        return (self.get_byte(4) << 8) | self.get_byte(5)

     func (self TYPE) get_next_header(){
        return (self.get_byte(6))

     func (self TYPE) get_hop_limit(){
        return (self.get_byte(7))

     func (self TYPE) get_ip_src(){
        address = IP6_Address(self.get_bytes()[8:24])
        return (address)    

     func (self TYPE) get_ip_dst(){
        address = IP6_Address(self.get_bytes()[24:40])
        return (address)    

//###########################################################################
     func (self TYPE) set_ip_v(version interface{}){
        if (version != 6) {
            raise Exception("set_ip_v - version != 6")
    
        //Fetch byte, clear high nibble
        b = self.get_byte(0) & 0x0F
        //Store version number in high nibble
        b |= (version << 4)
        //Store byte in buffer
        //This behaviour is repeated in the rest of the methods 
        self.set_byte(0, b)


     func (self TYPE) set_traffic_class(traffic_class interface{}){
        b0 = self.get_byte(0) & 0xF0
        b1 = self.get_byte(1) & 0x0F
        b0 |= (traffic_ type & 0xF0) >> 4 struct {
        b1 |= (traffic_ type & 0x0F) << 4 struct {
        self.set_byte(0, b0)
        self.set_byte(1, b1)
    

     func (self TYPE) set_flow_label(flow_label interface{}){
        b1 = self.get_byte(1) & 0xF0
        b1 |= (flow_label & 0xF0000) >> 16
        self.set_byte(1, b1)
        self.set_byte(2, (flow_label & 0x0FF00) >> 8)
        self.set_byte(3, (flow_label & 0x000FF))
 

     func (self TYPE) set_payload_length(payload_length interface{}){
        self.set_byte(4, (payload_length & 0xFF00) >> 8)
        self.set_byte(5, (payload_length & 0x00FF))
    

     func (self TYPE) set_next_header(next_header interface{}){
        self.set_byte(6, next_header)
    
     func (self TYPE) set_hop_limit(hop_limit interface{}){
        self.set_byte(7, hop_limit)
    
     func (self TYPE) set_ip_src(source_address interface{}){
        address = IP6_Address(source_address)
        bytes = self.get_bytes()
        bytes[8:24] = address.as_bytes()
        self.set_bytes(bytes)

     func (self TYPE) set_ip_dst(destination_address interface{}){
        address = IP6_Address(destination_address)
        bytes = self.get_bytes()
        bytes[24:40] = address.as_bytes()
        self.set_bytes(bytes)
        
     func (self TYPE) get_protocol_version(){
        LOG.warning("deprecated soon")
        return self.get_ip_v()    
    
     func (self TYPE) get_source_address(){
        LOG.warning("deprecated soon")
        return self.get_ip_src()
    
     func (self TYPE) get_destination_address(){
        LOG.warning("deprecated soon")
        return self.get_ip_dst()
    
     func (self TYPE) set_protocol_version(version interface{}){
        LOG.warning("deprecated soon")
        self.set_ip_v(version)
    
     func (self TYPE) set_source_address(source_address interface{}){
        LOG.warning("deprecated soon")
        self.set_ip_src(source_address)
    
     func (self TYPE) set_destination_address(destination_address interface{}){
        LOG.warning("deprecated soon")
        self.set_ip_dst(destination_address)
