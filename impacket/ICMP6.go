// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
// 
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
// 

import array
import struct

from impacket.ImpactPacket import Header, Data
from impacket.IP6_Address import IP6_Address


 type ICMP6 struct { // Header:    
    //IP Protocol number for ICMP6
    IP_PROTOCOL_NUMBER = 58
    protocol = IP_PROTOCOL_NUMBER   //ImpactDecoder uses the constant "protocol" as the IP Protocol Number
    
    //Size of ICMP6 header (excluding payload)
    HEADER_SIZE = 4

    //ICMP6 Message Type numbers
    DESTINATION_UNREACHABLE = 1
    PACKET_TOO_BIG = 2
    TIME_EXCEEDED = 3
    PARAMETER_PROBLEM = 4    
    ECHO_REQUEST = 128
    ECHO_REPLY = 129
    ROUTER_SOLICITATION = 133
    ROUTER_ADVERTISEMENT = 134
    NEIGHBOR_SOLICITATION = 135
    NEIGHBOR_ADVERTISEMENT = 136
    REDIRECT_MESSAGE = 137
    NODE_INFORMATION_QUERY = 139
    NODE_INFORMATION_REPLY = 140
    
    //Destination Unreachable codes
    NO_ROUTE_TO_DESTINATION = 0
    ADMINISTRATIVELY_PROHIBITED = 1
    BEYOND_SCOPE_OF_SOURCE_ADDRESS = 2
    ADDRESS_UNREACHABLE = 3
    PORT_UNREACHABLE = 4
    SOURCE_ADDRESS_FAILED_INGRESS_EGRESS_POLICY = 5
    REJECT_ROUTE_TO_DESTINATION = 6
    
    //Time Exceeded codes
    HOP_LIMIT_EXCEEDED_IN_TRANSIT = 0
    FRAGMENT_REASSEMBLY_TIME_EXCEEDED = 1
    
    //Parameter problem codes
    ERRONEOUS_HEADER_FIELD_ENCOUNTERED = 0
    UNRECOGNIZED_NEXT_HEADER_TYPE_ENCOUNTERED = 1
    UNRECOGNIZED_IPV6_OPTION_ENCOUNTERED = 2
    
    //Node Information codes
    NODE_INFORMATION_QUERY_IPV6 = 0
    NODE_INFORMATION_QUERY_NAME_OR_EMPTY = 1
    NODE_INFORMATION_QUERY_IPV4 = 2
    NODE_INFORMATION_REPLY_SUCCESS = 0
    NODE_INFORMATION_REPLY_REFUSED = 1
    NODE_INFORMATION_REPLY_UNKNOWN_QTYPE = 2
    
    //Node Information qtypes
    NODE_INFORMATION_QTYPE_NOOP = 0
    NODE_INFORMATION_QTYPE_UNUSED = 1
    NODE_INFORMATION_QTYPE_NODENAME = 2
    NODE_INFORMATION_QTYPE_NODEADDRS = 3
    NODE_INFORMATION_QTYPE_IPv4ADDRS = 4
    
    //ICMP Message semantic types (error or informational)    
    ERROR_MESSAGE = 0
    INFORMATIONAL_MESSAGE = 1
    
    //ICMP message dictionary - specifying text descriptions and valid message codes
    //Key: ICMP message number
    //Data: Tuple ( Message Type (error/informational), Text description, Codes dictionary (can be nil) )
    //Codes dictionary
    //Key: Code number
    //Data: Text description
    
    //ICMP message dictionary tuple indexes
    MSG_TYPE_INDEX = 0
    DESCRIPTION_INDEX = 1
    CODES_INDEX = 2

    icmp_messages = {
                     DESTINATION_UNREACHABLE : (ERROR_MESSAGE, "Destination unreachable",
                                                { NO_ROUTE_TO_DESTINATION : "No route to destination",
                                                  ADMINISTRATIVELY_PROHIBITED : "Administratively prohibited",
                                                  BEYOND_SCOPE_OF_SOURCE_ADDRESS : "Beyond scope of source address",
                                                  ADDRESS_UNREACHABLE : "Address unreachable",
                                                  PORT_UNREACHABLE : "Port unreachable",
                                                  SOURCE_ADDRESS_FAILED_INGRESS_EGRESS_POLICY : "Source address failed ingress/egress policy",
                                                  REJECT_ROUTE_TO_DESTINATION : "Reject route to destination"
                                                  }),
                     PACKET_TOO_BIG : (ERROR_MESSAGE, "Packet too big", nil),
                     TIME_EXCEEDED : (ERROR_MESSAGE, "Time exceeded",
                                        {HOP_LIMIT_EXCEEDED_IN_TRANSIT : "Hop limit exceeded in transit",
                                        FRAGMENT_REASSEMBLY_TIME_EXCEEDED : "Fragment reassembly time exceeded"                                      
                                       }),
                     PARAMETER_PROBLEM : (ERROR_MESSAGE, "Parameter problem",
                                          {
                                           ERRONEOUS_HEADER_FIELD_ENCOUNTERED : "Erroneous header field encountered",
                                           UNRECOGNIZED_NEXT_HEADER_TYPE_ENCOUNTERED : "Unrecognized Next Header type encountered",
                                           UNRECOGNIZED_IPV6_OPTION_ENCOUNTERED : "Unrecognized IPv6 Option Encountered"
                                           }),
                     ECHO_REQUEST : (INFORMATIONAL_MESSAGE, "Echo request", nil),
                     ECHO_REPLY : (INFORMATIONAL_MESSAGE, "Echo reply", nil),
                     ROUTER_SOLICITATION : (INFORMATIONAL_MESSAGE, "Router Solicitation", nil),
                     ROUTER_ADVERTISEMENT : (INFORMATIONAL_MESSAGE, "Router Advertisement", nil),
                     NEIGHBOR_SOLICITATION : (INFORMATIONAL_MESSAGE, "Neighbor Solicitation", nil),
                     NEIGHBOR_ADVERTISEMENT : (INFORMATIONAL_MESSAGE, "Neighbor Advertisement", nil),
                     REDIRECT_MESSAGE : (INFORMATIONAL_MESSAGE, "Redirect Message", nil),
                     NODE_INFORMATION_QUERY: (INFORMATIONAL_MESSAGE, "Node Information Query", nil),
                     NODE_INFORMATION_REPLY: (INFORMATIONAL_MESSAGE, "Node Information Reply", nil),
                    } 
    
    
    
    
//###########################################################################
     func (self TYPE) __init__(buffer = nil interface{}){
        Header.__init__(self, self.HEADER_SIZE)
        if (buffer) {
            self.load_header(buffer)
    
     func (self TYPE) get_header_size(){
        return self.HEADER_SIZE
    
     func (self TYPE) get_ip_protocol_number(){
        return self.IP_PROTOCOL_NUMBER

     func (self TYPE) __str__(){        
        type = self.get_type()
        code = self.get_code()
        checksum = self.get_checksum()

        s = "ICMP6 - Type: " + str(type) + " - "  + self.__get_message_description() + "\n"
        s += "Code: " + str(code)
        if (self.__get_code_description() != "") {
            s += " - " + self.__get_code_description()
        s += "\n"
        s += "Checksum: " + str(checksum) + "\n"
        return s
    
     func (self TYPE) __get_message_description(){
        return self.icmp_messages[self.get_type()][self.DESCRIPTION_INDEX]
    
     func (self TYPE) __get_code_description(){
        code_dictionary = self.icmp_messages[self.get_type()][self.CODES_INDEX]
        if (code_dictionary == nil) {
            return ""
        } else  {
            return code_dictionary[self.get_code()]
    
//###########################################################################
     func (self TYPE) get_type(){        
        return (self.get_byte(0))
    
     func (self TYPE) get_code(){
        return (self.get_byte(1))
    
     func (self TYPE) get_checksum(){
        return (self.get_word(2))
    
//###########################################################################
     func (self TYPE) set_type(type interface{}){
        self.set_byte(0, type)
    
     func (self TYPE) set_code(code interface{}){
        self.set_byte(1, code)
    
     func (self TYPE) set_checksum(checksum interface{}){
        self.set_word(2, checksum)
    
//###########################################################################
     func (self TYPE) calculate_checksum(){        
        //Initialize the checksum value to 0 to yield a correct calculation
        self.set_checksum(0)        
        //Fetch the pseudo header from the IP6 parent packet
        pseudo_header = self.parent().get_pseudo_header()
        //Fetch the ICMP data
        icmp_header = self.get_bytes()
        //Build an array of bytes concatenating the pseudo_header, the ICMP header and the ICMP data (if present)
        checksum_array = array.array("B")
        checksum_array.extend(pseudo_header)
        checksum_array.extend(icmp_header)
        if (self.child()) {
            checksum_array.extend(self.child().get_bytes())
            
        //Compute the checksum over that array
        self.set_checksum(self.compute_checksum(checksum_array))
        
     func (self TYPE) is_informational_message(){
        return self.icmp_messages[self.get_type()][self.MSG_TYPE_INDEX] == self.INFORMATIONAL_MESSAGE
        
     func (self TYPE) is_error_message(){
        return self.icmp_messages[self.get_type()][self.MSG_TYPE_INDEX] == self.ERROR_MESSAGE
    
     func (self TYPE) is_well_formed(){
        well_formed = true
        
        //Check that the message type is known
        well_formed &= self.get_type() in self.icmp_messages.keys()
        
        //Check that the code is known (zero, if there are no codes defined)
        code_dictionary = self.icmp_messages[self.get_type()][self.CODES_INDEX]
        if (code_dictionary == nil) {
            well_formed &= self.get_code() == 0
        } else  {            
            well_formed &= self.get_code() in code_dictionary.keys()
            
        return well_formed 
        
//###########################################################################

    @classmethod
     func Echo_Request(class_object, id, sequence_number, arbitrary_data = nil interface{}){
        return class_object.__build_echo_message(ICMP6.ECHO_REQUEST, id, sequence_number, arbitrary_data)
    
    @classmethod
     func Echo_Reply(class_object, id, sequence_number, arbitrary_data = nil interface{}){
        return class_object.__build_echo_message(ICMP6.ECHO_REPLY, id, sequence_number, arbitrary_data)
    
    @classmethod
     func __build_echo_message(class_object, type, id, sequence_number, arbitrary_data interface{}){
        //Build ICMP6 header
        icmp_packet = ICMP6()
        icmp_packet.set_type(type)
        icmp_packet.set_code(0)
        
        //Pack ICMP payload
        icmp_bytes = struct.pack('>H', id)
        icmp_bytes += struct.pack('>H', sequence_number)
        if (arbitrary_data is not nil) {
            icmp_bytes += array.array('B', arbitrary_data).tostring()
        icmp_payload = Data()
        icmp_payload.set_data(icmp_bytes)
        
        //Link payload to header
        icmp_packet.contains(icmp_payload)
        
        return icmp_packet
    
    
//###########################################################################
    @classmethod
     func Destination_Unreachable(class_object, code, originating_packet_data = nil interface{}){
        unused_bytes = [0x00, 0x00, 0x00, 0x00]
        return class_object.__build_error_message(ICMP6.DESTINATION_UNREACHABLE, code, unused_bytes, originating_packet_data)

    @classmethod
     func Packet_Too_Big(class_object, MTU, originating_packet_data = nil interface{}){
        MTU_bytes = struct.pack('!L', MTU)
        return class_object.__build_error_message(ICMP6.PACKET_TOO_BIG, 0, MTU_bytes, originating_packet_data)
    
    @classmethod
     func Time_Exceeded(class_object, code, originating_packet_data = nil interface{}){
        unused_bytes = [0x00, 0x00, 0x00, 0x00]
        return class_object.__build_error_message(ICMP6.TIME_EXCEEDED, code, unused_bytes, originating_packet_data)

    @classmethod
     func Parameter_Problem(class_object, code, pointer, originating_packet_data = nil interface{}){
        pointer_bytes = struct.pack('!L', pointer)
        return class_object.__build_error_message(ICMP6.PARAMETER_PROBLEM, code, pointer_bytes, originating_packet_data)
    
    @classmethod    
     func __build_error_message(class_object, type, code, data, originating_packet_data interface{}){
        //Build ICMP6 header
        icmp_packet = ICMP6()
        icmp_packet.set_type(type)
        icmp_packet.set_code(code)
        
        //Pack ICMP payload
        icmp_bytes = array.array('B', data).tostring()
        if (originating_packet_data is not nil) {
            icmp_bytes += array.array('B', originating_packet_data).tostring()
        icmp_payload = Data()
        icmp_payload.set_data(icmp_bytes)
        
        //Link payload to header
        icmp_packet.contains(icmp_payload)
        
        return icmp_packet

//###########################################################################

    @classmethod
     func Neighbor_Solicitation(class_object, target_address interface{}){
        return class_object.__build_neighbor_message(ICMP6.NEIGHBOR_SOLICITATION, target_address)
    
    @classmethod
     func Neighbor_Advertisement(class_object, target_address interface{}){
        return class_object.__build_neighbor_message(ICMP6.NEIGHBOR_ADVERTISEMENT, target_address)

    @classmethod
     func __build_neighbor_message(class_object, msg_type, target_address interface{}){
        //Build ICMP6 header
        icmp_packet = ICMP6()
        icmp_packet.set_type(msg_type)
        icmp_packet.set_code(0)
        
        // Flags + Reserved
        icmp_bytes = array.array('B', [0x00] * 4).tostring()       
        
        // Target Address: The IP address of the target of the solicitation.
        // It MUST NOT be a multicast address.
        icmp_bytes += array.array('B', IP6_Address(target_address).as_bytes()).tostring()
        
        icmp_payload = Data()
        icmp_payload.set_data(icmp_bytes)
        
        //Link payload to header
        icmp_packet.contains(icmp_payload)
        
        return icmp_packet

//###########################################################################

     func (self TYPE) get_target_address(){
        return IP6_Address(self.child().get_bytes()[4:20])

     func (self TYPE) set_target_address(target_address interface{}){
        address = IP6_Address(target_address)
        payload_bytes = self.child().get_bytes()
        payload_bytes[4:20] = address.get_bytes()
        self.child().set_bytes(payload_bytes)

    //  0 1 2 3 4 5 6 7 
    // +-+-+-+-+-+-+-+-+
    // |R|S|O|reserved |
    // +-+-+-+-+-+-+-+-+

     func (self TYPE) get_neighbor_advertisement_flags(){
        return self.child().get_byte(0)

     func (self TYPE) set_neighbor_advertisement_flags(flags interface{}){
        self.child().set_byte(0, flags)

     func (self TYPE) get_router_flag(){
        return (self.get_neighbor_advertisement_flags() & 0x80) != 0
    
     func (self TYPE) set_router_flag(flag_value interface{}){
        curr_flags = self.get_neighbor_advertisement_flags()
        if flag_value {
            curr_flags |= 0x80
        } else  {
            curr_flags &= ~0x80
        self.set_neighbor_advertisement_flags(curr_flags)
    
     func (self TYPE) get_solicited_flag(){
        return (self.get_neighbor_advertisement_flags() & 0x40) != 0
    
     func (self TYPE) set_solicited_flag(flag_value interface{}){
        curr_flags = self.get_neighbor_advertisement_flags()
        if flag_value {
            curr_flags |= 0x40
        } else  {
            curr_flags &= ~0x40
        self.set_neighbor_advertisement_flags(curr_flags)
    
     func (self TYPE) get_override_flag(){
        return (self.get_neighbor_advertisement_flags() & 0x20) != 0
    
     func (self TYPE) set_override_flag(flag_value interface{}){
        curr_flags = self.get_neighbor_advertisement_flags()
        if flag_value {
            curr_flags |= 0x20
        } else  {
            curr_flags &= ~0x20
        self.set_neighbor_advertisement_flags(curr_flags)

//###########################################################################
    @classmethod
     func Node_Information_Query(class_object, code, payload = nil interface{}){
        return class_object.__build_node_information_message(ICMP6.NODE_INFORMATION_QUERY, code, payload)

    @classmethod
     func Node_Information_Reply(class_object, code, payload = nil interface{}){
        return class_object.__build_node_information_message(ICMP6.NODE_INFORMATION_REPLY, code, payload)
        
    @classmethod
     func __build_node_information_message(class_object, type, code, payload = nil interface{}){
        //Build ICMP6 header
        icmp_packet = ICMP6()
        icmp_packet.set_type(type)
        icmp_packet.set_code(code)
        
        //Pack ICMP payload
        qtype = 0
        flags = 0
        nonce = [0x00] * 8
        
        icmp_bytes = struct.pack('>H', qtype)
        icmp_bytes += struct.pack('>H', flags)
        icmp_bytes += array.array('B', nonce).tostring()
        
        if payload is not nil {
            icmp_bytes += array.array('B', payload).tostring()
        
        icmp_payload = Data()
        icmp_payload.set_data(icmp_bytes)
        
        //Link payload to header
        icmp_packet.contains(icmp_payload)

        return icmp_packet
    
     func (self TYPE) get_qtype(){
        return self.child().get_word(0)

     func (self TYPE) set_qtype(qtype interface{}){
        self.child().set_word(0, qtype)

     func (self TYPE) get_nonce(){
        return self.child().get_bytes()[4:12]

     func (self TYPE) set_nonce(nonce interface{}){
        payload_bytes = self.child().get_bytes()
        payload_bytes[4:12] = array.array('B', nonce)
        self.child().set_bytes(payload_bytes)

    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |      unused       |G|S|L|C|A|T|
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

     func (self TYPE) get_flags(){
        return self.child().get_word(2)

     func (self TYPE) set_flags(flags interface{}){
        self.child().set_word(2, flags)

     func (self TYPE) get_flag_T(){
        return (self.get_flags() & 0x0001) != 0
    
     func (self TYPE) set_flag_T(flag_value interface{}){
        curr_flags = self.get_flags()
        if flag_value {
            curr_flags |= 0x0001
        } else  {
            curr_flags &= ~0x0001
        self.set_flags(curr_flags)
        
     func (self TYPE) get_flag_A(){
        return (self.get_flags() & 0x0002) != 0
    
     func (self TYPE) set_flag_A(flag_value interface{}){
        curr_flags = self.get_flags()
        if flag_value {
            curr_flags |= 0x0002
        } else  {
            curr_flags &= ~0x0002
        self.set_flags(curr_flags)

     func (self TYPE) get_flag_C(){
        return (self.get_flags() & 0x0004) != 0
    
     func (self TYPE) set_flag_C(flag_value interface{}){
        curr_flags = self.get_flags()
        if flag_value {
            curr_flags |= 0x0004
        } else  {
            curr_flags &= ~0x0004
        self.set_flags(curr_flags)

     func (self TYPE) get_flag_L(){
        return (self.get_flags() & 0x0008) != 0
    
     func (self TYPE) set_flag_L(flag_value interface{}){
        curr_flags = self.get_flags()
        if flag_value {
            curr_flags |= 0x0008
        } else  {
            curr_flags &= ~0x0008
        self.set_flags(curr_flags)

     func (self TYPE) get_flag_S(){
        return (self.get_flags() & 0x0010) != 0
    
     func (self TYPE) set_flag_S(flag_value interface{}){
        curr_flags = self.get_flags()
        if flag_value {
            curr_flags |= 0x0010
        } else  {
            curr_flags &= ~0x0010
        self.set_flags(curr_flags)

     func (self TYPE) get_flag_G(){
        return (self.get_flags() & 0x0020) != 0
    
     func (self TYPE) set_flag_G(flag_value interface{}){
        curr_flags = self.get_flags()
        if flag_value {
            curr_flags |= 0x0020
        } else  {
            curr_flags &= ~0x0020
        self.set_flags(curr_flags)

     func (self TYPE) set_node_information_data(data interface{}){
        payload_bytes = self.child().get_bytes()
        payload_bytes[12:] = array.array('B', data)
        self.child().set_bytes(payload_bytes)

     func (self TYPE) get_note_information_data(){
        return self.child().get_bytes()[12:]

//###########################################################################
     func (self TYPE) get_echo_id(){
        return self.child().get_word(0)
    
     func (self TYPE) get_echo_sequence_number(){
        return self.child().get_word(2)
    
     func (self TYPE) get_echo_arbitrary_data(){
        return self.child().get_bytes()[4:]
    
     func (self TYPE) get_mtu(){
        return self.child().get_long(0)
        
     func (self TYPE) get_parm_problem_pointer(){
        return self.child().get_long(0)
        
     func (self TYPE) get_originating_packet_data(){
        return self.child().get_bytes()[4:]
