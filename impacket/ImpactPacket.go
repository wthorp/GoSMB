// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Description:
//  Network packet codecs basic building blocks.
//  Low-level packet codecs for various Internet protocols.
//
// Author:
//  Javier Burroni (javier)
//  Bruce Leidl (brl)
//  Javier Kohen (jkohen)
from __future__ import division
from __future__ import print_function
import array
import struct
import socket
import string
import sys
from binascii import hexlify
from functools import reduce

"""Classes to build network packets programmatically.

Each protocol layer is represented by an object, and these objects are
hierarchically structured to form a packet. This list is traversable
in both directions: from parent to child and vice versa.

All objects can be turned back into a raw buffer ready to be sent over
the wire (see method get_packet).
"""

 type ImpactPacketException struct { // Exception:
     func (self TYPE) __init__(value interface{}){
        self.value = value
     func (self TYPE) __str__(){
        return repr(self.value)

 type PacketBuffer struct { // object:
    """Implement the basic operations utilized to operate on a
    packet's raw buffer. All the packet classes derive from this one.

    The byte, word, long and ip_address getters and setters accept
    negative indexes, having these the a similar effect as in a
    regular Python sequence slice.
    """

     func (self TYPE) __init__(length = nil interface{}){
        "If 'length' is specified the buffer is created with an initial size"
        if length {
            self.__bytes = array.array('B', b'\0' * length)
        } else  {
            self.__bytes = array.array("B")

     func (self TYPE) set_bytes_from_string(data interface{}){
        "Sets the value of the packet buffer from the string 'data'"
        self.__bytes = array.array('B', data)

     func (self TYPE) get_buffer_as_string(){
        "Returns the packet buffer as a string object"
        return self.__bytes.tostring()

     func (self TYPE) get_bytes(){
        "Returns the packet buffer as an array"
        return self.__bytes

     func (self TYPE) set_bytes(bytes interface{}){
        "Set the packet buffer from an array"
        // Make a copy to be safe
        self.__bytes = array.array('B', bytes.tolist())

     func (self TYPE) set_byte(index, value interface{}){
        "Set byte at 'index' to 'value'"
        index = self.__validate_index(index, 1)
        self.__bytes[index] = value

     func (self TYPE) get_byte(index interface{}){
        "Return byte at 'index'"
        index = self.__validate_index(index, 1)
        return self.__bytes[index]

     func (self TYPE) set_word(index, value, order = "!" interface{}){
        "Set 2-byte word at 'index' to 'value'. See struct module's documentation to understand the meaning of 'order'."
        index = self.__validate_index(index, 2)
        ary = array.array("B", struct.pack(order + 'H', value))
        if -2 == index {
            self.__bytes[index:] = ary
        } else  {
            self.__bytes[index:index+2] = ary

     func (self TYPE) get_word(index, order = "!" interface{}){
        "Return 2-byte word at 'index'. See struct module's documentation to understand the meaning of 'order'."
        index = self.__validate_index(index, 2)
        if -2 == index {
            bytes = self.__bytes[index:]
        } else  {
            bytes = self.__bytes[index:index+2]
        (value,) = struct.unpack(order + 'H', bytes.tostring())
        return value

     func (self TYPE) set_long(index, value, order = "!" interface{}){
        "Set 4-byte 'value' at 'index'. See struct module's documentation to understand the meaning of 'order'."
        index = self.__validate_index(index, 4)
        ary = array.array("B", struct.pack(order + 'L', value))
        if -4 == index {
            self.__bytes[index:] = ary
        } else  {
            self.__bytes[index:index+4] = ary

     func (self TYPE) get_long(index, order = "!" interface{}){
        "Return 4-byte value at 'index'. See struct module's documentation to understand the meaning of 'order'."
        index = self.__validate_index(index, 4)
        if -4 == index {
            bytes = self.__bytes[index:]
        } else  {
            bytes = self.__bytes[index:index+4]
        (value,) = struct.unpack(order + 'L', bytes.tostring())
        return value

     func (self TYPE) set_long_long(index, value, order = "!" interface{}){
        "Set 8-byte 'value' at 'index'. See struct module's documentation to understand the meaning of 'order'."
        index = self.__validate_index(index, 8)
        ary = array.array("B", struct.pack(order + 'Q', value))
        if -8 == index {
            self.__bytes[index:] = ary
        } else  {
            self.__bytes[index:index+8] = ary

     func (self TYPE) get_long_long(index, order = "!" interface{}){
        "Return 8-byte value at 'index'. See struct module's documentation to understand the meaning of 'order'."
        index = self.__validate_index(index, 8)
        if -8 == index {
            bytes = self.__bytes[index:]
        } else  {
            bytes = self.__bytes[index:index+8]
        (value,) = struct.unpack(order + 'Q', bytes.tostring())
        return value


     func (self TYPE) get_ip_address(index interface{}){
        "Return 4-byte value at 'index' as an IP string"
        index = self.__validate_index(index, 4)
        if -4 == index {
            bytes = self.__bytes[index:]
        } else  {
            bytes = self.__bytes[index:index+4]
        return socket.inet_ntoa(bytes.tostring())

     func (self TYPE) set_ip_address(index, ip_string interface{}){
        "Set 4-byte value at 'index' from 'ip_string'"
        index = self.__validate_index(index, 4)
        raw = socket.inet_aton(ip_string)
        (b1,b2,b3,b4) = struct.unpack("BBBB", raw)
        self.set_byte(index, b1)
        self.set_byte(index + 1, b2)
        self.set_byte(index + 2, b3)
        self.set_byte(index + 3, b4)

     func (self TYPE) set_checksum_from_data(index, data interface{}){
        "Set 16-bit checksum at 'index' by calculating checksum of 'data'"
        self.set_word(index, self.compute_checksum(data))

     func (self TYPE) compute_checksum(anArray interface{}){
        "Return the one's complement of the one's complement sum of all the 16-bit words in 'anArray'"
        nleft = len(anArray)
        sum = 0
        pos = 0
        while nleft > 1:
            sum = anArray[pos] * 256 + (anArray[pos + 1] + sum)
            pos = pos + 2
            nleft = nleft - 2
        if nleft == 1 {
            sum = sum + anArray[pos] * 256
        return self.normalize_checksum(sum)

     func (self TYPE) normalize_checksum(aValue interface{}){
        sum = aValue
        sum = (sum >> 16) + (sum & 0xFFFF)
        sum += (sum >> 16)
        sum = (~sum & 0xFFFF)
        return sum

     func (self TYPE) __validate_index(index, size interface{}){
        """This method performs two tasks: to allocate enough space to
        fit the elements at positions index through index+size, and to
        adjust negative indexes to their absolute equivalent.
        """

        orig_index = index

        curlen = len(self.__bytes)
        if index < 0 {
            index = curlen + index

        diff = index + size - curlen
        if diff > 0 {
            self.__bytes.fromstring('\0' * diff)
            if orig_index < 0 {
                orig_index -= diff

        return orig_index

 type ProtocolLayer struct { // :
    "Protocol Layer Manager for insertion and removal of protocol layers."

    __child = nil
    __parent = nil
        
     func (self TYPE) contains(aHeader interface{}){
        "Set 'aHeader' as the child of this protocol layer"
        self.__child = aHeader
        aHeader.set_parent(self)

     func (self TYPE) set_parent(my_parent interface{}){
        "Set the header 'my_parent' as the parent of this protocol layer"
        self.__parent = my_parent

     func (self TYPE) child(){
        "Return the child of this protocol layer"
        return self.__child

     func (self TYPE) parent(){
        "Return the parent of this protocol layer"
        return self.__parent
    
     func (self TYPE) unlink_child(){
        "Break the hierarchy parent/child child/parent"
        if self.__child {
            self.__child.set_parent(nil)
            self.__child = nil 

 type ProtocolPacket struct { // ProtocolLayer:
    __HEADER_SIZE = 0
    __BODY_SIZE = 0
    __TAIL_SIZE = 0
    
    __header = nil
    __body = nil
    __tail = nil

     func (self TYPE) __init__(header_size, tail_size interface{}){
        self.__HEADER_SIZE = header_size
        self.__TAIL_SIZE = tail_size
        self.__header=PacketBuffer(self.__HEADER_SIZE)
        self.__body=PacketBuffer()
        self.__tail=PacketBuffer(self.__TAIL_SIZE)
        
     func (self TYPE) __update_body_from_child(){
        // Update child raw packet in my body
        if self.child() {
            body=self.child().get_packet()
            self.__BODY_SIZE=len(body)
            self.__body.set_bytes_from_string(body)
            
     func (self TYPE) __get_header(){
        return self.__header
    
    header = property(__get_header)

     func (self TYPE) __get_body(){
        self.__update_body_from_child()
        return self.__body
    
    body = property(__get_body)
    
     func (self TYPE) __get_tail(){
        return self.__tail
    
    tail = property(__get_tail)

     func (self TYPE) get_header_size(){
        "Return frame header size"
        return self.__HEADER_SIZE
    
     func (self TYPE) get_tail_size(){
        "Return frame tail size"
        return self.__TAIL_SIZE
    
     func (self TYPE) get_body_size(){
        "Return frame body size"
        self.__update_body_from_child()
        return self.__BODY_SIZE

     func (self TYPE) get_size(){
        "Return frame total size"
        return self.get_header_size()+self.get_body_size()+self.get_tail_size()
    
     func (self TYPE) load_header(aBuffer interface{}){
        self.__HEADER_SIZE=len(aBuffer)
        self.__header.set_bytes_from_string(aBuffer)
    
     func (self TYPE) load_body(aBuffer interface{}){
        "Load the packet body from string. "\
        "WARNING: Using this function will break the hierarchy of preceding protocol layer"
        self.unlink_child()
        self.__BODY_SIZE=len(aBuffer)
        self.__body.set_bytes_from_string(aBuffer)
    
     func (self TYPE) load_tail(aBuffer interface{}){
        self.__TAIL_SIZE=len(aBuffer)
        self.__tail.set_bytes_from_string(aBuffer)
    
     func (self TYPE) __extract_header(aBuffer interface{}){
        self.load_header(aBuffer[:self.__HEADER_SIZE])
        
     func (self TYPE) __extract_body(aBuffer interface{}){
        if self.__TAIL_SIZE<=0 {
            end=nil
        } else  {
            end=-self.__TAIL_SIZE
        self.__BODY_SIZE=len(aBuffer[self.__HEADER_SIZE:end])
        self.__body.set_bytes_from_string(aBuffer[self.__HEADER_SIZE:end])
        
     func (self TYPE) __extract_tail(aBuffer interface{}){
        if self.__TAIL_SIZE<=0 {
            // leave the array empty
            return
        } else  {
            start=-self.__TAIL_SIZE
        self.__tail.set_bytes_from_string(aBuffer[start:])

     func (self TYPE) load_packet(aBuffer interface{}){
        "Load the whole packet from a string" \
        "WARNING: Using this function will break the hierarchy of preceding protocol layer"
        self.unlink_child()
        
        self.__extract_header(aBuffer)
        self.__extract_body(aBuffer)
        self.__extract_tail(aBuffer)
        
     func (self TYPE) get_header_as_string(){
        return self.__header.get_buffer_as_string()
        
     func (self TYPE) get_body_as_string(){
        self.__update_body_from_child()
        return self.__body.get_buffer_as_string()
    body_string = property(get_body_as_string)
    
     func (self TYPE) get_tail_as_string(){
        return self.__tail.get_buffer_as_string()
    tail_string = property(get_tail_as_string)
        
     func (self TYPE) get_packet(){
        self.__update_body_from_child()
        
        ret = b''
        
        header = self.get_header_as_string()
        if header {
            ret += header

        body = self.get_body_as_string()
        if body {
            ret += body
        
        tail = self.get_tail_as_string()    
        if tail {
            ret += tail
            
        return ret

 type Header struct { // PacketBuffer,ProtocolLayer:
    "This is the base  type from which all protocol definitions extend." struct {

    packet_printable = [c for c in string.printable if c not in string.whitespace] + [" "]

    ethertype = nil
    protocol = nil
     func (self TYPE) __init__(length = nil interface{}){
        PacketBuffer.__init__(self, length)
        self.auto_checksum = 1

     func (self TYPE) get_data_as_string(){
        "Returns all data from children of this header as string"

        if self.child() {
            return self.child().get_packet()
        } else  {
            return nil

     func (self TYPE) get_packet(){
        """Returns the raw representation of this packet and its
        children as a string. The output from this method is a packet
        ready to be transmitted over the wire.
        """
        self.calculate_checksum()

        data = self.get_data_as_string()
        if data {
            return self.get_buffer_as_string() + data
        } else  {
            return self.get_buffer_as_string()

     func (self TYPE) get_size(){
        "Return the size of this header and all of it's children"
        tmp_value = self.get_header_size()
        if self.child() {
            tmp_value = tmp_value + self.child().get_size()
        return tmp_value

     func (self TYPE) calculate_checksum(){
        "Calculate and set the checksum for this header"
        pass

     func (self TYPE) get_pseudo_header(){
        "Pseudo headers can be used to limit over what content will the checksums be calculated."
        // default implementation returns empty array
        return array.array("B")

     func (self TYPE) load_header(aBuffer interface{}){
        "Properly set the state of this instance to reflect that of the raw packet passed as argument."
        self.set_bytes_from_string(aBuffer)
        hdr_len = self.get_header_size()
        if(len(aBuffer) < hdr_len):         //we must do something like this
            diff = hdr_len - len(aBuffer)
            for i in range(0, diff):
                aBuffer += '\x00'
        self.set_bytes_from_string(aBuffer[:hdr_len])

     func (self TYPE) get_header_size(){
        "Return the size of this header, that is, not counting neither the size of the children nor of the parents."
        raise RuntimeError("Method %s.get_header_size must be overridden." % self.__class__)

     func (self TYPE) list_as_hex(aList interface{}){
        if len(aList) {
            ltmp = []
            line = []
            count = 0
            for byte in aList:
                if not (count % 2) {
                    if (count % 16) {
                        ltmp.append(" ")
                    } else  {
                        ltmp.append(' '*4)
                        ltmp.append(''.join(line))
                        ltmp.append("\n")
                        line = []
                if chr(byte) in Header.packet_printable {
                    line.append(chr(byte))
                } else  {
                    line.append(".")
                ltmp.append('%.2x' % byte)
                count += 1
            if (count%16) {
                left = 16 - (count%16)
                ltmp.append(' ' * (4+(left // 2) + (left*2)))
                ltmp.append(''.join(line))
                ltmp.append("\n")
            return ltmp
        } else  {
            return []

     func (self TYPE) __str__(){
        ltmp = self.list_as_hex(self.get_bytes().tolist())

        if self.child() {
            ltmp.append(['\n', str(self.child())])

        if len(ltmp)>0 {
            return ''.join(ltmp)
        } else  {
            return ''



 type Data struct { // Header:
    """This packet type can hold raw data. It's normally employed to
    hold a packet's innermost layer's contents in those cases for
    which the protocol details are unknown, and there's a copy of a
    valid packet available.

    For instance, if all that's known about a certain protocol is that
    a UDP packet with its contents set to "HELLO" initiate a new
    session, creating such packet is as simple as in the following code
    fragment:
    packet = UDP()
    packet.contains("HELLO")
    """

     func (self TYPE) __init__(aBuffer = nil interface{}){
        Header.__init__(self)
        if aBuffer {
            self.set_data(aBuffer)

     func (self TYPE) set_data(data interface{}){
        self.set_bytes_from_string(data)

     func (self TYPE) get_size(){
        return len(self.get_bytes())


 type EthernetTag struct { // PacketBuffer:
    """Represents a VLAN header specified in IEEE 802.1Q and 802.1ad.
       Provides methods for convenient manipulation with header fields."""

     func (self TYPE) __init__(value=0x81000000 interface{}){
        PacketBuffer.__init__(self, 4)
        self.set_long(0, value)

     func (self TYPE) get_tpid(){
        """Returns Tag Protocol Identifier"""
        return self.get_word(0)

     func (self TYPE) set_tpid(value interface{}){
        """Sets Tag Protocol Identifier"""
        return self.set_word(0, value)

     func (self TYPE) get_pcp(){
        """Returns Priority Code Point"""
        return (self.get_byte(2) & 0xE0) >> 5

     func (self TYPE) set_pcp(value interface{}){
        """Sets Priority Code Point"""
        orig_value = self.get_byte(2)
        self.set_byte(2, (orig_value & 0x1F) | ((value & 0x07) << 5))

     func (self TYPE) get_dei(){
        """Returns Drop Eligible Indicator"""
        return (self.get_byte(2) & 0x10) >> 4

     func (self TYPE) set_dei(value interface{}){
        """Sets Drop Eligible Indicator"""
        orig_value = self.get_byte(2)
        self.set_byte(2, orig_value | 0x10 if value else orig_value & 0xEF)

     func (self TYPE) get_vid(){
        """Returns VLAN Identifier"""
        return self.get_word(2) & 0x0FFF

     func (self TYPE) set_vid(value interface{}){
        """Sets VLAN Identifier"""
        orig_value = self.get_word(2)
        self.set_word(2, (orig_value & 0xF000) | (value & 0x0FFF))

     func (self TYPE) __str__(){
        priorities = (
            'Best Effort',
            'Background',
            'Excellent Effort',
            'Critical Applications',
            'Video, < 100 ms latency and jitter',
            'Voice, < 10 ms latency and jitter',
            'Internetwork Control',
            'Network Control')

        pcp = self.get_pcp()
        return '\n'.join((
            '802.1Q header: 0x{0:08X}'.format(self.get_long(0)),
            'Priority Code Point: {0} ({1})'.format(pcp, priorities[pcp]),
            'Drop Eligible Indicator: {0}'.format(self.get_dei()),
            'VLAN Identifier: {0}'.format(self.get_vid())))


 type Ethernet struct { // Header:
     func (self TYPE) __init__(aBuffer = nil interface{}){
        Header.__init__(self, 14)
        self.tag_cnt = 0
        if(aBuffer):
            self.load_header(aBuffer)

     func (self TYPE) set_ether_type(aValue interface{}){
        "Set ethernet data type field to 'aValue'"
        self.set_word(12 + 4*self.tag_cnt, aValue)

     func (self TYPE) get_ether_type(){
        "Return ethernet data type field"
        return self.get_word(12 + 4*self.tag_cnt)

     func (self TYPE) get_tag(index interface{}){
        """Returns an EthernetTag initialized from index-th VLAN tag.
           The tags are numbered from 0 to self.tag_cnt-1 as they appear in the frame.
           It is possible to use negative indexes as well."""
        index = self.__validate_tag_index(index)
        return EthernetTag(self.get_long(12+4*index))

     func (self TYPE) set_tag(index, tag interface{}){
        """Sets the index-th VLAN tag to contents of an EthernetTag object.
           The tags are numbered from 0 to self.tag_cnt-1 as they appear in the frame.
           It is possible to use negative indexes as well."""
        index = self.__validate_tag_index(index)
        pos = 12 + 4*index
        for i,val in enumerate(tag.get_bytes()):
            self.set_byte(pos+i, val)

     func (self TYPE) push_tag(tag, index=0 interface{}){
        """Inserts contents of an EthernetTag object before the index-th VLAN tag.
           Index defaults to 0 (the top of the stack)."""
        if index < 0 {
            index += self.tag_cnt
        pos = 12 + 4*max(0, min(index, self.tag_cnt))
        data = self.get_bytes()
        data[pos:pos] = tag.get_bytes()
        self.set_bytes(data)
        self.tag_cnt += 1

     func (self TYPE) pop_tag(index=0 interface{}){
        """Removes the index-th VLAN tag and returns it as an EthernetTag object.
           Index defaults to 0 (the top of the stack)."""
        index = self.__validate_tag_index(index)
        pos = 12 + 4*index
        tag = self.get_long(pos)
        data = self.get_bytes()
        del data[pos:pos+4]
        self.set_bytes(data)
        self.tag_cnt -= 1
        return EthernetTag(tag)

     func (self TYPE) load_header(aBuffer interface{}){
        self.tag_cnt = 0
        while aBuffer[12+4*self.tag_cnt:14+4*self.tag_cnt] in (b'\x81\x00', b'\x88\xa8', b'\x91\x00'):
            self.tag_cnt += 1

        hdr_len = self.get_header_size()
        diff = hdr_len - len(aBuffer)
        if diff > 0 {
            aBuffer += b'\x00'*diff
        self.set_bytes_from_string(aBuffer[:hdr_len])

     func (self TYPE) get_header_size(){
        "Return size of Ethernet header"
        return 14 + 4*self.tag_cnt

     func (self TYPE) get_packet(){

        if self.child() {
            try:
                self.set_ether_type(self.child().ethertype)
            except:
                " an Ethernet packet may have a Data() "
                pass
        return Header.get_packet(self)

     func (self TYPE) get_ether_dhost(){
        "Return 48 bit destination ethernet address as a 6 byte array"
        return self.get_bytes()[0:6]

     func (self TYPE) set_ether_dhost(aValue interface{}){
        "Set destination ethernet address from 6 byte array 'aValue'"
        for i in range(0, 6):
            self.set_byte(i, aValue[i])

     func (self TYPE) get_ether_shost(){
        "Return 48 bit source ethernet address as a 6 byte array"
        return self.get_bytes()[6:12]

     func (self TYPE) set_ether_shost(aValue interface{}){
        "Set source ethernet address from 6 byte array 'aValue'"
        for i in range(0, 6):
            self.set_byte(i + 6, aValue[i])

    @staticmethod
     func as_eth_addr(anArray interface{}){
        tmp_list = [x > 15 and '%x'%x or '0%x'%x for x in anArray]
        return '' + reduce(lambda x, y: x+':'+y, tmp_list)

     func (self TYPE) __str__(){
        tmp_str = "Ether: " + self.as_eth_addr(self.get_ether_shost()) + ' -> '
        tmp_str += self.as_eth_addr(self.get_ether_dhost())
        if self.child() {
            tmp_str += '\n' + str( self.child())
        return tmp_str

     func (self TYPE) __validate_tag_index(index interface{}){
        """Adjusts negative indices to their absolute equivalents.
           Raises IndexError when out of range <0, self.tag_cnt-1>."""
        if index < 0 {
            index += self.tag_cnt
        if index < 0 or index >= self.tag_cnt {
            raise IndexError("Tag index out of range")
        return index

// Linux "cooked" capture encapsulation.
// Used, for instance, for packets returned by the "any" interface.
 type LinuxSLL struct { // Header:
    type_descriptions = [
        "sent to us by somebody else",
        "broadcast by somebody else",
        "multicast by somebody else",
        "sent to somebody else to somebody else",
        "sent by us",
        ]

     func (self TYPE) __init__(aBuffer = nil interface{}){
        Header.__init__(self, 16)
        if (aBuffer) {
            self.load_header(aBuffer)

     func (self TYPE) set_type(type interface{}){
        "Sets the packet type field to type"
        self.set_word(0, type)

     func (self TYPE) get_type(){
        "Returns the packet type field"
        return self.get_word(0)

     func (self TYPE) set_arphdr(value interface{}){
        "Sets the ARPHDR value for the link layer device type"
        self.set_word(2, type)

     func (self TYPE) get_arphdr(){
        "Returns the ARPHDR value for the link layer device type"
        return self.get_word(2)

     func (self TYPE) set_addr_len(len interface{}){
        "Sets the length of the sender's address field to len"
        self.set_word(4, len)

     func (self TYPE) get_addr_len(){
        "Returns the length of the sender's address field"
        return self.get_word(4)

     func (self TYPE) set_addr(addr interface{}){
        "Sets the sender's address field to addr. Addr must be at most 8-byte long."
        if (len(addr) < 8) {
            addr += b'\0' * (8 - len(addr))
        self.get_bytes()[6:14] = addr

     func (self TYPE) get_addr(){
        "Returns the sender's address field"
        return self.get_bytes()[6:14].tostring()

     func (self TYPE) set_ether_type(aValue interface{}){
        "Set ethernet data type field to 'aValue'"
        self.set_word(14, aValue)

     func (self TYPE) get_ether_type(){
        "Return ethernet data type field"
        return self.get_word(14)

     func (self TYPE) get_header_size(){
        "Return size of packet header"
        return 16

     func (self TYPE) get_packet(){
        if self.child() {
            self.set_ether_type(self.child().ethertype)
        return Header.get_packet(self)

     func (self TYPE) get_type_desc(){
        type = self.get_type()
        if type < len(LinuxSLL.type_descriptions) {
            return LinuxSLL.type_descriptions[type]
        } else  {
            return "Unknown"

     func (self TYPE) __str__(){
        ss = []
        alen = self.get_addr_len()
        addr = hexlify(self.get_addr()[0:alen])
        ss.append("Linux SLL: addr=%s type=`%s'" % (addr, self.get_type_desc()))
        if self.child() {
            ss.append(str(self.child()))

        return '\n'.join(ss)


 type IP struct { // Header:
    ethertype = 0x800
     func (self TYPE) __init__(aBuffer = nil interface{}){
        Header.__init__(self, 20)
        self.set_ip_v(4)
        self.set_ip_hl(5)
        self.set_ip_ttl(255)
        self.__option_list = []
        if(aBuffer):
            // When decoding, checksum shouldn't be modified
            self.auto_checksum = 0
            self.load_header(aBuffer)
            
        if sys.platform.count("bsd") {
            self.is_BSD = true
        } else  {
            self.is_BSD = false


     func (self TYPE) get_packet(){
        // set protocol
        if self.get_ip_p() == 0 and self.child() {
            self.set_ip_p(self.child().protocol)

        // set total length
        if self.get_ip_len() == 0 {
            self.set_ip_len(self.get_size())

        child_data = self.get_data_as_string()

        if self.auto_checksum {
            self.reset_ip_sum()

        my_bytes = self.get_bytes()

        for op in self.__option_list:
            my_bytes.extend(op.get_bytes())

        // Pad to a multiple of 4 bytes
        num_pad = (4 - (len(my_bytes) % 4)) % 4
        if num_pad {
            my_bytes.fromstring(b"\0"* num_pad)

        // only change ip_hl value if options are present
        if len(self.__option_list) {
            self.set_ip_hl(len(my_bytes) // 4)


        // set the checksum if the user hasn't modified it
        if self.auto_checksum {
            self.set_ip_sum(self.compute_checksum(my_bytes))

        if child_data == nil {
            return my_bytes.tostring()
        } else  {
            return my_bytes.tostring() + child_data



    //   func (self TYPE) calculate_checksum(buffer = nil interface{}){
    //      tmp_value = self.get_ip_sum()
    //      if self.auto_checksum and (not tmp_value) {
    //          if buffer {
    //              tmp_bytes = buffer
    //          } else  {
    //              tmp_bytes = self.bytes[0:self.get_header_size()]
    //
    //          self.set_ip_sum(self.compute_checksum(tmp_bytes))


     func (self TYPE) get_pseudo_header(){
        pseudo_buf = array.array("B")
        pseudo_buf.extend(self.get_bytes()[12:20])
        pseudo_buf.fromlist([0])
        pseudo_buf.extend(self.get_bytes()[9:10])
        tmp_size = self.child().get_size()

        size_str = struct.pack("!H", tmp_size)

        pseudo_buf.fromstring(size_str)
        return pseudo_buf

     func (self TYPE) add_option(option interface{}){
        self.__option_list.append(option)
        sum = 0
        for op in self.__option_list:
            sum += op.get_len()
        if sum > 40 {
            raise ImpactPacketException("Options overflowed in IP packet with length: %d" % sum)


     func (self TYPE) get_ip_v(){
        n = self.get_byte(0)
        return (n >> 4)

     func (self TYPE) set_ip_v(value interface{}){
        n = self.get_byte(0)
        version = value & 0xF
        n = n & 0xF
        n = n | (version << 4)
        self.set_byte(0, n)

     func (self TYPE) get_ip_hl(){
        n = self.get_byte(0)
        return (n & 0xF)

     func (self TYPE) set_ip_hl(value interface{}){
        n = self.get_byte(0)
        len = value & 0xF
        n = n & 0xF0
        n = (n | len)
        self.set_byte(0, n)

     func (self TYPE) get_ip_tos(){
        return self.get_byte(1)

     func set_ip_tos(self,value interface{}){
        self.set_byte(1, value)

     func (self TYPE) get_ip_len(){
        if self.is_BSD {
            return self.get_word(2, order = "=")
        } else  {
            return self.get_word(2)

     func (self TYPE) set_ip_len(value interface{}){
        if self.is_BSD {
            self.set_word(2, value, order = "=")
        } else  {
            self.set_word(2, value)

     func (self TYPE) get_ip_id(){
        return self.get_word(4)
     func (self TYPE) set_ip_id(value interface{}){
        return self.set_word(4, value)

     func (self TYPE) get_ip_off(){
        if self.is_BSD {
            return self.get_word(6, order = "=")
        } else  {
            return self.get_word(6)

     func (self TYPE) set_ip_off(aValue interface{}){
        if self.is_BSD {
            self.set_word(6, aValue, order = "=")
        } else  {
            self.set_word(6, aValue)

     func (self TYPE) get_ip_offmask(){
        return self.get_ip_off() & 0x1FFF

     func (self TYPE) set_ip_offmask(aValue interface{}){
        tmp_value = self.get_ip_off() & 0xD000
        tmp_value |= aValue
        self.set_ip_off(tmp_value)

     func (self TYPE) get_ip_rf(){
        return self.get_ip_off() & 0x8000

     func (self TYPE) set_ip_rf(aValue interface{}){
        tmp_value = self.get_ip_off()
        if aValue {
            tmp_value |= 0x8000
        } else  {
            my_not = 0xFFFF ^ 0x8000
            tmp_value &= my_not
        self.set_ip_off(tmp_value)

     func (self TYPE) get_ip_df(){
        return self.get_ip_off() & 0x4000

     func (self TYPE) set_ip_df(aValue interface{}){
        tmp_value = self.get_ip_off()
        if aValue {
            tmp_value |= 0x4000
        } else  {
            my_not = 0xFFFF ^ 0x4000
            tmp_value &= my_not
        self.set_ip_off(tmp_value)

     func (self TYPE) get_ip_mf(){
        return self.get_ip_off() & 0x2000

     func (self TYPE) set_ip_mf(aValue interface{}){
        tmp_value = self.get_ip_off()
        if aValue {
            tmp_value |= 0x2000
        } else  {
            my_not = 0xFFFF ^ 0x2000
            tmp_value &= my_not
        self.set_ip_off(tmp_value)


     func (self TYPE) fragment_by_list(aList interface{}){
        if self.child() {
            proto = self.child().protocol
        } else  {
            proto = 0

        child_data = self.get_data_as_string()
        if not child_data {
            return [self]

        ip_header_bytes = self.get_bytes()
        current_offset = 0
        fragment_list = []

        for frag_size in aList:
            ip = IP()
            ip.set_bytes(ip_header_bytes) // copy of original header
            ip.set_ip_p(proto)


            if frag_size % 8 {   // round this fragment size up to next multiple of 8
                frag_size += 8 - (frag_size % 8)


            ip.set_ip_offmask(current_offset // 8)
            current_offset += frag_size

            data = Data(child_data[:frag_size])
            child_data = child_data[frag_size:]

            ip.set_ip_len(20 + data.get_size())
            ip.contains(data)


            if child_data {

                ip.set_ip_mf(1)

                fragment_list.append(ip)
            } else  { // no more data bytes left to add to fragments

                ip.set_ip_mf(0)

                fragment_list.append(ip)
                return fragment_list

        if child_data { // any remaining data?
            // create a fragment containing all of the remaining child_data
            ip = IP()
            ip.set_bytes(ip_header_bytes)
            ip.set_ip_offmask(current_offset)
            ip.set_ip_len(20 + len(child_data))
            data = Data(child_data)
            ip.contains(data)
            fragment_list.append(ip)

        return fragment_list


     func (self TYPE) fragment_by_size(aSize interface{}){
        data_len = len(self.get_data_as_string())
        num_frags = data_len // aSize

        if data_len % aSize {
            num_frags += 1

        size_list = []
        for i in range(0, num_frags):
            size_list.append(aSize)
        return self.fragment_by_list(size_list)


     func (self TYPE) get_ip_ttl(){
        return self.get_byte(8)
     func (self TYPE) set_ip_ttl(value interface{}){
        self.set_byte(8, value)

     func (self TYPE) get_ip_p(){
        return self.get_byte(9)

     func (self TYPE) set_ip_p(value interface{}){
        self.set_byte(9, value)

     func (self TYPE) get_ip_sum(){
        return self.get_word(10)
     func (self TYPE) set_ip_sum(value interface{}){
        self.auto_checksum = 0
        self.set_word(10, value)

     func (self TYPE) reset_ip_sum(){
        self.set_ip_sum(0x0000)
        self.auto_checksum = 1

     func (self TYPE) get_ip_src(){
        return self.get_ip_address(12)
     func (self TYPE) set_ip_src(value interface{}){
        self.set_ip_address(12, value)

     func (self TYPE) get_ip_dst(){
        return self.get_ip_address(16)

     func (self TYPE) set_ip_dst(value interface{}){
        self.set_ip_address(16, value)

     func (self TYPE) get_header_size(){
        op_len = 0
        for op in self.__option_list:
            op_len += op.get_len()

        num_pad = (4 - (op_len % 4)) % 4

        return 20 + op_len + num_pad

     func (self TYPE) load_header(aBuffer interface{}){
        self.set_bytes_from_string(aBuffer[:20])
        opt_left = (self.get_ip_hl() - 5) * 4
        opt_bytes = array.array('B', aBuffer[20:(20 + opt_left)])
        if len(opt_bytes) != opt_left {
            raise ImpactPacketException("Cannot load options from truncated packet")


        while opt_left:
            op_type = opt_bytes[0]
            if op_type == IPOption.IPOPT_EOL or op_type == IPOption.IPOPT_NOP {
                new_option = IPOption(op_type)
                op_len = 1
            } else  {
                op_len = opt_bytes[1]
                if op_len > len(opt_bytes) {
                    raise ImpactPacketException("IP Option length is too high")

                new_option = IPOption(op_type, op_len)
                new_option.set_bytes(opt_bytes[:op_len])

            opt_bytes = opt_bytes[op_len:]
            opt_left -= op_len
            self.add_option(new_option)
            if op_type == IPOption.IPOPT_EOL {
                break


     func (self TYPE) __str__(){
        flags = " "
        if self.get_ip_df() {
            flags += 'DF '
        if self.get_ip_mf() {
            flags += 'MF '
        if self.get_ip_rf() {
            flags += 'RF '
        tmp_str = "IP%s%s -> %s " % (flags, self.get_ip_src(),self.get_ip_dst())
        for op in self.__option_list:
            tmp_str += '\n' + str(op)
        if self.child() {
            tmp_str += '\n' + str(self.child())
        return tmp_str


 type IPOption struct { // PacketBuffer:
    IPOPT_EOL = 0
    IPOPT_NOP = 1
    IPOPT_RR = 7
    IPOPT_TS = 68
    IPOPT_LSRR = 131
    IPOPT_SSRR = 137

     func (self TYPE) __init__(opcode = 0, size = nil interface{}){
        if size and (size < 3 or size > 40) {
            raise ImpactPacketException("IP Options must have a size between 3 and 40 bytes")

        if(opcode == IPOption.IPOPT_EOL):
            PacketBuffer.__init__(self, 1)
            self.set_code(IPOption.IPOPT_EOL)
        elif(opcode == IPOption.IPOPT_NOP):
            PacketBuffer.__init__(self, 1)
            self.set_code(IPOption.IPOPT_NOP)
        elif(opcode == IPOption.IPOPT_RR):
            if not size {
                size = 39
            PacketBuffer.__init__(self, size)
            self.set_code(IPOption.IPOPT_RR)
            self.set_len(size)
            self.set_ptr(4)

        elif(opcode == IPOption.IPOPT_LSRR):
            if not size {
                size = 39
            PacketBuffer.__init__(self, size)
            self.set_code(IPOption.IPOPT_LSRR)
            self.set_len(size)
            self.set_ptr(4)

        elif(opcode == IPOption.IPOPT_SSRR):
            if not size {
                size = 39
            PacketBuffer.__init__(self, size)
            self.set_code(IPOption.IPOPT_SSRR)
            self.set_len(size)
            self.set_ptr(4)

        elif(opcode == IPOption.IPOPT_TS):
            if not size {
                size = 40
            PacketBuffer.__init__(self, size)
            self.set_code(IPOption.IPOPT_TS)
            self.set_len(size)
            self.set_ptr(5)
            self.set_flags(0)
        } else  {
            if not size {
                raise ImpactPacketException("Size required for this type")
            PacketBuffer.__init__(self,size)
            self.set_code(opcode)
            self.set_len(size)


     func (self TYPE) append_ip(ip interface{}){
        op = self.get_code()
        if not (op == IPOption.IPOPT_RR or op == IPOption.IPOPT_LSRR or op == IPOption.IPOPT_SSRR or op == IPOption.IPOPT_TS) {
            raise ImpactPacketException("append_ip() not support for option type %d" % self.opt_type)

        p = self.get_ptr()
        if not p {
            raise ImpactPacketException("append_ip() failed, option ptr uninitialized")

        if (p + 4) > self.get_len() {
            raise ImpactPacketException("append_ip() would overflow option")

        self.set_ip_address(p - 1, ip)
        p += 4
        self.set_ptr(p)


     func (self TYPE) set_code(value interface{}){
        self.set_byte(0, value)

     func (self TYPE) get_code(){
        return self.get_byte(0)


     func (self TYPE) set_flags(flags interface{}){
        if not (self.get_code() == IPOption.IPOPT_TS) {
            raise ImpactPacketException("Operation only supported on Timestamp option")
        self.set_byte(3, flags)

     func (self TYPE) get_flags(flags interface{}){
        if not (self.get_code() == IPOption.IPOPT_TS) {
            raise ImpactPacketException("Operation only supported on Timestamp option")
        return self.get_byte(3)


     func (self TYPE) set_len(len interface{}){
        self.set_byte(1, len)


     func (self TYPE) set_ptr(ptr interface{}){
        self.set_byte(2, ptr)

     func (self TYPE) get_ptr(){
        return self.get_byte(2)

     func (self TYPE) get_len(){
        return len(self.get_bytes())


     func (self TYPE) __str__(){
        map = {IPOption.IPOPT_EOL : "End of List ",
               IPOption.IPOPT_NOP : "No Operation ",
               IPOption.IPOPT_RR  : "Record Route ",
               IPOption.IPOPT_TS  : "Timestamp ",
               IPOption.IPOPT_LSRR : "Loose Source Route ",
               IPOption.IPOPT_SSRR : "Strict Source Route "}

        tmp_str = "\tIP Option: "
        op = self.get_code()
        if op in map {
            tmp_str += map[op]
        } else  {
            tmp_str += "Code: %d " % op

        if op == IPOption.IPOPT_RR or op == IPOption.IPOPT_LSRR or op ==IPOption.IPOPT_SSRR {
            tmp_str += self.print_addresses()


        return tmp_str


     func (self TYPE) print_addresses(){
        p = 3
        tmp_str = "["
        if self.get_len() >= 7 { // at least one complete IP address
            while 1:
                if p + 1 == self.get_ptr() {
                    tmp_str += "//"
                tmp_str += self.get_ip_address(p)
                p += 4
                if p >= self.get_len() {
                    break
                } else  {
                    tmp_str += ", "
        tmp_str += "] "
        if self.get_ptr() % 4 { // ptr field should be a multiple of 4
            tmp_str += "nonsense ptr field: %d " % self.get_ptr()
        return tmp_str


 type UDP struct { // Header:
    protocol = 17
     func (self TYPE) __init__(aBuffer = nil interface{}){
        Header.__init__(self, 8)
        if(aBuffer):
            self.load_header(aBuffer)

     func (self TYPE) get_uh_sport(){
        return self.get_word(0)
     func (self TYPE) set_uh_sport(value interface{}){
        self.set_word(0, value)

     func (self TYPE) get_uh_dport(){
        return self.get_word(2)
     func (self TYPE) set_uh_dport(value interface{}){
        self.set_word(2, value)

     func (self TYPE) get_uh_ulen(){
        return self.get_word(4)

     func (self TYPE) set_uh_ulen(value interface{}){
        self.set_word(4, value)

     func (self TYPE) get_uh_sum(){
        return self.get_word(6)

     func (self TYPE) set_uh_sum(value interface{}){
        self.set_word(6, value)
        self.auto_checksum = 0

     func (self TYPE) calculate_checksum(){
        if self.auto_checksum and (not self.get_uh_sum()) {
            // if there isn't a parent to grab a pseudo-header from we'll assume the user knows what they're doing
            // and won't meddle with the checksum or throw an exception
            if not self.parent() {
                return

            buffer = self.parent().get_pseudo_header()

            buffer += self.get_bytes()
            data = self.get_data_as_string()
            if(data):
                buffer.fromstring(data)
            self.set_uh_sum(self.compute_checksum(buffer))

     func (self TYPE) get_header_size(){
        return 8

     func (self TYPE) __str__(){
        tmp_str = "UDP %d -> %d" % (self.get_uh_sport(), self.get_uh_dport())
        if self.child() {
            tmp_str += '\n' + str(self.child())
        return tmp_str

     func (self TYPE) get_packet(){
        // set total length
        if(self.get_uh_ulen() == 0):
            self.set_uh_ulen(self.get_size())
        return Header.get_packet(self)

 type TCP struct { // Header:
    protocol = 6
    TCP_FLAGS_MASK = 0x00FF // lowest 16 bits are the flags
     func (self TYPE) __init__(aBuffer = nil interface{}){
        Header.__init__(self, 20)
        self.set_th_off(5)
        self.__option_list = []
        if aBuffer {
            self.load_header(aBuffer)

     func (self TYPE) add_option(option interface{}){
        self.__option_list.append(option)

        sum = 0
        for op in self.__option_list:
            sum += op.get_size()

        if sum > 40 {
            raise ImpactPacketException("Cannot add TCP option, would overflow option space")

     func (self TYPE) get_options(){
        return self.__option_list

     func (self TYPE) swapSourceAndDestination(){
        oldSource = self.get_th_sport()
        self.set_th_sport(self.get_th_dport())
        self.set_th_dport(oldSource)

    //
    // Header field accessors
    //

     func (self TYPE) set_th_sport(aValue interface{}){
        self.set_word(0, aValue)

     func (self TYPE) get_th_sport(){
        return self.get_word(0)

     func (self TYPE) get_th_dport(){
        return self.get_word(2)

     func (self TYPE) set_th_dport(aValue interface{}){
        self.set_word(2, aValue)

     func (self TYPE) get_th_seq(){
        return self.get_long(4)

     func (self TYPE) set_th_seq(aValue interface{}){
        self.set_long(4, aValue)

     func (self TYPE) get_th_ack(){
        return self.get_long(8)

     func (self TYPE) set_th_ack(aValue interface{}){
        self.set_long(8, aValue)

     func (self TYPE) get_th_flags(){
        return self.get_word(12) & self.TCP_FLAGS_MASK
    
     func (self TYPE) set_th_flags(aValue interface{}){
        masked = self.get_word(12) & (~self.TCP_FLAGS_MASK)
        nb = masked | (aValue & self.TCP_FLAGS_MASK)
        return self.set_word(12, nb, ">")
     
     func (self TYPE) get_th_win(){
        return self.get_word(14)

     func (self TYPE) set_th_win(aValue interface{}){
        self.set_word(14, aValue)

     func (self TYPE) set_th_sum(aValue interface{}){
        self.set_word(16, aValue)
        self.auto_checksum = 0

     func (self TYPE) get_th_sum(){
        return self.get_word(16)

     func (self TYPE) get_th_urp(){
        return self.get_word(18)

     func (self TYPE) set_th_urp(aValue interface{}){
        return self.set_word(18, aValue)

    // Flag accessors

     func (self TYPE) get_th_reserved(){
        tmp_value = self.get_byte(12) & 0x0f
        return tmp_value


     func (self TYPE) get_th_off(){
        tmp_value = self.get_byte(12) >> 4
        return tmp_value

     func (self TYPE) set_th_off(aValue interface{}){
        mask = 0xF0
        masked = self.get_byte(12) & (~mask)
        nb = masked | ( (aValue << 4) & mask)
        return self.set_byte(12, nb)

     func (self TYPE) get_CWR(){
        return self.get_flag(128)
     func (self TYPE) set_CWR(){
        return self.set_flags(128)
     func (self TYPE) reset_CWR(){
        return self.reset_flags(128)

     func (self TYPE) get_ECE(){
        return self.get_flag(64)
     func (self TYPE) set_ECE(){
        return self.set_flags(64)
     func (self TYPE) reset_ECE(){
        return self.reset_flags(64)

     func (self TYPE) get_URG(){
        return self.get_flag(32)
     func (self TYPE) set_URG(){
        return self.set_flags(32)
     func (self TYPE) reset_URG(){
        return self.reset_flags(32)

     func (self TYPE) get_ACK(){
        return self.get_flag(16)
     func (self TYPE) set_ACK(){
        return self.set_flags(16)
     func (self TYPE) reset_ACK(){
        return self.reset_flags(16)

     func (self TYPE) get_PSH(){
        return self.get_flag(8)
     func (self TYPE) set_PSH(){
        return self.set_flags(8)
     func (self TYPE) reset_PSH(){
        return self.reset_flags(8)

     func (self TYPE) get_RST(){
        return self.get_flag(4)
     func (self TYPE) set_RST(){
        return self.set_flags(4)
     func (self TYPE) reset_RST(){
        return self.reset_flags(4)

     func (self TYPE) get_SYN(){
        return self.get_flag(2)
     func (self TYPE) set_SYN(){
        return self.set_flags(2)
     func (self TYPE) reset_SYN(){
        return self.reset_flags(2)

     func (self TYPE) get_FIN(){
        return self.get_flag(1)
     func (self TYPE) set_FIN(){
        return self.set_flags(1)
     func (self TYPE) reset_FIN(){
        return self.reset_flags(1)

    // Overridden Methods

     func (self TYPE) get_header_size(){
        return 20 + len(self.get_padded_options())

     func (self TYPE) calculate_checksum(){
        if not self.auto_checksum or not self.parent() {
            return

        self.set_th_sum(0)
        buffer = self.parent().get_pseudo_header()
        buffer += self.get_bytes()
        buffer += self.get_padded_options()

        data = self.get_data_as_string()
        if(data):
            buffer.fromstring(data)

        res = self.compute_checksum(buffer)

        self.set_th_sum(self.compute_checksum(buffer))

     func (self TYPE) get_packet(){
        "Returns entire packet including child data as a string.  This is the function used to extract the final packet"

        // only change th_off value if options are present
        if len(self.__option_list) {
            self.set_th_off(self.get_header_size() // 4)

        self.calculate_checksum()

        bytes = self.get_bytes() + self.get_padded_options()
        data = self.get_data_as_string()

        if data {
            return bytes.tostring() + data
        } else  {
            return bytes.tostring()

     func (self TYPE) load_header(aBuffer interface{}){
        self.set_bytes_from_string(aBuffer[:20])
        opt_left = (self.get_th_off() - 5) * 4
        opt_bytes = array.array('B', aBuffer[20:(20 + opt_left)])
        if len(opt_bytes) != opt_left {
            raise ImpactPacketException("Cannot load options from truncated packet")

        while opt_left:
            op_kind = opt_bytes[0]
            if op_kind == TCPOption.TCPOPT_EOL or op_kind == TCPOption.TCPOPT_NOP {
                new_option = TCPOption(op_kind)
                op_len = 1
            } else  {
                op_len = opt_bytes[1]
                if op_len > len(opt_bytes) {
                    raise ImpactPacketException("TCP Option length is too high")
                if op_len < 2 {
                    raise ImpactPacketException("TCP Option length is too low")

                new_option = TCPOption(op_kind)
                new_option.set_bytes(opt_bytes[:op_len])

            opt_bytes = opt_bytes[op_len:]
            opt_left -= op_len
            self.add_option(new_option)
            if op_kind == TCPOption.TCPOPT_EOL {
                break

    //
    // Private
    //

     func (self TYPE) get_flag(bit interface{}){
        if self.get_th_flags() & bit {
            return 1
        } else  {
            return 0

     func (self TYPE) reset_flags(aValue interface{}){
        tmp_value = self.get_th_flags() & (~aValue)
        return self.set_th_flags(tmp_value)

     func (self TYPE) set_flags(aValue interface{}){
        tmp_value =  self.get_th_flags() | aValue
        return self.set_th_flags(tmp_value)

     func (self TYPE) get_padded_options(){
        "Return an array containing all options padded to a 4 byte boundary"
        op_buf = array.array("B")
        for op in self.__option_list:
            op_buf += op.get_bytes()
        num_pad = (4 - (len(op_buf) % 4)) % 4
        if num_pad {
            op_buf.fromstring("\0" * num_pad)
        return op_buf

     func (self TYPE) __str__(){
        tmp_str = "TCP "
        if self.get_ECE() {
            tmp_str += 'ece '
        if self.get_CWR() {
            tmp_str += 'cwr '
        if self.get_ACK() {
            tmp_str += 'ack '
        if self.get_FIN() {
            tmp_str += 'fin '
        if self.get_PSH() {
            tmp_str += 'push '
        if self.get_RST() {
            tmp_str += 'rst '
        if self.get_SYN() {
            tmp_str += 'syn '
        if self.get_URG() {
            tmp_str += 'urg '
        tmp_str += '%d -> %d' % (self.get_th_sport(), self.get_th_dport())
        for op in self.__option_list:
            tmp_str += '\n' + str(op)

        if self.child() {
            tmp_str += '\n' + str(self.child())
        return tmp_str


 type TCPOption struct { // PacketBuffer:
    TCPOPT_EOL =             0
    TCPOPT_NOP  =            1
    TCPOPT_MAXSEG =          2
    TCPOPT_WINDOW  =         3
    TCPOPT_SACK_PERMITTED =  4
    TCPOPT_SACK         =    5
    TCPOPT_TIMESTAMP    =    8
    TCPOPT_SIGNATURE    =    19


     func (self TYPE) __init__(kind, data = nil interface{}){

        if kind == TCPOption.TCPOPT_EOL {
            PacketBuffer.__init__(self, 1)
            self.set_kind(TCPOption.TCPOPT_EOL)
        elif kind == TCPOption.TCPOPT_NOP {
            PacketBuffer.__init__(self, 1)
            self.set_kind(TCPOption.TCPOPT_NOP)
        elif kind == TCPOption.TCPOPT_MAXSEG {
            PacketBuffer.__init__(self, 4)
            self.set_kind(TCPOption.TCPOPT_MAXSEG)
            self.set_len(4)
            if data {
                self.set_mss(data)
            } else  {
                self.set_mss(512)
        elif kind == TCPOption.TCPOPT_WINDOW {
            PacketBuffer.__init__(self, 3)
            self.set_kind(TCPOption.TCPOPT_WINDOW)
            self.set_len(3)
            if data {
                self.set_shift_cnt(data)
            } else  {
                self.set_shift_cnt(0)
        elif kind == TCPOption.TCPOPT_TIMESTAMP {
            PacketBuffer.__init__(self, 10)
            self.set_kind(TCPOption.TCPOPT_TIMESTAMP)
            self.set_len(10)
            if data {
                self.set_ts(data)
            } else  {
                self.set_ts(0)
        elif kind == TCPOption.TCPOPT_SACK_PERMITTED {
            PacketBuffer.__init__(self, 2)
            self.set_kind(TCPOption.TCPOPT_SACK_PERMITTED)
            self.set_len(2)                

        elif kind == TCPOption.TCPOPT_SACK {
            PacketBuffer.__init__(self, 2)
            self.set_kind(TCPOption.TCPOPT_SACK)

     func (self TYPE) set_left_edge(aValue interface{}){
        self.set_long (2, aValue)

     func (self TYPE) set_right_edge(aValue interface{}){
        self.set_long (6, aValue)

     func (self TYPE) set_kind(kind interface{}){
        self.set_byte(0, kind)


     func (self TYPE) get_kind(){
        return self.get_byte(0)


     func (self TYPE) set_len(len interface{}){
        if self.get_size() < 2 {
            raise ImpactPacketException("Cannot set length field on an option having a size smaller than 2 bytes")
        self.set_byte(1, len)

     func (self TYPE) get_len(){
        if self.get_size() < 2 {
            raise ImpactPacketException("Cannot retrieve length field from an option having a size smaller than 2 bytes")
        return self.get_byte(1)

     func (self TYPE) get_size(){
        return len(self.get_bytes())


     func (self TYPE) set_mss(len interface{}){
        if self.get_kind() != TCPOption.TCPOPT_MAXSEG {
            raise ImpactPacketException("Can only set MSS on TCPOPT_MAXSEG option")
        self.set_word(2, len)

     func (self TYPE) get_mss(){
        if self.get_kind() != TCPOption.TCPOPT_MAXSEG {
            raise ImpactPacketException("Can only retrieve MSS from TCPOPT_MAXSEG option")
        return self.get_word(2)

     func (self TYPE) set_shift_cnt(cnt interface{}){
        if self.get_kind() != TCPOption.TCPOPT_WINDOW {
            raise ImpactPacketException("Can only set Shift Count on TCPOPT_WINDOW option")
        self.set_byte(2, cnt)

     func (self TYPE) get_shift_cnt(){
        if self.get_kind() != TCPOption.TCPOPT_WINDOW {
            raise ImpactPacketException("Can only retrieve Shift Count from TCPOPT_WINDOW option")
        return self.get_byte(2)

     func (self TYPE) get_ts(){
        if self.get_kind() != TCPOption.TCPOPT_TIMESTAMP {
            raise ImpactPacketException("Can only retrieve timestamp from TCPOPT_TIMESTAMP option")
        return self.get_long(2)

     func (self TYPE) set_ts(ts interface{}){
        if self.get_kind() != TCPOption.TCPOPT_TIMESTAMP {
            raise ImpactPacketException("Can only set timestamp on TCPOPT_TIMESTAMP option")
        self.set_long(2, ts)

     func (self TYPE) get_ts_echo(){
        if self.get_kind() != TCPOption.TCPOPT_TIMESTAMP {
            raise ImpactPacketException("Can only retrieve timestamp from TCPOPT_TIMESTAMP option")
        return self.get_long(6)

     func (self TYPE) set_ts_echo(ts interface{}){
        if self.get_kind() != TCPOption.TCPOPT_TIMESTAMP {
            raise ImpactPacketException("Can only set timestamp on TCPOPT_TIMESTAMP option")
        self.set_long(6, ts)

     func (self TYPE) __str__(){
        map = { TCPOption.TCPOPT_EOL : "End of List ",
                TCPOption.TCPOPT_NOP : "No Operation ",
                TCPOption.TCPOPT_MAXSEG : "Maximum Segment Size ",
                TCPOption.TCPOPT_WINDOW : "Window Scale ",
                TCPOption.TCPOPT_TIMESTAMP : "Timestamp " }

        tmp_str = "\tTCP Option: "
        op = self.get_kind()
        if op in map {
            tmp_str += map[op]
        } else  {
            tmp_str += " kind: %d " % op
        if op == TCPOption.TCPOPT_MAXSEG {
            tmp_str += " MSS : %d " % self.get_mss()
        elif op == TCPOption.TCPOPT_WINDOW {
            tmp_str += " Shift Count: %d " % self.get_shift_cnt()
        elif op == TCPOption.TCPOPT_TIMESTAMP {
            pass // TODO
        return tmp_str

 type ICMP struct { // Header:
    protocol = 1
    ICMP_ECHOREPLY              = 0
    ICMP_UNREACH                = 3
    ICMP_UNREACH_NET            = 0
    ICMP_UNREACH_HOST           = 1
    ICMP_UNREACH_PROTOCOL       = 2
    ICMP_UNREACH_PORT           = 3
    ICMP_UNREACH_NEEDFRAG       = 4
    ICMP_UNREACH_SRCFAIL        = 5
    ICMP_UNREACH_NET_UNKNOWN    = 6
    ICMP_UNREACH_HOST_UNKNOWN   = 7
    ICMP_UNREACH_ISOLATED       = 8
    ICMP_UNREACH_NET_PROHIB     = 9
    ICMP_UNREACH_HOST_PROHIB    = 10
    ICMP_UNREACH_TOSNET         = 11
    ICMP_UNREACH_TOSHOST        = 12
    ICMP_UNREACH_FILTERPROHIB   = 13
    ICMP_UNREACH_HOST_PRECEDENCE = 14
    ICMP_UNREACH_PRECEDENCE_CUTOFF = 15
    ICMP_SOURCEQUENCH               = 4
    ICMP_REDIRECT                   = 5
    ICMP_REDIRECT_NET           = 0
    ICMP_REDIRECT_HOST          = 1
    ICMP_REDIRECT_TOSNET        = 2
    ICMP_REDIRECT_TOSHOST       = 3
    ICMP_ALTHOSTADDR                = 6
    ICMP_ECHO                       = 8
    ICMP_ROUTERADVERT               = 9
    ICMP_ROUTERSOLICIT              = 10
    ICMP_TIMXCEED                   = 11
    ICMP_TIMXCEED_INTRANS       = 0
    ICMP_TIMXCEED_REASS         = 1
    ICMP_PARAMPROB                  = 12
    ICMP_PARAMPROB_ERRATPTR     = 0
    ICMP_PARAMPROB_OPTABSENT    = 1
    ICMP_PARAMPROB_LENGTH       = 2
    ICMP_TSTAMP                     = 13
    ICMP_TSTAMPREPLY                = 14
    ICMP_IREQ                       = 15
    ICMP_IREQREPLY                  = 16
    ICMP_MASKREQ                    = 17
    ICMP_MASKREPLY                  = 18

     func (self TYPE) __init__(aBuffer = nil interface{}){
        Header.__init__(self, 8)
        if aBuffer {
            self.load_header(aBuffer)

     func (self TYPE) get_header_size(){
        anamolies = { ICMP.ICMP_TSTAMP : 20, ICMP.ICMP_TSTAMPREPLY : 20, ICMP.ICMP_MASKREQ : 12, ICMP.ICMP_MASKREPLY : 12 }
        if self.get_icmp_type() in anamolies {
            return anamolies[self.get_icmp_type()]
        } else  {
            return 8

     func (self TYPE) get_icmp_type(){
        return self.get_byte(0)

     func (self TYPE) set_icmp_type(aValue interface{}){
        self.set_byte(0, aValue)

     func (self TYPE) get_icmp_code(){
        return self.get_byte(1)

     func (self TYPE) set_icmp_code(aValue interface{}){
        self.set_byte(1, aValue)

     func (self TYPE) get_icmp_cksum(){
        return self.get_word(2)

     func (self TYPE) set_icmp_cksum(aValue interface{}){
        self.set_word(2, aValue)
        self.auto_checksum = 0

     func (self TYPE) get_icmp_gwaddr(){
        return self.get_ip_address(4)

     func (self TYPE) set_icmp_gwaddr(ip interface{}){
        self.set_ip_address(4, ip)

     func (self TYPE) get_icmp_id(){
        return self.get_word(4)

     func (self TYPE) set_icmp_id(aValue interface{}){
        self.set_word(4, aValue)

     func (self TYPE) get_icmp_seq(){
        return self.get_word(6)

     func (self TYPE) set_icmp_seq(aValue interface{}){
        self.set_word(6, aValue)

     func (self TYPE) get_icmp_void(){
        return self.get_long(4)

     func (self TYPE) set_icmp_void(aValue interface{}){
        self.set_long(4, aValue)


     func (self TYPE) get_icmp_nextmtu(){
        return self.get_word(6)

     func (self TYPE) set_icmp_nextmtu(aValue interface{}){
        self.set_word(6, aValue)

     func (self TYPE) get_icmp_num_addrs(){
        return self.get_byte(4)

     func (self TYPE) set_icmp_num_addrs(aValue interface{}){
        self.set_byte(4, aValue)

     func (self TYPE) get_icmp_wpa(){
        return self.get_byte(5)

     func (self TYPE) set_icmp_wpa(aValue interface{}){
        self.set_byte(5, aValue)

     func (self TYPE) get_icmp_lifetime(){
        return self.get_word(6)

     func (self TYPE) set_icmp_lifetime(aValue interface{}){
        self.set_word(6, aValue)

     func (self TYPE) get_icmp_otime(){
        return self.get_long(8)

     func (self TYPE) set_icmp_otime(aValue interface{}){
        self.set_long(8, aValue)

     func (self TYPE) get_icmp_rtime(){
        return self.get_long(12)

     func (self TYPE) set_icmp_rtime(aValue interface{}){
        self.set_long(12, aValue)

     func (self TYPE) get_icmp_ttime(){
        return self.get_long(16)

     func (self TYPE) set_icmp_ttime(aValue interface{}){
        self.set_long(16, aValue)

     func (self TYPE) get_icmp_mask(){
        return self.get_ip_address(8)

     func (self TYPE) set_icmp_mask(mask interface{}){
        self.set_ip_address(8, mask)


     func (self TYPE) calculate_checksum(){
        if self.auto_checksum and (not self.get_icmp_cksum()) {
            buffer = self.get_buffer_as_string()
            data = self.get_data_as_string()
            if data {
                buffer += data

            tmp_array = array.array('B', buffer)
            self.set_icmp_cksum(self.compute_checksum(tmp_array))

     func (self TYPE) get_type_name(aType interface{}){
        tmp_type = {0:'ECHOREPLY', 3:'UNREACH', 4:'SOURCEQUENCH',5:'REDIRECT', 6:'ALTHOSTADDR', 8:'ECHO', 9:'ROUTERADVERT', 10:'ROUTERSOLICIT', 11:'TIMXCEED', 12:'PARAMPROB', 13:'TSTAMP', 14:'TSTAMPREPLY', 15:'IREQ', 16:'IREQREPLY', 17:'MASKREQ', 18:'MASKREPLY', 30:'TRACEROUTE', 31:'DATACONVERR', 32:'MOBILE REDIRECT', 33:'IPV6 WHEREAREYOU', 34:'IPV6 IAMHERE', 35:'MOBILE REGREQUEST', 36:'MOBILE REGREPLY', 39:'SKIP', 40:'PHOTURIS'}
        answer = tmp_type.get(aType, 'UNKNOWN')
        return answer

     func (self TYPE) get_code_name(aType, aCode interface{}){
        tmp_code = {3:['UNREACH NET', 'UNREACH HOST', 'UNREACH PROTOCOL', 'UNREACH PORT', 'UNREACH NEEDFRAG', 'UNREACH SRCFAIL', 'UNREACH NET UNKNOWN', 'UNREACH HOST UNKNOWN', 'UNREACH ISOLATED', 'UNREACH NET PROHIB', 'UNREACH HOST PROHIB', 'UNREACH TOSNET', 'UNREACH TOSHOST', 'UNREACH FILTER PROHIB', 'UNREACH HOST PRECEDENCE', 'UNREACH PRECEDENCE CUTOFF', 'UNKNOWN ICMP UNREACH']}
        tmp_code[5] = ['REDIRECT NET', 'REDIRECT HOST', 'REDIRECT TOSNET', 'REDIRECT TOSHOST']
        tmp_code[9] = ['ROUTERADVERT NORMAL', nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,'ROUTERADVERT NOROUTE COMMON']
        tmp_code[11] = ['TIMXCEED INTRANS ', 'TIMXCEED REASS']
        tmp_code[12] = ['PARAMPROB ERRATPTR ', 'PARAMPROB OPTABSENT', 'PARAMPROB LENGTH']
        tmp_code[40] = [nil, 'PHOTURIS UNKNOWN INDEX', 'PHOTURIS AUTH FAILED', 'PHOTURIS DECRYPT FAILED']
        if aType in tmp_code {
            tmp_list = tmp_code[aType]
            if ((aCode + 1) > len(tmp_list)) or (not tmp_list[aCode]) {
                return 'UNKNOWN'
            } else  {
                return tmp_list[aCode]
        } else  {
            return 'UNKNOWN'

     func (self TYPE) __str__(){
        tmp_type = self.get_icmp_type()
        tmp_code = self.get_icmp_code()
        tmp_str = "ICMP type: " + self.get_type_name(tmp_type)
        tmp_str+= ' code: ' + self.get_code_name(tmp_type, tmp_code)
        if self.child() {
            tmp_str += '\n' + str( self.child() )
        return tmp_str

     func (self TYPE) isDestinationUnreachable(){
        return self.get_icmp_type() == 3

     func (self TYPE) isError(){
        return not self.isQuery()

     func (self TYPE) isHostUnreachable(){
        return self.isDestinationUnreachable() and (self.get_icmp_code() == 1)

     func (self TYPE) isNetUnreachable(){
        return self.isDestinationUnreachable() and (self.get_icmp_code() == 0)

     func (self TYPE) isPortUnreachable(){
        return self.isDestinationUnreachable() and (self.get_icmp_code() == 3)

     func (self TYPE) isProtocolUnreachable(){
        return self.isDestinationUnreachable() and (self.get_icmp_code() == 2)

     func (self TYPE) isQuery(){
        tmp_dict = {8:'',  9:'',  10:'', 13:'', 14:'', 15:'', 16:'', 17:'', 18:''}
        return self.get_icmp_type() in tmp_dict

 type IGMP struct { // Header:
    protocol = 2
     func (self TYPE) __init__(aBuffer = nil interface{}){
        Header.__init__(self, 8)
        if aBuffer {
            self.load_header(aBuffer)

     func (self TYPE) get_igmp_type(){
        return self.get_byte(0)

     func (self TYPE) set_igmp_type(aValue interface{}){
        self.set_byte(0, aValue)

     func (self TYPE) get_igmp_code(){
        return self.get_byte(1)

     func (self TYPE) set_igmp_code(aValue interface{}){
        self.set_byte(1, aValue)

     func (self TYPE) get_igmp_cksum(){
        return self.get_word(2)

     func (self TYPE) set_igmp_cksum(aValue interface{}){
        self.set_word(2, aValue)

     func (self TYPE) get_igmp_group(){
        return self.get_long(4)

     func (self TYPE) set_igmp_group(aValue interface{}){
        self.set_long(4, aValue)

     func (self TYPE) get_header_size(){
        return 8

     func (self TYPE) get_type_name(aType interface{}){
        tmp_dict = {0x11:'HOST MEMBERSHIP QUERY ', 0x12:'v1 HOST MEMBERSHIP REPORT ', 0x13:'IGMP DVMRP ', 0x14:' PIM ', 0x16:'v2 HOST MEMBERSHIP REPORT ', 0x17:'HOST LEAVE MESSAGE ', 0x1e:'MTRACE REPLY ', 0X1f:'MTRACE QUERY '}
        answer = tmp_dict.get(aType, 'UNKNOWN TYPE OR VERSION ')
        return answer

     func (self TYPE) calculate_checksum(){
        if self.auto_checksum and (not self.get_igmp_cksum()) {
            self.set_igmp_cksum(self.compute_checksum(self.get_bytes()))

     func (self TYPE) __str__(){
        tmp_str = "IGMP: " + self.get_type_name(self.get_igmp_type())
        tmp_str += 'Group: ' +  socket.inet_ntoa(struct.pack('!L',self.get_igmp_group()))
        if self.child() {
            tmp_str += '\n' + str(self.child())
        return tmp_str



 type ARP struct { // Header:
    ethertype = 0x806
     func (self TYPE) __init__(aBuffer = nil interface{}){
        Header.__init__(self, 7)
        if aBuffer {
            self.load_header(aBuffer)

     func (self TYPE) get_ar_hrd(){
        return self.get_word(0)

     func (self TYPE) set_ar_hrd(aValue interface{}){
        self.set_word(0, aValue)

     func (self TYPE) get_ar_pro(){
        return self.get_word(2)

     func (self TYPE) set_ar_pro(aValue interface{}){
        self.set_word(2, aValue)

     func (self TYPE) get_ar_hln(){
        return self.get_byte(4)

     func (self TYPE) set_ar_hln(aValue interface{}){
        self.set_byte(4, aValue)

     func (self TYPE) get_ar_pln(){
        return self.get_byte(5)

     func (self TYPE) set_ar_pln(aValue interface{}){
        self.set_byte(5, aValue)

     func (self TYPE) get_ar_op(){
        return self.get_word(6)

     func (self TYPE) set_ar_op(aValue interface{}){
        self.set_word(6, aValue)

     func (self TYPE) get_ar_sha(){
        tmp_size = self.get_ar_hln()
        return self.get_bytes().tolist()[8: 8 + tmp_size]

     func (self TYPE) set_ar_sha(aValue interface{}){
        for i in range(0, self.get_ar_hln()):
            self.set_byte(i + 8, aValue[i])

     func (self TYPE) get_ar_spa(){
        tmp_size = self.get_ar_pln()
        return self.get_bytes().tolist()[8 + self.get_ar_hln(): 8 + self.get_ar_hln() + tmp_size]

     func (self TYPE) set_ar_spa(aValue interface{}){
        for i in range(0, self.get_ar_pln()):
            self.set_byte(i + 8 + self.get_ar_hln(), aValue[i])

     func (self TYPE) get_ar_tha(){
        tmp_size = self.get_ar_hln()
        tmp_from = 8 + self.get_ar_hln() + self.get_ar_pln()
        return self.get_bytes().tolist()[tmp_from: tmp_from + tmp_size]

     func (self TYPE) set_ar_tha(aValue interface{}){
        tmp_from = 8 + self.get_ar_hln() + self.get_ar_pln()
        for i in range(0, self.get_ar_hln()):
            self.set_byte(i + tmp_from, aValue[i])

     func (self TYPE) get_ar_tpa(){
        tmp_size = self.get_ar_pln()
        tmp_from = 8 + ( 2 * self.get_ar_hln()) + self.get_ar_pln()
        return self.get_bytes().tolist()[tmp_from: tmp_from + tmp_size]

     func (self TYPE) set_ar_tpa(aValue interface{}){
        tmp_from = 8 + (2 * self.get_ar_hln()) + self.get_ar_pln()
        for i in range(0, self.get_ar_pln()):
            self.set_byte(i + tmp_from, aValue[i])

     func (self TYPE) get_header_size(){
        return 8 + (2 * self.get_ar_hln()) + (2 * self.get_ar_pln())

     func (self TYPE) get_op_name(ar_op interface{}){
        tmp_dict = {1:'REQUEST', 2:'REPLY', 3:'REVREQUEST', 4:'REVREPLY', 8:'INVREQUEST', 9:'INVREPLY'}
        answer = tmp_dict.get(ar_op, 'UNKNOWN')
        return answer

     func (self TYPE) get_hrd_name(ar_hrd interface{}){
        tmp_dict = { 1:'ARPHRD ETHER', 6:'ARPHRD IEEE802', 15:'ARPHRD FRELAY'}
        answer = tmp_dict.get(ar_hrd, 'UNKNOWN')
        return answer


     func (self TYPE) as_hrd(anArray interface{}){
        if not anArray {
            return ''
        tmp_str = "%x" % anArray[0]
        for i in range(1, len(anArray)):
            tmp_str += ':%x' % anArray[i]
        return tmp_str

     func (self TYPE) as_pro(anArray interface{}){
        if not anArray {
            return ''
        tmp_str = "%d" % anArray[0]
        for i in range(1, len(anArray)):
            tmp_str += '.%d' % anArray[i]
        return tmp_str

     func (self TYPE) __str__(){
        tmp_op = self.get_ar_op()
        tmp_str = "ARP format: " + self.get_hrd_name(self.get_ar_hrd()) + ' '
        tmp_str += 'opcode: ' + self.get_op_name(tmp_op)
        tmp_str += '\n' + self.as_hrd(self.get_ar_sha()) + ' -> '
        tmp_str += self.as_hrd(self.get_ar_tha())
        tmp_str += '\n' + self.as_pro(self.get_ar_spa()) + ' -> '
        tmp_str += self.as_pro(self.get_ar_tpa())
        if self.child() {
            tmp_str += '\n' + str(self.child())
        return tmp_str

 func example(){ //To execute an example, remove this line
    a = Ethernet()
    b = ARP()
    c = Data("Hola loco!!!")
    b.set_ar_hln(6)
    b.set_ar_pln(4)
    //a.set_ip_dst("192.168.22.6")
    //a.set_ip_src("1.1.1.2")
    a.contains(b)
    b.contains(c)
    b.set_ar_op(2)
    b.set_ar_hrd(1)
    b.set_ar_spa((192, 168, 22, 6))
    b.set_ar_tpa((192, 168, 66, 171))
    a.set_ether_shost((0x0, 0xe0, 0x7d, 0x8a, 0xef, 0x3d))
    a.set_ether_dhost((0x0, 0xc0, 0xdf, 0x6, 0x5, 0xe))
    print("beto %s" % a)
