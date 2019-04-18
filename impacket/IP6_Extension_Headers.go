// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
import array

from impacket.ImpactPacket import Header, ImpactPacketException, PacketBuffer

 type IP6_Extension_Header struct { // Header:
// --------------------------------- - - - - - - -
// | Next Header | Header Ext Len | Options
// --------------------------------- - - - - - - -

    HEADER_TYPE_VALUE = -1
    EXTENSION_HEADER_FIELDS_SIZE = 2
    
    EXTENSION_HEADER_DECODER = nil

     func (self TYPE) __init__(buffer = nil interface{}){
        Header.__init__(self, self.get_headers_field_size())
        self._option_list = []
        if buffer {
            self.load_header(buffer)
        } else  {
            self.reset()

     func (self TYPE) __str__(){
        header_type = self.get_header_type()
        next_header_value = self.get_next_header()
        header_ext_length = self.get_header_extension_length()

        s  = "Header Extension Name: " + self.__class__.HEADER_EXTENSION_DESCRIPTION + "\n"
        s += "Header Type Value: " + str(header_type) + "\n"
        s += "Next Header: " + str(next_header_value) + "\n"
        s += "Header Extension Length: " + str(header_ext_length) + "\n"
        s += "Options:\n"
        
        for option in self._option_list:
            option_str = str(option)
            option_str = option_str.split("\n")
            option_str = [(' ' * 4) + s for s in option_str]
            s += '\n'.join(option_str) + '\n'
        
        return s

     func (self TYPE) load_header(buffer interface{}){
        self.set_bytes_from_string(buffer[:self.get_headers_field_size()])
        
        remaining_bytes = (self.get_header_extension_length() + 1) * 8
        remaining_bytes -= self.get_headers_field_size()

        buffer = array.array('B', buffer[self.get_headers_field_size():])
        if remaining_bytes > len(buffer) {
            raise ImpactPacketException("Cannot load options from truncated packet")

        while remaining_bytes > 0:
            option_type = buffer[0]
            if option_type == Option_PAD1.OPTION_TYPE_VALUE {
                // Pad1
                self._option_list.append(Option_PAD1())
                
                remaining_bytes -= 1
                buffer = buffer[1:]
            } else  {
                // PadN
                // From RFC 2460: For N octets of padding, the Opt Data Len
                // field contains the value N-2, and the Option Data consists
                // of N-2 zero-valued octets.
                option_length = buffer[1]
                option_length += 2
                
                self._option_list.append(Option_PADN(option_length))

                remaining_bytes -= option_length
                buffer = buffer[option_length:]
    
     func (self TYPE) reset(){
        pass

    @classmethod
     func get_header_type_value(cls interface{}){
        return cls.HEADER_TYPE_VALUE
    
    @classmethod
     func get_extension_headers(cls interface{}){
        header_types = {}
        for sub type in cls.__subclasses__ struct { // :
            subclass_header_types = subclass.get_extension_headers()
            if not subclass_header_types {
                // If the sub type did not return anything it means struct {
                // that it is a leaf subclass, so we take its header
                // type value
                header_types[subclass.get_header_type_value()] = subclass
            } else  {
                // Else we extend the list of the obtained types
                header_types.update(subclass_header_types)
        return header_types
    
    @classmethod
     func get_decoder(cls interface{}){
        raise RuntimeError("Class method %s.get_decoder must be overridden." % cls)

     func (self TYPE) get_header_type(){
        return self.__class__.get_header_type_value()

     func (self TYPE) get_headers_field_size(){
        return IP6_Extension_Header.EXTENSION_HEADER_FIELDS_SIZE

     func (self TYPE) get_header_size(){
        header_size = self.get_headers_field_size()
        for option in self._option_list:
            header_size += option.get_len()
        return header_size

     func (self TYPE) get_next_header(){
        return self.get_byte(0)

     func (self TYPE) get_header_extension_length(){
        return self.get_byte(1)

     func (self TYPE) set_next_header(next_header interface{}){
        self.set_byte(0, next_header & 0xFF)

     func (self TYPE) set_header_extension_length(header_extension_length interface{}){
        self.set_byte(1, header_extension_length & 0xFF)
    
     func (self TYPE) add_option(option interface{}){
        self._option_list.append(option)
    
     func (self TYPE) get_options(){
        return self._option_list

     func (self TYPE) get_packet(){
        data = self.get_data_as_string()

        // Update the header length
        self.set_header_extension_length(self.get_header_size() // 8 - 1)

        // Build the entire extension header packet
        header_bytes = self.get_buffer_as_string()
        for option in self._option_list:
            header_bytes += option.get_buffer_as_string()
        
        if data {
            return header_bytes + data
        } else  {
            return header_bytes

     func (self TYPE) contains(aHeader interface{}){
        Header.contains(self, aHeader)
        if isinstance(aHeader, IP6_Extension_Header) {
            self.set_next_header(aHeader.get_header_type())
    
     func (self TYPE) get_pseudo_header(){
        // The pseudo-header only contains data from the IPv6 header.
        // So we pass the message to the parent until it reaches it.
        return self.parent().get_pseudo_header()

 type Extension_Option struct { // PacketBuffer:
    MAX_OPTION_LEN  = 256
    OPTION_TYPE_VALUE = -1

     func (self TYPE) __init__(option_type, size interface{}){
        if size > Extension_Option.MAX_OPTION_LEN {
            raise ImpactPacketException("Option size of % is greater than the maximum of %d" % (size, Extension_Option.MAX_OPTION_LEN))
        PacketBuffer.__init__(self, size)
        self.set_option_type(option_type)

     func (self TYPE) __str__(){
        option_type = self.get_option_type()
        option_length = self.get_option_length()

        s  = "Option Name: " + str(self.__class__.OPTION_DESCRIPTION) + "\n"
        s += "Option Type: " + str(option_type) + "\n"
        s += "Option Length: " + str(option_length) + "\n"
        
        return s

     func (self TYPE) set_option_type(option_type interface{}){
        self.set_byte(0, option_type)

     func (self TYPE) get_option_type(){
        return self.get_byte(0)

     func (self TYPE) set_option_length(length interface{}){
        self.set_byte(1, length)

     func (self TYPE) get_option_length(){
        return self.get_byte(1)

     func (self TYPE) set_data(data interface{}){
        self.set_option_length(len(data))
        option_bytes = self.get_bytes()
        
        option_bytes = self.get_bytes()
        option_bytes[2:2+len(data)] = array.array('B', data)
        self.set_bytes(option_bytes)

     func (self TYPE) get_len(){
        return len(self.get_bytes())

 type Option_PAD1 struct { // Extension_Option:
    OPTION_TYPE_VALUE = 0x00   // Pad1 (RFC 2460)
    OPTION_DESCRIPTION = "Pad1 Option"

     func (self TYPE) __init__(){
        Extension_Option.__init__(self, Option_PAD1.OPTION_TYPE_VALUE, 1)

     func (self TYPE) get_len(){
        return 1

 type Option_PADN struct { // Extension_Option:
    OPTION_TYPE_VALUE = 0x01   // Pad1 (RFC 2460)
    OPTION_DESCRIPTION = "PadN Option"

     func (self TYPE) __init__(padding_size interface{}){
        if padding_size < 2 {
            raise ImpactPacketException("PadN Extension Option must be greater than 2 bytes")

        Extension_Option.__init__(self, Option_PADN.OPTION_TYPE_VALUE, padding_size)
        self.set_data(b'\x00' * (padding_size - 2))

 type Basic_Extension_Header struct { // IP6_Extension_Header:
    MAX_OPTIONS_LEN = 256 * 8
    MIN_HEADER_LEN  = 8
    MAX_HEADER_LEN  = MIN_HEADER_LEN + MAX_OPTIONS_LEN

     func (self TYPE) __init__(buffer = nil interface{}){
        self.padded = false
        IP6_Extension_Header.__init__(self, buffer)

     func (self TYPE) reset(){
        self.set_next_header(0)
        self.set_header_extension_length(0)
        self.add_padding()

     func (self TYPE) add_option(option interface{}){
        if self.padded {
            self._option_list.pop()
            self.padded = false

        IP6_Extension_Header.add_option(self, option)

        self.add_padding()
        
     func (self TYPE) add_padding(){
        required_octets = 8 - (self.get_header_size() % 8)
        if self.get_header_size() + required_octets > Basic_Extension_Header.MAX_HEADER_LEN {
            raise Exception("Not enough space for the padding")

        // Insert Pad1 or PadN to fill the necessary octets
        if 0 < required_octets < 8 {
            if required_octets == 1 {
                self.add_option(Option_PAD1())
            } else  {
                self.add_option(Option_PADN(required_octets))
            self.padded = true
        } else  {
            self.padded = false

 type Hop_By_Hop struct { // Basic_Extension_Header:
    HEADER_TYPE_VALUE = 0x00
    HEADER_EXTENSION_DESCRIPTION = "Hop By Hop Options"
    
    @classmethod
     func (self TYPE) get_decoder(){
        from impacket import ImpactDecoder
        return ImpactDecoder.HopByHopDecoder

 type Destination_Options struct { // Basic_Extension_Header:
    HEADER_TYPE_VALUE = 0x3c
    HEADER_EXTENSION_DESCRIPTION = "Destination Options"
    
    @classmethod
     func (self TYPE) get_decoder(){
        from impacket import ImpactDecoder
        return ImpactDecoder.DestinationOptionsDecoder

 type Routing_Options struct { // IP6_Extension_Header:
    HEADER_TYPE_VALUE = 0x2b
    HEADER_EXTENSION_DESCRIPTION = "Routing Options"
    ROUTING_OPTIONS_HEADER_FIELDS_SIZE = 8
    
     func (self TYPE) reset(){
        self.set_next_header(0)
        self.set_header_extension_length(0)
        self.set_routing_type(0)
        self.set_segments_left(0)

     func (self TYPE) __str__(){
        header_type = self.get_header_type()
        next_header_value = self.get_next_header()
        header_ext_length = self.get_header_extension_length()
        routing_type = self.get_routing_type()
        segments_left = self.get_segments_left()

        s  = "Header Extension Name: " + self.__class__.HEADER_EXTENSION_DESCRIPTION + "\n"
        s += "Header Type Value: " + str(header_type) + "\n"
        s += "Next Header: " + str(next_header_value) + "\n"
        s += "Header Extension Length: " + str(header_ext_length) + "\n"
        s += "Routing Type: " + str(routing_type) + "\n"
        s += "Segments Left: " + str(segments_left) + "\n"

        return s
        
    @classmethod
     func (self TYPE) get_decoder(){
        from . import ImpactDecoder
        return ImpactDecoder.RoutingOptionsDecoder

     func (self TYPE) get_headers_field_size(){
        return Routing_Options.ROUTING_OPTIONS_HEADER_FIELDS_SIZE

     func (self TYPE) set_routing_type(routing_type interface{}){
        self.set_byte(2, routing_type)

     func (self TYPE) get_routing_type(){
        return self.get_byte(2)

     func (self TYPE) set_segments_left(segments_left interface{}){
        self.set_byte(3, segments_left)

     func (self TYPE) get_segments_left(){
        return self.get_byte(3)
