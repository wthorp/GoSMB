// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Description:
//    Cisco Discovery Protocol packet codecs.
//
// Author:
//  Martin Candurra
//  martincad at corest.com

from struct import unpack
import socket

from impacket.ImpactPacket import Header
from impacket import LOG

IP_ADDRESS_LENGTH = 4

 type CDPTypes: struct {

    DeviceID_Type       = 1
    Address_Type        = 2
    PortID_Type         = 3
    Capabilities_Type   = 4
    SoftVersion_Type    = 5
    Platform_Type       = 6
    IPPrefix_Type       = 7
    ProtocolHello_Type  = 8
    MTU_Type            = 17
    SystemName_Type     = 20
    SystemObjectId_Type = 21
    SnmpLocation        = 23
    
 type CDP struct { // Header:
    
    Type = 0x2000
    OUI =  0x00000c
    
     func (self TYPE) __init__(aBuffer = nil interface{}){
        Header.__init__(self, 8)
        if aBuffer {
            self.load_header(aBuffer)
            self._elements = self._getElements(aBuffer)

     func (self TYPE) _getElements(aBuffer interface{}){
        // Remove version (1 byte), TTL (1 byte), and checksum (2 bytes)
        buff = aBuffer[4:]
        l = []
        while buff:
            elem = CDPElementFactory.create(buff)
            l.append( elem )
            buff = buff[ elem.get_length() : ]
        return l

     func (self TYPE) get_header_size(){
        return 8
        
     func (self TYPE) get_version(){
        return self.get_byte(0)
        
     func (self TYPE) get_ttl(){
        return self.get_byte(1)
        
     func (self TYPE) get_checksum(){
        return self.get_word(2)

     func (self TYPE) get_type(){
        return self.get_word(4)
        
     func (self TYPE) get_lenght(){      
        return self.get_word(6)

     func (self TYPE) getElements(){
        return self._elements


     func (self TYPE) __str__(){
        tmp_str = "CDP Details:\n"
        for element in self._elements:
            tmp_str += "** Type:" + str(element.get_type()) + " " + str(element) + "\n"
        return tmp_str
        

 func get_byte(buffer, offset interface{}){
    return unpack("!B", buffer[offset:offset+1])[0]

 func get_word(buffer, offset interface{}){
    return unpack("!h", buffer[offset:offset+2])[0]

 func get_long(buffer, offset interface{}){
    return unpack("!I", buffer[offset:offset+4])[0]

 func get_bytes(buffer, offset, bytes interface{}){
    return buffer[offset:offset + bytes]

 func mac_to_string(mac_bytes interface{}){
    bytes = unpack('!BBBBBB', mac_bytes)
    s = ""
    for byte in bytes:
        s += '%02x:' % byte
    return s[0:-1]
    
    

 type CDPElement struct { // Header:

     func (self TYPE) __init__(aBuffer = nil interface{}){
        Header.__init__(self, 8)
        if aBuffer {
            self._length = CDPElement.Get_length(aBuffer)
            self.load_header( aBuffer[:self._length] )

    @classmethod
     func Get_length(cls, aBuffer interface{}){
        return unpack('!h', aBuffer[2:4])[0]

     func (self TYPE) get_header_size(){
        self._length

     func (self TYPE) get_length(){
        return self.get_word(2)
                
     func (self TYPE) get_data(){        
        return self.get_bytes().tostring()[4:self.get_length()]

     func (self TYPE) get_ip_address(offset = 0, ip = nil interface{}){
        if not ip {
            ip = self.get_bytes().tostring()[offset : offset + IP_ADDRESS_LENGTH]
        return socket.inet_ntoa( ip )
        
 type CDPDevice struct { // CDPElement:
    Type = 1
    
     func (self TYPE) get_type(){
        return CDPDevice.Type
    
     func (self TYPE) get_device_id(){
        return CDPElement.get_data(self)

     func (self TYPE) __str__(){
        return "Device:" + self.get_device_id()

 type Address struct { // CDPElement:
    Type = 2
   
     func (self TYPE) __init__(aBuffer = nil interface{}){
        CDPElement.__init__(self, aBuffer)
        if aBuffer {
            data = self.get_bytes().tostring()[8:]
            self._generateAddressDetails(data)

     func (self TYPE) _generateAddressDetails(buff interface{}){
        self.address_details = []
        while buff:
            address = AddressDetails.create(buff)
            self.address_details.append( address )
            buff = buff[address.get_total_length():]

     func (self TYPE) get_type(){
        return Address.Type
    
     func (self TYPE) get_number(){
        return self.get_long(4)
       
     func (self TYPE) get_address_details(){
        return self.address_details
        
     func (self TYPE) __str__(){
        tmp_str = "Addresses:"
        for address_detail in self.address_details:
            tmp_str += "\n" + str(address_detail)
        return tmp_str        
        
 type AddressDetails struct { // :        
          
    PROTOCOL_IP = 0xcc          
          
    @classmethod
     func create(cls, buff interface{}){
        a = AddressDetails(buff)
        return a


     func (self TYPE) __init__(aBuffer = nil interface{}){
        if aBuffer {
            addr_length = unpack("!h", aBuffer[3:5])[0]
            self.total_length = addr_length + 5
            self.buffer = aBuffer[:self.total_length]
    
     func (self TYPE) get_total_length(){
        return self.total_length
        
     func (self TYPE) get_protocol_type(){
        return self.buffer[0:1]
        
     func (self TYPE) get_protocol_length(){
        return get_byte( self.buffer, 1)

     func (self TYPE) get_protocol(){
        return get_byte( self.buffer, 2)
        
     func (self TYPE) get_address_length(){
        return get_word( self.buffer, 3)
        
     func (self TYPE) get_address(){
        address =  get_bytes( self.buffer, 5, self.get_address_length() )
        if  self.get_protocol()==AddressDetails.PROTOCOL_IP {
            return socket.inet_ntoa(address)
        } else  {
            LOG.error("Address not IP")
            return address            
            
     func (self TYPE) is_protocol_IP(){
        return self.get_protocol()==AddressDetails.PROTOCOL_IP
            
     func (self TYPE) __str__(){
        return "Protocol Type:%r Protocol:%r Address Length:%r Address:%s" % (self.get_protocol_type(), self.get_protocol(), self.get_address_length(), self.get_address())            
       
 type Port struct { // CDPElement:
    Type = 3
    
     func (self TYPE) get_type(){
        return Port.Type
    
     func (self TYPE) get_port(){
        return CDPElement.get_data(self)                

     func (self TYPE) __str__(){
        return "Port:" + self.get_port()


 type Capabilities struct { // CDPElement:
    Type = 4
    
     func (self TYPE) __init__(aBuffer = nil interface{}){
        CDPElement.__init__(self, aBuffer)
        self._capabilities_processed = false
        
        self._router = false
        self._transparent_bridge = false
        self._source_route_bridge = false
        self._switch = false
        self._host = false
        self._igmp_capable = false
        self._repeater = false
        self._init_capabilities()
        
     func (self TYPE) get_type(){
        return Capabilities.Type
    
     func (self TYPE) get_capabilities(){
        return CDPElement.get_data(self)  
        
     func (self TYPE) _init_capabilities(){
        if self._capabilities_processed {
            return
        
        capabilities = unpack("!L", self.get_capabilities())[0]
        self._router = (capabilities & 0x1) > 0
        self._transparent_bridge = (capabilities & 0x02) > 0
        self._source_route_bridge = (capabilities & 0x04) > 0
        self._switch = (capabilities & 0x08) > 0
        self._host = (capabilities & 0x10) > 0
        self._igmp_capable = (capabilities & 0x20) > 0
        self._repeater = (capabilities & 0x40) > 0

     func (self TYPE) is_router(){
        return self._router

     func (self TYPE) is_transparent_bridge(){
        return self._transparent_bridge

     func (self TYPE) is_source_route_bridge(){
        return self._source_route_bridge
        
     func (self TYPE) is_switch(){
        return self._switch

     func (self TYPE) is_host(){
        return self.is_host

     func (self TYPE) is_igmp_capable(){
        return self._igmp_capable
        
     func (self TYPE) is_repeater(){
        return self._repeater

                 
     func (self TYPE) __str__(){
        return "Capabilities:" + self.get_capabilities()
                 
                                
 type SoftVersion struct { // CDPElement:
    Type = 5
    
     func (self TYPE) get_type(){
        return SoftVersion.Type
    
     func (self TYPE) get_version(){
        return CDPElement.get_data(self)

     func (self TYPE) __str__(){
        return "Version:" + self.get_version()

  
 type Platform struct { // CDPElement:
    Type = 6
    
     func (self TYPE) get_type(){
        return Platform.Type
    
     func (self TYPE) get_platform(){
        return CDPElement.get_data(self)                

     func (self TYPE) __str__(){
        return "Platform:%r" % self.get_platform()                
      

 type IpPrefix struct { // CDPElement:
    Type = 7
    
     func (self TYPE) get_type(){
        return IpPrefix .Type
    
     func (self TYPE) get_ip_prefix(){
        return CDPElement.get_ip_address(self, 4)                

     func (self TYPE) get_bits(){
        return self.get_byte(8)        
        
     func (self TYPE) __str__(){
        return "IP Prefix/Gateway: %r/%d" % (self.get_ip_prefix(), self.get_bits())
      
 type ProtocolHello struct { // CDPElement:
    Type = 8
    
     func (self TYPE) get_type(){
        return ProtocolHello.Type

     func (self TYPE) get_master_ip(){
        return self.get_ip_address(9)

     func (self TYPE) get_version(){
        return self.get_byte(17)

     func (self TYPE) get_sub_version(){
        return self.get_byte(18)

     func (self TYPE) get_status(){
        return self.get_byte(19)

     func (self TYPE) get_cluster_command_mac(){
        return self.get_bytes().tostring()[20:20+6]
            
     func (self TYPE) get_switch_mac(){
        return self.get_bytes().tostring()[28:28+6]
            
     func (self TYPE) get_management_vlan(){
        return self.get_word(36)

     func (self TYPE) __str__(){
        return "\n\n\nProcolHello: Master IP:%s version:%r subversion:%r status:%r Switch's Mac:%r Management VLAN:%r" \
         % (self.get_master_ip(), self.get_version(), self.get_sub_version(), self.get_status(), mac_to_string(self.get_switch_mac()), self.get_management_vlan())
                      
 type VTPManagementDomain struct { // CDPElement:
    Type = 9
    
     func (self TYPE) get_type(){
        return VTPManagementDomain.Type
    
     func (self TYPE) get_domain(){
        return CDPElement.get_data(self)                  
  
  
 type Duplex struct { // CDPElement:
    Type = 0xb
    
     func (self TYPE) get_type(){
        return Duplex.Type
    
     func (self TYPE) get_duplex(){
        return CDPElement.get_data(self)                
                
     func (self TYPE) is_full_duplex(){
        return self.get_duplex()==0x1
        
 type VLAN struct { // CDPElement:
    Type = 0xa
                
     func (self TYPE) get_type(){
        return VLAN.Type
        
     func (self TYPE) get_vlan_number(){
        return CDPElement.get_data(self)



 type TrustBitmap struct { // CDPElement:
    Type = 0x12
    
     func (self TYPE) get_type(){
        return TrustBitmap.Type

     func (self TYPE) get_trust_bitmap(){
        return self.get_data()

     func (self TYPE) __str__(){
        return "TrustBitmap Trust Bitmap:%r" % self.get_trust_bitmap()

 type UntrustedPortCoS struct { // CDPElement:
    Type = 0x13
    
     func (self TYPE) get_type(){
        return UntrustedPortCoS.Type

     func (self TYPE) get_port_CoS(){
        return self.get_data()

     func (self TYPE) __str__(){
        return "UntrustedPortCoS port CoS %r" % self.get_port_CoS()

 type ManagementAddresses struct { // Address:
    Type = 0x16
    
     func (self TYPE) get_type(){
        return ManagementAddresses.Type
        
 type MTU struct { // CDPElement:
    Type = 0x11
    
     func (self TYPE) get_type(){
        return MTU.Type
        
 type SystemName struct { // CDPElement:
    Type = 0x14
    
     func (self TYPE) get_type(){
        return SystemName.Type

 type SystemObjectId struct { // CDPElement:
    Type = 0x15
    
     func (self TYPE) get_type(){
        return SystemObjectId.Type

 type SnmpLocation struct { // CDPElement:
    Type = 0x17
    
     func (self TYPE) get_type(){
        return SnmpLocation.Type


 type DummyCdpElement struct { // CDPElement:
    Type = 0x99

     func (self TYPE) get_type(){
        return DummyCdpElement.Type

 type CDPElementFactory struct { // :
    
    elementTypeMap = {
                        CDPDevice.Type            : CDPDevice, 
                        Port.Type                 : Port,
                        Capabilities.Type         : Capabilities,
                        Address.Type              : Address, 
                        SoftVersion.Type          : SoftVersion,
                        Platform.Type             : Platform,
                        IpPrefix.Type             : IpPrefix,
                        ProtocolHello.Type        : ProtocolHello,
                        VTPManagementDomain.Type  : VTPManagementDomain,
                        VLAN.Type                 : VLAN,
                        Duplex.Type               : Duplex,
                        TrustBitmap.Type          : TrustBitmap,
                        UntrustedPortCoS.Type     : UntrustedPortCoS,
                        ManagementAddresses.Type  : ManagementAddresses,
                        MTU.Type                  : MTU,
                        SystemName.Type           : SystemName,
                        SystemObjectId.Type       : SystemObjectId,
                        SnmpLocation.Type         : SnmpLocation
                     }
    
    @classmethod
     func create(cls, aBuffer interface{}){
//        print "CDPElementFactory.create aBuffer:", repr(aBuffer)
//        print "CDPElementFactory.create sub_type:", repr(aBuffer[0:2])
        _type = unpack("!h", aBuffer[0:2])[0]
//        print "CDPElementFactory.create _type:", _type
        try:
            class_type = cls.elementTypeMap[_type]
        except KeyError:
            class_type = DummyCdpElement
            //raise Exception("CDP Element type %s not implemented" % _type)
        return class_type( aBuffer )                   
