// don't touch
package impacket

const(
    // Taken from socket module reference
    INADDR_ANY = "0.0.0.0"
    BROADCAST_ADDR = "<broadcast>"

    // Default port for NetBIOS name service
    NETBIOS_NS_PORT = 137
    // Default port for NetBIOS session service
    NETBIOS_SESSION_PORT = 139

    // Default port for SMB session service
    SMB_SESSION_PORT = 445

    // Owner Node Type Constants
    NODE_B = 0x0000
    NODE_P = 0x2000
    NODE_M = 0x4000
    NODE_RESERVED = 0x6000
    NODE_GROUP = 0x8000
    NODE_UNIQUE = 0x0

    // Name Type Constants
    TYPE_UNKNOWN = 0x01
    TYPE_WORKSTATION = 0x00
    TYPE_CLIENT = 0x03
    TYPE_SERVER = 0x20
    TYPE_DOMAIN_MASTER = 0x1B
    TYPE_DOMAIN_CONTROLLER = 0x1C
    TYPE_MASTER_BROWSER = 0x1D
    TYPE_BROWSER = 0x1E
    TYPE_NETDDE  = 0x1F
    TYPE_STATUS = 0x21

    // Opcodes values
    OPCODE_QUERY = 0
    OPCODE_REGISTRATION = 0x5 << 11
    OPCODE_RELEASE = 0x6 << 11
    OPCODE_WACK = 0x7 << 11
    OPCODE_REFRESH = 0x8 << 11
    OPCODE_REQUEST = 0 << 11
    OPCODE_RESPONSE = 0x10 << 11

    // NM_FLAGS
    NM_FLAGS_BROADCAST = 0x1 << 4
    NM_FLAGS_UNICAST = 0 << 4
    NM_FLAGS_RA = 0x8 << 4
    NM_FLAGS_RD = 0x10 << 4
    NM_FLAGS_TC = 0x20 << 4
    NM_FLAGS_AA = 0x40 << 4

    // QUESTION_TYPE
    QUESTION_TYPE_NB = 0x20     // NetBIOS general Name Service Resource Record
    QUESTION_TYPE_NBSTAT = 0x21 // NetBIOS NODE STATUS Resource Record
    // QUESTION_CLASS
    QUESTION_CLASS_IN = 0x1     // Internet class

    // RESOURCE RECORD RR_TYPE field definitions
    RR_TYPE_A = 0x1             // IP address Resource Record
    RR_TYPE_NS = 0x2            // Name Server Resource Record
    RR_TYPE_NULL = 0xA          // NULL Resource Record
    RR_TYPE_NB = 0x20           // NetBIOS general Name Service Resource Record
    RR_TYPE_NBSTAT = 0x21       // NetBIOS NODE STATUS Resource Record

    // RESOURCE RECORD RR_CLASS field definitions
    RR_CLASS_IN = 1             // Internet class

    // RCODE values
    RCODE_FMT_ERR   = 0x1       // Format Error.  Request was invalidly formatted.
    RCODE_SRV_ERR   = 0x2       // Server failure.  Problem with NBNS, cannot process name.
    RCODE_IMP_ERR   = 0x4       // Unsupported request error.  Allowable only for challenging NBNS when gets an Update type
                                // registration request.
    RCODE_RFS_ERR   = 0x5       // Refused error.  For policy reasons server will not register this name from this host.
    RCODE_ACT_ERR   = 0x6       // Active error.  Name is owned by another node.
    RCODE_CFT_ERR   = 0x7       // Name in conflict error.  A UNIQUE name is owned by more than one node.

    // NAME_FLAGS
    NAME_FLAGS_PRM = 0x0200       // Permanent Name Flag.  If one (1) then entry is for the permanent node name.  Flag is zero
                                // (0) for all other names.
    NAME_FLAGS_ACT = 0x0400       // Active Name Flag.  All entries have this flag set to one (1).
    NAME_FLAG_CNF  = 0x0800       // Conflict Flag.  If one (1) then name on this node is in conflict.
    NAME_FLAG_DRG  = 0x1000       // Deregister Flag.  If one (1) then this name is in the process of being deleted.

    // NB_FLAGS
    NB_FLAGS_ONT_B = 0
    NB_FLAGS_ONT_P = 1 << 13
    NB_FLAGS_ONT_M = 2 << 13
    NB_FLAGS_G     = 1 << 15

    NAME_TYPES = {TYPE_UNKNOWN: "Unknown", TYPE_WORKSTATION: "Workstation", TYPE_CLIENT: "Client",
                TYPE_SERVER: "Server", TYPE_DOMAIN_MASTER: "Domain Master", TYPE_DOMAIN_CONTROLLER: "Domain Controller",
                TYPE_MASTER_BROWSER: "Master Browser", TYPE_BROWSER: "Browser Server", TYPE_NETDDE: "NetDDE Server",
                TYPE_STATUS: "Status"}

    // NetBIOS Session Types
    NETBIOS_SESSION_MESSAGE = 0x0
    NETBIOS_SESSION_REQUEST = 0x81
    NETBIOS_SESSION_POSITIVE_RESPONSE = 0x82
    NETBIOS_SESSION_NEGATIVE_RESPONSE = 0x83
    NETBIOS_SESSION_RETARGET_RESPONSE = 0x84
    NETBIOS_SESSION_KEEP_ALIVE = 0x85
)


//###############################################################################
// HELPERS
//###############################################################################

// encodeName performs first and second level encoding of name as specified in RFC 1001 (Section 4)
// :param string name: the name to encode
// :param integer nametype: the name type constants
// :param string scope: the name's scope 
// :return string/bytes: the encoded name.
func encodeName(name string, nametype byte, scope string) string {
    // ToDo: Rewrite this simpler, we're using less than written

    if name == '*' {
        name += new String('\x00', 15)
    }else if len(name) > 15 {
        name = name[:15] + string(nametype)
    } else  {
        spaces := new String('\x00', 15-len(name))
        name = name + spaces + string(nametype)
    }

    encoded_name = chr(len(name) * 2) + re.sub('.', _do_first_level_encoding, name)

    try:
        if isinstance(encoded_name, unicode) {
            encoded_name = encoded_name.encode("utf-8")
        }
    except NameError:
        pass
    if scope {
        encoded_scope = ""
        for s in scope.split("."){
            encoded_scope = encoded_scope + chr(len(s)) + s
        }
        return b(encoded_name + encoded_scope) + '\x00'
    } else  {
        return b(encoded_name) + '\x00'
    }
}

// Internal method for use in encodeName()
 func _do_first_level_encoding(m interface{}){
    s = ord(m.group(0))
    return string.ascii_uppercase[s >> 4] + string.ascii_uppercase[s & 0x0f]
 }

// decodeName performs first and second level decoding of name as specified in RFC 1001 (Section 4)
// :param string/bytes name: the name to decode
// :return string: the decoded name.
 func decodeName(name interface{}){
    // ToDo: Rewrite this simpler, we're using less than written

    name_length = ord(name[0:1])
    assert name_length == 32

    decoded_name = re.sub('..', _do_first_level_decoding, name[1:33].decode("utf-8"))
    if name[33:34] == '\x00' {
        return 34, decoded_name, ''
    } else  {
        decoded_domain = ""
        offset = 34
        for{
            domain_length = byte2int(name[offset:offset+1])
            if domain_length == 0 {
                break
            }
            decoded_domain = "." + name[offset:offset + domain_length].decode("utf-8")
            offset += domain_length
        }
        return offset + 1, decoded_name, decoded_domain
    }

 func _do_first_level_decoding(m interface{}){
    s = m.group(0)
    return chr(((ord(s[0]) - ord("A")) << 4) | (ord(s[1]) - ord("A")))
 }

ERRCLASS_QUERY = 0x00
ERRCLASS_SESSION = 0xf0
ERRCLASS_OS = 0xff

QUERY_ERRORS := map int[string] {
    0x01: "Format Error. Request was invalidly formatted",
    0x02: "Server failure. Problem with NBNS, cannot process name.",
    0x03: "Name does not exist",
    0x04: "Unsupported request error.  Allowable only for challenging NBNS when gets an Update type registration request.",
    0x05: "Refused error.  For policy reasons server will not register this name from this host.",
    0x06: "Active error.  Name is owned by another node.",
    0x07: "Name in conflict error.  A UNIQUE name is owned by more than one node.",
}

SESSION_ERRORS := map int[string] {
    0x80: "Not listening on called name",
    0x81: "Not listening for calling name",
    0x82: "Called name not present",
    0x83: "Sufficient resources",
    0x8f: "Unspecified error"
}

 type NetBIOSError struct { 
     Exception
 }
func (self NetBIOSError) __init__(error_message='', error_class=nil, error_code=nil interface{}){
    self.error_ type = error_class struct {
    self.error_code = error_code
    self.error_msg = error_message
}

func (self NetBIOSError) get_error_code(){
    return self.error
}

func (self NetBIOSError) getErrorCode(){
    return self.get_error_code()
}

func (self NetBIOSError) get_error_string(){
    return str(self)
}

func (self NetBIOSError) getErrorString(){
    return str(self)
}

func (self NetBIOSError) __str__(){
    if self.error_code is not nil {
        if self.error_code in QUERY_ERRORS {
            return "%s-%s(%s)" % (self.error_msg, QUERY_ERRORS[self.error_code], self.error_code)
        } else if self.error_code in SESSION_ERRORS {
            return "%s-%s(%s)" % (self.error_msg, SESSION_ERRORS[self.error_code], self.error_code)
        } else  {
            return "%s(%s)" % (self.error_msg, self.error_code)
    } else  {
        return "%s" % self.error_msg
    }
}

type NetBIOSTimeout struct {
    Exception
}

func (self NetBIOSTimeout) __init__(message = "The NETBIOS connection with the remote host timed out." interface{}){
    Exception.__init__(self, message)
}


//###############################################################################
// 4.2 NAME SERVER PACKETS
//###############################################################################
 type NBNSResourceRecord struct { // Structure: (
    ("RR_NAME","z=\x00"),
    ("RR_TYPE",">H=0"),
    ("RR_CLASS",">H=0"),
    ("TTL",">L=0"),
    ("RDLENGTH",">H-RDATA"),
    ("RDATA",":="""),
}

 type NBNodeStatusResponse struct { // NBNSResourceRecord:
    NBNSResourceRecord
 }
     func (self NBNodeStatusResponse) __init__(data = 0 interface{}){
        NBNSResourceRecord.__init__(self, data)
        self.mac = b'00-00-00-00-00-00'
        self.num_names = unpack('B', self.RDATA[:1])[0]
        self.entries = list()
        data = self.RDATA[1:]
        for _ in range(self.num_names){
            entry = NODE_NAME_ENTRY(data)
            data = data[len(entry):]
            self.entries.append(entry)
        }
        self.statistics = STATISTICS(data)
        self.set_mac_in_hexa(self.statistics["UNIT_ID"])
    }

     func (self NBNodeStatusResponse) set_mac_in_hexa(data interface{}){
        data_aux = u''
        for d in bytearray(data){
            if data_aux == '' {
                data_aux = "%02x" % d
            } else  {
                data_aux += '-%02x' % d
            }
        }
        self.mac = data_aux.upper()
    }

     func (self NBNodeStatusResponse) get_mac(){
        return self.mac
     }

     func (self NBNodeStatusResponse) rawData(){
        res = pack('!B', self.num_names )
        for i in range(0, self.num_names){
            res += self.entries[i].getData()
        }
    }

 type NBPositiveNameQueryResponse struct { // NBNSResourceRecord:
    NBNSResourceRecord
 }
     func (self NBPositiveNameQueryResponse) __init__(data = 0 interface{}){
        NBNSResourceRecord.__init__(self, data)
        self.entries = [ ]
        rdata = self.RDATA
        for len(rdata) > 0{
            entry = ADDR_ENTRY(rdata)
            rdata = rdata[len(entry):]
            self.entries.append(socket.inet_ntoa(entry["NB_ADDRESS"]))
        }
    }

// 4.2.1.  GENERAL FORMAT OF NAME SERVICE PACKETS
 type NAME_SERVICE_PACKET struct { // Structure:
    commonHdr = (
        ("NAME_TRN_ID",">H=0"),
        ("FLAGS",">H=0"),
        ("QDCOUNT",">H=0"),
        ("ANCOUNT",">H=0"),
        ("NSCOUNT",">H=0"),
        ("ARCOUNT",">H=0"),
    )
        ("ANSWERS",":"),
    }

// 4.2.1.2.  QUESTION SECTION
 type QUESTION_ENTRY struct { // Structure:
    commonHdr = (
        ("QUESTION_NAME","z"),
        ("QUESTION_TYPE",">H=0"),
        ("QUESTION_CLASS",">H=0"),
    }

// 4.2.1.3.  RESOURCE RECORD
 type RESOURCE_RECORD struct { // Structure: (
        ("RR_NAME","z=\x00"),
        ("RR_TYPE",">H=0"),
        ("RR_CLASS",">H=0"),
        ("TTL",">L=0"),
        ("RDLENGTH",">H-RDATA"),
        ("RDATA",":="""),
    }

// 4.2.2.  NAME REGISTRATION REQUEST
 type NAME_REGISTRATION_REQUEST struct { // NAME_SERVICE_PACKET: (
    NAME_SERVICE_PACKET
        ("QUESTION_NAME", ":"),
        ("QUESTION_TYPE", ">H=0"),
        ("QUESTION_CLASS", ">H=0"),
        ("RR_NAME",":", ),
        ("RR_TYPE", ">H=0"),
        ("RR_CLASS",">H=0"),
        ("TTL", ">L=0"),
        ("RDLENGTH", ">H=6"),
        ("NB_FLAGS", ">H=0"),
         NB_ADDRESS [4]byte // =b""
    }
     func (self NAME_REGISTRATION_REQUEST) __init__(data=nil interface{}){
        NAME_SERVICE_PACKET.__init__(self,data)
        self.FLAGS = OPCODE_REQUEST | NM_FLAGS_RD | OPCODE_REGISTRATION
        self.QDCOUNT = 1
        self.ANCOUNT = 0
        self.NSCOUNT = 0
        self.ARCOUNT = 1

        self.QUESTION_TYPE = QUESTION_TYPE_NB
        self.QUESTION_CLASS = QUESTION_CLASS_IN

        self.RR_TYPE = RR_TYPE_NB
        self.RR_CLASS = RR_CLASS_IN
     }

// 4.2.3.  NAME OVERWRITE REQUEST & DEMAND
 type NAME_OVERWRITE_REQUEST struct { // NAME_REGISTRATION_REQUEST:
    NAME_REGISTRATION_REQUEST
 }
     func (self NAME_OVERWRITE_REQUEST) __init__(data=nil interface{}){
        NAME_REGISTRATION_REQUEST.__init__(self,data)
        self.FLAGS = OPCODE_REQUEST | OPCODE_REGISTRATION
        self.QDCOUNT = 1
        self.ANCOUNT = 0
        self.NSCOUNT = 0
        self.ARCOUNT = 1
     }

// 4.2.4.  NAME REFRESH REQUEST
 type NAME_REFRESH_REQUEST struct { // NAME_REGISTRATION_REQUEST:
    NAME_REGISTRATION_REQUEST
 }
     func (self NAME_REFRESH_REQUEST) __init__(data=nil interface{}){
        NAME_REGISTRATION_REQUEST.__init__(self,data)
        self.FLAGS = OPCODE_REFRESH | 0x1
        self.QDCOUNT = 1
        self.ANCOUNT = 0
        self.NSCOUNT = 0
        self.ARCOUNT = 1
     }

// 4.2.5.  POSITIVE NAME REGISTRATION RESPONSE
// 4.2.6.  NEGATIVE NAME REGISTRATION RESPONSE
// 4.2.7.  END-NODE CHALLENGE REGISTRATION RESPONSE
 type NAME_REGISTRATION_RESPONSE struct { // NAME_REGISTRATION_REQUEST:
    NAME_REGISTRATION_REQUEST
 }
     func (self NAME_REGISTRATION_RESPONSE) __init__(data=nil interface{}){
        NAME_REGISTRATION_REQUEST.__init__(self,data)
     }

// 4.2.8.  NAME CONFLICT DEMAND
 type NAME_CONFLICT_DEMAND struct { // NAME_REGISTRATION_REQUEST:
    NAME_REGISTRATION_REQUEST
 }
     func (self NAME_CONFLICT_DEMAND) __init__(data=nil interface{}){
        NAME_REGISTRATION_REQUEST.__init__(self,data)
     }

// ToDo: 4.2.9.  NAME RELEASE REQUEST & DEMAND
// ToDo: 4.2.10.  POSITIVE NAME RELEASE RESPONSE
// ToDo: 4.2.11.  NEGATIVE NAME RELEASE RESPONSE

// 4.2.12.  NAME QUERY REQUEST
 type NAME_QUERY_REQUEST struct { // NAME_SERVICE_PACKET: (
    NAME_SERVICE_PACKET
        ("QUESTION_NAME", ":"),
        ("QUESTION_TYPE", ">H=0"),
        ("QUESTION_CLASS", ">H=0"),
    }
     func (self NAME_QUERY_REQUEST) __init__(data=nil interface{}){
        NAME_SERVICE_PACKET.__init__(self,data)
        self.FLAGS = OPCODE_REQUEST | OPCODE_REGISTRATION | NM_FLAGS_RD
        self.RCODE = 0
        self.QDCOUNT = 1
        self.ANCOUNT = 0
        self.NSCOUNT = 0
        self.ARCOUNT = 0

        self.QUESTION_TYPE = QUESTION_TYPE_NB
        self.QUESTION_CLASS = QUESTION_CLASS_IN
     }

// 4.2.13.  POSITIVE NAME QUERY RESPONSE
 type ADDR_ENTRY struct { // Structure: (
        ("NB_FLAGS", ">H=0"),
         NB_ADDRESS [4]byte // =b""
    }

// ToDo: 4.2.15.  REDIRECT NAME QUERY RESPONSE
// ToDo: 4.2.16.  WAIT FOR ACKNOWLEDGEMENT (WACK) RESPONSE

// 4.2.17.  NODE STATUS REQUEST
 type NODE_STATUS_REQUEST struct { // NAME_QUERY_REQUEST:
    NAME_QUERY_REQUEST
 }
func (self NODE_STATUS_REQUEST) __init__(data=nil interface{}){
    NAME_QUERY_REQUEST.__init__(self,data)
    self.FLAGS = 0
    self.QUESTION_TYPE = QUESTION_TYPE_NBSTAT
}

// 4.2.18.  NODE STATUS RESPONSE
 type NODE_NAME_ENTRY struct { // Structure: (
         NAME [5]byte // =b""
        ("TYPE","B=0"),
        ("NAME_FLAGS",">H"),
    }

 type STATISTICS struct {
         UNIT_ID [6]byte // =b""
        ("JUMPERS","B"),
        ("TEST_RESULT","B"),
        ("VERSION_NUMBER",">H"),
        ("PERIOD_OF_STATISTICS",">H"),
        ("NUMBER_OF_CRCs",">H"),
        ("NUMBER_ALIGNMENT_ERRORS",">H"),
        ("NUMBER_OF_COLLISIONS",">H"),
        ("NUMBER_SEND_ABORTS",">H"),
        ("NUMBER_GOOD_SENDS",">L"),
        ("NUMBER_GOOD_RECEIVES",">L"),
        ("NUMBER_RETRANSMITS",">H"),
        ("NUMBER_NO_RESOURCE_CONDITIONS",">H"),
        ("NUMBER_FREE_COMMAND_BLOCKS",">H"),
        ("TOTAL_NUMBER_COMMAND_BLOCKS",">H"),
        ("MAX_TOTAL_NUMBER_COMMAND_BLOCKS",">H"),
        ("NUMBER_PENDING_SESSIONS",">H"),
        ("MAX_NUMBER_PENDING_SESSIONS",">H"),
        ("MAX_TOTAL_SESSIONS_POSSIBLE",">H"),
        ("SESSION_DATA_PACKET_SIZE",">H"),
    }

 type NetBIOS struct {
 }
    // Creates a NetBIOS instance without specifying any default NetBIOS domain nameserver.
    // All queries will be sent through the servport.
     func (self NetBIOS) __init__(servport = NETBIOS_NS_PORT interface{}){
        self.__servport = NETBIOS_NS_PORT
        self.__nameserver = nil
        self.__broadcastaddr = BROADCAST_ADDR
        self.mac = b"00-00-00-00-00-00"
     }

     func (self NetBIOS) _setup_connection(dstaddr, timeout=nil interface{}){
        port = rand.randint(10000, 60000)
        af, socktype, proto, _canonname, _sa = socket.getaddrinfo(dstaddr, port, socket.AF_INET, socket.SOCK_DGRAM)[0]
        s = socket.socket(af, socktype, proto)
        has_bind = 1
        for _i in range(0, 10){
            // We try to bind to a port for 10 tries
            try:
                s.bind((INADDR_ANY, rand.randint(10000, 60000)))
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                has_bind = 1
            except socket.error:
                pass
        }
        if not has_bind {
            raise NetBIOSError("Cannot bind to a good UDP port", ERRCLASS_OS, errno.EAGAIN)
        }
        self.__sock = s
    }

     func (self TYPE) send(request, destaddr, timeout interface{}){
        self._setup_connection(destaddr)

        tries = 3
        for {
            try:
                self.__sock.sendto(request.getData(), 0, (destaddr, self.__servport))
                ready, _, _ = select.select([self.__sock.fileno()], [], [], timeout)
                if not ready {
                    if tries {
                        // Retry again until tries == 0
                        tries -= 1
                    } else  {
                        raise NetBIOSTimeout
                    }
                } else  {
                    try:
                        data, _ = self.__sock.recvfrom(65536, 0)
                    except Exception as e:
                        raise NetBIOSError("recvfrom error: %s" % str(e))
                    self.__sock.close()
                    res = NAME_SERVICE_PACKET(data)
                    if res["NAME_TRN_ID"] == request["NAME_TRN_ID"] {
                        if (res["FLAGS"] & 0xf) > 0 {
                            raise NetBIOSError("Negative response", ERRCLASS_QUERY, res["FLAGS"] & 0xf)
                        }
                        return res
                    }
                }
            except select.error as ex:
                if ex[0] != errno.EINTR and ex[0] != errno.EAGAIN {
                    raise NetBIOSError("Error occurs while waiting for response", ERRCLASS_OS, ex[0])
                }
            except socket.error as ex:
                raise NetBIOSError("Connection error: %s" % str(ex))
        }
    }
                

    // Set the default NetBIOS domain nameserver.
     func (self NetBIOS) set_nameserver(nameserver interface{}){
        self.__nameserver = nameserver
     }

    // Return the default NetBIOS domain nameserver, or nil if none is specified.
     func (self NetBIOS) get_nameserver(){
        return self.__nameserver
     }

    // Set the broadcast address to be used for query.
     func (self NetBIOS) set_broadcastaddr(broadcastaddr interface{}){
        self.__broadcastaddr = broadcastaddr
     }

    // Return the broadcast address to be used, or BROADCAST_ADDR if default broadcast address is used.   
     func (self NetBIOS) get_broadcastaddr(){
        return self.__broadcastaddr
     }

    // Returns a NBPositiveNameQueryResponse instance containing the host information for nbname.
    // If a NetBIOS domain nameserver has been specified, it will be used for the query.
    // Otherwise, the query is broadcasted on the broadcast address.
     func (self NetBIOS) gethostbyname(nbname, qtype = TYPE_WORKSTATION, scope = nil, timeout = 1 interface{}){
        resp = self.name_query_request(nbname, self.__nameserver, qtype, scope, timeout)
        return resp
     }

    // Returns a list of NBNodeEntry instances containing node status information for nbname.
    // If destaddr contains an IP address, then this will become an unicast query on the destaddr.
    // Raises NetBIOSTimeout if timeout (in secs) is reached.
    // Raises NetBIOSError for other errors
     func (self NetBIOS) getnodestatus(nbname, destaddr = nil, type = TYPE_WORKSTATION, scope = nil, timeout = 1 interface{}){
        if destaddr {
            return self.node_status_request(nbname, destaddr, type, scope, timeout)
        } else  {
            return self.node_status_request(nbname, self.__nameserver, type, scope, timeout)
        }
    }

     func (self NetBIOS) getnetbiosname(ip interface{}){
        entries = self.getnodestatus('*',ip)
        entries = [x for x in entries if x["TYPE"] == TYPE_SERVER]
        return entries[0]["NAME"].strip().decode("latin-1")
     }

     func (self NetBIOS) getmacaddress(){
        return self.mac
     }

     func (self NetBIOS) name_registration_request(nbname, destaddr, qtype, scope, nb_flags=0, nb_address="0.0.0.0" interface{}){
        netbios_name = nbname.upper()
        qn_label = encodeName(netbios_name, qtype, scope)

        p = NAME_REGISTRATION_REQUEST()
        p["NAME_TRN_ID"] = rand.randint(1, 32000)
        p["QUESTION_NAME"] = qn_label[:-1] + b'\x00'
        p["RR_NAME"] = qn_label[:-1] + b'\x00'
        p["TTL"] = 0xffff
        p["NB_FLAGS"] = nb_flags
        p["NB_ADDRESS"] = socket.inet_aton(nb_address)
        if not destaddr {
            p["FLAGS"] |= NM_FLAGS_BROADCAST
            destaddr = self.__broadcastaddr
        }
        res = self.send(p, destaddr, 1)
        return res
    }

     func (self NetBIOS) name_query_request(nbname, destaddr = nil, qtype = TYPE_SERVER, scope = nil, timeout = 1 interface{}){
        netbios_name = nbname.upper()
        qn_label = encodeName(netbios_name, qtype, scope)

        p = NAME_QUERY_REQUEST()
        p["NAME_TRN_ID"] = rand.randint(1, 32000)
        p["QUESTION_NAME"] = qn_label[:-1] + b'\x00'
        p["FLAGS"] = NM_FLAGS_RD
        if not destaddr {
            p["FLAGS"] |= NM_FLAGS_BROADCAST
            destaddr = self.__broadcastaddr
        }
        res = self.send(p, destaddr, timeout)
        return NBPositiveNameQueryResponse(res["ANSWERS"])
    }

     func (self NetBIOS) node_status_request(nbname, destaddr, type, scope, timeout interface{}){
        netbios_name = nbname.upper()
        qn_label = encodeName(netbios_name, type, scope)
        p = NODE_STATUS_REQUEST()
        p["NAME_TRN_ID"] = rand.randint(1, 32000)
        p["QUESTION_NAME"] = qn_label[:-1] + b'\x00'
        if not destaddr {
            p["FLAGS"] = NM_FLAGS_BROADCAST
            destaddr = self.__broadcastaddr
        }
        res = self.send(p, destaddr, timeout)
        answ = NBNodeStatusResponse(res["ANSWERS"])
        self.mac = answ.get_mac()
        return answ.entries
    }

//###############################################################################
// 4.2 SESSION SERVICE PACKETS
//###############################################################################

 type NetBIOSSessionPacket struct {
 }
     func (self NetBIOSSessionPacket) __init__(data=0 interface{}){
        self.type = 0x0
        self.flags = 0x0
        self.length = 0x0
        if data == 0 {
            self._trailer = b''
        } else  {
            try:
                self.type = indexbytes(data,0)
                if self.type == NETBIOS_SESSION_MESSAGE {
                    self.length = indexbytes(data,1) << 16 | (unpack("!H", data[2:4])[0])
                } else  {
                    self.flags = data[1]
                    self.length = unpack("!H", data[2:4])[0]
                }
                self._trailer = data[4:]
            except:
                raise NetBIOSError("Wrong packet format ")
        
        }
    }

     func (self NetBIOSSessionPacket) set_type(type interface{}){
        self.type = type
     }

     func (self NetBIOSSessionPacket) get_type(){
        return self.type
     }

     func (self NetBIOSSessionPacket) rawData(){
        if self.type == NETBIOS_SESSION_MESSAGE {
            data = pack("!BBH", self.type, self.length >> 16, self.length & 0xFFFF) + self._trailer
        } else  {
            data = pack("!BBH", self.type, self.flags, self.length) + self._trailer
        }
        return data
    }

     func (self NetBIOSSessionPacket) set_trailer(data interface{}){
        self._trailer = data
        self.length = len(data)
     }

     func (self NetBIOSSessionPacket) get_length(){
        return self.length
     }

     func (self NetBIOSSessionPacket) get_trailer(){
        return self._trailer
     }
        
 type NetBIOSSession struct {
    func (self NetBIOSSession) __init__(myname, remote_name, remote_host, remote_type=TYPE_SERVER, sess_port=NETBIOS_SESSION_PORT,
                 timeout=nil, local_type=TYPE_WORKSTATION, sock=nil){
        /*
        :param unicode myname: My local NetBIOS name
        :param unicode remote_name: Remote NetBIOS name
        :param unicode remote_host: Remote IP Address
        :param integer remote_type: NetBIOS Host type
        :param integer sess_port: Session port to connect (139,445)
        :param integer timeout: Timeout for connection
        :param integer local_type: My Local Host Type
        :param socket sock: Socket for already established connection
        */
        if len(myname) > 15 {
            self.__myname = myname[:15].upper()
        } else  {
            self.__myname = myname.upper()
        }
        self.__local_type = local_type

        assert remote_name
        // if destination port SMB_SESSION_PORT and remote name *SMBSERVER, we're changing it to its IP address
        // helping solving the client mistake ;)
        if remote_name == "*SMBSERVER" and sess_port == SMB_SESSION_PORT {
            remote_name = remote_host
        }

        // If remote name is *SMBSERVER let"s try to query its name.. if can"t be guessed, continue and hope for the best

        if remote_name == "*SMBSERVER" {
            nb = NetBIOS()
            try:
                res = nb.getnetbiosname(remote_host)
            except:
                res = nil
                pass

            if res != nil {
                remote_name = res
            }
        }

        if len(remote_name) > 15 {
            self.__remote_name = remote_name[:15].upper()
        } else  {
            self.__remote_name = remote_name.upper()
        }
        self.__remote_type = remote_type
        self.__remote_host = remote_host

        if sock != nil {
            // We are acting as a server
            self._sock = sock
        } else  {
            self._sock = self._setup_connection((remote_host, sess_port), timeout)
        }

        if sess_port == NETBIOS_SESSION_PORT {
            self._request_session(remote_type, local_type, timeout)
        }
    }

     func (self NetBIOSSession) _request_session(remote_type, local_type, timeout interface{}){
        raise NotImplementedError("Not Implemented!")
     }

     func (self NetBIOSSession) _setup_connection(peer, timeout=nil interface{}){
        raise NotImplementedError("Not Implemented!")
     }

     func (self NetBIOSSession) get_myname(){
        return self.__myname
     }

     func (self NetBIOSSession) get_mytype(){
        return self.__local_type
     }

     func (self NetBIOSSession) get_remote_host(){
        return self.__remote_host
     }

     func (self NetBIOSSession) get_remote_name(){
        return self.__remote_name
     }

     func (self NetBIOSSession) get_remote_type(){
        return self.__remote_type
     }

     func (self NetBIOSSession) close(){
        self._sock.close()
     }

     func (self NetBIOSSession) get_socket(){
        return self._sock
     }

 type NetBIOSUDPSessionPacket struct { // Structure:
    TYPE_DIRECT_UNIQUE = 16
    TYPE_DIRECT_GROUP  = 17

    FLAGS_MORE_FRAGMENTS = 1
    FLAGS_FIRST_FRAGMENT = 2
    FLAGS_B_NODE         = 0 (
        ("Type","B=16"),    // Direct Unique Datagram
        ("Flags","B=2"),    // FLAGS_FIRST_FRAGMENT
         ID uint16 // 
        ("_SourceIP",">L"),
        ("SourceIP",""""),
        ("SourcePort",">H=138"),
        ("DataLegth",">H-Data"),
        ("Offset",">H=0"),
        ("SourceName","z"),
        ("DestinationName","z"),
        ("Data",":"),
    }

     func (self NetBIOSUDPSessionPacket) getData(){
        addr = self.SourceIP.split(".")
        addr = [int(x) for x in addr]
        addr = (((addr[0] << 8) + addr[1] << 8) + addr[2] << 8) + addr[3]
        self._SourceIP = addr
        return Structure.getData(self)
     }

     func (self NetBIOSUDPSessionPacket) get_trailer(){
        return self.Data
     }

 type NetBIOSUDPSession struct {
     NetBIOSSession
 }
     func (self NetBIOSUDPSession) _setup_connection(peer, timeout=nil interface{}){
        af, socktype, proto, canonname, sa = socket.getaddrinfo(peer[0], peer[1], 0, socket.SOCK_DGRAM)[0]
        sock = socket.socket(af, socktype, proto)
        sock.connect(sa)

        sock = socket.socket(af, socktype, proto)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((INADDR_ANY, 138))
        self.peer = peer
        return sock
     }

     func (self NetBIOSUDPSession) _request_session(remote_type, local_type, timeout = nil interface{}){
        pass
     }

     func (self NetBIOSUDPSession) next_id(){
        if hasattr(self, "__dgram_id") {
            answer = self.__dgram_id
        } else  {
            self.__dgram_id = rand.randint(1,65535)
            answer = self.__dgram_id
        }
        self.__dgram_id += 1
        return answer
    }

     func (self NetBIOSUDPSession) send_packet(data interface{}){
        // Yes... I know...
        self._sock.connect(self.peer)

        p = NetBIOSUDPSessionPacket()
        p["ID"] = self.next_id()
        p["SourceIP"] = self._sock.getsockname()[0]
        p["SourceName"] = encodeName(self.get_myname(), self.get_mytype(), '')[:-1]
        p["DestinationName"] = encodeName(self.get_remote_name(), self.get_remote_type(), '')[:-1]
        p["Data"] = data

        self._sock.sendto(str(p), self.peer)
        self._sock.close()

        self._sock = self._setup_connection(self.peer)
     }

     func (self NetBIOSUDPSession) recv_packet(timeout = nil interface{}){
        // The next loop is a workaround for a bigger problem:
        // When data reaches higher layers, the lower headers are lost,
        // and with them, for example, the source IP. Hence, SMB users
        // can't know where packets are coming from... we need a better
        // solution, right now, we will filter everything except packets
        // coming from the remote_host specified in __init__()

        for{
            data, peer = self._sock.recvfrom(8192)
//            print "peer: %r  self.peer: %r" % (peer, self.peer)
            if peer == self.peer {
                break
            }
        }

        return NetBIOSUDPSessionPacket(data)
    }

 type NetBIOSTCPSession struct {
    NetBIOSSession
 }
    def (self NetBIOSTCPSession) __init__(myname, remote_name, remote_host, remote_type=TYPE_SERVER, sess_port=NETBIOS_SESSION_PORT,
                 timeout=nil, local_type=TYPE_WORKSTATION, sock=nil, select_poll=false){
        /*
        :param unicode myname: My local NetBIOS name
        :param unicode remote_name: Remote NetBIOS name
        :param unicode remote_host: Remote IP Address
        :param integer remote_type: NetBIOS Host type
        :param integer sess_port: Session port to connect (139,445)
        :param integer timeout: Timeout for connection
        :param integer local_type: My Local Host Type
        :param socket sock: Socket for already established connection
        :param boolean select_poll: Type of polling mechanism
        */
        self.__select_poll = select_poll
        if self.__select_poll {
            self.read_function = self.polling_read
        } else  {
            self.read_function = self.non_polling_read
        }
        NetBIOSSession.__init__(self, myname, remote_name, remote_host, remote_type=remote_type, sess_port=sess_port,
                                timeout=timeout, local_type=local_type, sock=sock)
        }

     func (self TYPE) _setup_connection(peer, timeout=nil interface{}){
        try:
            af, socktype, proto, canonname, sa = socket.getaddrinfo(peer[0], peer[1], 0, socket.SOCK_STREAM)[0]
            sock = socket.socket(af, socktype, proto)
            oldtimeout = sock.gettimeout()
            sock.settimeout(timeout)
            sock.connect(sa)
            sock.settimeout(oldtimeout)
        except socket.error as e:
            raise socket.error("Connection error (%s:%s)" % (peer[0], peer[1]), e)
        return sock
     }

     func (self TYPE) send_packet(data interface{}){
        p = NetBIOSSessionPacket()
        p.set_type(NETBIOS_SESSION_MESSAGE)
        p.set_trailer(data)
        self._sock.sendall(p.rawData())
     }

     func (self TYPE) recv_packet(timeout = nil interface{}){
        data = self.__read(timeout)
        return NetBIOSSessionPacket(data)
     }

     func (self TYPE) _request_session(remote_type, local_type, timeout = nil interface{}){
        p = NetBIOSSessionPacket()
        remote_name = encodeName(self.get_remote_name(), remote_type, '')
        myname = encodeName(self.get_myname(), local_type, '')
        p.set_type(NETBIOS_SESSION_REQUEST)
        p.set_trailer(remote_name + myname)

        self._sock.sendall(p.rawData())
        for {
            p = self.recv_packet(timeout)
            if p.get_type() == NETBIOS_SESSION_NEGATIVE_RESPONSE {
                raise NetBIOSError("Cannot request session (Called Name:%s)" % self.get_remote_name())
            }else if p.get_type() == NETBIOS_SESSION_POSITIVE_RESPONSE {
                break
            } else  {
                // Ignore all other messages, most probably keepalive messages
                pass
            }
        }
    }

     func (self TYPE) polling_read(read_length, timeout interface{}){
        data = b''
        if timeout == nil {
            timeout = 3600
        }

        time_left = timeout
        CHUNK_TIME = 0.025
        bytes_left = read_length

        for bytes_left > 0 {
            try:
                ready, _, _ = select.select([self._sock.fileno()], [], [], 0)

                if not ready {
                    if time_left <= 0 {
                        raise NetBIOSTimeout
                    } else  {
                        time.sleep(CHUNK_TIME)
                        time_left -= CHUNK_TIME
                        continue
                    }
                }

                received = self._sock.recv(bytes_left)
                if len(received) == 0 {
                    raise NetBIOSError("Error while reading from remote", ERRCLASS_OS, nil)
                }

                data = data + received
                bytes_left = read_length - len(data)
            except select.error as ex:
                if ex[0] != errno.EINTR and ex[0] != errno.EAGAIN {
                    raise NetBIOSError("Error occurs while reading from remote", ERRCLASS_OS, ex[0])
                }
        }

        return bytes(data)
    }

     func (self TYPE) non_polling_read(read_length, timeout interface{}){
        data = b''
        bytes_left = read_length

        for bytes_left > 0{
            try:
                ready, _, _ = select.select([self._sock.fileno()], [], [], timeout)

                if not ready {
                    raise NetBIOSTimeout
                }

                received = self._sock.recv(bytes_left)
                if len(received) == 0 {
                    raise NetBIOSError("Error while reading from remote", ERRCLASS_OS, nil)
                }

                data = data + received
                bytes_left = read_length - len(data)
            except select.error as ex:
                if ex[0] != errno.EINTR and ex[0] != errno.EAGAIN {
                    raise NetBIOSError("Error occurs while reading from remote", ERRCLASS_OS, ex[0])
                }
        }

        return bytes(data)
    }

     func (self TYPE) __read(timeout = nil interface{}){
        data = self.read_function(4, timeout)
        type, flags, length = unpack(">ccH", data)
        if ord(type) == NETBIOS_SESSION_MESSAGE {
            length |= ord(flags) << 16
        } else  {
            if ord(flags) & 0x01 {
                length |= 0x10000
            }
        }
        data2 = self.read_function(length, timeout)

        return data + data2
    }
        
