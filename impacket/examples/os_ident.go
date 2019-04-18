// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This computer software is owned by Core SDI Inc. and is
// protected by U.S. copyright laws and other laws and by international
// treaties.  This computer software is furnished by CORE SDI Inc.
// pursuant to a written license agreement and may be used, copied,
// transmitted, and stored only in accordance with the terms of such
// license and with the inclusion of the above copyright notice.  This
// computer software or any other copies thereof may not be provided or
// otherwise made available to any other person.
//
//`
// THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
// WARRANTIES ARE DISCLAIMED. IN NO EVENT SHALL CORE SDI Inc. BE LIABLE
// FOR ANY DIRECT,  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY OR
// CONSEQUENTIAL  DAMAGES RESULTING FROM THE USE OR MISUSE OF
// THIS SOFTWARE
//
//--
import math
import array
from six.moves import xrange, reduce

from pcapy import lookupdev, open_live
from impacket.ImpactPacket import UDP, TCPOption, Data, TCP, IP, ICMP, Ethernet
from impacket.ImpactDecoder import EthDecoder
from impacket import LOG

g_nmap1_signature_filename="nmap-os-fingerprints"
g_nmap2_signature_filename="nmap-os-db"


 func my_gcd(a, b interface{}){
    if a < b {
        c = a
        a = b
        b = c

    while 0 != b:
        c = a & b
        a = b
        b = c
    return a

 type os_id_exception: struct {
     func (self TYPE) __init__(value interface{}){
        self.value = value
     func (self TYPE) __str__(){
        return repr(self.value)

 type os_id_test: struct {
    
     func (self TYPE) __init__(id interface{}){
        self.__id = id
        self.__my_packet = nil
        self.__result_dict = {}

     func (self TYPE) test_id(){
        return self.__class__.__name__

     func (self TYPE) get_test_packet(){
        return self.__my_packet.get_packet()

     func (self TYPE) set_packet(packet interface{}){
        self.__my_packet = packet

     func (self TYPE) get_packet(){
        return self.__my_packet
        
     func (self TYPE) process(packet interface{}){
        pass

     func (self TYPE) add_result(name, value interface{}){
        self.__result_dict[name] = value
                
     func (self TYPE) get_id(){
        return self.__id
     func (self TYPE) is_mine(packet interface{}){
        pass

     func (self TYPE) get_result_dict(){
        return self.__result_dict;

     func (self TYPE) get_final_result(){
        "Returns a string representation of the final result of this test or nil if no response was received"
        pass


 type icmp_request struct { // os_id_test:
    type_filter = { ICMP.ICMP_ECHO : ICMP.ICMP_ECHOREPLY,
                    ICMP.ICMP_IREQ : ICMP.ICMP_IREQREPLY,
                    ICMP.ICMP_MASKREQ : ICMP.ICMP_MASKREPLY,
                    ICMP.ICMP_TSTAMP : ICMP.ICMP_TSTAMPREPLY }

     func (self TYPE) __init__(id, addresses, type interface{}){
        os_id_test.__init__(self, id)
        self.e = Ethernet()
        self.i = IP()
        self.icmp = ICMP()

        self.i.set_ip_src(addresses[0])
        self.i.set_ip_dst(addresses[1])

        self.__type = type
        self.icmp.set_icmp_type(type)
        
        self.e.contains(self.i)
        self.i.contains(self.icmp)
        self.set_packet(self.e)

     func (self TYPE) is_mine(packet interface{}){

        if packet.get_ether_type() != IP.ethertype {
            return 0
        ip = packet.child()
        if not ip or ip.get_ip_p() != ICMP.protocol {
            return 0
        icmp = ip.child()
        
        // icmp_request.type_filter is a dictionary that maps request 
        // type codes to the reply codes
        
        if not icmp or \
           icmp.get_icmp_type() != icmp_request.type_filter[self.__type]:
            return 0
        if icmp.get_icmp_id() != self.get_id() {
            return 0

        return 1

     func (self TYPE) process(packet interface{}){
        pass


 type nmap2_icmp_echo_probe_1 struct { // icmp_request:
    // The first one has the IP DF bit set, a type-of-service (TOS)  byte 
    // value of zero, a code of nine (even though it should be zero), 
    // the sequence number 295, a random IP ID and ICMP request identifier, 
    // and a random character repeated 120 times for the data payload.
    sequence_number = 295
    id = 0x5678

     func (self TYPE) __init__(id, addresses interface{}){
        icmp_request.__init__(self, id, addresses, ICMP.ICMP_ECHO)
        self.i.set_ip_df(true)
        self.i.set_ip_tos(0)
        self.icmp.set_icmp_code(9)
        self.icmp.set_icmp_seq(nmap2_icmp_echo_probe_1.sequence_number)
        self.i.set_ip_id(nmap2_icmp_echo_probe_1.id)
        self.icmp.set_icmp_id(nmap2_icmp_echo_probe_1.id)
        self.icmp.contains(Data("I" * 120))
        
     func (self TYPE) process(packet interface{}){
        pass

 type nmap2_icmp_echo_probe_2 struct { // icmp_request:
    // The second ping query is similar, except a TOS of four 
    // (IP_TOS_RELIABILITY) is used, the code is zero, 150 bytes of data is 
    // sent, and the IP ID, request ID, and sequence numbers are incremented 
    // by one from the previous query values.

     func (self TYPE) __init__(id, addresses interface{}){
        icmp_request.__init__(self, id, addresses, ICMP.ICMP_ECHO)
        self.i.set_ip_df(false)
        self.i.set_ip_tos(4)
        self.icmp.set_icmp_code(0)
        self.icmp.set_icmp_seq(nmap2_icmp_echo_probe_1.sequence_number + 1)
        self.i.set_ip_id(nmap2_icmp_echo_probe_1.id + 1)
        self.icmp.set_icmp_id(nmap2_icmp_echo_probe_1.id + 1)
        self.icmp.contains(Data("I" * 150))
        
     func (self TYPE) process(packet interface{}){
        pass

 type udp_closed_probe struct { // os_id_test:

    ip_id = 0x1234 // HARDCODED

     func (self TYPE) __init__(id, addresses, udp_closed  interface{}){

        os_id_test.__init__(self, id )
        self.e = Ethernet()
        self.i = IP()
        self.u = UDP()

        self.i.set_ip_src(addresses[0])
        self.i.set_ip_dst(addresses[1])
        self.i.set_ip_id(udp_closed_probe.ip_id)
        self.u.set_uh_sport(id)
        
        self.u.set_uh_dport( udp_closed )

        self.e.contains(self.i)
        self.i.contains(self.u)
        self.set_packet(self.e)

     func (self TYPE) is_mine(packet interface{}){
        if packet.get_ether_type() != IP.ethertype {
            return 0
        ip = packet.child()
        if not ip or ip.get_ip_p() != ICMP.protocol {
            return 0
        icmp = ip.child()
        if not icmp or icmp.get_icmp_type() != ICMP.ICMP_UNREACH {
            return 0
  
        if icmp.get_icmp_code() != ICMP.ICMP_UNREACH_PORT {
            return 0;
        
        
        self.err_data = icmp.child()
        if not self.err_data {
            return 0
        

        return 1


 type tcp_probe struct { // os_id_test:

     func (self TYPE) __init__(id, addresses, tcp_ports, open_port  interface{}){

        self.result_string = "[]"
        os_id_test.__init__(self, id)
        self.e = Ethernet()
        self.i = IP()
        self.t = TCP()
        self.i.set_ip_src(addresses[0])
        self.i.set_ip_dst(addresses[1])
        self.i.set_ip_id(0x2323) // HARDCODED
        self.t.set_th_sport(id)

        if open_port {        
            self.target_port = tcp_ports[0]
        } else  {
            self.target_port = tcp_ports[1]
                
        self.t.set_th_dport(self.target_port)
        
        self.e.contains(self.i)
        self.i.contains(self.t)
        self.set_packet(self.e)
        
        self.source_ip = addresses[0]
        self.target_ip = addresses[1]

     func (self TYPE) socket_match(ip, tcp interface{}){
        // scr ip and port
        if (ip.get_ip_src() != self.target_ip) or (tcp.get_th_sport() != self.target_port) {
            return 0
        // dst ip and port
        if(ip.get_ip_dst() != self.source_ip) or (tcp.get_th_dport() != self.get_id()):
            return 0
        return 1

     func (self TYPE) is_mine(packet interface{}){
        if packet.get_ether_type() != IP.ethertype {
            return 0
        ip = packet.child()
        if not ip or ip.get_ip_p() != TCP.protocol {
            return 0
        tcp = ip.child()
        if self.socket_match(ip, tcp) {
            return 1

        return 0        


 type nmap_tcp_probe struct { // tcp_probe:

     func (self TYPE) __init__(id, addresses, tcp_ports, open_port, sequence, options interface{}){
        tcp_probe.__init__(self, id, addresses, tcp_ports, open_port)
        self.t.set_th_seq(sequence)
        self.set_resp(false)
        for op in options:
            self.t.add_option(op)

     func set_resp(self,resp interface{}){
        pass

 type nmap1_tcp_probe struct { // nmap_tcp_probe:
    sequence = 0x8453 // 0xBASE, obviously
    mss = 265

    // From: https://nmap.org/nmap-fingerprinting-old.html
    // [...]
    // Nmap sends these options along with almost every probe packet:
    //   Window Scale=10; NOP; Max Segment Size = 265; Timestamp; End of Ops;
    // [...]
    // From nmap-4.22SOC8/osscan.cc:get_fingerprint(...)
    // [...]
    // "\003\003\012\001\002\004\001\011\010\012\077\077\077\077\000\000\000\000\000\000"
    // [...]
    tcp_options = [
        TCPOption(TCPOption.TCPOPT_WINDOW, 0o12), //\003\003\012
        TCPOption(TCPOption.TCPOPT_NOP), //\001
        TCPOption(TCPOption.TCPOPT_MAXSEG, mss), //\002\004\001\011
        TCPOption(TCPOption.TCPOPT_TIMESTAMP, 0x3F3F3F3F), //\010\012\077\077\077\077\000\000\000\000
        TCPOption(TCPOption.TCPOPT_EOL), //\000
        TCPOption(TCPOption.TCPOPT_EOL) //\000
    ]

     func (self TYPE) __init__(id, addresses, tcp_ports, open_port interface{}){
        nmap_tcp_probe.__init__(self, id, addresses, tcp_ports, open_port, 
                                self.sequence, self.tcp_options)

     func set_resp(self,resp interface{}){
        if resp {
            self.add_result("Resp", "Y")
        } else  {
            self.add_result("Resp", "N")

     func (self TYPE) process(packet interface{}){
        ip = packet.child()
        tcp = ip.child()

        self.set_resp(true)

        if ip.get_ip_df() {
            self.add_result("DF", "Y")
        } else  {
            self.add_result("DF", "N")

        self.add_result("W", tcp.get_th_win())

        if tcp.get_th_ack() == self.sequence + 1 {
            self.add_result("ACK", "S++")
        elif tcp.get_th_ack() == self.sequence {
            self.add_result("ACK", "S")
        } else  {
            self.add_result("ACK", "O")

        flags = []

        // TCP flags
        if tcp.get_ECE() {
            flags.append("B")
        if tcp.get_URG() {
            flags.append("U")
        if tcp.get_ACK() {
            flags.append("A")
        if tcp.get_PSH() {
            flags.append("P")
        if tcp.get_RST() {
            flags.append("R")
        if tcp.get_SYN() {
            flags.append("S")
        if tcp.get_FIN() {
            flags.append("F")

        self.add_result("FLAGS", flags)

        options = []

        for op in tcp.get_options():
            if op.get_kind() == TCPOption.TCPOPT_EOL {
                options.append("L")
            elif op.get_kind() == TCPOption.TCPOPT_MAXSEG {
                options.append("M")
                if op.get_mss() == self.mss {
                    options.append("E") // Echoed
            elif op.get_kind() == TCPOption.TCPOPT_NOP {
                options.append("N")
            elif op.get_kind() == TCPOption.TCPOPT_TIMESTAMP {
                options.append("T")
            elif op.get_kind() == TCPOption.TCPOPT_WINDOW {
                options.append("W")

        self.add_result("OPTIONS", options)

     func (self TYPE) get_final_result(){
        return {self.test_id(): self.get_result_dict()}


 type nmap2_tcp_probe struct { // nmap_tcp_probe:
    acknowledgment = 0x181d4f7b

     func (self TYPE) __init__(id, addresses, tcp_ports, open_port, sequence, options interface{}){
        nmap_tcp_probe.__init__(self, id, addresses, tcp_ports, open_port, 
                                sequence, options)
        self.t.set_th_ack(self.acknowledgment)

     func set_resp(self,resp interface{}){
        // Responsiveness (R)
        // This test simply records whether the target responded to a given probe. 
        // Possible values are Y and N. If there is no reply, remaining fields 
        // for the test are omitted.
        if resp {
            self.add_result("R", "Y")
        } else  {
            self.add_result("R", "N")

     func (self TYPE) process(packet interface{}){
        ip = packet.child()
        tcp = ip.child()

        // R, DF, T*, TG*, W, S, A, F, O, RD*, Q
        self.set_resp(true)

        tests = nmap2_tcp_tests(ip, tcp, self.sequence, self.acknowledgment)

        self.add_result("DF", tests.get_df())
        self.add_result("W", tests.get_win())
        self.add_result("S", tests.get_seq())
        self.add_result("A", tests.get_ack())
        self.add_result("F", tests.get_flags())
        self.add_result("O", tests.get_options())
        self.add_result("Q", tests.get_quirks())

     func (self TYPE) get_final_result(){
        return {self.test_id() : self.get_result_dict()}


 type nmap2_ecn_probe struct { // nmap_tcp_probe:
    // From nmap-4.22SOC8/osscan2.cc:
    // [...]
    // "\003\003\012\001\002\004\005\264\004\002\001\001"
    // [...]

    // From: https://nmap.org/book/osdetect-methods.html
    // [...]
    // This probe tests for explicit congestion notification (ECN) support 
    // in the target TCP stack. ECN is a method for improving Internet 
    // performance by allowing routers to signal congestion problems before 
    // they start having to drop packets. It is documented in RFC 3168. 
    // Nmap tests this by sending a SYN packet which also has the ECN CWR 
    // and ECE congestion control flags set. For an unrelated (to ECN) test, 
    // the urgent field value of 0xF7F5 is used even though the urgent flag 
    // is not set. The acknowledgment number is zero, sequence number is 
    // random, window size field is three, and the reserved bit which 
    // immediately precedes the CWR bit is set. TCP options are WScale (10), 
    // NOP, MSS (1460), SACK permitted, NOP, NOP. The probe is sent to an 
    // open port.
    // [...]
    tcp_options = [
        TCPOption(TCPOption.TCPOPT_WINDOW, 0o12), //\003\003\012
        TCPOption(TCPOption.TCPOPT_NOP), //\001
        TCPOption(TCPOption.TCPOPT_MAXSEG, 1460), //\002\004\005\0264
        TCPOption(TCPOption.TCPOPT_SACK_PERMITTED), //\004\002
        TCPOption(TCPOption.TCPOPT_NOP), //\001
        TCPOption(TCPOption.TCPOPT_NOP) //\001
    ]


     func (self TYPE) __init__(id, addresses, tcp_ports interface{}){
        nmap_tcp_probe.__init__(self, id, addresses, tcp_ports, 1, 
                                0x8b6a, self.tcp_options)
        self.t.set_SYN()
        self.t.set_CWR()
        self.t.set_ECE()
        self.t.set_flags(0x800)
        self.t.set_th_urp(0xF7F5)
        self.t.set_th_ack(0)
        self.t.set_th_win(3)
        //self.t.set_th_flags(self.t.get_th_flags() | 0x0100) # 0000 0001 00000000

     func (self TYPE) test_id(){
        return "ECN"

     func set_resp(self,resp interface{}){
        if resp {
            self.add_result("R", "Y")
        } else  {
            self.add_result("R", "N")

     func (self TYPE) process(packet interface{}){
        ip = packet.child()
        tcp = ip.child()

        // R, DF, T*, TG*, W, O, CC, Q
        self.set_resp(true)

        tests = nmap2_tcp_tests(ip, tcp, 0, 0)

        self.add_result("DF", tests.get_df())
        self.add_result("W", tests.get_win())
        self.add_result("O", tests.get_options())
        self.add_result("CC", tests.get_cc())
        self.add_result("Q", tests.get_quirks())

     func (self TYPE) get_final_result(){
        return {self.test_id() : self.get_result_dict()}

 type nmap2_tcp_tests: struct {
     func (self TYPE) __init__(ip, tcp, sequence, acknowledgment interface{}){
        self.__ip = ip
        self.__tcp = tcp
        self.__sequence = sequence
        self.__acknowledgment = acknowledgment

     func (self TYPE) get_df(){
        // IP don't fragment bit (DF)
        // The IP header contains a single bit which forbids routers from fragmenting 
        // a packet. If the packet is too large for routers to handle, they will just 
        // have to drop it (and ideally return a "destination unreachable,
        // fragmentation needed" response). This test records Y if the bit is set, 
        // and N if it isn't.
        if self.__ip.get_ip_df() {
            return "Y"
        } else  {
            return "N"

     func (self TYPE) get_win(){
        // TCP initial window size (W, W1-W6)
        // This test simply records the 16-bit TCP window size of the received packet. 
        return "%X" % self.__tcp.get_th_win()

     func (self TYPE) get_ack(){
        // TCP acknowledgment number (A)
        // This test is the same as S except that it tests how the acknowledgment 
        // number in the response compares to the sequence number in the 
        // respective probe.
        // Value	Description
        // Z	    Acknowledgment number is zero.
        // S	    Acknowledgment number is the same as the sequence number in the probe.
        // S+	Acknowledgment number is the same as the sequence number in the probe plus one.
        // O	    Acknowledgment number is something else (other).
        if self.__tcp.get_th_ack() == self.__sequence + 1 {
            return "S+"
        elif self.__tcp.get_th_ack() == self.__sequence {
            return "S"
        elif self.__tcp.get_th_ack() == 0 {
            return "Z"
        } else  {
            return "O"

     func (self TYPE) get_seq(){
        // TCP sequence number (S)
        // This test examines the 32-bit sequence number field in the TCP 
        // header. Rather than record the field value as some other tests 
        // do, this one examines how it compares to the TCP acknowledgment 
        // number from the probe that elicited the response. 
        // Value	    Description
        // Z	        Sequence number is zero.
        // A	        Sequence number is the same as the acknowledgment number in the probe.
        // A+	    Sequence number is the same as the acknowledgment number in the probe plus one.
        // O	        Sequence number is something else (other).
        if self.__tcp.get_th_seq() == self.__acknowledgment + 1 {
            return "A+"
        elif self.__tcp.get_th_seq() == self.__acknowledgment {
            return "A"
        elif self.__tcp.get_th_seq() == 0 {
            return "Z"
        } else  {
            return "O"

     func (self TYPE) get_flags(){
        // TCP flags (F)
        // This field records the TCP flags in the response. Each letter represents 
        // one flag, and they occur in the same order as in a TCP packet (from 
        // high-bit on the left, to the low ones). So the value SA represents the 
        // SYN and ACK bits set, while the value AS is illegal (wrong order). 
        // The possible flags are shown in Table 8.7.
        // Character	Flag name	            Flag byte value
        // E	        ECN Echo (ECE)	        64
        // U	        Urgent Data (URG)	    32
        // A	        Acknowledgment (ACK)	16
        // P	        Push (PSH)	            8
        // R	        Reset (RST)	            4
        // S	        Synchronize (SYN)	    2
        // F	        Final (FIN)	            1
        
        flags = ""

        if self.__tcp.get_ECE() {
            flags += "E"
        if self.__tcp.get_URG() {
            flags += "U"
        if self.__tcp.get_ACK() {
            flags += "A"
        if self.__tcp.get_PSH() {
            flags += "P"
        if self.__tcp.get_RST() {
            flags += "R"
        if self.__tcp.get_SYN() {
            flags += "S"
        if self.__tcp.get_FIN() {
            flags += "F"

        return flags

     func (self TYPE) get_options(){
        // Option Name	                    Character    Argument (if any)
        // End of Options List (EOL)	        L	         
        // No operation (NOP)	            N	         
        // Maximum Segment Size (MSS)	    M	         The value is appended. Many systems 
        //                                                echo the value used in the corresponding probe.
        // Window Scale (WS)	                W	         The actual value is appended.
        // Timestamp (TS)	                T	         The T is followed by two binary characters 
        //                                                representing the TSval and TSecr values respectively. 
        //                                                The characters are 0 if the field is zero 
        //                                                and 1 otherwise.
        // Selective ACK permitted (SACK)	S	        

        options = ""
        
        for op in self.__tcp.get_options():
            if op.get_kind() == TCPOption.TCPOPT_EOL {
                options += "L"
            elif op.get_kind() == TCPOption.TCPOPT_MAXSEG {
                options += "M%X" % (op.get_mss())
            elif op.get_kind() == TCPOption.TCPOPT_NOP {
                options += "N"
            elif op.get_kind() == TCPOption.TCPOPT_TIMESTAMP {
                options += "T%i%i" % (int(op.get_ts()!=0),
                                      int(op.get_ts_echo()!=0))
            elif op.get_kind() == TCPOption.TCPOPT_WINDOW {
                options += "W%X" % (op.get_shift_cnt())
            elif op.get_kind() == TCPOption.TCPOPT_SACK_PERMITTED {
                options += "S"

        return options

     func (self TYPE) get_cc(){
        // Explicit congestion notification (CC)
        // This test is only used for the ECN probe. That probe is a SYN packet 
        // which includes the CWR and ECE congestion control flags. When the 
        // response SYN/ACK is received, those flags are examined to set the 
        // CC (congestion control) test value as described in Table 8.3.

        // Table 8.3. CC test values
        // Value	Description
        // Y	    Only the ECE bit is set (not CWR). This host supports ECN.
        // N	    Neither of these two bits is set. The target does not support 
        //       ECN.
        // S	    Both bits are set. The target does not support ECN, but it 
        //       echoes back what it thinks is a reserved bit.
        // O	    The one remaining combination of these two bits (other).
        ece, cwr = self.__tcp.get_ECE(), self.__tcp.get_CWR()
        if ece and not cwr {
            return "Y"
        elif not ece and not cwr {
            return "N"
        elif ece and cwr {
            return "S"
        } else  {
            return "O"

     func (self TYPE) get_quirks(){
        // TCP miscellaneous quirks (Q)
        // This tests for two quirks that a few implementations have in their 
        // TCP stack. The first is that the reserved field in the TCP header 
        // (right after the header length) is nonzero. This is particularly 
        // likely to happen in response to the ECN test as that one sets a 
        // reserved bit in the probe. If this is seen in a packet, an "R"
        // is recorded in the Q string.

        // The other quirk Nmap tests for is a nonzero urgent pointer field 
        // value when the URG flag is not set. This is also particularly 
        // likely to be seen in response to the ECN probe, which sets a 
        // non-zero urgent field. A "U" is appended to the Q string when 
        // this is seen.

        // The Q string must always be generated in alphabetical order. 
        // If no quirks are present, the Q test is empty but still shown.

        quirks = ""

        if ((self.__tcp.get_th_flags() >> 8) & 0x0f) != 0 {
            quirks += "R"
        if self.__tcp.get_URG() == 0 and self.__tcp.get_th_urp() != 0 {
            quirks += "U"

        return quirks

 type nmap2_tcp_probe_2_6 struct { // nmap2_tcp_probe:
    sequence = 0x8453 // 0xBASE, obviously
    mss = 265

    // From nmap-4.22SOC8/osscan2.cc:
    // [...]
    // "\003\003\012\001\002\004\001\011\010\012\377\377\377\377\000\000\000\000\004\002"
    // [...]

    // From: https://nmap.org/book/osdetect-methods.html
    // [...]
    // The six T2 through T7 tests each send one TCP probe packet. 
    // With one exception, the TCP options data in each case is (in hex) 
    // 03030A0102040109080AFFFFFFFF000000000402. 
    // Those 20 bytes correspond to window scale (10), NOP, MSS (265), 
    // Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), then SACK permitted. 
    // (...
    tcp_options = [
        TCPOption(TCPOption.TCPOPT_WINDOW, 0o12), //\003\003\012
        TCPOption(TCPOption.TCPOPT_NOP), //\001
        TCPOption(TCPOption.TCPOPT_MAXSEG, mss), //\002\004\001\011
        TCPOption(TCPOption.TCPOPT_TIMESTAMP, 0xFFFFFFFF), //\010\012\377\377\377\377\000\000\000\000
        TCPOption(TCPOption.TCPOPT_SACK_PERMITTED) //\004\002
    ]

     func (self TYPE) __init__(id, addresses, tcp_ports, open_port interface{}){
        nmap2_tcp_probe.__init__(self, id, addresses, tcp_ports, open_port, 
                                 self.sequence, self.tcp_options)

 type nmap2_tcp_probe_7 struct { // nmap2_tcp_probe:
    sequence = 0x8453 // 0xBASE, obviously
    mss = 265

    // ...)
    // The exception is that T7 uses a Window scale value of 15 rather than 10
    // [...]
    tcp_options = [
        TCPOption(TCPOption.TCPOPT_WINDOW, 0o17), //\003\003\017
        TCPOption(TCPOption.TCPOPT_NOP), //\001
        TCPOption(TCPOption.TCPOPT_MAXSEG, mss), //\002\004\001\011
        TCPOption(TCPOption.TCPOPT_TIMESTAMP, 0xFFFFFFFF), //\010\012\377\377\377\377\000\000\000\000
        TCPOption(TCPOption.TCPOPT_SACK_PERMITTED) //\004\002
    ]

     func (self TYPE) __init__(id, addresses, tcp_ports, open_port interface{}){
        nmap2_tcp_probe.__init__(self, id, addresses, tcp_ports, open_port, 
                                 self.sequence, self.tcp_options)

 type nmap_port_unreachable struct { // udp_closed_probe:

     func (self TYPE) __init__(id, addresses, ports interface{}){
        udp_closed_probe.__init__(self, id, addresses, ports[2])
        self.set_resp(false)

     func (self TYPE) test_id(){
        pass

     func (self TYPE) set_resp(resp interface{}){
        pass

     func (self TYPE) process(packet interface{}){
        pass

 type nmap1_port_unreachable struct { // nmap_port_unreachable:

     func (self TYPE) __init__(id, addresses, ports interface{}){
        nmap_port_unreachable.__init__(self, id, addresses, ports)
        self.u.contains(Data("A" * 300))

     func (self TYPE) test_id(){
        return "PU"

     func set_resp(self,resp interface{}){
        if resp {
            self.add_result("Resp", "Y")
        } else  {
            self.add_result("Resp", "N")

     func (self TYPE) process(packet interface{}){
        ip_orig = self.err_data
        if ip_orig.get_ip_p() != UDP.protocol {
            return

        udp = ip_orig.child()

        if not udp {
            return

        ip = packet.child()

        self.set_resp(true)

        if ip.get_ip_df() {
            self.add_result("DF", "Y")
        } else  {
            self.add_result("DF", "N")

        self.add_result("TOS", ip.get_ip_tos())

        self.add_result("IPLEN", ip.get_ip_len())

        self.add_result("RIPTL", ip_orig.get_ip_len()) // Some systems return a different IPLEN

        recv_ip_id = ip_orig.get_ip_id()
        if 0 == recv_ip_id {
            self.add_result("RID", "0")
        elif udp_closed_probe.ip_id == recv_ip_id {
            self.add_result("RID", "E")
        } else  {
            self.add_result("RID", "F")

        ip_sum = ip_orig.get_ip_sum()
        ip_orig.set_ip_sum(0)
        checksum = ip_orig.compute_checksum(ip_orig.get_bytes())

        if 0 == checksum {
            self.add_result("RIPCK", "0")
        elif checksum == ip_sum {
            self.add_result("RIPCK", "E")
        } else  {
            self.add_result("RIPCK", "F")

        udp_sum = udp.get_uh_sum()
        udp.set_uh_sum(0)
        udp.auto_checksum = 1
        udp.calculate_checksum()

        if 0 == udp_sum {
            self.add_result("UCK", "0")
        elif self.u.get_uh_sum() == udp_sum {
            self.add_result("UCK", "E")
        } else  {
            self.add_result("UCK", "F")
            
        self.add_result("ULEN", udp.get_uh_ulen())

        if ip.child().child().child().child() == udp.child() { // Some systems meddle with the data
            self.add_result("DAT", "E")
        } else  {
            self.add_result("DAT", "F")

     func (self TYPE) get_final_result(){
        return {self.test_id(): self.get_result_dict()}        

 type nmap2_port_unreachable struct { // nmap_port_unreachable:
    // UDP (U1)
    // This probe is a UDP packet sent to a closed port. The character 'C'
    // (0x43) is repeated 300 times for the data field. The IP ID value is 
    // set to 0x1042 for operating systems which allow us to set this. If 
    // the port is truly closed and there is no firewall in place, Nmap 
    // expects to receive an ICMP port unreachable message in return. 
    // That response is then subjected to the R, DF, T, TG, TOS, IPL, UN, 
    // RIPL, RID, RIPCK, RUCK, RUL, and RUD tests. 
     func (self TYPE) __init__(id, addresses, ports interface{}){
        nmap_port_unreachable.__init__(self, id, addresses, ports)
        self.u.contains(Data("C" * 300))
        self.i.set_ip_id(0x1042)

     func (self TYPE) test_id(){
        return "U1"

     func set_resp(self,resp interface{}){
        if resp {
            self.add_result("R", "Y")
        } else  {
            self.add_result("R", "N")

     func (self TYPE) process(packet interface{}){
        ip_orig = self.err_data
        if ip_orig.get_ip_p() != UDP.protocol {
            return

        udp = ip_orig.child()

        if not udp {
            return

        ip = packet.child()

        icmp = ip.child()

        if ip.get_ip_df() {
            self.add_result("DF", "Y")
        } else  {
            self.add_result("DF", "N")

    // XXX T
        // IP initial time-to-live (T)
        // IP packets contain a field named time-to-live (TTL) which is 
        // decremented every time they traverse a router. If the field 
        // reaches zero, the packet must be discarded. This prevents 
        // packets from looping endlessly. Because operating systems differ 
        // on which TTL they start with, it can be used for OS detection. 
        // Nmap determines how many hops away it is from the target by 
        // examining the ICMP port unreachable response to the U1 probe. 
        // That response includes the original IP packet, including the 
        // already-decremented TTL field, received by the target. By 
        // subtracting that value from our as-sent TTL, we learn how many 
        // hops away the machine is. Nmap then adds that hop distance to 
        // the probe response TTL to determine what the initial TTL was 
        // when that ICMP probe response packet was sent. That initial TTL 
        // value is stored in the fingerprint as the T result.
        // Even though an eight-bit field like TTL can never hold values 
        // greater than 0xFF, this test occasionally results in values of 
        // 0x100 or higher. This occurs when a system (could be the source, 
        // a target, or a system in between) corrupts or otherwise fails to
        // correctly decrement the TTL. It can also occur due to asymmetric 
        // routes.

    // XXX TG
        // IP initial time-to-live guess (TG)
        // It is not uncommon for Nmap to receive no response to the U1 probe, 
        // which prevents Nmap from learning how many hops away a target is. 
        // Firewalls and NAT devices love to block unsolicited UDP packets. 
        // But since common TTL values are spread well apart and targets are 
        // rarely more than 20 hops away, Nmap can make a pretty good guess 
        // anyway. Most systems send packets with an initial TTL of 32, 60, 64, 
        // 128, or 255. So the TTL value received in the response is rounded 
        // up to the next value out of 32, 64, 128, or 255. 60 is not in that 
        // list because it cannot be reliably distinguished from 64. It is 
        // rarely seen anyway. 
        // The resulting guess is stored in the TG field. This TTL guess field 
        // is not printed in a subject fingerprint if the actual TTL (T) value 
        // was discovered.

        // IP type of service (TOS)
        // This test simply records the type of service byte from the 
        // IP header of ICMP port unreachable packets. 
        // This byte is described in RFC 791
        self.add_result("TOS", "%X" % ip.get_ip_tos())

        // IP total length (IPL)
        // This test records the total length (in octets) of an IP packet. 
        // It is only used for the port unreachable response elicited by the 
        // U1 test.
        self.add_result("IPL", "%X" % ip.get_ip_len())

        // Unused port unreachable field nonzero (UN)
        // An ICMP port unreachable message header is eight bytes long, but 
        // only the first four are used. RFC 792 states that the last four 
        // bytes must be zero. A few implementations (mostly ethernet switches 
        // and some specialized embedded devices) set it anyway. The value of 
        // those last four bytes is recorded in this field.
        self.add_result("UN", "%X" % icmp.get_icmp_void()) 

        // Returned probe IP total length value (RIPL)
        // ICMP port unreachable messages (as are sent in response to the U1 
        // probe) are required to include the IP header which generated them. 
        // This header should be returned just as they received it, but some 
        // implementations send back a corrupted version due to changes they 
        // made during IP processing. This test simply records the returned 
        // IP total length value. If the correct value of 0x148 (328) is 
        // returned, the value G (for good) is stored instead of the actual value.
        if ip_orig.get_ip_len() == 0x148 {
            self.add_result("RIPL","G")
        } else  {
            self.add_result("RIPL", "%X" % ip_orig.get_ip_len())

        // Returned probe IP ID value (RID)
        // The U1 probe has a static IP ID value of 0x1042. If that value is 
        // returned in the port unreachable message, the value G is stored for 
        // this test. Otherwise the exact value returned is stored. Some systems, 
        // such as Solaris, manipulate IP ID values for raw IP packets that 
        // Nmap sends. In such cases, this test is skipped. We have found 
        // that some systems, particularly HP and Xerox printers, flip the bytes 
        // and return 0x4210 instead. 
        if 0x1042 == ip_orig.get_ip_id() {
            self.add_result("RID", "G")
        } else  {
            self.add_result("RID", "%X" % ip_orig.get_ip_id())

        // Integrity of returned probe IP checksum value (RIPCK)
        // The IP checksum is one value that we don't expect to remain the same 
        // when returned in a port unreachable message. After all, each network 
        // hop during transit changes the checksum as the TTL is decremented. 
        // However, the checksum we receive should match the enclosing IP packet. 
        // If it does, the value G (good) is stored for this test. If the returned 
        // value is zero, then Z is stored. Otherwise the result is I (invalid).
        ip_sum = ip_orig.get_ip_sum()
        ip_orig.set_ip_sum(0)
        checksum = ip_orig.compute_checksum(ip_orig.get_bytes())

        if 0 == checksum {
            self.add_result("RIPCK", "Z")
        elif checksum == ip_sum {
            self.add_result("RIPCK", "G")
        } else  {
            self.add_result("RIPCK", "I")

        // Integrity of returned probe UDP length and checksum (RUL and RUCK)
        // The UDP header length and checksum values should be returned exactly 
        // as they were sent. If so, G is recorded for these tests. Otherwise 
        // the value actually returned is recorded. The proper length is 0x134 (308).
        udp_sum = udp.get_uh_sum()
        udp.set_uh_sum(0)
        udp.auto_checksum = 1
        udp.calculate_checksum()

        if self.u.get_uh_sum() == udp_sum {
            self.add_result("RUCK", "G")
        } else  {
            self.add_result("RUCK", "%X" % udp_sum)
            
        if udp.get_uh_ulen() == 0x134 {
            self.add_result("RUL","G")
        } else  {
            self.add_result("RUL", "%X" % udp.get_uh_ulen())

        // Integrity of returned UDP data (RUD)
        // If the UDP payload returned consists of 300 'C' (0x43) 
        // characters as expected, a G is recorded for this test. 
        // Otherwise I (invalid) is recorded.
        if ip.child().child().child().child() == udp.child() {
            self.add_result("RUD", "G")
        } else  {
            self.add_result("RUD", "I")

     func (self TYPE) get_final_result(){
        return {self.test_id(): self.get_result_dict()}        

 type OS_ID: struct {

     func (self TYPE) __init__(target, ports interface{}){
        pcap_dev = lookupdev()
        self.p = open_live(pcap_dev, 600, 0, 3000)
        
        self.__source = self.p.getlocalip()
        self.__target = target
        
        self.p.setfilter("src host %s and dst host %s" % (target, self.__source), 1, 0xFFFFFF00)
        self.p.setmintocopy(10)
        self.decoder = EthDecoder()
        
        self.tests_sent = []
        self.outstanding_count = 0
        self.results = {}
        self.current_id = 12345

        self.__ports = ports

     func (self TYPE) releasePcap(){
        if not (self.p == nil) {
            self.p.close()

     func (self TYPE) get_new_id(){
        id = self.current_id
        self.current_id += 1
        self.current_id &= 0xFFFF
        return id
        
     func (self TYPE) send_tests(tests interface{}){
        self.outstanding_count = 0
        
        for t_ type in tests: struct {

            // Ok, I need to know if the constructor accepts the parameter port
            // We could ask also by co_varnames, but the port parameters is not a standarized... asking by args count :(
            if t_class.__init__.im_func.func_code.co_argcount == 4 {
                test = t_class(self.get_new_id(), [self.__source, self.__target], self.__ports )
            } else  {
                test = t_class(self.get_new_id(), [self.__source, self.__target] )

            self.p.sendpacket(test.get_test_packet())
            self.outstanding_count += 1
            self.tests_sent.append(test)
            while self.p.readready():
                self.p.dispatch(1, self.packet_handler)

        while self.outstanding_count > 0:
            data = self.p.next()[0]
            if data {
                self.packet_handler(0, data)
            } else  {                
                break

     func (self TYPE) run(){
        pass

     func (self TYPE) get_source(){
        return self.__source

     func (self TYPE) get_target(){
        return self.__target

     func (self TYPE) get_ports(){
        return self.__ports

     func (self TYPE) packet_handler(len, data interface{}){
        packet = self.decoder.decode(data)
        
        for t in self.tests_sent:
            if t.is_mine(packet) {
                t.process(packet)
                self.outstanding_count -= 1


 type nmap1_tcp_open_1 struct { // nmap1_tcp_probe:
     func (self TYPE) __init__(id, addresses, tcp_ports interface{}){
        nmap1_tcp_probe.__init__(self, id, addresses, tcp_ports, 1)
        self.t.set_ECE()
        self.t.set_SYN()

     func (self TYPE) test_id(){
        return "T1"

     func (self TYPE) is_mine(packet interface{}){
        if tcp_probe.is_mine(self, packet) {
            ip = packet.child()
            if not ip {
                return 0
            tcp = ip.child()
            if not tcp {
                return 0
            if tcp.get_SYN() and tcp.get_ACK() {
                return 1
            } else  {
                return 0
        } else  {
            return 0


 type nmap1_tcp_open_2 struct { // nmap1_tcp_probe:
     func (self TYPE) __init__(id, addresses, tcp_ports interface{}){
        nmap1_tcp_probe.__init__(self, id, addresses, tcp_ports, 1)

     func (self TYPE) test_id(){
        return "T2"

 type nmap2_tcp_open_2 struct { // nmap2_tcp_probe_2_6:
    // From: https://nmap.org/book/osdetect-methods.html
    // [...]
    // T2 sends a TCP null (no flags set) packet with the IP DF bit set and a 
    // window field of 128 to an open port.
    // ...
     func (self TYPE) __init__(id, addresses, tcp_ports interface{}){
        nmap2_tcp_probe_2_6.__init__(self, id, addresses, tcp_ports, 1)
        self.i.set_ip_df(1)
        self.t.set_th_win(128)

     func (self TYPE) test_id(){
        return "T2"

 type nmap1_tcp_open_3 struct { // nmap1_tcp_probe:
     func (self TYPE) __init__(id, addresses, tcp_ports  interface{}){
        nmap1_tcp_probe.__init__(self, id, addresses, tcp_ports, 1)
        self.t.set_SYN()
        self.t.set_FIN()
        self.t.set_URG()
        self.t.set_PSH()

     func (self TYPE) test_id(){
        return "T3"

 type nmap2_tcp_open_3 struct { // nmap2_tcp_probe_2_6:
    // ...
    // T3 sends a TCP packet with the SYN, FIN, URG, and PSH flags set and a 
    // window field of 256 to an open port. The IP DF bit is not set.
    // ...
     func (self TYPE) __init__(id, addresses, tcp_ports  interface{}){
        nmap2_tcp_probe_2_6.__init__(self, id, addresses, tcp_ports, 1)
        self.t.set_SYN()
        self.t.set_FIN()
        self.t.set_URG()
        self.t.set_PSH()
        self.t.set_th_win(256)
        self.i.set_ip_df(0)

     func (self TYPE) test_id(){
        return "T3"

 type nmap1_tcp_open_4 struct { // nmap1_tcp_probe:
     func (self TYPE) __init__(id, addresses, tcp_ports interface{}){
        nmap1_tcp_probe.__init__(self, id, addresses, tcp_ports, 1)
        self.t.set_ACK()

     func (self TYPE) test_id(){
        return "T4"

 type nmap2_tcp_open_4 struct { // nmap2_tcp_probe_2_6:
    // ...
    // T4 sends a TCP ACK packet with IP DF and a window field of 1024 to 
    // an open port.
    // ...
     func (self TYPE) __init__(id, addresses, tcp_ports  interface{}){
        nmap2_tcp_probe_2_6.__init__(self, id, addresses, tcp_ports, 1)
        self.t.set_ACK()
        self.i.set_ip_df(1)
        self.t.set_th_win(1024)

     func (self TYPE) test_id(){
        return "T4"


 type nmap1_seq struct { // nmap1_tcp_probe:
    SEQ_UNKNOWN = 0
    SEQ_64K = 1
    SEQ_TD = 2
    SEQ_RI = 4
    SEQ_TR = 8
    SEQ_i800 = 16
    SEQ_CONSTANT = 32

    TS_SEQ_UNKNOWN = 0
    TS_SEQ_ZERO = 1 // At least one of the timestamps we received back was 0
    TS_SEQ_2HZ = 2
    TS_SEQ_100HZ = 3
    TS_SEQ_1000HZ = 4
    TS_SEQ_UNSUPPORTED = 5 // System didn't send back a timestamp

    IPID_SEQ_UNKNOWN = 0
    IPID_SEQ_INCR = 1  // simple increment by one each time
    IPID_SEQ_BROKEN_INCR = 2 // Stupid MS -- forgot htons() so it counts by 256 on little-endian platforms
    IPID_SEQ_RPI = 3 // Goes up each time but by a "random" positive increment
    IPID_SEQ_RD = 4 // Appears to select IPID using a "random" distributions (meaning it can go up or down)
    IPID_SEQ_CONSTANT = 5 // Contains 1 or more sequential duplicates
    IPID_SEQ_ZERO = 6 // Every packet that comes back has an IP.ID of 0 (eg Linux 2.4 does this)

     func (self TYPE) __init__(id, addresses, tcp_ports interface{}){
        nmap1_tcp_probe.__init__(self, id, addresses, tcp_ports, 1)
        self.t.set_SYN()
        self.t.set_th_seq(id) // Used to match results with sent packets.

     func (self TYPE) process(p interface{}){
        raise Exception("Method process is meaningless for  type %s." % self.__class__.__name__) struct {


 type nmap2_seq struct { // nmap2_tcp_probe:
    TS_SEQ_UNKNOWN = 0
    TS_SEQ_ZERO = 1 // At least one of the timestamps we received back was 0
    TS_SEQ_UNSUPPORTED = 5 // System didn't send back a timestamp

    IPID_SEQ_UNKNOWN = 0
    IPID_SEQ_INCR = 1  // simple increment by one each time
    IPID_SEQ_BROKEN_INCR = 2 // Stupid MS -- forgot htons() so it counts by 256 on little-endian platforms
    IPID_SEQ_RPI = 3 // Goes up each time but by a "random" positive increment
    IPID_SEQ_RD = 4 // Appears to select IPID using a "random" distributions (meaning it can go up or down)
    IPID_SEQ_CONSTANT = 5 // Contains 1 or more sequential duplicates
    IPID_SEQ_ZERO = 6 // Every packet that comes back has an IP.ID of 0 (eg Linux 2.4 does this)

     func (self TYPE) __init__(id, addresses, tcp_ports, options interface{}){
        nmap2_tcp_probe.__init__(self, id, addresses, tcp_ports, 1, 
                                 id, options)
        self.t.set_SYN()

     func (self TYPE) process(p interface{}){
        raise Exception("Method process is meaningless for  type %s." % self.__class__.__name__) struct {

 type nmap2_seq_1 struct { // nmap2_seq:
    // Packet #1: window scale (10), 
    //            NOP, 
    //            MSS (1460), 
    //            timestamp (TSval: 0xFFFFFFFF; TSecr: 0), 
    //            SACK permitted. 
    // The window field is 1.
    tcp_options = [
        TCPOption(TCPOption.TCPOPT_WINDOW, 10),
        TCPOption(TCPOption.TCPOPT_NOP),
        TCPOption(TCPOption.TCPOPT_MAXSEG, 1460),
        TCPOption(TCPOption.TCPOPT_TIMESTAMP, 0xFFFFFFFF),
        TCPOption(TCPOption.TCPOPT_SACK_PERMITTED)
    ]

     func (self TYPE) __init__(id, addresses, tcp_ports interface{}){
        nmap2_seq.__init__(self, id, addresses, tcp_ports, self.tcp_options)
        self.t.set_th_win(1)

 type nmap2_seq_2 struct { // nmap2_seq:
    // Packet #2: MSS (1400), 
    //            window scale (0), 
    //            SACK permitted, 
    //            timestamp (TSval: 0xFFFFFFFF; TSecr: 0), 
    //            EOL. 
    // The window field is 63.
    tcp_options = [
        TCPOption(TCPOption.TCPOPT_MAXSEG, 1400),
        TCPOption(TCPOption.TCPOPT_WINDOW, 0),
        TCPOption(TCPOption.TCPOPT_SACK_PERMITTED),
        TCPOption(TCPOption.TCPOPT_TIMESTAMP, 0xFFFFFFFF),
        TCPOption(TCPOption.TCPOPT_EOL)
    ]

     func (self TYPE) __init__(id, addresses, tcp_ports interface{}){
        nmap2_seq.__init__(self, id, addresses, tcp_ports, self.tcp_options)
        self.t.set_th_win(63)

 type nmap2_seq_3 struct { // nmap2_seq:
    // Packet #3: Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), 
    //            NOP, 
    //            NOP, 
    //            window scale (5), 
    //            NOP, 
    //            MSS (640). 
    // The window field is 4.
    tcp_options = [
        TCPOption(TCPOption.TCPOPT_TIMESTAMP, 0xFFFFFFFF),
        TCPOption(TCPOption.TCPOPT_NOP),
        TCPOption(TCPOption.TCPOPT_NOP),
        TCPOption(TCPOption.TCPOPT_WINDOW, 5),
        TCPOption(TCPOption.TCPOPT_NOP),
        TCPOption(TCPOption.TCPOPT_MAXSEG, 640)
    ]

     func (self TYPE) __init__(id, addresses, tcp_ports interface{}){
        nmap2_seq.__init__(self, id, addresses, tcp_ports, self.tcp_options)
        self.t.set_th_win(4)

 type nmap2_seq_4 struct { // nmap2_seq:
    // Packet #4: SACK permitted, 
    //            Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), 
    //            window scale (10), 
    //            EOL. 
    // The window field is 4.
    tcp_options = [
        TCPOption(TCPOption.TCPOPT_SACK_PERMITTED),
        TCPOption(TCPOption.TCPOPT_TIMESTAMP, 0xFFFFFFFF),
        TCPOption(TCPOption.TCPOPT_WINDOW, 10),
        TCPOption(TCPOption.TCPOPT_EOL)
    ]

     func (self TYPE) __init__(id, addresses, tcp_ports interface{}){
        nmap2_seq.__init__(self, id, addresses, tcp_ports, self.tcp_options)
        self.t.set_th_win(4)
    
 type nmap2_seq_5 struct { // nmap2_seq:
    // Packet #5: MSS (536), 
    //            SACK permitted,
    //            Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), 
    //            window scale (10), 
    //            EOL. 
    // The window field is 16.
    tcp_options = [
        TCPOption(TCPOption.TCPOPT_MAXSEG, 536),
        TCPOption(TCPOption.TCPOPT_SACK_PERMITTED),
        TCPOption(TCPOption.TCPOPT_TIMESTAMP, 0xFFFFFFFF),
        TCPOption(TCPOption.TCPOPT_WINDOW, 10),
        TCPOption(TCPOption.TCPOPT_EOL)
    ]

     func (self TYPE) __init__(id, addresses, tcp_ports interface{}){
        nmap2_seq.__init__(self, id, addresses, tcp_ports, self.tcp_options)
        self.t.set_th_win(16)
    
 type nmap2_seq_6 struct { // nmap2_seq:
    // Packet #6: MSS (265), 
    //            SACK permitted, 
    //            Timestamp (TSval: 0xFFFFFFFF; TSecr: 0). 
    // The window field is 512.
    tcp_options = [
        TCPOption(TCPOption.TCPOPT_MAXSEG, 265),
        TCPOption(TCPOption.TCPOPT_SACK_PERMITTED),
        TCPOption(TCPOption.TCPOPT_TIMESTAMP, 0xFFFFFFFF)
    ]

     func (self TYPE) __init__(id, addresses, tcp_ports interface{}){
        nmap2_seq.__init__(self, id, addresses, tcp_ports, self.tcp_options)
        self.t.set_th_win(512)

 type nmap1_seq_container struct { // os_id_test:
     func (self TYPE) __init__(num_seq_samples, responses, seq_diffs, ts_diffs, time_diffs interface{}){
        os_id_test.__init__(self, 0)

        self.num_seq_samples = num_seq_samples
        self.seq_responses = responses
        self.seq_num_responses = len(responses)
        self.seq_diffs = seq_diffs
        self.ts_diffs = ts_diffs
        self.time_diffs = time_diffs
        self.pre_ts_seq type = nmap1_seq.TS_SEQ_UNKNOWN struct {

     func (self TYPE) test_id(){
        return "TSEQ"

     func (self TYPE) set_ts_seqclass(ts_seqclass interface{}){
        self.pre_ts_seq type = ts_seqclass struct {

     func (self TYPE) process(){
        ipid_seq type = self.ipid_sequence struct { // 
        if nmap1_seq.TS_SEQ_UNKNOWN != self.pre_ts_seqclass {
            ts_seq type = self.pre_ts_seqclass struct {
        } else  {
            ts_seq type = self.ts_sequence struct { // 
        
        if self.seq_num_responses >= 4 {
            seq_seq type = self.seq_sequence struct { // 
            if nmap1_seq.SEQ_UNKNOWN != seq_seqclass {
                self.add_seqclass(seq_seqclass)
            if nmap1_seq.IPID_SEQ_UNKNOWN != ipid_seqclass {
                self.add_ipidclass(ipid_seqclass)
            if nmap1_seq.TS_SEQ_UNKNOWN != ts_seqclass {
                self.add_tsclass(ts_seqclass)
        } else  {
            LOG.error("Insufficient responses for TCP sequencing (%d out of %d), OS detection may be less accurate."
                           % (self.seq_num_responses, self.num_seq_samples))

     func (self TYPE) get_final_result(){
        "Returns a string representation of the final result of this test or nil if no response was received"
        return {self.test_id(): self.get_result_dict()}

     func (self TYPE) ipid_sequence(){
        if self.seq_num_responses < 2 {
            return nmap1_seq.IPID_SEQ_UNKNOWN

        ipid_diffs = array.array('H', [0] * (self.seq_num_responses - 1))

        null_ipids = 1
        for i in xrange(1, self.seq_num_responses):
            prev_ipid = self.seq_responses[i-1].get_ipid()
            cur_ipid = self.seq_responses[i].get_ipid()

            if cur_ipid < prev_ipid and (cur_ipid > 500 or prev_ipid < 65000) {
                return nmap1_seq.IPID_SEQ_RD

            if prev_ipid != 0 or cur_ipid != 0 {
                null_ipids = 0
            ipid_diffs[i-1] = abs(cur_ipid - prev_ipid)

        if null_ipids {
            return nmap1_seq.IPID_SEQ_ZERO

        // Battle plan:
        // If any diff is > 1000, set to random, if 0, set to constant.
        // If any of the diffs are 1, or all are less than 9, set to incremental.

        for i in xrange(0, self.seq_num_responses - 1):
            if ipid_diffs[i] > 1000 {
                return nmap1_seq.IPID_SEQ_RPI
            if ipid_diffs[i] == 0 {
                return nmap1_seq.IPID_SEQ_CONSTANT

        is_incremental = 1 // All diferences are less than 9
        is_ms = 1 // All diferences are multiples of 256
        for i in xrange(0, self.seq_num_responses - 1):
            if ipid_diffs[i] == 1 {
                return nmap1_seq.IPID_SEQ_INCR
            if is_ms and ipid_diffs[i] < 2560 and (ipid_diffs[i] % 256) != 0 {
                is_ms = 0
            if ipid_diffs[i] > 9 {
                is_incremental = 0

        if is_ms {
            return nmap1_seq.IPID_SEQ_BROKEN_INCR
        if is_incremental {
            return nmap1_seq.IPID_SEQ_INCR

        return nmap1_seq.IPID_SEQ_UNKNOWN

     func (self TYPE) ts_sequence(){
        if self.seq_num_responses < 2 {
            return nmap1_seq.TS_SEQ_UNKNOWN

        // Battle plan:
        // 1) Compute average increments per second, and variance in incr. per second.
        // 2) If any are 0, set to constant.
        // 3) If variance is high, set to random incr. [ skip for now ]
        // 4) if ~10/second, set to appropriate thing.
        // 5) Same with ~100/s.

        avg_freq = 0.0
        for i in xrange(0, self.seq_num_responses - 1):
            dhz = self.ts_diffs[i] / self.time_diffs[i]
            avg_freq += dhz / (self.seq_num_responses - 1)

        LOG.info("The avg TCP TS HZ is: %f" % avg_freq)

        if 0 < avg_freq < 3.9 {
            return nmap1_seq.TS_SEQ_2HZ
        if 85 < avg_freq < 115 {
            return nmap1_seq.TS_SEQ_100HZ
        if 900 < avg_freq < 1100 {
            return nmap1_seq.TS_SEQ_1000HZ

        return nmap1_seq.TS_SEQ_UNKNOWN

     func (self TYPE) seq_sequence(){
        self.seq_gcd = reduce(my_gcd, self.seq_diffs)
        avg_incr = 0
        seq type = nmap1_seq.SEQ_UNKNOWN struct {

        if 0 != self.seq_gcd {
            map(lambda x, gcd = self.seq_gcd: x / gcd, self.seq_diffs)
            for i in xrange(0, self.seq_num_responses - 1):
                if abs(self.seq_responses[i+1].get_seq() - self.seq_responses[i].get_seq()) > 50000000 {
                    seq type = nmap1_seq.SEQ_TR; struct {
                    self.index = 9999999
                    break
                avg_incr += self.seq_diffs[i]

        if 0 == self.seq_gcd {
            seq type = nmap1_seq.SEQ_CONSTANT struct {
            self.index = 0
        elif 0 == self.seq_gcd % 64000 {
            seq type = nmap1_seq.SEQ_64K struct {
            self.index = 1
        elif 0 == self.seq_gcd % 800 {
            seq type = nmap1_seq.SEQ_i800 struct {
            self.index = 10
        elif nmap1_seq.SEQ_UNKNOWN == seqclass {
            avg_incr = int(.5 + avg_incr / (self.seq_num_responses - 1))
            sum_incr = 0.0
            for i in range(0, self.seq_num_responses - 1):
                d = abs(self.seq_diffs[i] - avg_incr)
                sum_incr += float(d * d)
            sum_incr /= self.seq_num_responses - 1
            self.index = int(.5 + math.sqrt(sum_incr))
            if self.index < 75 {
                seq type = nmap1_seq.SEQ_TD struct {
            } else  {
                seq type = nmap1_seq.SEQ_RI struct {

        return seqclass

    seqclasses = {
        nmap1_seq.SEQ_64K: '64K',
        nmap1_seq.SEQ_TD: 'TD',
        nmap1_seq.SEQ_RI: 'RI',
        nmap1_seq.SEQ_TR: 'TR',
        nmap1_seq.SEQ_i800: 'i800',
        nmap1_seq.SEQ_CONSTANT: 'C',
        }

     func (self TYPE) add_seqclass(id interface{}){
        self.add_result('CLASS', nmap1_seq_container.seqclasses[id])

        if nmap1_seq.SEQ_CONSTANT == id {
            self.add_result('VAL', '%i' % self.seq_responses[0].get_seq())
        elif id in (nmap1_seq.SEQ_TD, nmap1_seq.SEQ_RI) {
            self.add_result('GCD', '%i' % self.seq_gcd)
            self.add_result('SI', '%i' % self.index)

    tsclasses = {
        nmap1_seq.TS_SEQ_ZERO: '0',
        nmap1_seq.TS_SEQ_2HZ: '2HZ',
        nmap1_seq.TS_SEQ_100HZ: '100HZ',
        nmap1_seq.TS_SEQ_1000HZ: '1000HZ',
        nmap1_seq.TS_SEQ_UNSUPPORTED: 'U',
        }

     func (self TYPE) add_tsclass(id interface{}){
        self.add_result('TS', nmap1_seq_container.tsclasses[id])

    ipidclasses = {
        nmap1_seq.IPID_SEQ_INCR: 'I',
        nmap1_seq.IPID_SEQ_BROKEN_INCR: 'BI',
        nmap1_seq.IPID_SEQ_RPI: 'RPI',
        nmap1_seq.IPID_SEQ_RD: 'RD',
        nmap1_seq.IPID_SEQ_CONSTANT: 'C',
        nmap1_seq.IPID_SEQ_ZERO: 'Z',
        }

     func (self TYPE) add_ipidclass(id interface{}){
        self.add_result('IPID', nmap1_seq_container.ipidclasses[id])


 type nmap2_seq_container struct { // os_id_test:
     func (self TYPE) __init__(num_seq_samples, responses, seq_diffs, ts_diffs, time_diffs interface{}){
        os_id_test.__init__(self, 0)

        self.num_seq_samples = num_seq_samples
        self.seq_responses = responses
        self.seq_num_responses = len(responses)
        self.seq_diffs = seq_diffs
        self.ts_diffs = ts_diffs
        self.time_diffs = time_diffs
        self.pre_ts_seq type = nmap2_seq.TS_SEQ_UNKNOWN struct {

     func (self TYPE) test_id(){
        return "SEQ"

     func (self TYPE) set_ts_seqclass(ts_seqclass interface{}){
        self.pre_ts_seq type = ts_seqclass struct {

     func (self TYPE) process(){
        if self.seq_num_responses >= 4 {
            self.calc_ti()
            self.calc_ts()
            self.calc_sp()
        } else  {
            self.add_result('R', 'N')
            LOG.error("Insufficient responses for TCP sequencing (%d out of %d), OS detection may be less accurate."
                           % (self.seq_num_responses, self.num_seq_samples))

     func (self TYPE) get_final_result(){
        return {self.test_id(): self.get_result_dict()}

     func (self TYPE) calc_ti(){
        if self.seq_num_responses < 2 { 
            return

        ipidclasses = {
            nmap2_seq.IPID_SEQ_INCR: 'I',
            nmap2_seq.IPID_SEQ_BROKEN_INCR: 'BI',
            nmap2_seq.IPID_SEQ_RPI: 'RI',
            nmap2_seq.IPID_SEQ_RD: 'RD',
            nmap2_seq.IPID_SEQ_CONSTANT: 'C',
            nmap2_seq.IPID_SEQ_ZERO: 'Z',
        }

        ipid_diffs = array.array('H', [0] * (self.seq_num_responses - 1))

        // Random and zero
        null_ipids = 1
        for i in xrange(1, self.seq_num_responses):
            prev_ipid = self.seq_responses[i-1].get_ipid()
            cur_ipid = self.seq_responses[i].get_ipid()

            if prev_ipid != 0 or cur_ipid != 0 { 
                null_ipids = 0

            if prev_ipid <= cur_ipid {
                ipid_diffs[i-1] = cur_ipid - prev_ipid
            } else  {
                ipid_diffs[i-1] = (cur_ipid - prev_ipid + 65536) & 0xffff

            if self.seq_num_responses > 2 and ipid_diffs[i-1] > 20000 {
                self.add_result('TI', ipidclasses[nmap2_seq.IPID_SEQ_RD])
                return

        if null_ipids { 
            self.add_result('TI', ipidclasses[nmap2_seq.IPID_SEQ_ZERO])
            return

        // Constant
        all_zero = 1
        for i in xrange(0, self.seq_num_responses - 1):
            if ipid_diffs[i] != 0 { 
                all_zero = 0
                break

        if all_zero {
            self.add_result('TI', ipidclasses[nmap2_seq.IPID_SEQ_CONSTANT])
            return

        // Random positive increments
        for i in xrange(0, self.seq_num_responses - 1):
            if ipid_diffs[i] > 1000 and \
               ((ipid_diffs[i] % 256 != 0) or \
                ((ipid_diffs[i] % 256 == 0) and (ipid_diffs[i] >= 25600))):
                self.add_result('TI', ipidclasses[nmap2_seq.IPID_SEQ_RPI])
                return

        // Broken Increment and Incremental
        is_incremental = 1 // All diferences are less than 10
        is_ms = 1 // All diferences are multiples of 256 and no greater than 5120
        for i in xrange(0, self.seq_num_responses - 1):
            if is_ms and ((ipid_diffs[i] > 5120) or (ipid_diffs[i] % 256) != 0) { 
                is_ms = 0
            if is_incremental and ipid_diffs[i] > 9 { 
                is_incremental = 0

        if is_ms { 
            self.add_result('TI', ipidclasses[nmap2_seq.IPID_SEQ_BROKEN_INCR])
        elif is_incremental { 
            self.add_result('TI', ipidclasses[nmap2_seq.IPID_SEQ_INCR])

     func (self TYPE) calc_ts(){
        // 1. If any of the responses have no timestamp option, TS 
        //    is set to U (unsupported).
        // 2. If any of the timestamp values are zero, TS is set to 0.
        // 3. If the average increments per second falls within the 
        //    ranges 0-5.66, 70-150, or 150-350, TS is set to 1, 7, or 8, 
        //    respectively. These three ranges get special treatment 
        //    because they correspond to the 2 Hz, 100 Hz, and 200 Hz 
        //    frequencies used by many hosts.
        // 4. In all other cases, Nmap records the binary logarithm of 
        //    the average increments per second, rounded to the nearest 
        //    integer. Since most hosts use 1,000 Hz frequencies, A is 
        //    a common result.

        if self.pre_ts_seq type == nmap2_seq.TS_SEQ_ZERO {  struct {
            self.add_result('TS', '0')
        elif self.pre_ts_seq type == nmap2_seq.TS_SEQ_UNSUPPORTED {  struct {
            self.add_result('TS', 'U')
        elif self.seq_num_responses < 2 { 
            return

        avg_freq = 0.0
        for i in xrange(0, self.seq_num_responses - 1):
            dhz = self.ts_diffs[i] / self.time_diffs[i]
            avg_freq += dhz / (self.seq_num_responses - 1)

        LOG.info("The avg TCP TS HZ is: %f" % avg_freq)

        if avg_freq <= 5.66 { 
            self.add_result('TS', "1")
        elif 70 < avg_freq <= 150 {
            self.add_result('TS', "7")
        elif 150 < avg_freq <= 350 {
            self.add_result('TS', "8")
        } else  {
            ts = int(round(.5 + math.log(avg_freq)/math.log(2)))
            self.add_result('TS', "%X" % ts)

     func (self TYPE) calc_sp(){
        seq_gcd = reduce(my_gcd, self.seq_diffs)

        seq_avg_rate = 0.0
        for i in xrange(0, self.seq_num_responses - 1):
            seq_avg_rate += self.seq_diffs[i] / self.time_diffs[i]
        seq_avg_rate /= (self.seq_num_responses - 1)

        seq_rate = seq_avg_rate
        si_index = 0
        seq_stddev = 0

        if 0 == seq_gcd {
            seq_rate = 0
        } else  {
            seq_rate = int(round(.5 + (math.log(seq_rate) / math.log(2)) * 8))

            div_gcd = 1
            if seq_gcd > 9 {
                div_gcd = seq_gcd

            for i in xrange(0, self.seq_num_responses - 1):
                rtmp = (self.seq_diffs[i] / self.time_diffs[i]) / div_gcd - \
                       seq_avg_rate / div_gcd
                seq_stddev += rtmp * rtmp

            seq_stddev /= self.seq_num_responses - 2
            seq_stddev = math.sqrt(seq_stddev)

            if seq_stddev <= 1 {
                si_index = 0
            } else  {
                si_index = int(round(.5 + (math.log(seq_stddev) / math.log(2)) * 8.0))

        self.add_result('SP', "%X" % si_index)
        self.add_result('GCD', "%X" % seq_gcd)
        self.add_result('ISR', "%X" % seq_rate)

 type nmap2_ops_container struct { // os_id_test:
     func (self TYPE) __init__(responses interface{}){
        os_id_test.__init__(self, 0)

        self.seq_responses = responses
        self.seq_num_responses = len(responses)

     func (self TYPE) test_id(){
        return "OPS"

     func (self TYPE) process(){
        if self.seq_num_responses != 6 {
            self.add_result('R', 'N')
            return

        for i in xrange(0, self.seq_num_responses):
            tests = nmap2_tcp_tests(self.seq_responses[i].get_ip(),
                                    self.seq_responses[i].get_tcp(),
                                    0,
                                    0)
            self.add_result("O%i" % (i+1), tests.get_options())

     func (self TYPE) get_final_result(){
        if not self.get_result_dict() {
            return nil
        } else  {
            return {self.test_id(): self.get_result_dict()}

 type nmap2_win_container struct { // os_id_test:
     func (self TYPE) __init__(responses interface{}){
        os_id_test.__init__(self, 0)

        self.seq_responses = responses
        self.seq_num_responses = len(responses)

     func (self TYPE) test_id(){
        return "WIN"

     func (self TYPE) process(){
        if self.seq_num_responses != 6 {
            self.add_result('R', 'N')
            return

        for i in xrange(0, self.seq_num_responses):
            tests = nmap2_tcp_tests(self.seq_responses[i].get_ip(),
                                    self.seq_responses[i].get_tcp(),
                                    0,
                                    0)
            self.add_result("W%i" % (i+1), tests.get_win())

     func (self TYPE) get_final_result(){
        if not self.get_result_dict() {
            return nil
        } else  {
            return {self.test_id(): self.get_result_dict()}

 type nmap2_t1_container struct { // os_id_test:
     func (self TYPE) __init__(responses, seq_base interface{}){
        os_id_test.__init__(self, 0)

        self.seq_responses = responses
        self.seq_num_responses = len(responses)
        self.seq_base = seq_base

     func (self TYPE) test_id(){
        return "T1"

     func (self TYPE) process(){
        // R, DF, T*, TG*, W-, S, A, F, O-, RD*, Q
        if self.seq_num_responses < 1 {
            self.add_result("R","N")
            return

        response = self.seq_responses[0]
        tests = nmap2_tcp_tests(response.get_ip(), 
                                response.get_tcp(), 
                                self.seq_base,
                                nmap2_tcp_probe.acknowledgment)
        self.add_result("R", "Y")
        self.add_result("DF", tests.get_df())
        self.add_result("S", tests.get_seq())
        self.add_result("A", tests.get_ack())
        self.add_result("F", tests.get_flags())
        self.add_result("Q", tests.get_quirks())

     func (self TYPE) get_final_result(){
        if not self.get_result_dict() {
            return nil
        } else  {
            return {self.test_id(): self.get_result_dict()}

 type nmap2_icmp_container struct { // os_id_test:
     func (self TYPE) __init__(responses interface{}){
        os_id_test.__init__(self, 0)

        self.icmp_responses = responses
        self.icmp_num_responses = len(responses)

     func (self TYPE) test_id(){
        return "IE"

     func (self TYPE) process(){
        // R, DFI, T*, TG*, TOSI, CD, SI, DLI*
        if self.icmp_num_responses != 2 {
            self.add_result("R","N")
            return

        ip1 = self.icmp_responses[0].child()
        ip2 = self.icmp_responses[1].child()
        icmp1 = ip1.child()
        icmp2 = ip2.child()

        self.add_result("R", "Y")

        // Value	Description
        // N	    Neither of the ping responses have the DF bit set.
        // S	    Both responses echo the DF value of the probe.
        // Y	    Both of the response DF bits are set.
        // O	    The one remaining other combination-both responses have the DF bit toggled.
        if not ip1.get_ip_df() and not ip2.get_ip_df() {
            self.add_result("DFI","N")
        elif ip1.get_ip_df() and not ip2.get_ip_df() {
            self.add_result("DFI","S")
        elif ip1.get_ip_df() and ip2.get_ip_df() {
            self.add_result("DFI","Y")
        } else  {
            self.add_result("DFI","O")

        // Value	Description
        // Z	    Both TOS values are zero.
        // S	    Both TOS values are each the same as in the corresponding probe.
        // <NN>	When they both use the same non-zero number, it is recorded here.
        // O	    Any other combination.
        if ip1.get_ip_tos() == 0 and ip2.get_ip_tos() == 0 {
            self.add_result("TOSI","Z")
        elif ip1.get_ip_tos() == 0 and ip2.get_ip_tos() == 4 {
            self.add_result("TOSI","S")
        elif ip1.get_ip_tos() == ip2.get_ip_tos() {
            self.add_result("TOSI","%X" % ip1.get_ip_tos())
        } else  {
            self.add_result("TOSI","O")
        
        // Value	Description
        // Z	    Both code values are zero.
        // S	    Both code values are the same as in the corresponding probe.
        // <NN>	When they both use the same non-zero number, it is shown here.
        // O	    Any other combination.
        if icmp1.get_icmp_code() == 0 and icmp2.get_icmp_code() == 0 {
            self.add_result("CD","Z")
        elif icmp1.get_icmp_code() == 9 and icmp2.get_icmp_code() == 0 {
            self.add_result("CD","S")
        elif icmp1.get_icmp_code() == icmp2.get_icmp_code() {
            self.add_result("CD","%X" % icmp1.get_icmp_code())
        } else  {
            self.add_result("CD","O")
        
        // Value	Description
        // Z	    Both sequence numbers are set to 0.
        // S	    Both sequence numbers echo the ones from the probes.
        // <NNNN> When they both use the same non-zero number, it is recorded here.
        // O	    Any other combination.
        if icmp1.get_icmp_seq() == 0 and icmp2.get_icmp_seq() == 0 {
            self.add_result("SI","Z")
        elif (icmp1.get_icmp_seq() == nmap2_icmp_echo_probe_1.sequence_number and 
              icmp2.get_icmp_seq() == nmap2_icmp_echo_probe_1.sequence_number + 1):
            self.add_result("SI","S")
        elif icmp1.get_icmp_seq() == icmp2.get_icmp_seq() {
            self.add_result("SI","%X" % icmp1.get_icmp_code())
        } else  {
            self.add_result("SI","O")

     func (self TYPE) get_final_result(){
        if not self.get_result_dict() {
            return nil
        } else  {
            return {self.test_id(): self.get_result_dict()}

 type nmap1_tcp_closed_1 struct { // nmap1_tcp_probe:
     func (self TYPE) __init__(id, addresses, tcp_ports interface{}){
        nmap1_tcp_probe.__init__(self, id, addresses, tcp_ports, 0)
        self.t.set_SYN()

     func (self TYPE) test_id(){
        return "T5"

     func (self TYPE) is_mine(packet interface{}){
        if tcp_probe.is_mine(self, packet) {
            ip = packet.child()
            if not ip {
                return 0
            tcp = ip.child()
            if not tcp {
                return 0
            if tcp.get_RST() {
                return 1
            } else  {
                return 0
        } else  {
            return 0

 type nmap2_tcp_closed_1 struct { // nmap2_tcp_probe_2_6:
    // ...
    // T5 sends a TCP SYN packet without IP DF and a window field of 
    // 31337 to a closed port
    // ...
     func (self TYPE) __init__(id, addresses, tcp_ports interface{}){
        nmap2_tcp_probe_2_6.__init__(self, id, addresses, tcp_ports, 0)
        self.t.set_SYN()
        self.i.set_ip_df(0)
        self.t.set_th_win(31337)

     func (self TYPE) test_id(){
        return "T5"


 type nmap1_tcp_closed_2 struct { // nmap1_tcp_probe:

     func (self TYPE) __init__(id, addresses, tcp_ports interface{}){
        nmap1_tcp_probe.__init__(self, id, addresses, tcp_ports, 0)
        self.t.set_ACK()

     func (self TYPE) test_id(){
        return "T6"


 type nmap2_tcp_closed_2 struct { // nmap2_tcp_probe_2_6:
    // ...
    // T6 sends a TCP ACK packet with IP DF and a window field of 
    // 32768 to a closed port.
    // ...
     func (self TYPE) __init__(id, addresses, tcp_ports interface{}){
        nmap2_tcp_probe_2_6.__init__(self, id, addresses, tcp_ports, 0)
        self.t.set_ACK()
        self.i.set_ip_df(1)
        self.t.set_th_win(32768)

     func (self TYPE) test_id(){
        return "T6"


 type nmap1_tcp_closed_3 struct { // nmap1_tcp_probe:

     func (self TYPE) __init__(id, addresses, tcp_ports interface{}){
        nmap1_tcp_probe.__init__(self, id, addresses, tcp_ports, 0)
        self.t.set_FIN()
        self.t.set_URG()
        self.t.set_PSH()

     func (self TYPE) test_id(){
        return "T7"


 type nmap2_tcp_closed_3 struct { // nmap2_tcp_probe_7:
    // ...
    // T7 sends a TCP packet with the FIN, PSH, and URG flags set and a 
    // window field of 65535 to a closed port. The IP DF bit is not set.
    // ...
     func (self TYPE) __init__(id, addresses, tcp_ports interface{}){
        nmap2_tcp_probe_7.__init__(self, id, addresses, tcp_ports, 0)
        self.t.set_FIN()
        self.t.set_URG()
        self.t.set_PSH()
        self.t.set_th_win(65535)
        self.i.set_ip_df(0)

     func (self TYPE) test_id(){
        return "T7"


 type NMAP2_OS_Class: struct {
     func (self TYPE) __init__(vendor, name, family, device_type interface{}){
        self.__vendor = vendor
        self.__name = name
        self.__family = family
        self.__device_type = device_type

     func (self TYPE) get_vendor(){
        return self.__vendor
     func (self TYPE) get_name(){
        return self.__name
     func (self TYPE) get_family(){
        return self.__family
     func (self TYPE) get_device_type(){
        return self.__device_type

 type NMAP2_Fingerprint: struct {
     func (self TYPE) __init__(id, os_class, tests interface{}){
        self.__id = id
        self.__os_ type = os_class struct {
        self.__tests = tests

     func (self TYPE) get_id(){
        return self.__id
     func (self TYPE) get_os_class(){
        return self.__os_class
     func (self TYPE) get_tests(){
        return self.__tests

     func (self TYPE) __str__(){
        ret = "FP: [%s]" % self.__id
        ret += "\n vendor: %s" % self.__os_class.get_vendor()
        ret += "\n name: %s" % self.__os_class.get_name()
        ret += "\n family: %s" % self.__os_class.get_family()
        ret += "\n device_type: %s" % self.__os_class.get_device_type()

        for test in self.__tests:
            ret += "\n  test: %s" % test
            for pair in self.__tests[test]:
                ret += "\n   %s = [%s]" % (pair, self.__tests[test][pair])

        return ret

    literal_conv = { "RIPL" : { "G" : 0x148 },
                     "RID" : { "G" : 0x1042 },
                     "RUL" : { "G" : 0x134 } }

     func (self TYPE) parse_int(field, value interface{}){
        try:
            return int(value, 16)
        except ValueError:
            if field in NMAP2_Fingerprint.literal_conv {
                if value in NMAP2_Fingerprint.literal_conv[field] {
                    return NMAP2_Fingerprint.literal_conv[field][value]
            return 0

     func (self TYPE) match(field, ref, value interface{}){
        options = ref.split("|")

        for option in options:
            if option.startswith(">") {
                if self.parse_int(field, value) > \
                   self.parse_int(field, option[1:]):
                    return true
            elif option.startswith("<") {
                if self.parse_int(field, value) < \
                   self.parse_int(field, option[1:]):
                    return true
            elif option.find("-") > -1 {
                range = option.split("-")
                if self.parse_int (field, value) >= self.parse_int (field, range[0]) and \
                        self.parse_int (field, value) <= self.parse_int (field, range[1]):
                    return true
            } else  {
                if str(value) == str(option) {
                    return true

        return false

     func (self TYPE) compare(sample, mp interface{}){
        max_points = 0
        total_points = 0

        for test in self.__tests:
            // ignore unknown response lines:
            if test not in sample {
                continue
        
            for field in self.__tests[test]:
                    // ignore unsupported fields:
                if field not in sample[test] or \
                   test not in mp or \
                   field not in mp[test]:
                    continue
            
                ref = self.__tests[test][field]
                value = sample[test][field]

                points = int(mp[test][field])

                max_points += points

                if self.match(field, ref, value) {
                    total_points += points

        return (total_points / float(max_points)) * 100

 type NMAP2_Fingerprint_Matcher: struct {
     func (self TYPE) __init__(filename interface{}){
        self.__filename = filename                

     func (self TYPE) find_matches(res, threshold interface{}){
        output = []

        try:
            infile = open(self.__filename,"r")
    
            mp = self.parse_mp(self.matchpoints(infile))

            for fingerprint in self.fingerprints(infile):
                fp = self.parse_fp(fingerprint)
                similarity = fp.compare(res, mp)
                if similarity >= threshold { 
                    print("\"%s\" matches with an accuracy of %.2f%%" \
                           % (fp.get_id(), similarity))
                    output.append((similarity / 100,
                                   fp.get_id(),
                                   (fp.get_os_class().get_vendor(),
                                    fp.get_os_class().get_name(),
                                    fp.get_os_class().get_family(),
                                    fp.get_os_class().get_device_type())))

            infile.close()
        except IOError as err:
            print("IOError: %s", err)

        return output

     func (self TYPE) sections(infile, token interface{}){
        OUT = 0
        IN = 1
        
        state = OUT
        output = []

        for line in infile:
            line = line.strip()
            if state == OUT {
                if line.startswith(token) {
                    state = IN
                    output = [line]
            elif state == IN {
                if line {
                    output.append(line)
                } else  {
                    state = OUT
                    yield output
                    output = []

        if output {
            yield output

     func (self TYPE) fingerprints(infile interface{}){
        for section in self.sections(infile,"Fingerprint"):
            yield section

     func (self TYPE) matchpoints(infile interface{}){
        return self.sections(infile,"MatchPoints").next()

     func (self TYPE) parse_line(line interface{}){
        name = line[:line.find("(")]
        pairs = line[line.find("(") + 1 : line.find(")")]
        
        test = {}
        
        for pair in pairs.split("%"):
            pair = pair.split("=")
            test[pair[0]] = pair[1]
       
        return (name, test)

     func (self TYPE) parse_fp(fp interface{}){
        tests = {}

        for line in fp:
            if line.startswith("//") {
                continue
            elif line.startswith("Fingerprint") {
                fingerprint = line[len("Fingerprint") + 1:]
            elif line.startswith("Class") {
                (vendor, 
                 name, 
                 family, 
                 device_type) = line[len("Class") + 1:].split("|")
                os_ type = NMAP2_OS_Class(vendor.strip struct { // , 
                                          name.strip(), 
                                          family.strip(), 
                                          device_type.strip()) 
            } else  {
                test = self.parse_line(line)
                tests[test[0]] = test[1]
        
        return NMAP2_Fingerprint(fingerprint, os_class, tests)
            
     func (self TYPE) parse_mp(fp interface{}){
        tests = {}

        for line in fp:
            if line.startswith("//") {
                continue
            elif line.startswith("MatchPoints") {
                continue
            } else  {
                test = self.parse_line(line)
                tests[test[0]] = test[1]
        
        return tests
