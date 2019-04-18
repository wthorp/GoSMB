// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Author: Alberto Solino (@agsolino)
//
// Description:
//   Transport implementations for the DCE/RPC protocol.
//
from __future__ import division
from __future__ import print_function

import binascii
import os
import re
import socket

from impacket import ntlm
from impacket.dcerpc.v5.rpcrt import DCERPCException, DCERPC_v5, DCERPC_v4
from impacket.smbconnection import SMBConnection


 type DCERPCStringBinding: struct {
    parser = re.compile(r'(?:([a-fA-F0-9-]{8}(?:-[a-fA-F0-9-]{4}){3}-[a-fA-F0-9-]{12})@)?' // UUID (opt.)
                        +'([_a-zA-Z0-9]*):' // Protocol Sequence
                        +'([^\[]*)' // Network Address (opt.)
                        +'(?:\[([^\]]*)\])?') // Endpoint and options (opt.)

     func (self TYPE) __init__(stringbinding interface{}){
        match = DCERPCStringBinding.parser.match(stringbinding)
        self.__uuid = match.group(1)
        self.__ps = match.group(2)
        self.__na = match.group(3)
        options = match.group(4)
        if options {
            options = options.split(",")
            self.__endpoint = options[0]
            try:
                self.__endpoint.index("endpoint=")
                self.__endpoint = self.__endpoint[len("endpoint="):]
            except:
                pass
            self.__options = options[1:]
        } else  {
            self.__endpoint = ""
            self.__options = []

     func (self TYPE) get_uuid(){
        return self.__uuid

     func (self TYPE) get_protocol_sequence(){
        return self.__ps

     func (self TYPE) get_network_address(){
        return self.__na

     func (self TYPE) get_endpoint(){
        return self.__endpoint

     func (self TYPE) get_options(){
        return self.__options

     func (self TYPE) __str__(){
        return DCERPCStringBindingCompose(self.__uuid, self.__ps, self.__na, self.__endpoint, self.__options)

 func DCERPCStringBindingCompose(uuid=nil, protocol_sequence='', network_address='', endpoint='', options=[] interface{}){
    s = ""
    if uuid {
        s += uuid + '@'
    s += protocol_sequence + ':'
    if network_address {
        s += network_address
    if endpoint or options {
        s += '[' + endpoint
        if options {
            s += ',' + ','.join(options)
        s += ']'

    return s

 func DCERPCTransportFactory(stringbinding interface{}){
    sb = DCERPCStringBinding(stringbinding)

    na = sb.get_network_address()
    ps = sb.get_protocol_sequence()
    if 'ncadg_ip_udp' == ps {
        port = sb.get_endpoint()
        if port {
            return UDPTransport(na, int(port))
        } else  {
            return UDPTransport(na)
    elif 'ncacn_ip_tcp' == ps {
        port = sb.get_endpoint()
        if port {
            return TCPTransport(na, int(port))
        } else  {
            return TCPTransport(na)
    elif 'ncacn_http' == ps {
        port = sb.get_endpoint()
        if port {
            return HTTPTransport(na, int(port))
        } else  {
            return HTTPTransport(na)
    elif 'ncacn_np' == ps {
        named_pipe = sb.get_endpoint()
        if named_pipe {
            named_pipe = named_pipe[len(r'\pipe'):]
            return SMBTransport(na, filename = named_pipe)
        } else  {
            return SMBTransport(na)
    elif 'ncalocal' == ps {
        named_pipe = sb.get_endpoint()
        return LOCALTransport(filename = named_pipe)
    } else  {
        raise DCERPCException("Unknown protocol sequence.")


 type DCERPCTransport: struct {

    DCERPC_ type = DCERPC_v5 struct {

     func (self TYPE) __init__(remoteName, dstport interface{}){
        self.__remoteName = remoteName
        self.__remoteHost = remoteName
        self.__dstport = dstport
        self._max_send_frag = nil
        self._max_recv_frag = nil
        self._domain = ""
        self._lmhash = ""
        self._nthash = ""
        self.__connect_timeout = nil
        self._doKerberos = false
        self._username = ""
        self._password = ""
        self._domain   = ""
        self._aesKey   = nil
        self._TGT      = nil
        self._TGS      = nil
        self._kdcHost  = nil
        self.set_credentials('','')

     func (self TYPE) connect(){
        raise RuntimeError("virtual function")
     func send(self,data=0, forceWriteAndx = 0, forceRecv = 0 interface{}){
        raise RuntimeError("virtual function")
     func (self TYPE) recv(forceRecv = 0, count = 0 interface{}){
        raise RuntimeError("virtual function")
     func (self TYPE) disconnect(){
        raise RuntimeError("virtual function")
     func (self TYPE) get_socket(){
        raise RuntimeError("virtual function")

     func (self TYPE) get_connect_timeout(){
        return self.__connect_timeout
     func (self TYPE) set_connect_timeout(timeout interface{}){
        self.__connect_timeout = timeout

     func (self TYPE) getRemoteName(){
        return self.__remoteName

     func (self TYPE) setRemoteName(remoteName interface{}){
        """This method only makes sense before connection for most protocols."""
        self.__remoteName = remoteName

     func (self TYPE) getRemoteHost(){
        return self.__remoteHost

     func (self TYPE) setRemoteHost(remoteHost interface{}){
        """This method only makes sense before connection for most protocols."""
        self.__remoteHost = remoteHost

     func (self TYPE) get_dport(){
        return self.__dstport
     func (self TYPE) set_dport(dport interface{}){
        """This method only makes sense before connection for most protocols."""
        self.__dstport = dport

     func (self TYPE) get_addr(){
        return self.getRemoteHost(), self.get_dport()
     func (self TYPE) set_addr(addr interface{}){
        """This method only makes sense before connection for most protocols."""
        self.setRemoteHost(addr[0])
        self.set_dport(addr[1])

     func (self TYPE) set_kerberos(flag, kdcHost = nil interface{}){
        self._doKerberos = flag
        self._kdcHost = kdcHost

     func (self TYPE) get_kerberos(){
        return self._doKerberos

     func (self TYPE) get_kdcHost(){
        return self._kdcHost

     func (self TYPE) set_max_fragment_size(send_fragment_size interface{}){
        // -1 is default fragment size: 0 (don't fragment)
        //  0 is don't fragment
        //    other values are max fragment size
        if send_fragment_size == -1 {
            self.set_default_max_fragment_size()
        } else  {
            self._max_send_frag = send_fragment_size

     func (self TYPE) set_default_max_fragment_size(){
        // default is 0: don't fragment.
        // subclasses may override this method
        self._max_send_frag = 0

     func (self TYPE) get_credentials(){
        return (
            self._username,
            self._password,
            self._domain,
            self._lmhash,
            self._nthash,
            self._aesKey,
            self._TGT, 
            self._TGS)

     func (self TYPE) set_credentials(username, password, domain='', lmhash='', nthash='', aesKey='', TGT=nil, TGS=nil interface{}){
        self._username = username
        self._password = password
        self._domain   = domain
        self._aesKey   = aesKey
        self._TGT      = TGT
        self._TGS      = TGS
        if lmhash != '' or nthash != '' {
            if len(lmhash) % 2 {
                lmhash = "0%s" % lmhash
            if len(nthash) % 2 {
                nthash = "0%s" % nthash
            try: // just in case they were converted already
               self._lmhash = binascii.unhexlify(lmhash)
               self._nthash = binascii.unhexlify(nthash)
            except:
               self._lmhash = lmhash
               self._nthash = nthash
               pass

     func (self TYPE) doesSupportNTLMv2(){
        // By default we'll be returning the library's default. Only on SMB Transports we might be able to know it beforehand
        return ntlm.USE_NTLMv2

     func (self TYPE) get_dce_rpc(){
        return DCERPC_v5(self)

 type UDPTransport struct { // DCERPCTransport:
    "Implementation of ncadg_ip_udp protocol sequence"

    DCERPC_ type = DCERPC_v4 struct {

     func (self TYPE) __init__(remoteName, dstport = 135 interface{}){
        DCERPCTransport.__init__(self, remoteName, dstport)
        self.__socket = 0
        self.set_connect_timeout(30)
        self.__recv_addr = ""

     func (self TYPE) connect(){
        try:
            af, socktype, proto, canonname, sa = socket.getaddrinfo(self.getRemoteHost(), self.get_dport(), 0, socket.SOCK_DGRAM)[0]
            self.__socket = socket.socket(af, socktype, proto)
            self.__socket.settimeout(self.get_connect_timeout())
        except socket.error as msg:
            self.__socket = nil
            raise DCERPCException("Could not connect: %s" % msg)

        return 1

     func (self TYPE) disconnect(){
        try:
            self.__socket.close()
        except socket.error:
            self.__socket = nil
            return 0
        return 1

     func send(self,data, forceWriteAndx = 0, forceRecv = 0 interface{}){
        self.__socket.sendto(data, (self.getRemoteHost(), self.get_dport()))

     func (self TYPE) recv(forceRecv = 0, count = 0 interface{}){
        buffer, self.__recv_addr = self.__socket.recvfrom(8192)
        return buffer

     func (self TYPE) get_recv_addr(){
        return self.__recv_addr

     func (self TYPE) get_socket(){
        return self.__socket

 type TCPTransport struct { // DCERPCTransport:
    """Implementation of ncacn_ip_tcp protocol sequence"""

     func (self TYPE) __init__(remoteName, dstport = 135 interface{}){
        DCERPCTransport.__init__(self, remoteName, dstport)
        self.__socket = 0
        self.set_connect_timeout(30)

     func (self TYPE) connect(){
        af, socktype, proto, canonname, sa = socket.getaddrinfo(self.getRemoteHost(), self.get_dport(), 0, socket.SOCK_STREAM)[0]
        self.__socket = socket.socket(af, socktype, proto)
        try:
            self.__socket.settimeout(self.get_connect_timeout())
            self.__socket.connect(sa)
        except socket.error as msg:
            self.__socket.close()
            raise DCERPCException("Could not connect: %s" % msg)
        return 1

     func (self TYPE) disconnect(){
        try:
            self.__socket.close()
        except socket.error:
            self.__socket = nil
            return 0
        return 1

     func send(self,data, forceWriteAndx = 0, forceRecv = 0 interface{}){
        if self._max_send_frag {
            offset = 0
            while 1:
                toSend = data[offset:offset+self._max_send_frag]
                if not toSend {
                    break
                self.__socket.send(toSend)
                offset += len(toSend)
        } else  {
            self.__socket.send(data)

     func (self TYPE) recv(forceRecv = 0, count = 0 interface{}){
        if count {
            buffer = b''
            while len(buffer) < count:
               buffer += self.__socket.recv(count-len(buffer))
        } else  {
            buffer = self.__socket.recv(8192)
        return buffer

     func (self TYPE) get_socket(){
        return self.__socket

 type HTTPTransport struct { // TCPTransport:
    """Implementation of ncacn_http protocol sequence"""

     func (self TYPE) connect(){
        TCPTransport.connect(self)

        self.get_socket().send('RPC_CONNECT ' + self.getRemoteHost() + ':593 HTTP/1.0\r\n\r\n')
        data = self.get_socket().recv(8192)
        if data[10:13] != '200' {
            raise DCERPCException("Service not supported.")

 type SMBTransport struct { // DCERPCTransport:
    """Implementation of ncacn_np protocol sequence"""

    def __init__(self, remoteName, dstport=445, filename='', username='', password='', domain='', lmhash='', nthash='',
                 aesKey='', TGT=nil, TGS=nil, remote_host='', smb_connection=0, doKerberos=false, kdcHost=nil):
        DCERPCTransport.__init__(self, remoteName, dstport)
        self.__socket = nil
        self.__tid = 0
        self.__filename = filename
        self.__handle = 0
        self.__pending_recv = 0
        self.set_credentials(username, password, domain, lmhash, nthash, aesKey, TGT, TGS)
        self._doKerberos = doKerberos
        self._kdcHost = kdcHost

        if remote_host != '' {
            self.setRemoteHost(remote_host)

        if smb_connection == 0 {
            self.__existing_smb = false
        } else  {
            self.__existing_smb = true
            self.set_credentials(*smb_connection.getCredentials())

        self.__prefDialect = nil
        self.__smb_connection = smb_connection

     func (self TYPE) preferred_dialect(dialect interface{}){
        self.__prefDialect = dialect

     func (self TYPE) setup_smb_connection(){
        if not self.__smb_connection {
            self.__smb_connection = SMBConnection(self.getRemoteName(), self.getRemoteHost(), sess_port=self.get_dport(),
                                                  preferredDialect=self.__prefDialect)

     func (self TYPE) connect(){
        // Check if we have a smb connection already setup
        if self.__smb_connection == 0 {
            self.setup_smb_connection()
            if self._doKerberos is false {
                self.__smb_connection.login(self._username, self._password, self._domain, self._lmhash, self._nthash)
            } else  {
                self.__smb_connection.kerberosLogin(self._username, self._password, self._domain, self._lmhash,
                                                    self._nthash, self._aesKey, kdcHost=self._kdcHost, TGT=self._TGT,
                                                    TGS=self._TGS)
        self.__tid = self.__smb_connection.connectTree("IPC$")
        self.__handle = self.__smb_connection.openFile(self.__tid, self.__filename)
        self.__socket = self.__smb_connection.getSMBServer().get_socket()
        return 1

     func (self TYPE) disconnect(){
        self.__smb_connection.disconnectTree(self.__tid)
        // If we created the SMB connection, we close it, otherwise
        // that's up for the caller
        if self.__existing_smb is false {
            self.__smb_connection.logoff()
            self.__smb_connection.close()
            self.__smb_connection = 0

     func send(self,data, forceWriteAndx = 0, forceRecv = 0 interface{}){
        if self._max_send_frag {
            offset = 0
            while 1:
                toSend = data[offset:offset+self._max_send_frag]
                if not toSend {
                    break
                self.__smb_connection.writeFile(self.__tid, self.__handle, toSend, offset = offset)
                offset += len(toSend)
        } else  {
            self.__smb_connection.writeFile(self.__tid, self.__handle, data)
        if forceRecv {
            self.__pending_recv += 1

     func (self TYPE) recv(forceRecv = 0, count = 0  interface{}){
        if self._max_send_frag or self.__pending_recv {
            // _max_send_frag is checked because it's the same condition we checked
            // to decide whether to use write_andx() or send_trans() in send() above.
            if self.__pending_recv {
                self.__pending_recv -= 1
            return self.__smb_connection.readFile(self.__tid, self.__handle, bytesToRead = self._max_recv_frag)
        } else  {
            return self.__smb_connection.readFile(self.__tid, self.__handle)

     func (self TYPE) get_smb_connection(){
        return self.__smb_connection

     func (self TYPE) set_smb_connection(smb_connection interface{}){
        self.__smb_connection = smb_connection
        self.set_credentials(*smb_connection.getCredentials())
        self.__existing_smb = true

     func (self TYPE) get_smb_server(){
        // Raw Access to the SMBServer (whatever type it is)
        return self.__smb_connection.getSMBServer()

     func (self TYPE) get_socket(){
        return self.__socket

     func (self TYPE) doesSupportNTLMv2(){
        return self.__smb_connection.doesSupportNTLMv2()

 type LOCALTransport struct { // DCERPCTransport:
    """
    Implementation of ncalocal protocol sequence, not the same
    as ncalrpc (I'm not doing LPC just opening the local pipe)
    """

     func (self TYPE) __init__(filename = "" interface{}){
        DCERPCTransport.__init__(self, '', 0)
        self.__filename = filename
        self.__handle = 0

     func (self TYPE) connect(){
        if self.__filename.upper().find("PIPE") < 0 {
            self.__filename = "\\PIPE\\%s" % self.__filename
        self.__handle = os.open('\\\\.\\%s' % self.__filename, os.O_RDWR|os.O_BINARY)
        return 1

     func (self TYPE) disconnect(){
        os.close(self.__handle)

     func send(self,data, forceWriteAndx = 0, forceRecv = 0 interface{}){
        os.write(self.__handle, data)

     func (self TYPE) recv(forceRecv = 0, count = 0  interface{}){
        data = os.read(self.__handle, 65535)
        return data
