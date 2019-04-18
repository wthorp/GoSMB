// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// MSSQL (TDS) Protocol Client
//
// Author:
//   Alberto Solino (@agsolino)
//   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
//
// Description:
// MSSQL client for relaying NTLMSSP authentication to MSSQL servers
//
// ToDo:
// [ ] Handle SQL Authentication
//
import random
import string
from struct import unpack

from impacket import LOG
from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.tds import MSSQL, DummyPrint, TDS_ENCRYPT_REQ, TDS_ENCRYPT_OFF, TDS_PRE_LOGIN, TDS_LOGIN, TDS_INIT_LANG_FATAL, \
    TDS_ODBC_ON, TDS_INTEGRATED_SECURITY_ON, TDS_LOGIN7, TDS_SSPI, TDS_LOGINACK_TOKEN
from impacket.ntlm import NTLMAuthChallenge
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.spnego import SPNEGO_NegTokenResp

try:
    from OpenSSL import SSL
except Exception:
    LOG.critical("pyOpenSSL is not installed, can't continue")

PROTOCOL_CLIENT_CLASS = "MSSQLRelayClient"

 type MYMSSQL struct { // MSSQL:
     func (self TYPE) __init__(address, port=1433, rowsPrinter=DummyPrint() interface{}){
        MSSQL.__init__(self,address, port, rowsPrinter)
        self.resp = nil
        self.sessionData = {}

     func (self TYPE) initConnection(){
        self.connect()
        //This is copied from tds.py
        resp = self.preLogin()
        if resp["Encryption"] == TDS_ENCRYPT_REQ or resp["Encryption"] == TDS_ENCRYPT_OFF {
            LOG.debug("Encryption required, switching to TLS")

            // Switching to TLS now
            ctx = SSL.Context(SSL.TLSv1_METHOD)
            ctx.set_cipher_list("RC4, AES256")
            tls = SSL.Connection(ctx,nil)
            tls.set_connect_state()
            while true:
                try:
                    tls.do_handshake()
                except SSL.WantReadError:
                    data = tls.bio_read(4096)
                    self.sendTDS(TDS_PRE_LOGIN, data,0)
                    tds = self.recvTDS()
                    tls.bio_write(tds["Data"])
                } else  {
                    break

            // SSL and TLS limitation: Secure Socket Layer (SSL) and its replacement,
            // Transport Layer Security(TLS), limit data fragments to 16k in size.
            self.packetSize = 16*1024-1
            self.tlsSocket = tls
        self.resp = resp
        return true

     func sendNegotiate(self,negotiateMessage interface{}){
        //Also partly copied from tds.py
        login = TDS_LOGIN()

        login["HostName"] = (''.join([random.choice(string.ascii_letters) for _ in range(8)])).encode("utf-16le")
        login["AppName"]  = (''.join([random.choice(string.ascii_letters) for _ in range(8)])).encode("utf-16le")
        login["ServerName"] = self.server.encode("utf-16le")
        login["CltIntName"]  = login["AppName"]
        login["ClientPID"] = random.randint(0,1024)
        login["PacketSize"] = self.packetSize
        login["OptionFlags2"] = TDS_INIT_LANG_FATAL | TDS_ODBC_ON | TDS_INTEGRATED_SECURITY_ON

        // NTLMSSP Negotiate
        login["SSPI"] = negotiateMessage
        login["Length"] = len(login.getData())

        // Send the NTLMSSP Negotiate
        self.sendTDS(TDS_LOGIN7, login.getData())

        // According to the specs, if encryption is not required, we must encrypt just
        // the first Login packet :-o
        if self.resp["Encryption"] == TDS_ENCRYPT_OFF {
            self.tlsSocket = nil

        tds = self.recvTDS()
        self.sessionData["NTLM_CHALLENGE"] = tds

        challenge = NTLMAuthChallenge()
        challenge.fromString(tds["Data"][3:])
        //challenge.dump()

        return challenge

     func sendAuth(self,authenticateMessageBlob, serverChallenge=nil interface{}){
        if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP {
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            token = respToken2["ResponseToken"]
        } else  {
            token = authenticateMessageBlob

        self.sendTDS(TDS_SSPI, token)
        tds = self.recvTDS()
        self.replies = self.parseReply(tds["Data"])
        if TDS_LOGINACK_TOKEN in self.replies {
            //Once we are here, there is a full connection and we can
            //do whatever the current user has rights to do
            self.sessionData["AUTH_ANSWER"] = tds
            return nil, STATUS_SUCCESS
        } else  {
            self.printReplies()
            return nil, STATUS_ACCESS_DENIED

     func (self TYPE) close(){
        return self.disconnect()


 type MSSQLRelayClient struct { // ProtocolClient:
    PLUGIN_NAME = "MSSQL"

     func (self TYPE) __init__(serverConfig, targetHost, targetPort = 1433, extendedSecurity=true  interface{}){
        ProtocolClient.__init__(self, serverConfig, targetHost, targetPort, extendedSecurity)
        self.extendedSecurity = extendedSecurity

        self.domainIp = nil
        self.machineAccount = nil
        self.machineHashes = nil

     func (self TYPE) initConnection(){
        self.session = MYMSSQL(self.targetHost, self.targetPort)
        self.session.initConnection()
        return true

     func (self TYPE) keepAlive(){
        // Don't know yet what needs to be done for TDS
        pass

     func (self TYPE) killConnection(){
        if self.session is not nil {
            self.session.disconnect()
            self.session = nil

     func (self TYPE) sendNegotiate(negotiateMessage interface{}){
        return self.session.sendNegotiate(negotiateMessage)

     func (self TYPE) sendAuth(authenticateMessageBlob, serverChallenge=nil interface{}){
        self.sessionData = self.session.sessionData
        return self.session.sendAuth(authenticateMessageBlob, serverChallenge)
