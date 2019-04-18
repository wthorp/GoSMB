// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// HTTP Protocol Client
//
// Author:
//   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
//   Alberto Solino (@agsolino)
//
// Description:
// HTTP(s) client for relaying NTLMSSP authentication to webservers
//
import re
import ssl
try:
    from http.client import HTTPConnection, HTTPSConnection, ResponseNotReady
except ImportError:
    from httplib import HTTPConnection, HTTPSConnection, ResponseNotReady
import base64

from struct import unpack
from impacket import LOG
from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.ntlm import NTLMAuthChallenge
from impacket.spnego import SPNEGO_NegTokenResp

PROTOCOL_CLIENT_CLASSES = ["HTTPRelayClient","HTTPSRelayClient"]

 type HTTPRelayClient struct { // ProtocolClient:
    PLUGIN_NAME = "HTTP"

     func (self TYPE) __init__(serverConfig, target, targetPort = 80, extendedSecurity=true  interface{}){
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
        self.extendedSecurity = extendedSecurity
        self.negotiateMessage = nil
        self.authenticateMessageBlob = nil
        self.server = nil

     func (self TYPE) initConnection(){
        self.session = HTTPConnection(self.targetHost,self.targetPort)
        self.lastresult = nil
        if self.target.path == '' {
            self.path = "/"
        } else  {
            self.path = self.target.path
        return true

     func sendNegotiate(self,negotiateMessage interface{}){
        //Check if server wants auth
        self.session.request('GET', self.path)
        res = self.session.getresponse()
        res.read()
        if res.status != 401 {
            LOG.info('Status code returned: %d. Authentication does not seem required for URL' % res.status)
        try:
            if 'NTLM' not in res.getheader("WWW-Authenticate") {
                LOG.error('NTLM Auth not offered by URL, offered protocols: %s' % res.getheader("WWW-Authenticate"))
                return false
        except (KeyError, TypeError):
            LOG.error('No authentication requested by the server for url %s' % self.targetHost)
            return false

        //Negotiate auth
        negotiate = base64.b64encode(negotiateMessage)
        headers = {'Authorization':'NTLM %s' % negotiate}
        self.session.request('GET', self.path ,headers=headers)
        res = self.session.getresponse()
        res.read()
        try:
            serverChallengeBase64 = re.search('NTLM ([a-zA-Z0-9+/]+={0,2})', res.getheader("WWW-Authenticate")).group(1)
            serverChallenge = base64.b64decode(serverChallengeBase64)
            challenge = NTLMAuthChallenge()
            challenge.fromString(serverChallenge)
            return challenge
        except (IndexError, KeyError, AttributeError):
            LOG.error("No NTLM challenge returned from server")

     func (self TYPE) sendAuth(authenticateMessageBlob, serverChallenge=nil interface{}){
        if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP {
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            token = respToken2["ResponseToken"]
        } else  {
            token = authenticateMessageBlob
        auth = base64.b64encode(token)
        headers = {'Authorization':'NTLM %s' % auth}
        self.session.request('GET', self.path,headers=headers)
        res = self.session.getresponse()
        if res.status == 401 {
            return nil, STATUS_ACCESS_DENIED
        } else  {
            LOG.info('HTTP server returned error code %d, treating as a successful login' % res.status)
            //Cache this
            self.lastresult = res.read()
            return nil, STATUS_SUCCESS

     func (self TYPE) killConnection(){
        if self.session is not nil {
            self.session.close()
            self.session = nil

     func (self TYPE) keepAlive(){
        // Do a HEAD for favicon.ico
        self.session.request('HEAD','/favicon.ico')
        self.session.getresponse()

 type HTTPSRelayClient struct { // HTTPRelayClient:
    PLUGIN_NAME = "HTTPS"

     func (self TYPE) __init__(serverConfig, target, targetPort = 443, extendedSecurity=true  interface{}){
        HTTPRelayClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)

     func (self TYPE) initConnection(){
        self.lastresult = nil
        if self.target.path == '' {
            self.path = "/"
        } else  {
            self.path = self.target.path
        try:
            uv_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            self.session = HTTPSConnection(self.targetHost,self.targetPort, context=uv_context)
        except AttributeError:
            self.session = HTTPSConnection(self.targetHost,self.targetPort)
        return true
