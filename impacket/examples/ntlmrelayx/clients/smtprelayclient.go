// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// SMTP Protocol Client
//
// Author:
//   Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
//   Alberto Solino (@agsolino)
//
// Description:
// SMTP client for relaying NTLMSSP authentication to mailservers, for example Exchange
//
import smtplib
import base64
from struct import unpack

from impacket import LOG
from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.ntlm import NTLMAuthChallenge
from impacket.spnego import SPNEGO_NegTokenResp

PROTOCOL_CLIENT_CLASSES = ["SMTPRelayClient"]

 type SMTPRelayClient struct { // ProtocolClient:
    PLUGIN_NAME = "SMTP"

     func (self TYPE) __init__(serverConfig, target, targetPort = 25, extendedSecurity=true  interface{}){
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)

     func (self TYPE) initConnection(){
        self.session = smtplib.SMTP(self.targetHost,self.targetPort)
        // Turn on to debug SMTP messages
        // self.session.debuglevel = 3
        self.session.ehlo()

        if 'AUTH NTLM' not in self.session.ehlo_resp {
            LOG.error("SMTP server does not support NTLM authentication!")
            return false
        return true

     func sendNegotiate(self,negotiateMessage interface{}){
        negotiate = base64.b64encode(negotiateMessage)
        self.session.putcmd("AUTH NTLM")
        code, resp = self.session.getreply()
        if code != 334 {
            LOG.error('SMTP Client error, expected 334 NTLM supported, got %d %s ' % (code, resp))
            return false
        } else  {
            self.session.putcmd(negotiate)
        try:
            code, serverChallengeBase64 = self.session.getreply()
            serverChallenge = base64.b64decode(serverChallengeBase64)
            challenge = NTLMAuthChallenge()
            challenge.fromString(serverChallenge)
            return challenge
        except (IndexError, KeyError, AttributeError):
            LOG.error("No NTLM challenge returned from SMTP server")
            raise

     func (self TYPE) sendAuth(authenticateMessageBlob, serverChallenge=nil interface{}){
        if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP {
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            token = respToken2["ResponseToken"]
        } else  {
            token = authenticateMessageBlob
        auth = base64.b64encode(token)
        self.session.putcmd(auth)
        typ, data = self.session.getreply()
        if typ == 235 {
            self.session.state = "AUTH"
            return nil, STATUS_SUCCESS
        } else  {
            LOG.error('SMTP: %s' % ''.join(data))
            return nil, STATUS_ACCESS_DENIED

     func (self TYPE) killConnection(){
        if self.session is not nil {
            self.session.close()
            self.session = nil

     func (self TYPE) keepAlive(){
        // Send a NOOP
        self.session.noop()
