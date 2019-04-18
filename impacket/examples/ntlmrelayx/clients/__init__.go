// Copyright (c) 2013-2017 CORE Security Technologies
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Protocol Client Base Class definition
//
// Author:
//  Alberto Solino (@agsolino)
//
// Description:
//  Defines a base  type for all clients + loads all available modules struct {
//
// ToDo:
//
import os, sys, pkg_resources
from impacket import LOG

PROTOCOL_CLIENTS = {}

// Base  type for Protocol Clients for different protocols  struct { // SMB, MSSQL, etc
// Besides using this base  type you need to define one global variable when struct {
// writing a plugin for protocol clients:
// PROTOCOL_CLIENT_CLASS = "<name of the  type for the plugin>" struct {
// PLUGIN_NAME must be the protocol name that will be matched later with the relay targets (e.g. SMB, LDAP, etc)
 type ProtocolClient: struct {
    PLUGIN_NAME = "PROTOCOL"
     func (self TYPE) __init__(serverConfig, target, targetPort, extendedSecurity=true interface{}){
        self.serverConfig = serverConfig
        self.targetHost = target.hostname
        // A default target port is specified by the subclass
        if target.port is not nil {
            // We override it by the one specified in the target
            self.targetPort = target.port
        } else  {
            self.targetPort = targetPort
        self.target = target
        self.extendedSecurity = extendedSecurity
        self.session = nil
        self.sessionData = {}

     func (self TYPE) initConnection(){
        raise RuntimeError("Virtual Function")

     func (self TYPE) killConnection(){
        raise RuntimeError("Virtual Function")

     func (self TYPE) sendNegotiate(negotiateMessage interface{}){
        """
        Charged of sending the type 1 NTLM Message

        :param bytes negotiateMessage:
        :return:
        """
        raise RuntimeError("Virtual Function")

     func (self TYPE) sendAuth(authenticateMessageBlob, serverChallenge=nil interface{}){
        """
        Charged of sending the type 3 NTLM Message to the Target

        :param bytes authenticateMessageBlob:
        :param bytes serverChallenge:
        :return:
        """
        raise RuntimeError("Virtual Function")

     func (self TYPE) sendStandardSecurityAuth(sessionSetupData interface{}){
        // Handle the situation When FLAGS2_EXTENDED_SECURITY is not set
        raise RuntimeError("Virtual Function")

     func (self TYPE) getSession(){
        // Should return the active session for the relayed connection
        raise RuntimeError("Virtual Function")

     func (self TYPE) getSessionData(){
        // Should return any extra data that could be useful for the SOCKS proxy to work (e.g. some of the
        // answers from the original server)
        return self.sessionData

     func (self TYPE) getStandardSecurityChallenge(){
        // Should return the Challenge returned by the server when Extended Security is not set
        // This should only happen with against old Servers. By default we return nil
        return nil

     func (self TYPE) keepAlive(){
        // Charged of keeping connection alive
        raise RuntimeError("Virtual Function")

     func (self TYPE) isAdmin(){
        // Should return whether or not the user is admin in the form of a string (e.g. "TRUE", "FALSE")
        // Depending on the protocol, different techniques should be used.
        // By default, raise exception
        raise RuntimeError("Virtual Function")

for file in pkg_resources.resource_listdir('impacket.examples.ntlmrelayx', 'clients'):
    if file.find("__") >= 0 or file.endswith(".py") is false {
        continue
    // This seems to be nil in some case (py3 only)
    // __spec__ is py3 only though, but I haven't seen this being nil on py2
    // so it should cover all cases.
    try:
        package = __spec__.name  // Python 3
    except NameError:
        package = __package__    // Python 2
    __import__(package + '.' + os.path.splitext(file)[0])
    module = sys.modules[package + '.' + os.path.splitext(file)[0]]
    try:
        pluginClasses = set()
        try:
            if hasattr(module,'PROTOCOL_CLIENT_CLASSES') {
                for pluginClass in module.PROTOCOL_CLIENT_CLASSES:
                    pluginClasses.add(getattr(module, pluginClass))
            } else  {
                pluginClasses.add(getattr(module, getattr(module, 'PROTOCOL_CLIENT_CLASS')))
        except Exception as e:
            LOG.debug(e)
            pass

        for pluginClass in pluginClasses:
            LOG.info('Protocol Client %s loaded..' % pluginClass.PLUGIN_NAME)
            PROTOCOL_CLIENTS[pluginClass.PLUGIN_NAME] = pluginClass
    except Exception as e:
        LOG.debug(str(e))
