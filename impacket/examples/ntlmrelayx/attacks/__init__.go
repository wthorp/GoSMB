// Copyright (c) 2013-2017 CORE Security Technologies
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Protocol Attack Base Class definition
//
// Authors:
//  Alberto Solino (@agsolino)
//  Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
//
// Description:
//  Defines a base  type for all attacks + loads all available modules struct {
//
// ToDo:
//
import os, sys
import pkg_resources
from impacket import LOG
from threading import Thread

PROTOCOL_ATTACKS = {}

// Base  type for Protocol Attacks for different protocols  struct { // SMB, MSSQL, etc
// Besides using this base  type you need to define one global variable when struct {
// writing a plugin for protocol clients:
//     PROTOCOL_ATTACK_CLASS = "<name of the  type for the plugin>" struct {
// or (to support multiple classes in one file)
//     PROTOCOL_ATTACK_CLASSES = ["<name of the  type for the plugin>", "<another class>"] struct {
// These classes must have the attribute PLUGIN_NAMES which is a list of protocol names
// that will be matched later with the relay targets (e.g. SMB, LDAP, etc)
 type ProtocolAttack struct { // Thread:
    PLUGIN_NAMES = ["PROTOCOL"]
     func (self TYPE) __init__(config, client, username interface{}){
        Thread.__init__(self)
        // Set threads as daemon
        self.daemon = true
        self.config = config
        self.client = client
        // By default we only use the username and remove the domain
        self.username = username.split("/")[1]

     func (self TYPE) run(){
        raise RuntimeError("Virtual Function")

for file in pkg_resources.resource_listdir('impacket.examples.ntlmrelayx', 'attacks'):
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
            if hasattr(module, 'PROTOCOL_ATTACK_CLASSES') {
                // Multiple classes
                for pluginClass in module.PROTOCOL_ATTACK_CLASSES:
                    pluginClasses.add(getattr(module, pluginClass))
            } else  {
                // Single class
                pluginClasses.add(getattr(module, getattr(module, 'PROTOCOL_ATTACK_CLASS')))
        except Exception as e:
            LOG.debug(e)
            pass

        for pluginClass in pluginClasses:
            for pluginName in pluginClass.PLUGIN_NAMES:
                LOG.debug('Protocol Attack %s loaded..' % pluginName)
                PROTOCOL_ATTACKS[pluginName] = pluginClass
    except Exception as e:
        LOG.debug(str(e))
