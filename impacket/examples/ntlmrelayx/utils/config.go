// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Config utilities
//
// Author:
//  Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
//
// Description:
//     Configuration  type which holds the config specified on the struct {
// command line, this can be passed to the tools' servers and clients
 type NTLMRelayxConfig: struct {
     func (self TYPE) __init__(){

        self.daemon = true

        // Set the value of the interface ip address
        self.interfaceIp = nil

        self.listeningPort = nil

        self.domainIp = nil
        self.machineAccount = nil
        self.machineHashes = nil
        self.target = nil
        self.mode = nil
        self.redirecthost = nil
        self.outputFile = nil
        self.attacks = nil
        self.lootdir = nil
        self.randomtargets = false
        self.encoding = nil
        self.ipv6 = false

        //WPAD options
        self.serve_wpad = false
        self.wpad_host = nil
        self.wpad_auth_num = 0
        self.smb2support = false

        //WPAD options
        self.serve_wpad = false
        self.wpad_host = nil
        self.wpad_auth_num = 0
        self.smb2support = false

        // SMB options
        self.exeFile = nil
        self.command = nil
        self.interactive = false
        self.enumLocalAdmins = false

        // LDAP options
        self.dumpdomain = true
        self.addda = true
        self.aclattack = true
        self.validateprivs = true
        self.escalateuser = nil

        // MSSQL options
        self.queries = []

        // Registered protocol clients
        self.protocolClients = {}

        // SOCKS options
        self.runSocks = false
        self.socksServer = nil


     func (self TYPE) setSMB2Support(value interface{}){
        self.smb2support = value

     func (self TYPE) setProtocolClients(clients interface{}){
        self.protocolClients = clients

     func (self TYPE) setInterfaceIp(ip interface{}){
        self.interfaceIp = ip
    
     func (self TYPE) setListeningPort(port interface{}){
        self.listeningPort = port

     func (self TYPE) setRunSocks(socks, server interface{}){
        self.runSocks = socks
        self.socksServer = server

     func (self TYPE) setOutputFile(outputFile interface{}){
        self.outputFile = outputFile

     func (self TYPE) setTargets(target interface{}){
        self.target = target

     func (self TYPE) setExeFile(filename interface{}){
        self.exeFile = filename

     func (self TYPE) setCommand(command interface{}){
        self.command = command

     func (self TYPE) setEnumLocalAdmins(enumLocalAdmins interface{}){
        self.enumLocalAdmins = enumLocalAdmins

     func (self TYPE) setEncoding(encoding interface{}){
        self.encoding = encoding

     func (self TYPE) setMode(mode interface{}){
        self.mode = mode

     func (self TYPE) setAttacks(attacks interface{}){
        self.attacks = attacks

     func (self TYPE) setLootdir(lootdir interface{}){
        self.lootdir = lootdir

     func setRedirectHost(self,redirecthost interface{}){
        self.redirecthost = redirecthost

     func setDomainAccount( self, machineAccount,  machineHashes, domainIp interface{}){
        self.machineAccount = machineAccount
        self.machineHashes = machineHashes
        self.domainIp = domainIp

     func (self TYPE) setRandomTargets(randomtargets interface{}){
        self.randomtargets = randomtargets

     func (self TYPE) setLDAPOptions(dumpdomain, addda, aclattack, validateprivs, escalateuser, addcomputer, delegateaccess interface{}){
        self.dumpdomain = dumpdomain
        self.addda = addda
        self.aclattack = aclattack
        self.validateprivs = validateprivs
        self.escalateuser = escalateuser
        self.addcomputer = addcomputer
        self.delegateaccess = delegateaccess

     func (self TYPE) setMSSQLOptions(queries interface{}){
        self.queries = queries

     func (self TYPE) setInteractive(interactive interface{}){
        self.interactive = interactive

     func (self TYPE) setIMAPOptions(keyword, mailbox, dump_all, dump_max interface{}){
        self.keyword = keyword
        self.mailbox = mailbox
        self.dump_all = dump_all
        self.dump_max = dump_max

     func (self TYPE) setIPv6(use_ipv6 interface{}){
        self.ipv6 = use_ipv6

     func (self TYPE) setWpadOptions(wpad_host, wpad_auth_num interface{}){
        if wpad_host is not nil {
            self.serve_wpad = true
        self.wpad_host = wpad_host
        self.wpad_auth_num = wpad_auth_num
