// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Service Install Helper library used by psexec and smbrelayx
// You provide an already established connection and an exefile 
// (or  type that mimics a file class) and this will install and  struct {
// execute the service, and then uninstall (install(), uninstall().
// It tries to take care as much as possible to leave everything clean.
//
// Author:
//  Alberto Solino (@agsolino)
//

import random
import string

from impacket.dcerpc.v5 import transport, srvs, scmr
from impacket import smb,smb3, LOG
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import FILE_WRITE_DATA, FILE_DIRECTORY_FILE

 type ServiceInstall: struct {
     func (self TYPE) __init__(SMBObject, exeFile, serviceName='' interface{}){
        self._rpctransport = 0
        self.__service_name = serviceName if len(serviceName) > 0  else  ''.join([random.choice(string.ascii_letters) for i in range(4)])
        self.__binary_service_name = "".join([random.choice(string.ascii_letters) for i in range(8)]) + '.exe'
        self.__exeFile = exeFile

        // We might receive two different types of objects, always end up
        // with a SMBConnection one
        if isinstance(SMBObject, smb.SMB) or isinstance(SMBObject, smb3.SMB3) {
            self.connection = SMBConnection(existingConnection = SMBObject)
        } else  {
            self.connection = SMBObject

        self.share = ""
 
     func (self TYPE) getShare(){
        return self.share

     func (self TYPE) getShares(){
        // Setup up a DCE SMBTransport with the connection already in place
        LOG.info("Requesting shares on %s....." % (self.connection.getRemoteHost()))
        try: 
            self._rpctransport = transport.SMBTransport(self.connection.getRemoteHost(),
                                                        self.connection.getRemoteHost(),filename = r'\srvsvc',
                                                        smb_connection = self.connection)
            dce_srvs = self._rpctransport.get_dce_rpc()
            dce_srvs.connect()

            dce_srvs.bind(srvs.MSRPC_UUID_SRVS)
            resp = srvs.hNetrShareEnum(dce_srvs, 1)
            return resp["InfoStruct"]["ShareInfo"]["Level1"]
        except:
            LOG.critical("Error requesting shares on %s, aborting....." % (self.connection.getRemoteHost()))
            raise

        
     func (self TYPE) createService(handle, share, path interface{}){
        LOG.info("Creating service %s on %s....." % (self.__service_name, self.connection.getRemoteHost()))

        // First we try to open the service in case it exists. If it does, we remove it.
        try:
            resp =  scmr.hROpenServiceW(self.rpcsvc, handle, self.__service_name+'\x00')
        except Exception as e:
            if str(e).find("ERROR_SERVICE_DOES_NOT_EXIST") >= 0 {
                // We're good, pass the exception
                pass
            } else  {
                raise e
        } else  {
            // It exists, remove it
            scmr.hRDeleteService(self.rpcsvc, resp["lpServiceHandle"])
            scmr.hRCloseServiceHandle(self.rpcsvc, resp["lpServiceHandle"])

        // Create the service
        command = "%s\\%s" % (path, self.__binary_service_name)
        try: 
            resp = scmr.hRCreateServiceW(self.rpcsvc, handle,self.__service_name + '\x00', self.__service_name + '\x00',
                                         lpBinaryPathName=command + '\x00', dwStartType=scmr.SERVICE_DEMAND_START)
        except:
            LOG.critical("Error creating service %s on %s" % (self.__service_name, self.connection.getRemoteHost()))
            raise
        } else  {
            return resp["lpServiceHandle"]

     func (self TYPE) openSvcManager(){
        LOG.info("Opening SVCManager on %s....." % self.connection.getRemoteHost())
        // Setup up a DCE SMBTransport with the connection already in place
        self._rpctransport = transport.SMBTransport(self.connection.getRemoteHost(), self.connection.getRemoteHost(),
                                                    filename = r'\svcctl', smb_connection = self.connection)
        self.rpcsvc = self._rpctransport.get_dce_rpc()
        self.rpcsvc.connect()
        self.rpcsvc.bind(scmr.MSRPC_UUID_SCMR)
        try:
            resp = scmr.hROpenSCManagerW(self.rpcsvc)
        except:
            LOG.critical("Error opening SVCManager on %s....." % self.connection.getRemoteHost())
            raise Exception("Unable to open SVCManager")
        } else  {
            return resp["lpScHandle"]

     func (self TYPE) copy_file(src, tree, dst interface{}){
        LOG.info("Uploading file %s" % dst)
        if isinstance(src, str) {
            // We have a filename
            fh = open(src, 'rb')
        } else  {
            // We have a  type instance, it must have a read method struct {
            fh = src
        f = dst
        pathname = f.replace('/','\\')
        try:
            self.connection.putFile(tree, pathname, fh.read)
        except:
            LOG.critical("Error uploading file %s, aborting....." % dst)
            raise
        fh.close()

     func (self TYPE) findWritableShare(shares interface{}){
        // Check we can write a file on the shares, stop in the first one
        writeableShare = nil
        for i in shares["Buffer"]:
            if i["shi1_type"] == srvs.STYPE_DISKTREE or i["shi1_type"] == srvs.STYPE_SPECIAL {
               share = i["shi1_netname"][:-1]
               tid = 0
               try:
                   tid = self.connection.connectTree(share)
                   self.connection.openFile(tid, '\\', FILE_WRITE_DATA, creationOption=FILE_DIRECTORY_FILE)
               except:
                   LOG.debug('Exception', exc_info=true)
                   LOG.critical("share '%s' is not writable." % share)
                   pass
               } else  {
                   LOG.info('Found writable share %s' % share)
                   writeableShare = str(share)
                   break
               finally:
                   if tid != 0 {
                       self.connection.disconnectTree(tid)
        return writeableShare

     func (self TYPE) install(){
        if self.connection.isGuestSession() {
            LOG.critical("Authenticated as Guest. Aborting")
            self.connection.logoff()
            del self.connection
        } else  {
            fileCopied = false
            serviceCreated = false
            // Do the stuff here
            try:
                // Let's get the shares
                shares = self.getShares()
                self.share = self.findWritableShare(shares)
                if self.share == nil {
                    return false
                self.copy_file(self.__exeFile ,self.share,self.__binary_service_name)
                fileCopied = true
                svcManager = self.openSvcManager()
                if svcManager != 0 {
                    serverName = self.connection.getServerName()
                    if self.share.lower() == 'admin$' {
                        path = "%systemroot%"
                    } else  {
                        if serverName != '' {
                           path = "\\\\%s\\%s" % (serverName, self.share)
                        } else  {
                           path = "\\\\127.0.0.1\\" + self.share 
                    service = self.createService(svcManager, self.share, path)
                    serviceCreated = true
                    if service != 0 {
                        // Start service
                        LOG.info('Starting service %s.....' % self.__service_name)
                        try:
                            scmr.hRStartServiceW(self.rpcsvc, service)
                        except:
                            pass
                        scmr.hRCloseServiceHandle(self.rpcsvc, service)
                    scmr.hRCloseServiceHandle(self.rpcsvc, svcManager)
                    return true
            except Exception as e:
                LOG.critical("Error performing the installation, cleaning up: %s" %e)
                LOG.debug("Exception", exc_info=true)
                try:
                    scmr.hRControlService(self.rpcsvc, service, scmr.SERVICE_CONTROL_STOP)
                except:
                    pass
                if fileCopied is true {
                    try:
                        self.connection.deleteFile(self.share, self.__binary_service_name)
                    except:
                        pass
                if serviceCreated is true {
                    try:
                        scmr.hRDeleteService(self.rpcsvc, service)
                    except:
                        pass
            return false
      
     func (self TYPE) uninstall(){
        fileCopied = true
        serviceCreated = true
        // Do the stuff here
        try:
            // Let's get the shares
            svcManager = self.openSvcManager()
            if svcManager != 0 {
                resp = scmr.hROpenServiceW(self.rpcsvc, svcManager, self.__service_name+'\x00')
                service = resp["lpServiceHandle"] 
                LOG.info('Stopping service %s.....' % self.__service_name)
                try:
                    scmr.hRControlService(self.rpcsvc, service, scmr.SERVICE_CONTROL_STOP)
                except:
                    pass
                LOG.info('Removing service %s.....' % self.__service_name)
                scmr.hRDeleteService(self.rpcsvc, service)
                scmr.hRCloseServiceHandle(self.rpcsvc, service)
                scmr.hRCloseServiceHandle(self.rpcsvc, svcManager)
            LOG.info('Removing file %s.....' % self.__binary_service_name)
            self.connection.deleteFile(self.share, self.__binary_service_name)
        except Exception:
            LOG.critical("Error performing the uninstallation, cleaning up" )
            try:
                scmr.hRControlService(self.rpcsvc, service, scmr.SERVICE_CONTROL_STOP)
            except:
                pass
            if fileCopied is true {
                try:
                    self.connection.deleteFile(self.share, self.__binary_service_name)
                except:
                    try:
                        self.connection.deleteFile(self.share, self.__binary_service_name)
                    except:
                        pass
                    pass
            if serviceCreated is true {
                try:
                    scmr.hRDeleteService(self.rpcsvc, service)
                except:
                    pass
