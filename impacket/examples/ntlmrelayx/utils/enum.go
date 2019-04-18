// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Config utilities
//
// Author:
//  Ronnie Flathers / @ropnop
//
// Description:
//     Helpful enum methods for discovering local admins through SAMR and LSAT

from impacket.dcerpc.v5 import transport, lsat, samr, lsad
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED


 type EnumLocalAdmins: struct {
     func (self TYPE) __init__(smbConnection interface{}){
        self.__smbConnection = smbConnection
        self.__samrBinding = r'ncacn_np:445[\pipe\samr]'
        self.__lsaBinding = r'ncacn_np:445[\pipe\lsarpc]'

     func (self TYPE) __getDceBinding(strBinding interface{}){
        rpc = transport.DCERPCTransportFactory(strBinding)
        rpc.set_smb_connection(self.__smbConnection)
        return rpc.get_dce_rpc()

     func (self TYPE) getLocalAdmins(){
        adminSids = self.__getLocalAdminSids()
        adminNames = self.__resolveSids(adminSids)
        return adminSids, adminNames

     func (self TYPE) __getLocalAdminSids(){
        dce = self.__getDceBinding(self.__samrBinding)
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        resp = samr.hSamrConnect(dce)
        serverHandle = resp["ServerHandle"]

        resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, 'Builtin')
        resp = samr.hSamrOpenDomain(dce, serverHandle=serverHandle, domainId=resp["DomainId"])
        domainHandle = resp["DomainHandle"]
        resp = samr.hSamrOpenAlias(dce, domainHandle, desiredAccess=MAXIMUM_ALLOWED, aliasId=544)
        resp = samr.hSamrGetMembersInAlias(dce, resp["AliasHandle"])
        memberSids = []
        for member in resp["Members"]["Sids"]:
            memberSids.append(member["SidPointer"].formatCanonical())
        dce.disconnect()
        return memberSids

     func (self TYPE) __resolveSids(sids interface{}){
        dce = self.__getDceBinding(self.__lsaBinding)
        dce.connect()
        dce.bind(lsat.MSRPC_UUID_LSAT)
        resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policyHandle = resp["PolicyHandle"]
        resp = lsat.hLsarLookupSids(dce, policyHandle, sids, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
        names = []
        for n, item in enumerate(resp["TranslatedNames"]["Names"]):
            names.append("{}\\{}".format(resp["ReferencedDomains"]["Domains"][item["DomainIndex"]]["Name"].encode("utf-16-le"), item["Name"]))
        dce.disconnect()
        return names
