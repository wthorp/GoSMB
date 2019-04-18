// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Author: Alberto Solino (@agsolino)
//
// Description:
//   [MS-LSAT] Interface implementation
//
//   Best way to learn how to use these calls is to grab the protocol standard
//   so you understand what the call does, and then read the test case located
//   at https://github.com/SecureAuthCorp/impacket/tree/master/tests/SMB_RPC
//
//   Some calls have helper functions, which makes it even easier to use.
//   They are located at the end of this file. 
//   Helper functions start with "h"<name of the call>.
//   There are test cases for them too. 
//
from impacket import nt_errors
from impacket.dcerpc.v5.dtypes import ULONG, LONG, PRPC_SID, RPC_UNICODE_STRING, LPWSTR, PRPC_UNICODE_STRING, NTSTATUS, \
    NULL
from impacket.dcerpc.v5.enum import Enum
from impacket.dcerpc.v5.lsad import LSAPR_HANDLE, PLSAPR_TRUST_INFORMATION_ARRAY
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRENUM, NDRPOINTER, NDRUniConformantArray
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_LSAT  = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AB','0.0'))

 type DCERPCSessionError struct { // DCERPCException:
     func (self TYPE) __init__(error_string=nil, error_code=nil, packet=nil interface{}){
        DCERPCException.__init__(self, error_string, error_code, packet)

     func __str__( self  interface{}){
        key = self.error_code
        if key in nt_errors.ERROR_MESSAGES {
            error_msg_short = nt_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = nt_errors.ERROR_MESSAGES[key][1] 
            return 'LSAT SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        } else  {
            return 'LSAT SessionError: unknown error code: 0x%x' % self.error_code

//###############################################################################
// CONSTANTS
//###############################################################################
// 2.2.10 ACCESS_MASK
POLICY_LOOKUP_NAMES             = 0x00000800

//###############################################################################
// STRUCTURES
//###############################################################################
// 2.2.12 LSAPR_REFERENCED_DOMAIN_LIST
 type LSAPR_REFERENCED_DOMAIN_LIST struct { // NDRSTRUCT: (
        ('Entries', ULONG),
        ('Domains', PLSAPR_TRUST_INFORMATION_ARRAY),
        ('MaxEntries', ULONG),
    }

 type PLSAPR_REFERENCED_DOMAIN_LIST struct { // NDRPOINTER:
    referent = (
        ('Data', LSAPR_REFERENCED_DOMAIN_LIST),
    }

// 2.2.14 LSA_TRANSLATED_SID
 type LSA_TRANSLATED_SID struct { // NDRSTRUCT: (
        ('Use', SID_NAME_USE),
        ('RelativeId', ULONG),
        ('DomainIndex', LONG),
    }

// 2.2.15 LSAPR_TRANSLATED_SIDS
 type LSA_TRANSLATED_SID_ARRAY struct { // NDRUniConformantArray:
    item = LSA_TRANSLATED_SID

 type PLSA_TRANSLATED_SID_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', LSA_TRANSLATED_SID_ARRAY),
    }

 type LSAPR_TRANSLATED_SIDS struct { // NDRSTRUCT: (
        ('Entries', ULONG),
        ('Sids', PLSA_TRANSLATED_SID_ARRAY),
    }

// 2.2.16 LSAP_LOOKUP_LEVEL
 type LSAP_LOOKUP_LEVEL struct { // NDRENUM:
     type enumItems struct { // Enum:
        LsapLookupWksta                = 1
        LsapLookupPDC                  = 2
        LsapLookupTDL                  = 3
        LsapLookupGC                   = 4
        LsapLookupXForestReferral      = 5
        LsapLookupXForestResolve       = 6
        LsapLookupRODCReferralToFullDC = 7

// 2.2.17 LSAPR_SID_INFORMATION
 type LSAPR_SID_INFORMATION struct { // NDRSTRUCT: (
        ('Sid', PRPC_SID),
    }

// 2.2.18 LSAPR_SID_ENUM_BUFFER
 type LSAPR_SID_INFORMATION_ARRAY struct { // NDRUniConformantArray:
    item = LSAPR_SID_INFORMATION

 type PLSAPR_SID_INFORMATION_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', LSAPR_SID_INFORMATION_ARRAY),
    }

 type LSAPR_SID_ENUM_BUFFER struct { // NDRSTRUCT: (
        ('Entries', ULONG),
        ('SidInfo', PLSAPR_SID_INFORMATION_ARRAY),
    }

// 2.2.19 LSAPR_TRANSLATED_NAME
 type LSAPR_TRANSLATED_NAME struct { // NDRSTRUCT: (
        ('Use', SID_NAME_USE),
        ('Name', RPC_UNICODE_STRING),
        ('DomainIndex', LONG),
    }

// 2.2.20 LSAPR_TRANSLATED_NAMES
 type LSAPR_TRANSLATED_NAME_ARRAY struct { // NDRUniConformantArray:
    item = LSAPR_TRANSLATED_NAME

 type PLSAPR_TRANSLATED_NAME_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', LSAPR_TRANSLATED_NAME_ARRAY),
    }

 type LSAPR_TRANSLATED_NAMES struct { // NDRSTRUCT: (
        ('Entries', ULONG),
        ('Names', PLSAPR_TRANSLATED_NAME_ARRAY),
    }

// 2.2.21 LSAPR_TRANSLATED_NAME_EX
 type LSAPR_TRANSLATED_NAME_EX struct { // NDRSTRUCT: (
        ('Use', SID_NAME_USE),
        ('Name', RPC_UNICODE_STRING),
        ('DomainIndex', LONG),
        ('Flags', ULONG),
    }

// 2.2.22 LSAPR_TRANSLATED_NAMES_EX
 type LSAPR_TRANSLATED_NAME_EX_ARRAY struct { // NDRUniConformantArray:
    item = LSAPR_TRANSLATED_NAME_EX

 type PLSAPR_TRANSLATED_NAME_EX_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', LSAPR_TRANSLATED_NAME_EX_ARRAY),
    }

 type LSAPR_TRANSLATED_NAMES_EX struct { // NDRSTRUCT: (
        ('Entries', ULONG),
        ('Names', PLSAPR_TRANSLATED_NAME_EX_ARRAY),
    }

// 2.2.23 LSAPR_TRANSLATED_SID_EX
 type LSAPR_TRANSLATED_SID_EX struct { // NDRSTRUCT: (
        ('Use', SID_NAME_USE),
        ('RelativeId', ULONG),
        ('DomainIndex', LONG),
        ('Flags', ULONG),
    }

// 2.2.24 LSAPR_TRANSLATED_SIDS_EX
 type LSAPR_TRANSLATED_SID_EX_ARRAY struct { // NDRUniConformantArray:
    item = LSAPR_TRANSLATED_SID_EX

 type PLSAPR_TRANSLATED_SID_EX_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', LSAPR_TRANSLATED_SID_EX_ARRAY),
    }

 type LSAPR_TRANSLATED_SIDS_EX struct { // NDRSTRUCT: (
        ('Entries', ULONG),
        ('Sids', PLSAPR_TRANSLATED_SID_EX_ARRAY),
    }

// 2.2.25 LSAPR_TRANSLATED_SID_EX2
 type LSAPR_TRANSLATED_SID_EX2 struct { // NDRSTRUCT: (
        ('Use', SID_NAME_USE),
        ('Sid', PRPC_SID),
        ('DomainIndex', LONG),
        ('Flags', ULONG),
    }

// 2.2.26 LSAPR_TRANSLATED_SIDS_EX2
 type LSAPR_TRANSLATED_SID_EX2_ARRAY struct { // NDRUniConformantArray:
    item = LSAPR_TRANSLATED_SID_EX2

 type PLSAPR_TRANSLATED_SID_EX2_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', LSAPR_TRANSLATED_SID_EX2_ARRAY),
    }

 type LSAPR_TRANSLATED_SIDS_EX2 struct { // NDRSTRUCT: (
        ('Entries', ULONG),
        ('Sids', PLSAPR_TRANSLATED_SID_EX2_ARRAY),
    }

 type RPC_UNICODE_STRING_ARRAY struct { // NDRUniConformantArray:
    item = RPC_UNICODE_STRING

//###############################################################################
// RPC CALLS
//###############################################################################
// 3.1.4.4 LsarGetUserName (Opnum 45)
 type LsarGetUserName struct { // NDRCALL:
    opnum = 45 (
       ('SystemName', LPWSTR),
       ('UserName', PRPC_UNICODE_STRING),
       ('DomainName', PRPC_UNICODE_STRING),
    }

 type LsarGetUserNameResponse struct { // NDRCALL: (
       ('UserName', PRPC_UNICODE_STRING),
       ('DomainName', PRPC_UNICODE_STRING),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.5 LsarLookupNames4 (Opnum 77)
 type LsarLookupNames4 struct { // NDRCALL:
    opnum = 77 (
       ('Count', ULONG),
       ('Names', RPC_UNICODE_STRING_ARRAY),
       ('TranslatedSids', LSAPR_TRANSLATED_SIDS_EX2),
       ('LookupLevel', LSAP_LOOKUP_LEVEL),
       ('MappedCount', ULONG),
       ('LookupOptions', ULONG),
       ('ClientRevision', ULONG),
    }

 type LsarLookupNames4Response struct { // NDRCALL: (
       ('ReferencedDomains', PLSAPR_REFERENCED_DOMAIN_LIST),
       ('TranslatedSids', LSAPR_TRANSLATED_SIDS_EX2),
       ('MappedCount', ULONG),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.6 LsarLookupNames3 (Opnum 68)
 type LsarLookupNames3 struct { // NDRCALL:
    opnum = 68 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('Count', ULONG),
       ('Names', RPC_UNICODE_STRING_ARRAY),
       ('TranslatedSids', LSAPR_TRANSLATED_SIDS_EX2),
       ('LookupLevel', LSAP_LOOKUP_LEVEL),
       ('MappedCount', ULONG),
       ('LookupOptions', ULONG),
       ('ClientRevision', ULONG),
    }

 type LsarLookupNames3Response struct { // NDRCALL: (
       ('ReferencedDomains', PLSAPR_REFERENCED_DOMAIN_LIST),
       ('TranslatedSids', LSAPR_TRANSLATED_SIDS_EX2),
       ('MappedCount', ULONG),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.7 LsarLookupNames2 (Opnum 58)
 type LsarLookupNames2 struct { // NDRCALL:
    opnum = 58 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('Count', ULONG),
       ('Names', RPC_UNICODE_STRING_ARRAY),
       ('TranslatedSids', LSAPR_TRANSLATED_SIDS_EX),
       ('LookupLevel', LSAP_LOOKUP_LEVEL),
       ('MappedCount', ULONG),
       ('LookupOptions', ULONG),
       ('ClientRevision', ULONG),
    }

 type LsarLookupNames2Response struct { // NDRCALL: (
       ('ReferencedDomains', PLSAPR_REFERENCED_DOMAIN_LIST),
       ('TranslatedSids', LSAPR_TRANSLATED_SIDS_EX),
       ('MappedCount', ULONG),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.8 LsarLookupNames (Opnum 14)
 type LsarLookupNames struct { // NDRCALL:
    opnum = 14 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('Count', ULONG),
       ('Names', RPC_UNICODE_STRING_ARRAY),
       ('TranslatedSids', LSAPR_TRANSLATED_SIDS),
       ('LookupLevel', LSAP_LOOKUP_LEVEL),
       ('MappedCount', ULONG),
    }

 type LsarLookupNamesResponse struct { // NDRCALL: (
       ('ReferencedDomains', PLSAPR_REFERENCED_DOMAIN_LIST),
       ('TranslatedSids', LSAPR_TRANSLATED_SIDS),
       ('MappedCount', ULONG),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.9 LsarLookupSids3 (Opnum 76)
 type LsarLookupSids3 struct { // NDRCALL:
    opnum = 76 (
       ('SidEnumBuffer', LSAPR_SID_ENUM_BUFFER),
       ('TranslatedNames', LSAPR_TRANSLATED_NAMES_EX),
       ('LookupLevel', LSAP_LOOKUP_LEVEL),
       ('MappedCount', ULONG),
       ('LookupOptions', ULONG),
       ('ClientRevision', ULONG),
    }

 type LsarLookupSids3Response struct { // NDRCALL: (
       ('ReferencedDomains', PLSAPR_REFERENCED_DOMAIN_LIST),
       ('TranslatedNames', LSAPR_TRANSLATED_NAMES_EX),
       ('MappedCount', ULONG),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.10 LsarLookupSids2 (Opnum 57)
 type LsarLookupSids2 struct { // NDRCALL:
    opnum = 57 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('SidEnumBuffer', LSAPR_SID_ENUM_BUFFER),
       ('TranslatedNames', LSAPR_TRANSLATED_NAMES_EX),
       ('LookupLevel', LSAP_LOOKUP_LEVEL),
       ('MappedCount', ULONG),
       ('LookupOptions', ULONG),
       ('ClientRevision', ULONG),
    }

 type LsarLookupSids2Response struct { // NDRCALL: (
       ('ReferencedDomains', PLSAPR_REFERENCED_DOMAIN_LIST),
       ('TranslatedNames', LSAPR_TRANSLATED_NAMES_EX),
       ('MappedCount', ULONG),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.11 LsarLookupSids (Opnum 15)
 type LsarLookupSids struct { // NDRCALL:
    opnum = 15 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('SidEnumBuffer', LSAPR_SID_ENUM_BUFFER),
       ('TranslatedNames', LSAPR_TRANSLATED_NAMES),
       ('LookupLevel', LSAP_LOOKUP_LEVEL),
       ('MappedCount', ULONG),
    }

 type LsarLookupSidsResponse struct { // NDRCALL: (
       ('ReferencedDomains', PLSAPR_REFERENCED_DOMAIN_LIST),
       ('TranslatedNames', LSAPR_TRANSLATED_NAMES),
       ('MappedCount', ULONG),
       ('ErrorCode', NTSTATUS),
    }

//###############################################################################
// OPNUMs and their corresponding structures
//###############################################################################
OPNUMS = {
 14 : (LsarLookupNames, LsarLookupNamesResponse),
 15 : (LsarLookupSids, LsarLookupSidsResponse),
 45 : (LsarGetUserName, LsarGetUserNameResponse),
 57 : (LsarLookupSids2, LsarLookupSids2Response),
 58 : (LsarLookupNames2, LsarLookupNames2Response),
 68 : (LsarLookupNames3, LsarLookupNames3Response),
 76 : (LsarLookupSids3, LsarLookupSids3Response),
 77 : (LsarLookupNames4, LsarLookupNames4Response),
}

//###############################################################################
// HELPER FUNCTIONS
//###############################################################################
 func hLsarGetUserName(dce, userName = NULL, domainName = NULL interface{}){
    request = LsarGetUserName()
    request["SystemName"] = NULL
    request["UserName"] = userName
    request["DomainName"] = domainName
    return dce.request(request)

 func hLsarLookupNames4(dce, names, lookupLevel = LSAP_LOOKUP_LEVEL.LsapLookupWksta, lookupOptions=0x00000000, clientRevision=0x00000001 interface{}){
    request = LsarLookupNames4()
    request["Count"] = len(names)
    for name in names:
        itemn = RPC_UNICODE_STRING()
        itemn["Data"] = name
        request["Names"].append(itemn)
    request["TranslatedSids"]["Sids"] = NULL
    request["LookupLevel"] = lookupLevel
    request["LookupOptions"] = lookupOptions
    request["ClientRevision"] = clientRevision

    return dce.request(request)

 func hLsarLookupNames3(dce, policyHandle, names, lookupLevel = LSAP_LOOKUP_LEVEL.LsapLookupWksta, lookupOptions=0x00000000, clientRevision=0x00000001 interface{}){
    request = LsarLookupNames3()
    request["PolicyHandle"] = policyHandle
    request["Count"] = len(names)
    for name in names:
        itemn = RPC_UNICODE_STRING()
        itemn["Data"] = name
        request["Names"].append(itemn)
    request["TranslatedSids"]["Sids"] = NULL
    request["LookupLevel"] = lookupLevel
    request["LookupOptions"] = lookupOptions
    request["ClientRevision"] = clientRevision

    return dce.request(request)

 func hLsarLookupNames2(dce, policyHandle, names, lookupLevel = LSAP_LOOKUP_LEVEL.LsapLookupWksta, lookupOptions=0x00000000, clientRevision=0x00000001 interface{}){
    request = LsarLookupNames2()
    request["PolicyHandle"] = policyHandle
    request["Count"] = len(names)
    for name in names:
        itemn = RPC_UNICODE_STRING()
        itemn["Data"] = name
        request["Names"].append(itemn)
    request["TranslatedSids"]["Sids"] = NULL
    request["LookupLevel"] = lookupLevel
    request["LookupOptions"] = lookupOptions
    request["ClientRevision"] = clientRevision

    return dce.request(request)

 func hLsarLookupNames(dce, policyHandle, names, lookupLevel = LSAP_LOOKUP_LEVEL.LsapLookupWksta interface{}){
    request = LsarLookupNames()
    request["PolicyHandle"] = policyHandle
    request["Count"] = len(names)
    for name in names:
        itemn = RPC_UNICODE_STRING()
        itemn["Data"] = name
        request["Names"].append(itemn)
    request["TranslatedSids"]["Sids"] = NULL
    request["LookupLevel"] = lookupLevel

    return dce.request(request)

 func hLsarLookupSids2(dce, policyHandle, sids, lookupLevel = LSAP_LOOKUP_LEVEL.LsapLookupWksta, lookupOptions=0x00000000, clientRevision=0x00000001 interface{}){
    request = LsarLookupSids2()
    request["PolicyHandle"] = policyHandle
    request["SidEnumBuffer"]["Entries"] = len(sids)
    for sid in sids:
        itemn = LSAPR_SID_INFORMATION()
        itemn["Sid"].fromCanonical(sid)
        request["SidEnumBuffer"]["SidInfo"].append(itemn)

    request["TranslatedNames"]["Names"] = NULL
    request["LookupLevel"] = lookupLevel
    request["LookupOptions"] = lookupOptions
    request["ClientRevision"] = clientRevision

    return dce.request(request)

 func hLsarLookupSids(dce, policyHandle, sids, lookupLevel = LSAP_LOOKUP_LEVEL.LsapLookupWksta interface{}){
    request = LsarLookupSids()
    request["PolicyHandle"] = policyHandle
    request["SidEnumBuffer"]["Entries"] = len(sids)
    for sid in sids:
        itemn = LSAPR_SID_INFORMATION()
        itemn["Sid"].fromCanonical(sid)
        request["SidEnumBuffer"]["SidInfo"].append(itemn)

    request["TranslatedNames"]["Names"] = NULL
    request["LookupLevel"] = lookupLevel

    return dce.request(request)
