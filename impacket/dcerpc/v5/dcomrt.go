// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Author: Alberto Solino (@agsolino)
//
// Description:
//   [MS-DCOM] Interface implementation
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
// ToDo:
// [X] Use the same DCE connection for all the calls. Right now is connecting to the remote machine
//     for each call, making it slower.
//
// [X] Implement a ping mechanism, otherwise the garbage collector at the server shuts down the objects if 
//    not used, returning RPC_E_DISCONNECTED
//
from __future__ import division
from __future__ import print_function
import socket
from struct import pack
from threading import Timer, currentThread

from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRPOINTER, NDRUniConformantArray, NDRTLSTRUCT, UNKNOWNDATA
from impacket.dcerpc.v5.dtypes import LPWSTR, ULONGLONG, HRESULT, GUID, USHORT, WSTR, DWORD, LPLONG, LONG, PGUID, ULONG, \
    UUID, WIDESTR, NULL
from impacket import hresult_errors, LOG
from impacket.uuid import string_to_bin, uuidtup_to_bin, generate
from impacket.dcerpc.v5.rpcrt import TypeSerialization1, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_NONE, \
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_WINNT, DCERPCException
from impacket.dcerpc.v5 import transport

CLSID_ActivationContextInfo   = string_to_bin("000001a5-0000-0000-c000-000000000046")
CLSID_ActivationPropertiesIn  = string_to_bin("00000338-0000-0000-c000-000000000046")
CLSID_ActivationPropertiesOut = string_to_bin("00000339-0000-0000-c000-000000000046")
CLSID_CONTEXT_EXTENSION       = string_to_bin("00000334-0000-0000-c000-000000000046")
CLSID_ContextMarshaler        = string_to_bin("0000033b-0000-0000-c000-000000000046")
CLSID_ERROR_EXTENSION         = string_to_bin("0000031c-0000-0000-c000-000000000046")
CLSID_ErrorObject             = string_to_bin("0000031b-0000-0000-c000-000000000046")
CLSID_InstanceInfo            = string_to_bin("000001ad-0000-0000-c000-000000000046")
CLSID_InstantiationInfo       = string_to_bin("000001ab-0000-0000-c000-000000000046")
CLSID_PropsOutInfo            = string_to_bin("00000339-0000-0000-c000-000000000046")
CLSID_ScmReplyInfo            = string_to_bin("000001b6-0000-0000-c000-000000000046")
CLSID_ScmRequestInfo          = string_to_bin("000001aa-0000-0000-c000-000000000046")
CLSID_SecurityInfo            = string_to_bin("000001a6-0000-0000-c000-000000000046")
CLSID_ServerLocationInfo      = string_to_bin("000001a4-0000-0000-c000-000000000046")
CLSID_SpecialSystemProperties = string_to_bin("000001b9-0000-0000-c000-000000000046")
IID_IActivation               = uuidtup_to_bin(('4d9f4ab8-7d1c-11cf-861e-0020af6e7c57','0.0'))
IID_IActivationPropertiesIn   = uuidtup_to_bin(('000001A2-0000-0000-C000-000000000046','0.0'))
IID_IActivationPropertiesOut  = uuidtup_to_bin(('000001A3-0000-0000-C000-000000000046','0.0'))
IID_IContext                  = uuidtup_to_bin(('000001c0-0000-0000-C000-000000000046','0.0'))
IID_IObjectExporter           = uuidtup_to_bin(('99fcfec4-5260-101b-bbcb-00aa0021347a','0.0'))
IID_IRemoteSCMActivator       = uuidtup_to_bin(('000001A0-0000-0000-C000-000000000046','0.0'))
IID_IRemUnknown               = uuidtup_to_bin(('00000131-0000-0000-C000-000000000046','0.0'))
IID_IRemUnknown2              = uuidtup_to_bin(('00000143-0000-0000-C000-000000000046','0.0'))
IID_IUnknown                  = uuidtup_to_bin(('00000000-0000-0000-C000-000000000046','0.0'))
IID_IClassFactory             = uuidtup_to_bin(('00000001-0000-0000-C000-000000000046','0.0'))

 type DCERPCSessionError struct { // DCERPCException:
     func (self TYPE) __init__(error_string=nil, error_code=nil, packet=nil interface{}){
        DCERPCException.__init__(self, error_string, error_code, packet)

     func __str__( self  interface{}){
        if self.error_code in hresult_errors.ERROR_MESSAGES {
            error_msg_short = hresult_errors.ERROR_MESSAGES[self.error_code][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[self.error_code][1]
            return 'DCOM SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        } else  {
            return 'DCOM SessionError: unknown error code: 0x%x' % self.error_code

//###############################################################################
// CONSTANTS
//###############################################################################
// 2.2.1 OID
OID = ULONGLONG

 type OID_ARRAY struct { // NDRUniConformantArray:
    item = OID

 type POID_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', OID_ARRAY),
    }

// 2.2.2 SETID
SETID = ULONGLONG

// 2.2.4 error_status_t
error_status_t = ULONG

// 2.2.6 CID
CID = GUID

// 2.2.7 CLSID
CLSID = GUID

// 2.2.8 IID
IID = GUID
PIID = PGUID

// 2.2.9 IPID
IPID = GUID

// 2.2.10 OXID
OXID = ULONGLONG

// 2.2.18 OBJREF
FLAGS_OBJREF_STANDARD = 0x00000001
FLAGS_OBJREF_HANDLER  = 0x00000002
FLAGS_OBJREF_CUSTOM   = 0x00000004
FLAGS_OBJREF_EXTENDED = 0x00000008

// 2.2.18.1 STDOBJREF
SORF_NOPING = 0x00001000

// 2.2.20 Context
CTXMSHLFLAGS_BYVAL = 0x00000002

// 2.2.20.1 PROPMARSHALHEADER
CPFLAG_PROPAGATE = 0x00000001
CPFLAG_EXPOSE    = 0x00000002
CPFLAG_ENVOY     = 0x00000004

// 2.2.22.2.1 InstantiationInfoData
ACTVFLAGS_DISABLE_AAA            = 0x00000002
ACTVFLAGS_ACTIVATE_32_BIT_SERVER = 0x00000004
ACTVFLAGS_ACTIVATE_64_BIT_SERVER = 0x00000008
ACTVFLAGS_NO_FAILURE_LOG         = 0x00000020

// 2.2.22.2.2 SpecialPropertiesData
SPD_FLAG_USE_CONSOLE_SESSION  = 0x00000001

// 2.2.28.1 IDL Range Constants
MAX_REQUESTED_INTERFACES = 0x8000
MAX_REQUESTED_PROTSEQS   = 0x8000
MIN_ACTPROP_LIMIT        = 1
MAX_ACTPROP_LIMIT        = 10

//###############################################################################
// STRUCTURES
//###############################################################################
 type handle_t struct { // NDRSTRUCT:  (
        ('context_handle_attributes',ULONG),
        ('context_handle_uuid',UUID),
    }
     func (self TYPE) __init__(data = nil,isNDR64 = false interface{}){
        NDRSTRUCT.__init__(self, data, isNDR64)
        self.context_handle_uuid = "\x00"*20

// 2.2.11 COMVERSION
 type COMVERSION struct { // NDRSTRUCT: (
        ('MajorVersion',USHORT),
        ('MinorVersion',USHORT),
    }
     func (self TYPE) __init__(data = nil,isNDR64 = false interface{}){
        NDRSTRUCT.__init__(self, data, isNDR64)
        if data == nil {
            self.MajorVersion = 5
            self.MinorVersion = 6

 type PCOMVERSION struct { // NDRPOINTER:
    referent = (
        ('Data', COMVERSION),
    }

// 2.2.13.1 ORPC_EXTENT
// This MUST contain an array of bytes that form the extent data. 
// The array size MUST be a multiple of 8 for alignment reasons.
 type BYTE_ARRAY struct { // NDRUniConformantArray:
    item = "c"

 type ORPC_EXTENT struct { // NDRSTRUCT: (
        ('id',GUID),
        ('size',ULONG),
        ('data',BYTE_ARRAY),
    }

// 2.2.13.2 ORPC_EXTENT_ARRAY
// ThisMUSTbeanarrayofORPC_EXTENTs.ThearraysizeMUSTbeamultipleof2for alignment reasons.
 type PORPC_EXTENT struct { // NDRPOINTER:
    referent = (
        ('Data', ORPC_EXTENT),
    }

 type EXTENT_ARRAY struct { // NDRUniConformantArray:
    item = PORPC_EXTENT

 type PEXTENT_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', EXTENT_ARRAY),
    }

 type ORPC_EXTENT_ARRAY struct { // NDRSTRUCT: (
        ('size',ULONG),
        ('reserved',ULONG),
        ('extent',PEXTENT_ARRAY),
    }

 type PORPC_EXTENT_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', ORPC_EXTENT_ARRAY),
    }

// 2.2.13.3 ORPCTHIS
 type ORPCTHIS struct { // NDRSTRUCT: (
        ('version',COMVERSION),
        ('flags',ULONG),
        ('reserved1',ULONG),
        ('cid',CID),
        ('extensions',PORPC_EXTENT_ARRAY),
    }

// 2.2.13.4 ORPCTHAT
 type ORPCTHAT struct { // NDRSTRUCT: (
        ('flags',ULONG),
        ('extensions',PORPC_EXTENT_ARRAY),
    }

// 2.2.14 MInterfacePointer
 type MInterfacePointer struct { // NDRSTRUCT: (
        ('ulCntData',ULONG),
        ('abData',BYTE_ARRAY),
    }

// 2.2.15 PMInterfacePointerInternal
 type PMInterfacePointerInternal struct { // NDRPOINTER:
    referent = (
        ('Data', MInterfacePointer),
    }

// 2.2.16 PMInterfacePointer
 type PMInterfacePointer struct { // NDRPOINTER:
    referent = (
        ('Data', MInterfacePointer),
    }

 type PPMInterfacePointer struct { // NDRPOINTER:
    referent = (
        ('Data', PMInterfacePointer),
    }

// 2.2.18 OBJREF
 type OBJREF struct { // NDRSTRUCT:
    commonHdr = (
        ('signature',ULONG),
        ('flags',ULONG),
        ('iid',GUID),
    }
     func (self TYPE) __init__(data = nil,isNDR64 = false interface{}){
        NDRSTRUCT.__init__(self, data, isNDR64)
        if data == nil {
            self.signature = 0x574F454D

// 2.2.18.1 STDOBJREF
 type STDOBJREF struct { // NDRSTRUCT: (
        ('flags',ULONG),
        ('cPublicRefs',ULONG),
        ('oxid',OXID),
        ('oid',OID),
        ('ipid',IPID),
    }

// 2.2.18.4 OBJREF_STANDARD
 type OBJREF_STANDARD struct { // OBJREF: (
        ('std',STDOBJREF),
        ('saResAddr',':'),
    }
     func (self TYPE) __init__(data = nil,isNDR64 = false interface{}){
        OBJREF.__init__(self, data, isNDR64)
        if data == nil {
            self.flags = FLAGS_OBJREF_STANDARD

// 2.2.18.5 OBJREF_HANDLER
 type OBJREF_HANDLER struct { // OBJREF: (
        ('std',STDOBJREF),
        ('clsid',CLSID),
        ('saResAddr',':'),
    }
     func (self TYPE) __init__(data = nil,isNDR64 = false interface{}){
        OBJREF.__init__(self, data, isNDR64)
        if data == nil {
            self.flags = FLAGS_OBJREF_HANDLER

// 2.2.18.6 OBJREF_CUSTOM
 type OBJREF_CUSTOM struct { // OBJREF: (
        ('clsid',CLSID),
        ('cbExtension',ULONG),
        ('ObjectReferenceSize',ULONG),
        ('pObjectData',':'),
    }
     func (self TYPE) __init__(data = nil,isNDR64 = false interface{}){
        OBJREF.__init__(self, data, isNDR64)
        if data == nil {
            self.flags = FLAGS_OBJREF_CUSTOM

// 2.2.18.8 DATAELEMENT
 type DATAELEMENT struct { // NDRSTRUCT: (
        ('dataID',GUID),
        ('cbSize',ULONG),
        ('cbRounded',ULONG),
        ('Data',':'),
    }

 type DUALSTRINGARRAYPACKED struct { // NDRSTRUCT: (
        ('wNumEntries',USHORT),
        ('wSecurityOffset',USHORT),
        ('aStringArray',':'),
    }
     func (self TYPE) getDataLen(data interface{}){
        return self.wNumEntries*2

// 2.2.18.7 OBJREF_EXTENDED
 type OBJREF_EXTENDED struct { // OBJREF: (
        ('std',STDOBJREF),
        ('Signature1',ULONG),
        ('saResAddr',DUALSTRINGARRAYPACKED),
        ('nElms',ULONG),
        ('Signature2',ULONG),
        ('ElmArray',DATAELEMENT),
    }
     func (self TYPE) __init__(data = nil, isNDR64 = false interface{}){
        OBJREF.__init__(self, data, isNDR64)
        if data == nil {
            self.flags = FLAGS_OBJREF_EXTENDED
            self.Signature1 = 0x4E535956
            self.Signature1 = 0x4E535956
            self.nElms = 0x4E535956

// 2.2.19 DUALSTRINGARRAY
 type USHORT_ARRAY struct { // NDRUniConformantArray:
    item = "<H"

 type PUSHORT_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', USHORT_ARRAY),
    }

 type DUALSTRINGARRAY struct { // NDRSTRUCT: (
        ('wNumEntries',USHORT),
        ('wSecurityOffset',USHORT),
        ('aStringArray',USHORT_ARRAY),
    }

 type PDUALSTRINGARRAY struct { // NDRPOINTER:
    referent = (
        ('Data',DUALSTRINGARRAY),
    }

// 2.2.19.3 STRINGBINDING
 type STRINGBINDING struct { // NDRSTRUCT: (
        ('wTowerId',USHORT),
        ('aNetworkAddr',WIDESTR),
    }

// 2.2.19.4 SECURITYBINDING
 type SECURITYBINDING struct { // NDRSTRUCT: (
        ('wAuthnSvc',USHORT),
        ('Reserved',USHORT),
        ('aPrincName',WIDESTR),
    }

// 2.2.20.1 PROPMARSHALHEADER
 type PROPMARSHALHEADER struct { // NDRSTRUCT: (
        ('clsid',CLSID),
        ('policyId',GUID),
        ('flags',ULONG),
        ('cb',ULONG),
        ('ctxProperty',':'),
    }

 type PROPMARSHALHEADER_ARRAY struct { // NDRUniConformantArray:
    item = PROPMARSHALHEADER

// 2.2.20 Context
 type Context struct { // NDRSTRUCT: (
        ('MajorVersion',USHORT),
        ('MinVersion',USHORT),
        ('ContextId',GUID),
        ('Flags',ULONG),
        ('Reserved',ULONG),
        ('dwNumExtents',ULONG),
        ('cbExtents',ULONG),
        ('MshlFlags',ULONG),
        ('Count',ULONG),
        ('Frozen',ULONG),
        ('PropMarshalHeader',PROPMARSHALHEADER_ARRAY),
    }

// 2.2.21.3 ErrorInfoString
 type ErrorInfoString struct { // NDRSTRUCT: (
        ('dwMax',ULONG),
        ('dwOffSet',ULONG),
        ('dwActual',IID),
        ('Name',WSTR),
    }

// 2.2.21.2 Custom-Marshaled Error Information Format
 type ORPC_ERROR_INFORMATION struct { // NDRSTRUCT: (
        ('dwVersion',ULONG),
        ('dwHelpContext',ULONG),
        ('iid',IID),
        ('dwSourceSignature',ULONG),
        ('Source',ErrorInfoString),
        ('dwDescriptionSignature',ULONG),
        ('Description',ErrorInfoString),
        ('dwHelpFileSignature',ULONG),
        ('HelpFile',ErrorInfoString),
    }

// 2.2.21.5 EntryHeader
 type EntryHeader struct { // NDRSTRUCT: (
        ('Signature',ULONG),
        ('cbEHBuffer',ULONG),
        ('cbSize',ULONG),
        ('reserved',ULONG),
        ('policyID',GUID),
    }

 type EntryHeader_ARRAY struct { // NDRUniConformantArray:
    item = EntryHeader

// 2.2.21.4 Context ORPC Extension
 type ORPC_CONTEXT struct { // NDRSTRUCT: (
        ('SignatureVersion',ULONG),
        ('Version',ULONG),
        ('cPolicies',ULONG),
        ('cbBuffer',ULONG),
        ('cbSize',ULONG),
        ('hr',ULONG),
        ('hrServer',ULONG),
        ('reserved',ULONG),
        ('EntryHeader',EntryHeader_ARRAY),
        ('PolicyData',':'),
    }
     func (self TYPE) __init__(data = nil, isNDR64 = false interface{}){
        NDRSTRUCT.__init__(self, data, isNDR64)
        if data == nil {
            self.SignatureVersion = 0x414E554B

// 2.2.22.1 CustomHeader
 type CLSID_ARRAY struct { // NDRUniConformantArray:
    item = CLSID

 type PCLSID_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', CLSID_ARRAY),
    }

 type DWORD_ARRAY struct { // NDRUniConformantArray:
    item = DWORD

 type PDWORD_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', DWORD_ARRAY),
    }

 type CustomHeader struct { // TypeSerialization1: (
        ('totalSize',DWORD),
        ('headerSize',DWORD),
        ('dwReserved',DWORD),
        ('destCtx',DWORD),
        ('cIfs',DWORD),
        ('classInfoClsid',CLSID),
        ('pclsid',PCLSID_ARRAY),
        ('pSizes',PDWORD_ARRAY),
        ('pdwReserved',LPLONG),
        //('pdwReserved',LONG),
    }
     func (self TYPE) getData(soFar = 0 interface{}){
        self.headerSize = len(TypeSerialization1.getData(self, soFar)) + len(
            TypeSerialization1.getDataReferents(self, soFar))
        self.cIfs"] = len(self["pclsid)
        return TypeSerialization1.getData(self, soFar)

// 2.2.22 Activation Properties BLOB
 type ACTIVATION_BLOB struct { // NDRTLSTRUCT: (
        ('dwSize',ULONG),
        ('dwReserved',ULONG),
        ('CustomHeader',CustomHeader),
        ('Property',UNKNOWNDATA),
    }
     func (self TYPE) getData(soFar = 0 interface{}){
        self.dwSize"] = len(self["CustomHeader.getData(soFar)) + len(
            self.CustomHeader"].getDataReferents(soFar)) + len(self["Property)
        self.CustomHeader"]["totalSize"] = self["dwSize
        return NDRTLSTRUCT.getData(self)

// 2.2.22.2.1 InstantiationInfoData
 type IID_ARRAY struct { // NDRUniConformantArray:
    item = IID

 type PIID_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', IID_ARRAY),
    }

 type InstantiationInfoData struct { // TypeSerialization1: (
        ('classId',CLSID),
        ('classCtx',DWORD),
        ('actvflags',DWORD),
        ('fIsSurrogate',LONG),
        ('cIID',DWORD),
        ('instFlag',DWORD),
        ('pIID',PIID_ARRAY),
        ('thisSize',DWORD),
        ('clientCOMVersion',COMVERSION),
    }

// 2.2.22.2.2 SpecialPropertiesData
 type SpecialPropertiesData struct { // TypeSerialization1: (
        ('dwSessionId',ULONG),
        ('fRemoteThisSessionId',LONG),
        ('fClientImpersonating',LONG),
        ('fPartitionIDPresent',LONG),
        ('dwDefaultAuthnLvl',DWORD),
        ('guidPartition',GUID),
        ('dwPRTFlags',DWORD),
        ('dwOrigClsctx',DWORD),
        ('dwFlags',DWORD),
        ('Reserved0',DWORD),
        ('Reserved0',DWORD),
         Reserved [2]byte // =""
        //('Reserved1',DWORD),
        //('Reserved2',ULONGLONG),
        //('Reserved3_1',DWORD),
        //('Reserved3_2',DWORD),
        //('Reserved3_3',DWORD),
        //('Reserved3_4',DWORD),
        //('Reserved3_5',DWORD),
    }

// 2.2.22.2.3 InstanceInfoData
 type InstanceInfoData struct { // TypeSerialization1: (
        ('fileName',LPWSTR),
        ('mode',DWORD),
        ('ifdROT',PMInterfacePointer),
        ('ifdStg',PMInterfacePointer),
    }

// 2.2.22.2.4.1 customREMOTE_REQUEST_SCM_INFO
 type customREMOTE_REQUEST_SCM_INFO struct { // NDRSTRUCT: (
        ('ClientImpLevel',DWORD),
        ('cRequestedProtseqs',USHORT),
        ('pRequestedProtseqs',PUSHORT_ARRAY),
    }

 type PcustomREMOTE_REQUEST_SCM_INFO struct { // NDRPOINTER:
    referent = (
        ('Data', customREMOTE_REQUEST_SCM_INFO),
    }

// 2.2.22.2.4 ScmRequestInfoData
 type ScmRequestInfoData struct { // TypeSerialization1: (
        ('pdwReserved',LPLONG),
        ('remoteRequest',PcustomREMOTE_REQUEST_SCM_INFO),
    }

// 2.2.22.2.5 ActivationContextInfoData
 type ActivationContextInfoData struct { // TypeSerialization1: (
        ('clientOK',LONG),
        ('bReserved1',LONG),
        ('dwReserved1',DWORD),
        ('dwReserved2',DWORD),
        ('pIFDClientCtx',PMInterfacePointer),
        ('pIFDPrototypeCtx',PMInterfacePointer),
    }

// 2.2.22.2.6 LocationInfoData
 type LocationInfoData struct { // TypeSerialization1: (
        ('machineName',LPWSTR),
        ('processId',DWORD),
        ('apartmentId',DWORD),
        ('contextId',DWORD),
    }

// 2.2.22.2.7.1 COSERVERINFO
 type COSERVERINFO struct { // NDRSTRUCT: (
        ('dwReserved1',DWORD),
        ('pwszName',LPWSTR),
        ('pdwReserved',LPLONG),
        ('dwReserved2',DWORD),
    }

 type PCOSERVERINFO struct { // NDRPOINTER:
    referent = (
        ('Data', COSERVERINFO),
    }

// 2.2.22.2.7 SecurityInfoData
 type SecurityInfoData struct { // TypeSerialization1: (
        ('dwAuthnFlags',DWORD),
        ('pServerInfo',PCOSERVERINFO),
        ('pdwReserved',LPLONG),
    }

// 2.2.22.2.8.1 customREMOTE_REPLY_SCM_INFO
 type customREMOTE_REPLY_SCM_INFO struct { // NDRSTRUCT: (
        ('Oxid',OXID),
        ('pdsaOxidBindings',PDUALSTRINGARRAY),
        ('ipidRemUnknown',IPID),
        ('authnHint',DWORD),
        ('serverVersion',COMVERSION),
    }

 type PcustomREMOTE_REPLY_SCM_INFO struct { // NDRPOINTER:
    referent = (
        ('Data', customREMOTE_REPLY_SCM_INFO),
    }

// 2.2.22.2.8 ScmReplyInfoData
 type ScmReplyInfoData struct { // TypeSerialization1: (
        ('pdwReserved',DWORD),
        ('remoteReply',PcustomREMOTE_REPLY_SCM_INFO),
    }

// 2.2.22.2.9 PropsOutInfo
 type HRESULT_ARRAY struct { // NDRUniConformantArray:
    item = HRESULT

 type PHRESULT_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', HRESULT_ARRAY),
    }

 type MInterfacePointer_ARRAY struct { // NDRUniConformantArray:
    item = MInterfacePointer

 type PMInterfacePointer_ARRAY struct { // NDRUniConformantArray:
    item = PMInterfacePointer

 type PPMInterfacePointer_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', PMInterfacePointer_ARRAY),
    }

 type PropsOutInfo struct { // TypeSerialization1: (
        ('cIfs',DWORD),
        ('piid',PIID_ARRAY),
        ('phresults',PHRESULT_ARRAY),
        ('ppIntfData',PPMInterfacePointer_ARRAY),
    }

// 2.2.23 REMINTERFACEREF
 type REMINTERFACEREF struct { // NDRSTRUCT: (
        ('ipid',IPID),
        ('cPublicRefs',LONG),
        ('cPrivateRefs',LONG),
    }

 type REMINTERFACEREF_ARRAY struct { // NDRUniConformantArray:
    item = REMINTERFACEREF

// 2.2.24 REMQIRESULT
 type REMQIRESULT struct { // NDRSTRUCT: (
        ('hResult',HRESULT),
        ('std',STDOBJREF),
    }

// 2.2.25 PREMQIRESULT
 type PREMQIRESULT struct { // NDRPOINTER:
    referent = (
        ('Data', REMQIRESULT),
    }

// 2.2.26 REFIPID
REFIPID = GUID

//###############################################################################
// RPC CALLS
//###############################################################################
 type DCOMCALL struct { // NDRCALL:
    commonHdr = (
       ('ORPCthis', ORPCTHIS),
    }

 type DCOMANSWER struct { // NDRCALL:
    commonHdr = (
       ('ORPCthat', ORPCTHAT),
    }

// 3.1.2.5.1.1 IObjectExporter::ResolveOxid (Opnum 0)
 type ResolveOxid struct { // NDRCALL:
    opnum = 0 (
       ('pOxid', OXID),
       ('cRequestedProtseqs', USHORT),
       ('arRequestedProtseqs', USHORT_ARRAY),
    }

 type ResolveOxidResponse struct { // NDRCALL: (
       ('ppdsaOxidBindings', PDUALSTRINGARRAY),
       ('pipidRemUnknown', IPID),
       ('pAuthnHint', DWORD),
       ('ErrorCode', error_status_t),
    }

// 3.1.2.5.1.2 IObjectExporter::SimplePing (Opnum 1)
 type SimplePing struct { // NDRCALL:
    opnum = 1 (
       ('pSetId', SETID),
    }

 type SimplePingResponse struct { // NDRCALL: (
       ('ErrorCode', error_status_t),
    }

// 3.1.2.5.1.3 IObjectExporter::ComplexPing (Opnum 2)
 type ComplexPing struct { // NDRCALL:
    opnum = 2 (
       ('pSetId', SETID),
       ('SequenceNum', USHORT),
       ('cAddToSet', USHORT),
       ('cDelFromSet', USHORT),
       ('AddToSet', POID_ARRAY),
       ('DelFromSet', POID_ARRAY),
    }

 type ComplexPingResponse struct { // NDRCALL: (
       ('pSetId', SETID),
       ('pPingBackoffFactor', USHORT),
       ('ErrorCode', error_status_t),
    }

// 3.1.2.5.1.4 IObjectExporter::ServerAlive (Opnum 3)
 type ServerAlive struct { // NDRCALL:
    opnum = 3 (
    }

 type ServerAliveResponse struct { // NDRCALL: (
       ('ErrorCode', error_status_t),
    }

// 3.1.2.5.1.5 IObjectExporter::ResolveOxid2 (Opnum 4)
 type ResolveOxid2 struct { // NDRCALL:
    opnum = 4 (
       ('pOxid', OXID),
       ('cRequestedProtseqs', USHORT),
       ('arRequestedProtseqs', USHORT_ARRAY),
    }

 type ResolveOxid2Response struct { // NDRCALL: (
       ('ppdsaOxidBindings', PDUALSTRINGARRAY),
       ('pipidRemUnknown', IPID),
       ('pAuthnHint', DWORD),
       ('pComVersion', COMVERSION),
       ('ErrorCode', error_status_t),
    }

// 3.1.2.5.1.6 IObjectExporter::ServerAlive2 (Opnum 5)
 type ServerAlive2 struct { // NDRCALL:
    opnum = 5 (
    }

 type ServerAlive2Response struct { // NDRCALL: (
       ('pComVersion', COMVERSION),
       ('ppdsaOrBindings', PDUALSTRINGARRAY),
       ('pReserved', LPLONG),
       ('ErrorCode', error_status_t),
    }

// 3.1.2.5.2.3.1 IActivation:: RemoteActivation (Opnum 0)
 type RemoteActivation struct { // NDRCALL:
    opnum = 0 (
       ('ORPCthis', ORPCTHIS),
       ('Clsid', GUID),
       ('pwszObjectName', LPWSTR),
       ('pObjectStorage', PMInterfacePointer),
       ('ClientImpLevel', DWORD),
       ('Mode', DWORD),
       ('Interfaces', DWORD),
       ('pIIDs', PIID_ARRAY),
       ('cRequestedProtseqs', USHORT),
       ('aRequestedProtseqs', USHORT_ARRAY),
    }

 type RemoteActivationResponse struct { // NDRCALL: (
       ('ORPCthat', ORPCTHAT),
       ('pOxid', OXID),
       ('ppdsaOxidBindings', PDUALSTRINGARRAY),
       ('pipidRemUnknown', IPID),
       ('pAuthnHint', DWORD),
       ('pServerVersion', COMVERSION),
       ('phr', HRESULT),
       ('ppInterfaceData', PMInterfacePointer_ARRAY),
       ('pResults', HRESULT_ARRAY),
       ('ErrorCode', error_status_t),
    }

// 3.1.2.5.2.3.2 IRemoteSCMActivator:: RemoteGetClassObject (Opnum 3)
 type RemoteGetClassObject struct { // NDRCALL:
    opnum = 3 (
       ('ORPCthis', ORPCTHIS),
       ('pActProperties', PMInterfacePointer),
    }

 type RemoteGetClassObjectResponse struct { // NDRCALL: (
       ('ORPCthat', ORPCTHAT),
       ('ppActProperties', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.2.5.2.3.3 IRemoteSCMActivator::RemoteCreateInstance (Opnum 4)
 type RemoteCreateInstance struct { // NDRCALL:
    opnum = 4 (
       ('ORPCthis', ORPCTHIS),
       ('pUnkOuter', PMInterfacePointer),
       ('pActProperties', PMInterfacePointer),
    }

 type RemoteCreateInstanceResponse struct { // NDRCALL: (
       ('ORPCthat', ORPCTHAT),
       ('ppActProperties', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.1.5.6.1.1 IRemUnknown::RemQueryInterface (Opnum 3)
 type RemQueryInterface struct { // DCOMCALL:
    opnum = 3 (
       ('ripid', REFIPID),
       ('cRefs', ULONG),
       ('cIids', USHORT),
       ('iids', IID_ARRAY),
    }

 type RemQueryInterfaceResponse struct { // DCOMANSWER: (
       ('ppQIResults', PREMQIRESULT),
       ('ErrorCode', error_status_t),
    }

// 3.1.1.5.6.1.2 IRemUnknown::RemAddRef (Opnum 4 )
 type RemAddRef struct { // DCOMCALL:
    opnum = 4 (
       ('cInterfaceRefs', USHORT),
       ('InterfaceRefs', REMINTERFACEREF_ARRAY),
    }

 type RemAddRefResponse struct { // DCOMANSWER: (
       ('pResults', DWORD_ARRAY),
       ('ErrorCode', error_status_t),
    }

// 3.1.1.5.6.1.3 IRemUnknown::RemRelease (Opnum 5)
 type RemRelease struct { // DCOMCALL:
    opnum = 5 (
       ('cInterfaceRefs', USHORT),
       ('InterfaceRefs', REMINTERFACEREF_ARRAY),
    }

 type RemReleaseResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

//###############################################################################
// OPNUMs and their corresponding structures
//###############################################################################
OPNUMS = {
}

//###############################################################################
// HELPER FUNCTIONS
//###############################################################################
 type DCOMConnection: struct {
    """
    This  type represents a DCOM Connection. It is in charge of establishing the  struct {
    DCE connection against the portmap, and then launch a thread that will be 
    pinging the objects created against the target.
    In theory, there should be a single instance of this  type for every target struct {
    """
    PINGTIMER = nil
    OID_ADD = {}
    OID_DEL = {}
    OID_SET = {}
    PORTMAPS = {}

    def __init__(self, target, username='', password='', domain='', lmhash='', nthash='', aesKey='', TGT=nil, TGS=nil,
                 authLevel=RPC_C_AUTHN_LEVEL_PKT_PRIVACY, oxidResolver=false, doKerberos=false, kdcHost=nil):
        self.__target = target
        self.__userName = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = lmhash
        self.__nthash = nthash
        self.__aesKey = aesKey
        self.__TGT    = TGT
        self.__TGS    = TGS
        self.__authLevel = authLevel
        self.__portmap = nil
        self.__oxidResolver = oxidResolver
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.initConnection()

    @classmethod
     func addOid(cls, target, oid interface{}){
        if (target in DCOMConnection.OID_ADD) is false {
            DCOMConnection.OID_ADD[target] = set()
        DCOMConnection.OID_ADD[target].add(oid)
        if (target in DCOMConnection.OID_SET) is false {
            DCOMConnection.OID_SET[target] = {}
            DCOMConnection.OID_SET[target]["oids"] = set()
            DCOMConnection.OID_SET[target]["setid"] = 0

    @classmethod
     func delOid(cls, target, oid interface{}){
        if (target in DCOMConnection.OID_DEL) is false {
            DCOMConnection.OID_DEL[target] = set()
        DCOMConnection.OID_DEL[target].add(oid)
        if (target in DCOMConnection.OID_SET) is false {
            DCOMConnection.OID_SET[target] = {}
            DCOMConnection.OID_SET[target]["oids"] = set()
            DCOMConnection.OID_SET[target]["setid"] = 0

    @classmethod
     func pingServer(cls interface{}){
        // Here we need to go through all the objects opened and ping them.
        // ToDo: locking for avoiding race conditions
        //print DCOMConnection.PORTMAPS
        //print DCOMConnection.OID_SET
        try:
            for target in DCOMConnection.OID_SET:
                addedOids = set()
                deletedOids = set()
                if target in DCOMConnection.OID_ADD {
                    addedOids = DCOMConnection.OID_ADD[target]
                    del(DCOMConnection.OID_ADD[target])

                if target in DCOMConnection.OID_DEL {
                    deletedOids = DCOMConnection.OID_DEL[target]
                    del(DCOMConnection.OID_DEL[target])

                objExporter = IObjectExporter(DCOMConnection.PORTMAPS[target])

                if len(addedOids) > 0 or len(deletedOids) > 0 {
                    if 'setid' in DCOMConnection.OID_SET[target] {
                        setId = DCOMConnection.OID_SET[target]["setid"]
                    } else  {
                        setId = 0
                    resp = objExporter.ComplexPing(setId, 0, addedOids, deletedOids)
                    DCOMConnection.OID_SET[target]["oids"] -= deletedOids
                    DCOMConnection.OID_SET[target]["oids"] |= addedOids
                    DCOMConnection.OID_SET[target]["setid"] = resp["pSetId"]
                } else  {
                    objExporter.SimplePing(DCOMConnection.OID_SET[target]["setid"])
        except Exception as e:
            // There might be exceptions when sending packets 
            // We should try to continue tho.
            LOG.error(str(e))
            pass

        DCOMConnection.PINGTIMER = Timer(120,DCOMConnection.pingServer)
        try:
            DCOMConnection.PINGTIMER.start()
        except Exception as e:
            if str(e).find("threads can only be started once") < 0 {
                raise e

     func (self TYPE) initTimer(){
        if self.__oxidResolver is true {
            if DCOMConnection.PINGTIMER == nil {
                DCOMConnection.PINGTIMER = Timer(120, DCOMConnection.pingServer)
            try:
                DCOMConnection.PINGTIMER.start()
            except Exception as e:
                if str(e).find("threads can only be started once") < 0 {
                    raise e

     func (self TYPE) initConnection(){
        stringBinding = r'ncacn_ip_tcp:%s' % self.__target
        rpctransport = transport.DCERPCTransportFactory(stringBinding)

        if hasattr(rpctransport, 'set_credentials') and len(self.__userName) >=0 {
            // This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__userName, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                         self.__aesKey, self.__TGT, self.__TGS)
            rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
        self.__portmap = rpctransport.get_dce_rpc()
        self.__portmap.set_auth_level(self.__authLevel)
        if self.__doKerberos is true {
            self.__portmap.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        self.__portmap.connect()
        DCOMConnection.PORTMAPS[self.__target] = self.__portmap

     func (self TYPE) CoCreateInstanceEx(clsid, iid interface{}){
        scm = IRemoteSCMActivator(self.__portmap)
        iInterface = scm.RemoteCreateInstance(clsid, iid)
        self.initTimer()
        return iInterface

     func (self TYPE) get_dce_rpc(){
        return DCOMConnection.PORTMAPS[self.__target]

     func (self TYPE) disconnect(){
        if DCOMConnection.PINGTIMER is not nil {
            del(DCOMConnection.PORTMAPS[self.__target])
            del(DCOMConnection.OID_SET[self.__target])
            if len(DCOMConnection.PORTMAPS) == 0 {
                // This means there are no more clients using this object, kill it
                DCOMConnection.PINGTIMER.cancel()
                DCOMConnection.PINGTIMER.join()
                DCOMConnection.PINGTIMER = nil
        if self.__target in INTERFACE.CONNECTIONS {
            del(INTERFACE.CONNECTIONS[self.__target][currentThread().getName()])
        self.__portmap.disconnect()
        //print INTERFACE.CONNECTIONS

 type CLASS_INSTANCE: struct {
     func (self TYPE) __init__(ORPCthis, stringBinding interface{}){
        self.__stringBindings = stringBinding
        self.__ORPCthis = ORPCthis
        self.__authType = RPC_C_AUTHN_WINNT
        self.__authLevel = RPC_C_AUTHN_LEVEL_PKT_PRIVACY
     func (self TYPE) get_ORPCthis(){
        return self.__ORPCthis
     func (self TYPE) get_string_bindings(){
        return self.__stringBindings
     func (self TYPE) get_auth_level(){
        if RPC_C_AUTHN_LEVEL_NONE < self.__authLevel < RPC_C_AUTHN_LEVEL_PKT_PRIVACY {
            if self.__authType == RPC_C_AUTHN_WINNT {
                return RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
            } else  {
                return RPC_C_AUTHN_LEVEL_PKT_PRIVACY
        return self.__authLevel
     func (self TYPE) set_auth_level(level interface{}){
        self.__authLevel = level
     func (self TYPE) get_auth_type(){
        return self.__authType
     func (self TYPE) set_auth_type(authType interface{}){
        self.__authType = authType


 type INTERFACE: struct {
    //  type variable holding the transport connections, organized by target IP struct {
    CONNECTIONS = {}

    def __init__(self, cinstance=nil, objRef=nil, ipidRemUnknown=nil, iPid=nil, oxid=nil, oid=nil, target=nil,
                 interfaceInstance=nil):
        if interfaceInstance is not nil {
            self.__target = interfaceInstance.get_target()
            self.__iPid = interfaceInstance.get_iPid()
            self.__oid  = interfaceInstance.get_oid()
            self.__oxid = interfaceInstance.get_oxid()
            self.__cinstance = interfaceInstance.get_cinstance()
            self.__objRef = interfaceInstance.get_objRef()
            self.__ipidRemUnknown = interfaceInstance.get_ipidRemUnknown()
        } else  {
            if target == nil {
                raise Exception("No target")
            self.__target = target
            self.__iPid = iPid
            self.__oid  = oid
            self.__oxid = oxid
            self.__cinstance = cinstance
            self.__objRef = objRef
            self.__ipidRemUnknown = ipidRemUnknown
            // We gotta check if we have a container inside our connection list, if not, create
            if (self.__target in INTERFACE.CONNECTIONS) is not true {
                INTERFACE.CONNECTIONS[self.__target] = {}
                INTERFACE.CONNECTIONS[self.__target][currentThread().getName()] = {}

            if objRef is not nil {
                self.process_interface(objRef)

     func (self TYPE) process_interface(data interface{}){
        objRefType = OBJREF(data)["flags"]
        objRef = nil
        if objRefType == FLAGS_OBJREF_CUSTOM {
            objRef = OBJREF_CUSTOM(data)
        elif objRefType == FLAGS_OBJREF_HANDLER {
            objRef = OBJREF_HANDLER(data)
        elif objRefType == FLAGS_OBJREF_STANDARD {
            objRef = OBJREF_STANDARD(data)
        elif objRefType == FLAGS_OBJREF_EXTENDED {
            objRef = OBJREF_EXTENDED(data)
        } else  {
            LOG.error("Unknown OBJREF Type! 0x%x" % objRefType)

        if objRefType != FLAGS_OBJREF_CUSTOM {
            if objRef["std"]["flags"] & SORF_NOPING == 0 {
                DCOMConnection.addOid(self.__target, objRef["std"]["oid"])
            self.__iPid = objRef["std"]["ipid"]
            self.__oid  = objRef["std"]["oid"]
            self.__oxid = objRef["std"]["oxid"]
            if self.__oxid == nil {
                objRef.dump()
                raise Exception("OXID == nil")

     func (self TYPE) get_oxid(){
        return self.__oxid

     func (self TYPE) set_oxid(oxid interface{}){
        self.__oxid = oxid

     func (self TYPE) get_oid(){
        return self.__oid

     func (self TYPE) set_oid(oid interface{}){
        self.__oid = oid

     func (self TYPE) get_target(){
        return self.__target

     func (self TYPE) get_iPid(){
        return self.__iPid

     func (self TYPE) set_iPid(iPid interface{}){
        self.__iPid = iPid

     func (self TYPE) get_objRef(){
        return self.__objRef

     func (self TYPE) set_objRef(objRef interface{}){
        self.__objRef = objRef

     func (self TYPE) get_ipidRemUnknown(){
        return self.__ipidRemUnknown

     func (self TYPE) get_dce_rpc(){
        return INTERFACE.CONNECTIONS[self.__target][currentThread().getName()][self.__oxid]["dce"]

     func (self TYPE) get_cinstance(){
        return self.__cinstance

     func (self TYPE) set_cinstance(cinstance interface{}){
        self.__cinstance = cinstance

     func (self TYPE) is_fdqn(){
        // I will assume the following
        // If I can't socket.inet_aton() then it's not an IPv4 address
        // Same for ipv6, but since socket.inet_pton is not available in Windows, I'll look for ':'. There can't be
        // an FQDN with ':'
        // Is it isn't both, then it is a FDQN
        try:
            socket.inet_aton(self.__target)
        except:
            // Not an IPv4
            try:
                self.__target.index(":")
            except:
                // Not an IPv6, it's a FDQN
                return true
        return false


     func (self TYPE) connect(iid = nil interface{}){
        if (self.__target in INTERFACE.CONNECTIONS) is true {
            if currentThread().getName() in INTERFACE.CONNECTIONS[self.__target] and \
                            (self.__oxid in INTERFACE.CONNECTIONS[self.__target][currentThread().getName()]) is true:
                dce = INTERFACE.CONNECTIONS[self.__target][currentThread().getName()][self.__oxid]["dce"]
                currentBinding = INTERFACE.CONNECTIONS[self.__target][currentThread().getName()][self.__oxid]["currentBinding"]
                if currentBinding == iid {
                    // We don't need to alter_ctx
                    pass
                } else  {
                    newDce = dce.alter_ctx(iid)
                    INTERFACE.CONNECTIONS[self.__target][currentThread().getName()][self.__oxid]["dce"] = newDce
                    INTERFACE.CONNECTIONS[self.__target][currentThread().getName()][self.__oxid]["currentBinding"] = iid
            } else  {
                stringBindings = self.get_cinstance().get_string_bindings()
                // No OXID present, we should create a new connection and store it
                stringBinding = nil
                isTargetFDQN = self.is_fdqn()
                LOG.debug('Target system is %s and isFDQN is %s' % (self.get_target(), isTargetFDQN))
                for strBinding in stringBindings:
                    // Here, depending on the get_target() value several things can happen
                    // 1) it's an IPv4 address
                    // 2) it's an IPv6 address
                    // 3) it's a NetBios Name
                    // we should handle all this cases accordingly
                    // Does this match exactly what get_target() returns?
                    LOG.debug('StringBinding: %s' % strBinding["aNetworkAddr"])
                    if strBinding["wTowerId"] == 7 {
                        // If there's port information, let's strip it for now.
                        if strBinding["aNetworkAddr"].find("[") >= 0 {
                            binding, _, bindingPort = strBinding["aNetworkAddr"].partition("[")
                            bindingPort = "[" + bindingPort
                        } else  {
                            binding = strBinding["aNetworkAddr"]
                            bindingPort = ""

                        if binding.upper().find(self.get_target().upper()) >= 0 {
                            stringBinding = "ncacn_ip_tcp:" + strBinding["aNetworkAddr"][:-1]
                            break
                        // If get_target() is a FQDN, does it match the hostname?
                        elif isTargetFDQN and binding.upper().find(self.get_target().upper().partition(".")[0]) >= 0 {
                            // Here we replace the aNetworkAddr with self.get_target()
                            // This is to help resolving the target system name.
                            // self.get_target() has been resolved already otherwise we wouldn't be here whereas
                            // aNetworkAddr is usually the NetBIOS name and unless you have your DNS resolver
                            // with the right suffixes it will probably not resolve right.
                            stringBinding = "ncacn_ip_tcp:%s%s" % (self.get_target(), bindingPort)
                            break

                LOG.debug('StringBinding chosen: %s' % stringBinding)
                if stringBinding == nil {
                    // Something wen't wrong, let's just report it
                    raise Exception('Can\'t find a valid stringBinding to connect')

                dcomInterface = transport.DCERPCTransportFactory(stringBinding)
                if hasattr(dcomInterface, 'set_credentials') {
                    // This method exists only for selected protocol sequences.
                    dcomInterface.set_credentials(*DCOMConnection.PORTMAPS[self.__target].get_credentials())
                    dcomInterface.set_kerberos(DCOMConnection.PORTMAPS[self.__target].get_rpc_transport().get_kerberos(),
                                               DCOMConnection.PORTMAPS[self.__target].get_rpc_transport().get_kdcHost())
                dcomInterface.set_connect_timeout(300)
                dce = dcomInterface.get_dce_rpc()

                if iid == nil {
                    raise Exception("IID == nil")
                } else  {
                    dce.set_auth_level(self.__cinstance.get_auth_level())
                    dce.set_auth_type(self.__cinstance.get_auth_type())

                dce.connect()

                if iid == nil {
                    raise Exception("IID == nil")
                } else  {
                    dce.bind(iid)

                if self.__oxid == nil {
                    //import traceback
                    //traceback.print_stack()
                    raise Exception("OXID NONE, something wrong!!!")

                INTERFACE.CONNECTIONS[self.__target][currentThread().getName()] = {}
                INTERFACE.CONNECTIONS[self.__target][currentThread().getName()][self.__oxid] = {}
                INTERFACE.CONNECTIONS[self.__target][currentThread().getName()][self.__oxid]["dce"] = dce
                INTERFACE.CONNECTIONS[self.__target][currentThread().getName()][self.__oxid]["currentBinding"] = iid
        } else  {
            // No connection created
            raise Exception("No connection created")

     func (self TYPE) request(req, iid = nil, uuid = nil interface{}){
        req["ORPCthis"] = self.get_cinstance().get_ORPCthis()
        req["ORPCthis"]["flags"] = 0
        self.connect(iid)
        dce = self.get_dce_rpc()
        try:
            resp = dce.request(req, uuid)
        except Exception as e:
            if str(e).find("RPC_E_DISCONNECTED") >= 0 {
                msg = str(e) + '\n'
                msg += "DCOM keep-alive pinging it might not be working as expected. You can't be idle for more than 14 minutes!\n"
                msg += "You should exit the app and start again\n"
                raise DCERPCException(msg)
            } else  {
                raise
        return resp

     func (self TYPE) disconnect(){
        return INTERFACE.CONNECTIONS[self.__target][currentThread().getName()][self.__oxid]["dce"].disconnect()


// 3.1.1.5.6.1 IRemUnknown Methods
 type IRemUnknown struct { // INTERFACE:
     func (self TYPE) __init__(interface interface{}){
        self._iid = IID_IRemUnknown
        //INTERFACE.__init__(self, interface.get_cinstance(), interface.get_objRef(), interface.get_ipidRemUnknown(),
        //                   interface.get_iPid(), target=interface.get_target())
        INTERFACE.__init__(self, interfaceInstance=interface)
        self.set_oxid(interface.get_oxid())

     func (self TYPE) RemQueryInterface(cRefs, iids interface{}){
        // For now, it only supports a single IID
        request = RemQueryInterface()
        request["ORPCthis"] = self.get_cinstance().get_ORPCthis()
        request["ORPCthis"]["flags"] = 0
        request["ripid"] = self.get_iPid()
        request["cRefs"] = cRefs
        request["cIids"] = len(iids)
        for iid in iids:
            _iid = IID()
            _iid["Data"] = iid
            request["iids"].append(_iid)
        resp = self.request(request, IID_IRemUnknown, self.get_ipidRemUnknown())
        //resp.dump()

        return IRemUnknown2(
            INTERFACE(self.get_cinstance(), nil, self.get_ipidRemUnknown(), resp["ppQIResults"]["std"]["ipid"],
                      oxid=resp["ppQIResults"]["std"]["oxid"], oid=resp["ppQIResults"]["std"]["oxid"],
                      target=self.get_target()))

     func (self TYPE) RemAddRef(){
        request = RemAddRef()
        request["ORPCthis"] = self.get_cinstance().get_ORPCthis()
        request["ORPCthis"]["flags"] = 0
        request["cInterfaceRefs"] = 1
        element = REMINTERFACEREF()
        element["ipid"] = self.get_iPid()
        element["cPublicRefs"] = 1
        request["InterfaceRefs"].append(element)
        resp = self.request(request, IID_IRemUnknown, self.get_ipidRemUnknown())
        return resp

     func (self TYPE) RemRelease(){
        request = RemRelease()
        request["ORPCthis"] = self.get_cinstance().get_ORPCthis()
        request["ORPCthis"]["flags"] = 0
        request["cInterfaceRefs"] = 1
        element = REMINTERFACEREF()
        element["ipid"] = self.get_iPid()
        element["cPublicRefs"] = 1
        request["InterfaceRefs"].append(element)
        resp = self.request(request, IID_IRemUnknown, self.get_ipidRemUnknown())
        DCOMConnection.delOid(self.get_target(), self.get_oid())
        return resp

// 3.1.1.5.7 IRemUnknown2 Interface
 type IRemUnknown2 struct { // IRemUnknown:
     func (self TYPE) __init__(interface interface{}){
        IRemUnknown.__init__(self, interface)
        self._iid = IID_IRemUnknown2

// 3.1.2.5.1 IObjectExporter Methods
 type IObjectExporter: struct {
     func (self TYPE) __init__(dce interface{}){
        self.__portmap = dce

    // 3.1.2.5.1.1 IObjectExporter::ResolveOxid (Opnum 0)
     func (self TYPE) ResolveOxid(pOxid, arRequestedProtseqs interface{}){
        self.__portmap.connect()
        self.__portmap.bind(IID_IObjectExporter)
        request = ResolveOxid()
        request["pOxid"] = pOxid
        request["cRequestedProtseqs"] = len(arRequestedProtseqs)
        for protSeq in arRequestedProtseqs:
            request["arRequestedProtseqs"].append(protSeq)
        resp = self.__portmap.request(request)
        Oxids = b''.join(pack('<H', x) for x in resp["ppdsaOxidBindings"]["aStringArray"])
        strBindings = Oxids[:resp["ppdsaOxidBindings"]["wSecurityOffset"]*2]

        done = false
        stringBindings = list()
        while not done:
            if strBindings[0:1] == b'\x00' and strBindings[1:2] == b'\x00' {
                done = true
            } else  {
                binding = STRINGBINDING(strBindings)
                stringBindings.append(binding)
                strBindings = strBindings[len(binding):]

        return stringBindings

    // 3.1.2.5.1.2 IObjectExporter::SimplePing (Opnum 1)
     func (self TYPE) SimplePing(setId interface{}){
        self.__portmap.connect()
        self.__portmap.bind(IID_IObjectExporter)
        request = SimplePing()
        request["pSetId"] = setId
        resp = self.__portmap.request(request)
        return resp

    // 3.1.2.5.1.3 IObjectExporter::ComplexPing (Opnum 2)
     func (self TYPE) ComplexPing(setId = 0, sequenceNum = 0, addToSet = [], delFromSet = [] interface{}){
        self.__portmap.connect()
        //self.__portmap.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        self.__portmap.bind(IID_IObjectExporter)
        request = ComplexPing()
        request["pSetId"] = setId
        request["SequenceNum"] = setId
        request["cAddToSet"] = len(addToSet)
        request["cDelFromSet"] = len(delFromSet)
        if len(addToSet) > 0 {
            for oid in addToSet:
                oidn = OID()
                oidn["Data"] = oid
                request["AddToSet"].append(oidn)
        } else  {
            request["AddToSet"] = NULL

        if len(delFromSet) > 0 {
            for oid in delFromSet:
                oidn = OID()
                oidn["Data"] = oid
                request["DelFromSet"].append(oidn)
        } else  {
            request["DelFromSet"] = NULL
        resp = self.__portmap.request(request)
        return resp

    // 3.1.2.5.1.4 IObjectExporter::ServerAlive (Opnum 3)
     func (self TYPE) ServerAlive(){
        self.__portmap.connect()
        self.__portmap.bind(IID_IObjectExporter)
        request = ServerAlive()
        resp = self.__portmap.request(request)
        return resp

    // 3.1.2.5.1.5 IObjectExporter::ResolveOxid2 (Opnum 4)
     func ResolveOxid2(self,pOxid, arRequestedProtseqs interface{}){
        self.__portmap.connect()
        self.__portmap.bind(IID_IObjectExporter)
        request = ResolveOxid2()
        request["pOxid"] = pOxid
        request["cRequestedProtseqs"] = len(arRequestedProtseqs)
        for protSeq in arRequestedProtseqs:
            request["arRequestedProtseqs"].append(protSeq)
        resp = self.__portmap.request(request)
        Oxids = b''.join(pack('<H', x) for x in resp["ppdsaOxidBindings"]["aStringArray"])
        strBindings = Oxids[:resp["ppdsaOxidBindings"]["wSecurityOffset"]*2]

        done = false
        stringBindings = list()
        while not done:
            if strBindings[0:1] == b'\x00' and strBindings[1:2] == b'\x00' {
                done = true
            } else  {
                binding = STRINGBINDING(strBindings)
                stringBindings.append(binding)
                strBindings = strBindings[len(binding):]

        return stringBindings

    // 3.1.2.5.1.6 IObjectExporter::ServerAlive2 (Opnum 5)
     func (self TYPE) ServerAlive2(){
        self.__portmap.connect()
        self.__portmap.bind(IID_IObjectExporter)
        request = ServerAlive2()
        resp = self.__portmap.request(request)

        Oxids = b''.join(pack('<H', x) for x in resp["ppdsaOrBindings"]["aStringArray"])
        strBindings = Oxids[:resp["ppdsaOrBindings"]["wSecurityOffset"]*2]

        done = false
        stringBindings = list()
        while not done:
            if strBindings[0:1] == b'\x00' and strBindings[1:2] == b'\x00' {
                done = true
            } else  {
                binding = STRINGBINDING(strBindings)
                stringBindings.append(binding)
                strBindings = strBindings[len(binding):]

        return stringBindings

// 3.1.2.5.2.1 IActivation Methods
 type IActivation: struct {
     func (self TYPE) __init__(dce interface{}){
        self.__portmap = dce

    // 3.1.2.5.2.3.1 IActivation:: RemoteActivation (Opnum 0)
     func (self TYPE) RemoteActivation(clsId, iid interface{}){
        // Only supports one interface at a time
        self.__portmap.bind(IID_IActivation)
        ORPCthis = ORPCTHIS()
        ORPCthis["cid"] = generate()
        ORPCthis["extensions"] = NULL
        ORPCthis["flags"] = 1

        request = RemoteActivation()
        request["Clsid"] = clsId
        request["pwszObjectName"] = NULL
        request["pObjectStorage"] = NULL
        request["ClientImpLevel"] = 2
        request["Mode"] = 0
        request["Interfaces"] = 1

        _iid = IID()
        _iid["Data"] = iid

        request["pIIDs"].append(_iid)
        request["cRequestedProtseqs"] = 1
        request["aRequestedProtseqs"].append(7)

        resp = self.__portmap.request(request)

        // Now let's parse the answer and build an Interface instance

        ipidRemUnknown = resp["pipidRemUnknown"]

        Oxids = b''.join(pack('<H', x) for x in resp["ppdsaOxidBindings"]["aStringArray"])
        strBindings = Oxids[:resp["ppdsaOxidBindings"]["wSecurityOffset"]*2]
        securityBindings = Oxids[resp["ppdsaOxidBindings"]["wSecurityOffset"]*2:]

        done = false
        stringBindings = list()
        while not done:
            if strBindings[0:1] == b'\x00' and strBindings[1:2] == b'\x00' {
                done = true
            } else  {
                binding = STRINGBINDING(strBindings)
                stringBindings.append(binding)
                strBindings = strBindings[len(binding):]

        done = false
        while not done:
            if len(securityBindings) < 2 {
                done = true
            } else if securityBindings[0:1] == b'\x00' and securityBindings[1 {2 ]== b'\x00' {
                done = true
            } else  {
                secBinding = SECURITYBINDING(securityBindings)
                securityBindings = securityBindings[len(secBinding):]

        classInstance = CLASS_INSTANCE(ORPCthis, stringBindings)
        return IRemUnknown2(INTERFACE(classInstance, b''.join(resp["ppInterfaceData"][0]["abData"]), ipidRemUnknown,
                                      target=self.__portmap.get_rpc_transport().getRemoteHost()))


// 3.1.2.5.2.2 IRemoteSCMActivator Methods
 type IRemoteSCMActivator: struct {
     func (self TYPE) __init__(dce interface{}){
        self.__portmap = dce

     func (self TYPE) RemoteGetClassObject(clsId, iid interface{}){
        //  iid should be IID_IClassFactory
        self.__portmap.bind(IID_IRemoteSCMActivator)
        ORPCthis = ORPCTHIS()
        ORPCthis["cid"] = generate()
        ORPCthis["extensions"] = NULL
        ORPCthis["flags"] = 1

        request = RemoteGetClassObject()
        request["ORPCthis"] = ORPCthis
        activationBLOB = ACTIVATION_BLOB()
        activationBLOB["CustomHeader"]["destCtx"] = 2
        activationBLOB["CustomHeader"]["pdwReserved"] = NULL
        clsid = CLSID()
        clsid["Data"] = CLSID_InstantiationInfo
        activationBLOB["CustomHeader"]["pclsid"].append(clsid)
        clsid = CLSID()
        clsid["Data"] = CLSID_ActivationContextInfo
        activationBLOB["CustomHeader"]["pclsid"].append(clsid)
        clsid = CLSID()
        clsid["Data"] = CLSID_ServerLocationInfo
        activationBLOB["CustomHeader"]["pclsid"].append(clsid)
        clsid = CLSID()
        clsid["Data"] = CLSID_ScmRequestInfo
        activationBLOB["CustomHeader"]["pclsid"].append(clsid)

        properties = b''
        // InstantiationInfo
        instantiationInfo = InstantiationInfoData()
        instantiationInfo["classId"] = clsId
        instantiationInfo["cIID"] = 1

        _iid = IID()
        _iid["Data"] = iid

        instantiationInfo["pIID"].append(_iid)

        dword = DWORD()
        marshaled = instantiationInfo.getData()+instantiationInfo.getDataReferents()
        pad = (8 - (len(marshaled) % 8)) % 8
        dword["Data"] = len(marshaled) + pad
        activationBLOB["CustomHeader"]["pSizes"].append(dword)
        instantiationInfo["thisSize"] = dword["Data"]

        properties += marshaled + b'\xFA'*pad

        // ActivationContextInfoData
        activationInfo = ActivationContextInfoData()
        activationInfo["pIFDClientCtx"] = NULL
        activationInfo["pIFDPrototypeCtx"] = NULL

        dword = DWORD()
        marshaled = activationInfo.getData()+activationInfo.getDataReferents()
        pad = (8 - (len(marshaled) % 8)) % 8
        dword["Data"] = len(marshaled) + pad
        activationBLOB["CustomHeader"]["pSizes"].append(dword)

        properties += marshaled + b'\xFA'*pad

        // ServerLocation
        locationInfo = LocationInfoData()
        locationInfo["machineName"] = NULL

        dword = DWORD()
        dword["Data"] = len(locationInfo.getData())
        activationBLOB["CustomHeader"]["pSizes"].append(dword)

        properties += locationInfo.getData()+locationInfo.getDataReferents()

        // ScmRequestInfo
        scmInfo = ScmRequestInfoData()
        scmInfo["pdwReserved"] = NULL
        //scmInfo["remoteRequest"]["ClientImpLevel"] = 2
        scmInfo["remoteRequest"]["cRequestedProtseqs"] = 1
        scmInfo["remoteRequest"]["pRequestedProtseqs"].append(7)

        dword = DWORD()
        marshaled = scmInfo.getData()+scmInfo.getDataReferents()
        pad = (8 - (len(marshaled) % 8)) % 8
        dword["Data"] = len(marshaled) + pad
        activationBLOB["CustomHeader"]["pSizes"].append(dword)

        properties += marshaled + b'\xFA'*pad

        activationBLOB["Property"] = properties


        objrefcustom = OBJREF_CUSTOM()
        objrefcustom["iid"] = IID_IActivationPropertiesIn[:-4]
        objrefcustom["clsid"] = CLSID_ActivationPropertiesIn

        objrefcustom["pObjectData"] = activationBLOB.getData()
        objrefcustom["ObjectReferenceSize"] = len(objrefcustom["pObjectData"])+8

        request["pActProperties"]["ulCntData"] = len(objrefcustom.getData())
        request["pActProperties"]["abData"] = list(objrefcustom.getData())
        resp = self.__portmap.request(request)
        // Now let's parse the answer and build an Interface instance

        objRefType = OBJREF(b''.join(resp["ppActProperties"]["abData"]))["flags"]
        objRef = nil
        if objRefType == FLAGS_OBJREF_CUSTOM {
            objRef = OBJREF_CUSTOM(b''.join(resp["ppActProperties"]["abData"]))
        elif objRefType == FLAGS_OBJREF_HANDLER {
            objRef = OBJREF_HANDLER(b''.join(resp["ppActProperties"]["abData"]))
        elif objRefType == FLAGS_OBJREF_STANDARD {
            objRef = OBJREF_STANDARD(b''.join(resp["ppActProperties"]["abData"]))
        elif objRefType == FLAGS_OBJREF_EXTENDED {
            objRef = OBJREF_EXTENDED(b''.join(resp["ppActProperties"]["abData"]))
        } else  {
            LOG.error("Unknown OBJREF Type! 0x%x" % objRefType)


        activationBlob = ACTIVATION_BLOB(objRef["pObjectData"])

        propOutput = activationBlob["Property"][:activationBlob["CustomHeader"]["pSizes"][0]["Data"]]
        scmReply = activationBlob["Property"][
                   activationBlob["CustomHeader"]["pSizes"][0]["Data"]:activationBlob["CustomHeader"]["pSizes"][0]["Data"] +
                                                                       activationBlob["CustomHeader"]["pSizes"][1]["Data"]]

        scmr = ScmReplyInfoData()
        size = scmr.fromString(scmReply)
        // Processing the scmReply
        scmr.fromStringReferents(scmReply[size:])
        ipidRemUnknown = scmr["remoteReply"]["ipidRemUnknown"]
        Oxids = b''.join(pack('<H', x) for x in scmr["remoteReply"]["pdsaOxidBindings"]["aStringArray"])
        strBindings = Oxids[:scmr["remoteReply"]["pdsaOxidBindings"]["wSecurityOffset"]*2]
        securityBindings = Oxids[scmr["remoteReply"]["pdsaOxidBindings"]["wSecurityOffset"]*2:]

        done = false
        stringBindings = list()
        while not done:
            if strBindings[0:1] == b'\x00' and strBindings[1:2] == b'\x00' {
                done = true
            } else  {
                binding = STRINGBINDING(strBindings)
                stringBindings.append(binding)
                strBindings = strBindings[len(binding):]

        done = false
        while not done:
            if len(securityBindings) < 2 {
                done = true
            } else if securityBindings[0:1] == b'\x00' and securityBindings[1 {2] == b'\x00' {
                done = true
            } else  {
                secBinding = SECURITYBINDING(securityBindings)
                securityBindings = securityBindings[len(secBinding):]

        // Processing the Properties Output
        propsOut = PropsOutInfo()
        size = propsOut.fromString(propOutput)
        propsOut.fromStringReferents(propOutput[size:])

        classInstance = CLASS_INSTANCE(ORPCthis, stringBindings)
        classInstance.set_auth_level(scmr["remoteReply"]["authnHint"])
        classInstance.set_auth_type(self.__portmap.get_auth_type())
        return IRemUnknown2(INTERFACE(classInstance, b''.join(propsOut["ppIntfData"][0]["abData"]), ipidRemUnknown,
                                      target=self.__portmap.get_rpc_transport().getRemoteHost()))

     func (self TYPE) RemoteCreateInstance(clsId, iid interface{}){
        // Only supports one interface at a time
        self.__portmap.bind(IID_IRemoteSCMActivator)

        ORPCthis = ORPCTHIS()
        ORPCthis["cid"] = generate()
        ORPCthis["extensions"] = NULL
        ORPCthis["flags"] = 1

        request = RemoteCreateInstance()
        request["ORPCthis"] = ORPCthis
        request["pUnkOuter"] = NULL

        activationBLOB = ACTIVATION_BLOB()
        activationBLOB["CustomHeader"]["destCtx"] = 2
        activationBLOB["CustomHeader"]["pdwReserved"] = NULL
        clsid = CLSID()
        clsid["Data"] = CLSID_InstantiationInfo
        activationBLOB["CustomHeader"]["pclsid"].append(clsid)
        clsid = CLSID()
        clsid["Data"] = CLSID_ActivationContextInfo
        activationBLOB["CustomHeader"]["pclsid"].append(clsid)
        clsid = CLSID()
        clsid["Data"] = CLSID_ServerLocationInfo
        activationBLOB["CustomHeader"]["pclsid"].append(clsid)
        clsid = CLSID()
        clsid["Data"] = CLSID_ScmRequestInfo
        activationBLOB["CustomHeader"]["pclsid"].append(clsid)

        properties = b''
        // InstantiationInfo
        instantiationInfo = InstantiationInfoData()
        instantiationInfo["classId"] = clsId
        instantiationInfo["cIID"] = 1

        _iid = IID()
        _iid["Data"] = iid

        instantiationInfo["pIID"].append(_iid)

        dword = DWORD()
        marshaled = instantiationInfo.getData()+instantiationInfo.getDataReferents()
        pad = (8 - (len(marshaled) % 8)) % 8
        dword["Data"] = len(marshaled) + pad
        activationBLOB["CustomHeader"]["pSizes"].append(dword)
        instantiationInfo["thisSize"] = dword["Data"]

        properties += marshaled + b'\xFA'*pad

        // ActivationContextInfoData
        activationInfo = ActivationContextInfoData()
        activationInfo["pIFDClientCtx"] = NULL
        activationInfo["pIFDPrototypeCtx"] = NULL

        dword = DWORD()
        marshaled = activationInfo.getData()+activationInfo.getDataReferents()
        pad = (8 - (len(marshaled) % 8)) % 8
        dword["Data"] = len(marshaled) + pad
        activationBLOB["CustomHeader"]["pSizes"].append(dword)

        properties += marshaled + b'\xFA'*pad

        // ServerLocation
        locationInfo = LocationInfoData()
        locationInfo["machineName"] = NULL

        dword = DWORD()
        dword["Data"] = len(locationInfo.getData())
        activationBLOB["CustomHeader"]["pSizes"].append(dword)

        properties += locationInfo.getData()+locationInfo.getDataReferents()

        // ScmRequestInfo
        scmInfo = ScmRequestInfoData()
        scmInfo["pdwReserved"] = NULL
        //scmInfo["remoteRequest"]["ClientImpLevel"] = 2
        scmInfo["remoteRequest"]["cRequestedProtseqs"] = 1
        scmInfo["remoteRequest"]["pRequestedProtseqs"].append(7)

        dword = DWORD()
        marshaled = scmInfo.getData()+scmInfo.getDataReferents()
        pad = (8 - (len(marshaled) % 8)) % 8
        dword["Data"] = len(marshaled) + pad
        activationBLOB["CustomHeader"]["pSizes"].append(dword)

        properties += marshaled + b'\xFA'*pad

        activationBLOB["Property"] = properties


        objrefcustom = OBJREF_CUSTOM()
        objrefcustom["iid"] = IID_IActivationPropertiesIn[:-4]
        objrefcustom["clsid"] = CLSID_ActivationPropertiesIn

        objrefcustom["pObjectData"] = activationBLOB.getData()
        objrefcustom["ObjectReferenceSize"] = len(objrefcustom["pObjectData"])+8

        request["pActProperties"]["ulCntData"] = len(objrefcustom.getData())
        request["pActProperties"]["abData"] = list(objrefcustom.getData())
        resp = self.__portmap.request(request)

        // Now let's parse the answer and build an Interface instance

        objRefType = OBJREF(b''.join(resp["ppActProperties"]["abData"]))["flags"]
        objRef = nil
        if objRefType == FLAGS_OBJREF_CUSTOM {
            objRef = OBJREF_CUSTOM(b''.join(resp["ppActProperties"]["abData"]))
        elif objRefType == FLAGS_OBJREF_HANDLER {
            objRef = OBJREF_HANDLER(b''.join(resp["ppActProperties"]["abData"]))
        elif objRefType == FLAGS_OBJREF_STANDARD {
            objRef = OBJREF_STANDARD(b''.join(resp["ppActProperties"]["abData"]))
        elif objRefType == FLAGS_OBJREF_EXTENDED {
            objRef = OBJREF_EXTENDED(b''.join(resp["ppActProperties"]["abData"]))
        } else  {
            LOG.error("Unknown OBJREF Type! 0x%x" % objRefType)


        activationBlob = ACTIVATION_BLOB(objRef["pObjectData"])

        propOutput = activationBlob["Property"][:activationBlob["CustomHeader"]["pSizes"][0]["Data"]]
        scmReply = activationBlob["Property"][
                   activationBlob["CustomHeader"]["pSizes"][0]["Data"]:activationBlob["CustomHeader"]["pSizes"][0]["Data"] +
                                                                       activationBlob["CustomHeader"]["pSizes"][1]["Data"]]

        scmr = ScmReplyInfoData()
        size = scmr.fromString(scmReply)
        // Processing the scmReply
        scmr.fromStringReferents(scmReply[size:])
        ipidRemUnknown = scmr["remoteReply"]["ipidRemUnknown"]
        Oxids = b''.join(pack('<H', x) for x in scmr["remoteReply"]["pdsaOxidBindings"]["aStringArray"])
        strBindings = Oxids[:scmr["remoteReply"]["pdsaOxidBindings"]["wSecurityOffset"]*2]
        securityBindings = Oxids[scmr["remoteReply"]["pdsaOxidBindings"]["wSecurityOffset"]*2:]

        done = false
        stringBindings = list()
        while not done:
            if strBindings[0:1] == b'\x00' and strBindings[1:2] == b'\x00' {
                done = true
            } else  {
                binding = STRINGBINDING(strBindings)
                stringBindings.append(binding)
                strBindings = strBindings[len(binding):]

        done = false
        while not done:
            if len(securityBindings) < 2 {
                done = true
            } else if securityBindings[0:1] == b'\x00' and securityBindings[1 {2] == b'\x00' {
                done = true
            } else  {
                secBinding = SECURITYBINDING(securityBindings)
                securityBindings = securityBindings[len(secBinding):]

        // Processing the Properties Output
        propsOut = PropsOutInfo()
        size = propsOut.fromString(propOutput)
        propsOut.fromStringReferents(propOutput[size:])

        classInstance = CLASS_INSTANCE(ORPCthis, stringBindings)
        classInstance.set_auth_level(scmr["remoteReply"]["authnHint"])
        classInstance.set_auth_type(self.__portmap.get_auth_type())
        return IRemUnknown2(INTERFACE(classInstance, b''.join(propsOut["ppIntfData"][0]["abData"]), ipidRemUnknown,
                                      target=self.__portmap.get_rpc_transport().getRemoteHost()))
