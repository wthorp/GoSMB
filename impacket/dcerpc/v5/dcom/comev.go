// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Author: Alberto Solino (@agsolino)
//
// Description:
//   [MS-COMEV]: Component Object Model Plus (COM+) Event System Protocol. 
//               This was used as a way to test the DCOM runtime. Further 
//               testing is needed to verify it is working as expected
//
//   Best way to learn how to use these calls is to grab the protocol standard
//   so you understand what the call does, and then read the test case located
//   at https://github.com/SecureAuthCorp/impacket/tree/master/tests/SMB_RPC
//
//   Since DCOM is like an OO RPC, instead of helper functions you will see the 
//   classes described in the standards developed. 
//   There are test cases for them too. 
//
from __future__ import division
from __future__ import print_function
from impacket.dcerpc.v5.ndr import NDRSTRUCT, NDRENUM, NDRUniConformantVaryingArray
from impacket.dcerpc.v5.dcomrt import DCOMCALL, DCOMANSWER, INTERFACE, PMInterfacePointer, IRemUnknown
from impacket.dcerpc.v5.dcom.oaut import IDispatch, BSTR, VARIANT
from impacket.dcerpc.v5.dtypes import INT, ULONG, LONG, BOOLEAN
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.enum import Enum
from impacket import hresult_errors
from impacket.uuid import string_to_bin, uuidtup_to_bin

 type DCERPCSessionError struct { // DCERPCException:
     func (self TYPE) __init__(error_string=nil, error_code=nil, packet=nil interface{}){
        DCERPCException.__init__(self, error_string, error_code, packet)

     func __str__( self  interface{}){
        if self.error_code in hresult_errors.ERROR_MESSAGES {
            error_msg_short = hresult_errors.ERROR_MESSAGES[self.error_code][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[self.error_code][1] 
            return 'COMEV SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        } else  {
            return 'COMEV SessionError: unknown error code: 0x%x' % self.error_code

//###############################################################################
// CONSTANTS
//###############################################################################
// 1.9 Standards Assignments
CLSID_EventSystem          = string_to_bin("4E14FBA2-2E22-11D1-9964-00C04FBBB345")
CLSID_EventSystem2         = string_to_bin("99CC098F-A48A-4e9c-8E58-965C0AFC19D5")
CLSID_EventClass           = string_to_bin("cdbec9c0-7a68-11d1-88f9-0080c7d771bf")
CLSID_EventSubscription    = string_to_bin("7542e960-79c7-11d1-88f9-0080c7d771bf")
GUID_DefaultAppPartition   = string_to_bin("41E90F3E-56C1-4633-81C3-6E8BAC8BDD70")
IID_IEventSystem           = uuidtup_to_bin(('4E14FB9F-2E22-11D1-9964-00C04FBBB345','0.0'))
IID_IEventSystem2          = uuidtup_to_bin(('99CC098F-A48A-4e9c-8E58-965C0AFC19D5','0.0'))
IID_IEventSystemInitialize = uuidtup_to_bin(('a0e8f27a-888c-11d1-b763-00c04fb926af','0.0'))
IID_IEventObjectCollection = uuidtup_to_bin(('f89ac270-d4eb-11d1-b682-00805fc79216','0.0'))
IID_IEnumEventObject       = uuidtup_to_bin(('F4A07D63-2E25-11D1-9964-00C04FBBB345','0.0'))
IID_IEventSubscription     = uuidtup_to_bin(('4A6B0E15-2E38-11D1-9965-00C04FBBB345','0.0'))
IID_IEventSubscription2    = uuidtup_to_bin(('4A6B0E16-2E38-11D1-9965-00C04FBBB345','0.0'))
IID_IEventSubscription3    = uuidtup_to_bin(('FBC1D17D-C498-43a0-81AF-423DDD530AF6','0.0'))
IID_IEventClass            = uuidtup_to_bin(('fb2b72a0-7a68-11d1-88f9-0080c7d771bf','0.0'))
IID_IEventClass2           = uuidtup_to_bin(('fb2b72a1-7a68-11d1-88f9-0080c7d771bf','0.0'))
IID_IEventClass3           = uuidtup_to_bin(('7FB7EA43-2D76-4ea8-8CD9-3DECC270295E','0.0'))

error_status_t = ULONG

// 2.2.2.2 Property Value Types
 type VARENUM struct { // NDRENUM:
     type enumItems struct { // Enum:
        VT_EMPTY       = 0
        VT_NULL        = 1
        VT_I2          = 2
        VT_I4          = 3
        VT_R4          = 4
        VT_R8          = 5
        VT_CY          = 6
        VT_DATE        = 7
        VT_BSTR        = 8
        VT_DISPATCH    = 9
        VT_ERROR       = 0xa
        VT_BOOL        = 0xb
        VT_VARIANT     = 0xc
        VT_UNKNOWN     = 0xd
        VT_DECIMAL     = 0xe
        VT_I1          = 0x10
        VT_UI1         = 0x11
        VT_UI2         = 0x12
        VT_UI4         = 0x13
        VT_I8          = 0x14
        VT_UI8         = 0x15
        VT_INT         = 0x16
        VT_UINT        = 0x17
        VT_VOID        = 0x18
        VT_HRESULT     = 0x19
        VT_PTR         = 0x1a
        VT_SAFEARRAY   = 0x1b
        VT_CARRAY      = 0x1c
        VT_USERDEFINED = 0x1d
        VT_LPSTR       = 0x1e
        VT_LPWSTR      = 0x1f
        VT_RECORD      = 0x24
        VT_INT_PTR     = 0x25
        VT_UINT_PTR    = 0x26
        VT_ARRAY       = 0x2000
        VT_BYREF       = 0x4000

//###############################################################################
// STRUCTURES
//###############################################################################
// 2.2.44 TYPEATTR
 type TYPEATTR struct { // NDRSTRUCT: (
    }

 type OBJECT_ARRAY struct { // NDRUniConformantVaryingArray:
    item = PMInterfacePointer

//###############################################################################
// RPC CALLS
//###############################################################################
// 3.1.4.1 IEventSystem
// 3.1.4.1.1 Query (Opnum 7)
 type IEventSystem_Query struct { // DCOMCALL:
    opnum = 7 (
       ('progID', BSTR),
       ('queryCriteria', BSTR),
    }

 type IEventSystem_QueryResponse struct { // DCOMANSWER: (
       ('errorIndex', INT),
       ('ppInterface', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.1.2 Store (Opnum 8)
 type IEventSystem_Store struct { // DCOMCALL:
    opnum = 8 (
       ('progID', BSTR),
       ('pInterface', PMInterfacePointer),
    }

 type IEventSystem_StoreResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.1.3 Remove (Opnum 9)
 type IEventSystem_Remove struct { // DCOMCALL:
    opnum = 9 (
       ('progID', BSTR),
       ('queryCriteria', BSTR),
    }

 type IEventSystem_RemoveResponse struct { // DCOMANSWER: (
       ('errorIndex', INT),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.1.4 get_EventObjectChangeEventClassID (Opnum 10)
 type IEventSystem_get_EventObjectChangeEventClassID struct { // DCOMCALL:
    opnum = 10 (
    }

 type IEventSystem_get_EventObjectChangeEventClassIDResponse struct { // DCOMANSWER: (
       ('pbstrEventClassID', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.1.5 QueryS (Opnum 11)
 type IEventSystem_QueryS struct { // DCOMCALL:
    opnum = 11 (
       ('progID', BSTR),
       ('queryCriteria', BSTR),
    }

 type IEventSystem_QuerySResponse struct { // DCOMANSWER: (
       ('pInterface', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.1.6 RemoveS (Opnum 12)
 type IEventSystem_RemoveS struct { // DCOMCALL:
    opnum = 12 (
       ('progID', BSTR),
       ('queryCriteria', BSTR),
    }

 type IEventSystem_RemoveSResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

//###############################################################################
// 3.1.4.2 IEventClass
// 3.1.4.2.1 get_EventClassID (Opnum 7)
 type IEventClass_get_EventClassID struct { // DCOMCALL:
    opnum = 7 (
    }

 type IEventClass_get_EventClassIDResponse struct { // DCOMANSWER: (
       ('pbstrEventClassID', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.2.2 put_EventClassID (Opnum 8)
 type IEventClass_put_EventClassID struct { // DCOMCALL:
    opnum = 8 (
       ('bstrEventClassID', BSTR),
    }

 type IEventClass_put_EventClassIDResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.2.3 get_EventClassName (Opnum 9)
 type IEventClass_get_EventClassName struct { // DCOMCALL:
    opnum = 9 (
    }

 type IEventClass_get_EventClassNameResponse struct { // DCOMANSWER: (
       ('pbstrEventClassName', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.2.4 put_EventClassName (Opnum 10)
 type IEventClass_put_EventClassName struct { // DCOMCALL:
    opnum = 10 (
       ('bstrEventClassName', BSTR),
    }

 type IEventClass_put_EventClassNameResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.2.5 get_OwnerSID (Opnum 11)
 type IEventClass_get_OwnerSID struct { // DCOMCALL:
    opnum = 11 (
    }

 type IEventClass_get_OwnerSIDResponse struct { // DCOMANSWER: (
       ('pbstrOwnerSID', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.2.6 put_OwnerSID (Opnum 12)
 type IEventClass_put_OwnerSID struct { // DCOMCALL:
    opnum = 12 (
       ('bstrOwnerSID', BSTR),
    }

 type IEventClass_put_OwnerSIDResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.2.7 get_FiringInterfaceID (Opnum 13)
 type IEventClass_get_FiringInterfaceID struct { // DCOMCALL:
    opnum = 13 (
    }

 type IEventClass_get_FiringInterfaceIDResponse struct { // DCOMANSWER: (
       ('pbstrFiringInterfaceID', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.2.8 put_FiringInterfaceID (Opnum 14)
 type IEventClass_put_FiringInterfaceID struct { // DCOMCALL:
    opnum = 14 (
       ('bstrFiringInterfaceID', BSTR),
    }

 type IEventClass_put_FiringInterfaceIDResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.2.9 get_Description (Opnum 15)
 type IEventClass_get_Description struct { // DCOMCALL:
    opnum = 15 (
    }

 type IEventClass_get_DescriptionResponse struct { // DCOMANSWER: (
       ('pbstrDescription', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.2.10 put_Description (Opnum 16)
 type IEventClass_put_Description struct { // DCOMCALL:
    opnum = 16 (
       ('bstrDescription', BSTR),
    }

 type IEventClass_put_DescriptionResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.2.11 get_TypeLib (Opnum 19)
 type IEventClass_get_TypeLib struct { // DCOMCALL:
    opnum = 19 (
    }

 type IEventClass_get_TypeLibResponse struct { // DCOMANSWER: (
       ('pbstrTypeLib', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.2.12 put_TypeLib (Opnum 20)
 type IEventClass_put_TypeLib struct { // DCOMCALL:
    opnum = 20 (
       ('bstrTypeLib', BSTR),
    }

 type IEventClass_put_TypeLibResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

//###############################################################################
// 3.1.4.3 IEventClass2
// 3.1.4.3.1 get_PublisherID (Opnum 21)
 type IEventClass2_get_PublisherID struct { // DCOMCALL:
    opnum = 21 (
    }

 type IEventClass2_get_PublisherIDResponse struct { // DCOMANSWER: (
       ('pbstrSubscriptionID', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.2 put_PublisherID (Opnum 22)
 type IEventClass2_put_PublisherID struct { // DCOMCALL:
    opnum = 22 (
       ('bstrPublisherID', BSTR),
    }

 type IEventClass2_put_PublisherIDResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.3 get_MultiInterfacePublisherFilterCLSID (Opnum 23)
 type IEventClass2_get_MultiInterfacePublisherFilterCLSID struct { // DCOMCALL:
    opnum = 23 (
    }

 type IEventClass2_get_MultiInterfacePublisherFilterCLSIDResponse struct { // DCOMANSWER: (
       ('pbstrPubFilCLSID', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.4 put_MultiInterfacePublisherFilterCLSID (Opnum 24)
 type IEventClass2_put_MultiInterfacePublisherFilterCLSID struct { // DCOMCALL:
    opnum = 24 (
       ('bstrPubFilCLSID', BSTR),
    }

 type IEventClass2_put_MultiInterfacePublisherFilterCLSIDResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.5 get_AllowInprocActivation (Opnum 25)
 type IEventClass2_get_AllowInprocActivation struct { // DCOMCALL:
    opnum = 25 (
    }

 type IEventClass2_get_AllowInprocActivationResponse struct { // DCOMANSWER: (
       ('pfAllowInprocActivation', BOOLEAN),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.6 put_AllowInprocActivation (Opnum 26)
 type IEventClass2_put_AllowInprocActivation struct { // DCOMCALL:
    opnum = 26 (
       ('fAllowInprocActivation', BOOLEAN),
    }

 type IEventClass2_put_AllowInprocActivationResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.7 get_FireInParallel (Opnum 27)
 type IEventClass2_get_FireInParallel struct { // DCOMCALL:
    opnum = 27 (
    }

 type IEventClass2_get_FireInParallelResponse struct { // DCOMANSWER: (
       ('pfFireInParallel', BOOLEAN),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3.8 put_FireInParallel (Opnum 28)
 type IEventClass2_put_FireInParallel struct { // DCOMCALL:
    opnum = 28 (
       ('pfFireInParallel', BOOLEAN),
    }

 type IEventClass2_put_FireInParallelResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

//###############################################################################
// 3.1.4.4 IEventSubscription
// 3.1.4.4.1 get_SubscriptionID (Opnum 7)
 type IEventSubscription_get_SubscriptionID struct { // DCOMCALL:
    opnum = 7 (
    }

 type IEventSubscription_get_SubscriptionIDResponse struct { // DCOMANSWER: (
       ('pbstrSubscriptionID', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.2 put_SubscriptionID (Opnum 8)
 type IEventSubscription_put_SubscriptionID struct { // DCOMCALL:
    opnum = 8 (
       ('bstrSubscriptionID', BSTR),
    }

 type IEventSubscription_put_SubscriptionIDResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.3 get_SubscriptionName (Opnum 9)
 type IEventSubscription_get_SubscriptionName struct { // DCOMCALL:
    opnum = 9 (
    }

 type IEventSubscription_get_SubscriptionNameResponse struct { // DCOMANSWER: (
       ('pbstrSubscriptionName', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.4 put_SubscriptionName (Opnum 10)
 type IEventSubscription_put_SubscriptionName struct { // DCOMCALL:
    opnum = 10 (
       ('strSubscriptionID', BSTR),
    }

 type IEventSubscription_put_SubscriptionNameResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.5 get_PublisherID (Opnum 11)
 type IEventSubscription_get_PublisherID struct { // DCOMCALL:
    opnum = 11 (
    }

 type IEventSubscription_get_PublisherIDResponse struct { // DCOMANSWER: (
       ('pbstrPublisherID', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.6 put_PublisherID (Opnum 12)
 type IEventSubscription_put_PublisherID struct { // DCOMCALL:
    opnum = 12 (
       ('bstrPublisherID', BSTR),
    }

 type IEventSubscription_put_PublisherIDResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.7 get_EventClassID (Opnum 13)
 type IEventSubscription_get_EventClassID struct { // DCOMCALL:
    opnum = 13 (
    }

 type IEventSubscription_get_EventClassIDResponse struct { // DCOMANSWER: (
       ('pbstrEventClassID', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.8 put_EventClassID (Opnum 14)
 type IEventSubscription_put_EventClassID struct { // DCOMCALL:
    opnum = 14 (
       ('bstrEventClassID', BSTR),
    }

 type IEventSubscription_put_EventClassIDResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.9 get_MethodName (Opnum 15)
 type IEventSubscription_get_MethodName struct { // DCOMCALL:
    opnum = 15 (
    }

 type IEventSubscription_get_MethodNameResponse struct { // DCOMANSWER: (
       ('pbstrMethodName', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.10 put_MethodName (Opnum 16)
 type IEventSubscription_put_MethodName struct { // DCOMCALL:
    opnum = 16 (
       ('bstrMethodName', BSTR),
    }

 type IEventSubscription_put_MethodNameResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.11 get_SubscriberCLSID (Opnum 17)
 type IEventSubscription_get_SubscriberCLSID struct { // DCOMCALL:
    opnum = 17 (
    }

 type IEventSubscription_get_SubscriberCLSIDResponse struct { // DCOMANSWER: (
       ('pbstrSubscriberCLSID', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.12 put_SubscriberCLSID (Opnum 18)
 type IEventSubscription_put_SubscriberCLSID struct { // DCOMCALL:
    opnum = 18 (
       ('bstrSubscriberCLSID', BSTR),
    }

 type IEventSubscription_put_SubscriberCLSIDResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.13 get_SubscriberInterface (Opnum 19)
 type IEventSubscription_get_SubscriberInterface struct { // DCOMCALL:
    opnum = 19 (
    }

 type IEventSubscription_get_SubscriberInterfaceResponse struct { // DCOMANSWER: (
       ('ppSubscriberInterface', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.14 put_SubscriberInterface (Opnum 20)
 type IEventSubscription_put_SubscriberInterface struct { // DCOMCALL:
    opnum = 20 (
       ('pSubscriberInterface', PMInterfacePointer),
    }

 type IEventSubscription_put_SubscriberInterfaceResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.15 get_PerUser (Opnum 21)
 type IEventSubscription_get_PerUser struct { // DCOMCALL:
    opnum = 21 (
    }

 type IEventSubscription_get_PerUserResponse struct { // DCOMANSWER: (
       ('pfPerUser', BOOLEAN),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.16 put_PerUser (Opnum 22)
 type IEventSubscription_put_PerUser struct { // DCOMCALL:
    opnum = 22 (
       ('fPerUser', BOOLEAN),
    }

 type IEventSubscription_put_PerUserResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.17 get_OwnerSID (Opnum 23)
 type IEventSubscription_get_OwnerSID struct { // DCOMCALL:
    opnum = 23 (
    }

 type IEventSubscription_get_OwnerSIDResponse struct { // DCOMANSWER: (
       ('pbstrOwnerSID', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.18 put_OwnerSID (Opnum 24)
 type IEventSubscription_put_OwnerSID struct { // DCOMCALL:
    opnum = 24 (
       ('bstrOwnerSID', BSTR),
    }

 type IEventSubscription_put_OwnerSIDResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.19 get_Enabled (Opnum 25)
 type IEventSubscription_get_Enabled struct { // DCOMCALL:
    opnum = 25 (
    }

 type IEventSubscription_get_EnabledResponse struct { // DCOMANSWER: (
       ('pfEnabled', BOOLEAN),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.20 put_Enabled (Opnum 26)
 type IEventSubscription_put_Enabled struct { // DCOMCALL:
    opnum = 26 (
       ('fEnabled', BOOLEAN),
    }

 type IEventSubscription_put_EnabledResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.21 get_Description (Opnum 27)
 type IEventSubscription_get_Description struct { // DCOMCALL:
    opnum = 27 (
    }

 type IEventSubscription_get_DescriptionResponse struct { // DCOMANSWER: (
       ('pbstrDescription', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.22 put_Description (Opnum 28)
 type IEventSubscription_put_Description struct { // DCOMCALL:
    opnum = 28 (
       ('bstrDescription', BSTR),
    }

 type IEventSubscription_put_DescriptionResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.23 get_MachineName (Opnum 29)
 type IEventSubscription_get_MachineName struct { // DCOMCALL:
    opnum = 29 (
    }

 type IEventSubscription_get_MachineNameResponse struct { // DCOMANSWER: (
       ('pbstrMachineName', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.24 put_MachineName (Opnum 30)
 type IEventSubscription_put_MachineName struct { // DCOMCALL:
    opnum = 30 (
       ('bstrMachineName', BSTR),
    }

 type IEventSubscription_put_MachineNameResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.25 GetPublisherProperty (Opnum 31)
 type IEventSubscription_GetPublisherProperty struct { // DCOMCALL:
    opnum = 31 (
       ('bstrPropertyName', BSTR),
    }

 type IEventSubscription_GetPublisherPropertyResponse struct { // DCOMANSWER: (
       ('propertyValue', VARIANT),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.26 PutPublisherProperty (Opnum 32)
 type IEventSubscription_PutPublisherProperty struct { // DCOMCALL:
    opnum = 32 (
       ('bstrPropertyName', BSTR),
       ('propertyValue', VARIANT),
    }

 type IEventSubscription_PutPublisherPropertyResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.27 RemovePublisherProperty (Opnum 33)
 type IEventSubscription_RemovePublisherProperty struct { // DCOMCALL:
    opnum = 33 (
       ('bstrPropertyName', BSTR),
    }

 type IEventSubscription_RemovePublisherPropertyResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.28 GetPublisherPropertyCollection (Opnum 34)
 type IEventSubscription_GetPublisherPropertyCollection struct { // DCOMCALL:
    opnum = 34 (
    }

 type IEventSubscription_GetPublisherPropertyCollectionResponse struct { // DCOMANSWER: (
       ('collection', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.29 GetSubscriberProperty (Opnum 35)
 type IEventSubscription_GetSubscriberProperty struct { // DCOMCALL:
    opnum = 35 (
       ('bstrPropertyName', BSTR),
    }

 type IEventSubscription_GetSubscriberPropertyResponse struct { // DCOMANSWER: (
       ('propertyValue', VARIANT),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.30 PutSubscriberProperty (Opnum 36)
 type IEventSubscription_PutSubscriberProperty struct { // DCOMCALL:
    opnum = 36 (
       ('bstrPropertyName', BSTR),
       ('propertyValue', VARIANT),
    }

 type IEventSubscription_PutSubscriberPropertyResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.31 RemoveSubscriberProperty (Opnum 37)
 type IEventSubscription_RemoveSubscriberProperty struct { // DCOMCALL:
    opnum = 37 (
       ('bstrPropertyName', BSTR),
    }

 type IEventSubscription_RemoveSubscriberPropertyResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.32 GetSubscriberPropertyCollection (Opnum 38)
 type IEventSubscription_GetSubscriberPropertyCollection struct { // DCOMCALL:
    opnum = 38 (
    }

 type IEventSubscription_GetSubscriberPropertyCollectionResponse struct { // DCOMANSWER: (
       ('collection', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.33 get_InterfaceID (Opnum 39)
 type IEventSubscription_get_InterfaceID struct { // DCOMCALL:
    opnum = 39 (
    }

 type IEventSubscription_get_InterfaceIDResponse struct { // DCOMANSWER: (
       ('pbstrInterfaceID', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4.34 put_InterfaceID (Opnum 40)
 type IEventSubscription_put_InterfaceID struct { // DCOMCALL:
    opnum = 40 (
       ('bstrInterfaceID', BSTR),
    }

 type IEventSubscription_put_InterfaceIDResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

//###############################################################################
// 3.1.4.5 IEnumEventObject
// 3.1.4.5.1 Clone (Opnum 3)
 type IEnumEventObject_Clone struct { // DCOMCALL:
    opnum = 3 (
    }

 type IEnumEventObject_CloneResponse struct { // DCOMANSWER: (
       ('ppInterface', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.5.2 Next (Opnum 4)
 type IEnumEventObject_Next struct { // DCOMCALL:
    opnum = 4 (
       ('cReqElem', ULONG),
    }

 type IEnumEventObject_NextResponse struct { // DCOMANSWER: (
       ('ppInterface', OBJECT_ARRAY),
       ('cRetElem', ULONG),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.5.3 Reset (Opnum 5)
 type IEnumEventObject_Reset struct { // DCOMCALL:
    opnum = 5 (
    }

 type IEnumEventObject_ResetResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.5.4 Skip (Opnum 6)
 type IEnumEventObject_Skip struct { // DCOMCALL:
    opnum = 6 (
       ('cSkipElem', ULONG),
    }

 type IEnumEventObject_SkipResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

//###############################################################################
// 3.1.4.6 IEventObjectCollection
// 3.1.4.6.1 get__NewEnum (Opnum 7)
 type IEventObjectCollection_get__NewEnum struct { // DCOMCALL:
    opnum = 7 (
    }

 type IEventObjectCollection_get__NewEnumResponse struct { // DCOMANSWER: (
       ('ppUnkEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.6.2 get_Item (Opnum 8)
 type IEventObjectCollection_get_Item struct { // DCOMCALL:
    opnum = 8 (
       ('objectID', BSTR),
    }

 type IEventObjectCollection_get_ItemResponse struct { // DCOMANSWER: (
       ('pItem', VARIANT),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.6.3 get_NewEnum (Opnum 9)
 type IEventObjectCollection_get_NewEnum struct { // DCOMCALL:
    opnum = 9 (
    }

 type IEventObjectCollection_get_NewEnumResponse struct { // DCOMANSWER: (
       ('ppEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.6.4 get_Count (Opnum 10)
 type IEventObjectCollection_get_Count struct { // DCOMCALL:
    opnum = 10 (
    }

 type IEventObjectCollection_get_CountResponse struct { // DCOMANSWER: (
       ('pCount', LONG),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.6.5 Add (Opnum 11)
 type IEventObjectCollection_Add struct { // DCOMCALL:
    opnum = 11 (
       ('item', VARIANT),
       ('objectID', BSTR),
    }

 type IEventObjectCollection_AddResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.6.6 Remove (Opnum 12)
 type IEventObjectCollection_Remove struct { // DCOMCALL:
    opnum = 12 (
       ('objectID', BSTR),
    }

 type IEventObjectCollection_RemoveResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

//###############################################################################
// 3.1.4.7 IEventClass3
// 3.1.4.7.1 get_EventClassPartitionID (Opnum 29)
 type IEventClass3_get_EventClassPartitionID struct { // DCOMCALL:
    opnum = 29 (
    }

 type IEventClass3_get_EventClassPartitionIDResponse struct { // DCOMANSWER: (
       ('pbstrEventClassPartitionID', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.7.2 put_EventClassPartitionID (Opnum 30)
 type IEventClass3_put_EventClassPartitionID struct { // DCOMCALL:
    opnum = 30 (
       ('bstrEventClassPartitionID', BSTR),
    }

 type IEventClass3_put_EventClassPartitionIDResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.7.3 get_EventClassApplicationID (Opnum 31)
 type IEventClass3_get_EventClassApplicationID struct { // DCOMCALL:
    opnum = 31 (
    }

 type IEventClass3_get_EventClassApplicationIDResponse struct { // DCOMANSWER: (
       ('pbstrEventClassApplicationID', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.7.4 put_EventClassApplicationID (Opnum 32)
 type IEventClass3_put_EventClassApplicationID struct { // DCOMCALL:
    opnum = 32 (
       ('bstrEventClassApplicationID', BSTR),
    }

 type IEventClass3_put_EventClassApplicationIDResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

//###############################################################################
// 3.1.4.8 IEventSubscription2
// 3.1.4.8.1 get_FilterCriteria (Opnum 41)
 type IEventSubscription2_get_FilterCriteria struct { // DCOMCALL:
    opnum = 41 (
    }

 type IEventSubscription2_get_FilterCriteriaResponse struct { // DCOMANSWER: (
       ('pbstrFilterCriteria', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.8.2 put_FilterCriteria (Opnum 42)
 type IEventSubscription2_put_FilterCriteria struct { // DCOMCALL:
    opnum = 42 (
       ('bstrFilterCriteria', BSTR),
    }

 type IEventSubscription2_put_FilterCriteriaResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.8.3 get_SubscriberMoniker (Opnum 43)
 type IEventSubscription2_get_SubscriberMoniker struct { // DCOMCALL:
    opnum = 43 (
    }

 type IEventSubscription2_get_SubscriberMonikerResponse struct { // DCOMANSWER: (
       ('pbstrMoniker', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.8.4 put_SubscriberMoniker (Opnum 44)
 type IEventSubscription2_put_SubscriberMoniker struct { // DCOMCALL:
    opnum = 44 (
       ('bstrMoniker', BSTR),
    }

 type IEventSubscription2_put_SubscriberMonikerResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

//###############################################################################
// 3.1.4.9 IEventSubscription3
// 3.1.4.9.1 get_EventClassPartitionID (Opnum 45)
 type IEventSubscription3_get_EventClassPartitionID struct { // DCOMCALL:
    opnum = 45 (
    }

 type IEventSubscription3_get_EventClassPartitionIDResponse struct { // DCOMANSWER: (
       ('pbstrEventClassPartitionID', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.9.2 put_EventClassPartitionID (Opnum 46)
 type IEventSubscription3_put_EventClassPartitionID struct { // DCOMCALL:
    opnum = 46 (
       ('bstrEventClassPartitionID', BSTR),
    }

 type IEventSubscription3_put_EventClassPartitionIDResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.9.3 get_EventClassApplicationID (Opnum 47)
 type IEventSubscription3_get_EventClassApplicationID struct { // DCOMCALL:
    opnum = 47 (
    }

 type IEventSubscription3_get_EventClassApplicationIDResponse struct { // DCOMANSWER: (
       ('pbstrEventClassApplicationID', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.9.4 put_EventClassApplicationID (Opnum 48)
 type IEventSubscription3_put_EventClassApplicationID struct { // DCOMCALL:
    opnum = 48 (
       ('bstrEventClassPartitionID', BSTR),
    }

 type IEventSubscription3_put_EventClassApplicationIDResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.9.5 get_SubscriberPartitionID (Opnum 49)
 type IEventSubscription3_get_SubscriberPartitionID struct { // DCOMCALL:
    opnum = 49 (
    }

 type IEventSubscription3_get_SubscriberPartitionIDResponse struct { // DCOMANSWER: (
       ('pbstrSubscriberPartitionID', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.9.6 put_SubscriberPartitionID (Opnum 50)
 type IEventSubscription3_put_SubscriberPartitionID struct { // DCOMCALL:
    opnum = 50 (
       ('bstrSubscriberPartitionID', BSTR),
    }

 type IEventSubscription3_put_SubscriberPartitionIDResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

// 3.1.4.9.7 get_SubscriberApplicationID (Opnum 51)
 type IEventSubscription3_get_SubscriberApplicationID struct { // DCOMCALL:
    opnum = 51 (
    }

 type IEventSubscription3_get_SubscriberApplicationIDResponse struct { // DCOMANSWER: (
       ('pbstrSubscriberApplicationID', BSTR),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.9.8 put_SubscriberApplicationID (Opnum 52)
 type IEventSubscription3_put_SubscriberApplicationID struct { // DCOMCALL:
    opnum = 52 (
       ('bstrSubscriberApplicationID', BSTR),
    }

 type IEventSubscription3_put_SubscriberApplicationIDResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

//###############################################################################
// 3.1.4.10 IEventSystem2
// 3.1.4.10.1 GetVersion (Opnum 13)
 type IEventSystem2_GetVersion struct { // DCOMCALL:
    opnum = 13 (
    }

 type IEventSystem2_GetVersionResponse struct { // DCOMANSWER: (
       ('pnVersion', INT),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.10.2 VerifyTransientSubscribers (Opnum 14)
 type IEventSystem2_VerifyTransientSubscribers struct { // DCOMCALL:
    opnum = 14 (
    }

 type IEventSystem2_VerifyTransientSubscribersResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }

//###############################################################################
// 3.1.4.11 IEventSystemInitialize
// 3.1.4.11.1 SetCOMCatalogBehaviour (Opnum 3)
 type IEventSystemInitialize_SetCOMCatalogBehaviour struct { // DCOMCALL:
    opnum = 3 (
       ('bRetainSubKeys', BOOLEAN),
    }

 type IEventSystemInitialize_SetCOMCatalogBehaviourResponse struct { // DCOMANSWER: (
       ('ErrorCode', error_status_t),
    }


//###############################################################################
// OPNUMs and their corresponding structures
//###############################################################################
OPNUMS = {
}

//###############################################################################
// HELPER FUNCTIONS AND INTERFACES
//###############################################################################
 type IEventClass struct { // IDispatch:
     func (self TYPE) __init__(interface interface{}){
        IDispatch.__init__(self,interface)
        self._iid = IID_IEventClass

     func (self TYPE) get_EventClassID(){
        request = IEventClass_get_EventClassID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func put_EventClassID(self,bstrEventClassID interface{}){
        request = IEventClass_put_EventClassID()
        request["bstrEventClassID"] = bstrEventClassID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_EventClassName(){
        request = IEventClass_get_EventClassName()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_EventClassName(bstrEventClassName interface{}){
        request = IEventClass_put_EventClassName()
        request["bstrEventClassName"] = bstrEventClassName
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_OwnerSID(){
        request = IEventClass_get_OwnerSID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_OwnerSID(bstrOwnerSID interface{}){
        request = IEventClass_put_OwnerSID()
        request["bstrOwnerSID"] = bstrOwnerSID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_FiringInterfaceID(){
        request = IEventClass_get_FiringInterfaceID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_FiringInterfaceID(bstrFiringInterfaceID interface{}){
        request = IEventClass_put_FiringInterfaceID()
        request["bstrFiringInterfaceID"] = bstrFiringInterfaceID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_Description(){
        request = IEventClass_get_Description()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_Description(bstrDescription interface{}){
        request = IEventClass_put_Description()
        request["bstrDescription"] = bstrDescription
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_TypeLib(){
        request = IEventClass_get_TypeLib()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_TypeLib(bstrTypeLib interface{}){
        request = IEventClass_put_TypeLib()
        request["bstrTypeLib"] = bstrTypeLib
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

 type IEventClass2 struct { // IEventClass:
     func (self TYPE) __init__(interface interface{}){
        IEventClass.__init__(self,interface)
        self._iid = IID_IEventClass2

     func (self TYPE) get_PublisherID(){
        request = IEventClass2_get_PublisherID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_PublisherID(bstrPublisherID interface{}){
        request = IEventClass2_put_PublisherID()
        request["bstrPublisherID"] = bstrPublisherID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_MultiInterfacePublisherFilterCLSID(){
        request = IEventClass2_get_MultiInterfacePublisherFilterCLSID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_MultiInterfacePublisherFilterCLSID(bstrPubFilCLSID interface{}){
        request = IEventClass2_put_MultiInterfacePublisherFilterCLSID()
        request["bstrPubFilCLSID"] = bstrPubFilCLSID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_AllowInprocActivation(){
        request = IEventClass2_get_AllowInprocActivation()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_AllowInprocActivation(fAllowInprocActivation interface{}){
        request = IEventClass2_put_AllowInprocActivation()
        request["fAllowInprocActivation "] = fAllowInprocActivation
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_FireInParallel(){
        request = IEventClass2_get_FireInParallel()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_FireInParallel(fFireInParallel interface{}){
        request = IEventClass2_put_FireInParallel()
        request["fFireInParallel "] = fFireInParallel
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

 type IEventClass3 struct { // IEventClass2:
     func (self TYPE) __init__(interface interface{}){
        IEventClass2.__init__(self,interface)
        self._iid = IID_IEventClass3

     func (self TYPE) get_EventClassPartitionID(){
        request = IEventClass3_get_EventClassPartitionID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_EventClassPartitionID(bstrEventClassPartitionID interface{}){
        request = IEventClass3_put_EventClassPartitionID()
        request["bstrEventClassPartitionID "] = bstrEventClassPartitionID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_EventClassApplicationID(){
        request = IEventClass3_get_EventClassApplicationID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_EventClassApplicationID(bstrEventClassApplicationID interface{}){
        request = IEventClass3_put_EventClassApplicationID()
        request["bstrEventClassApplicationID "] = bstrEventClassApplicationID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

 type IEventSubscription struct { // IDispatch:
     func (self TYPE) __init__(interface interface{}){
        IDispatch.__init__(self,interface)
        self._iid = IID_IEventSubscription

     func (self TYPE) get_SubscriptionID(){
        request = IEventSubscription_get_SubscriptionID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_SubscriptionID(bstrSubscriptionID interface{}){
        request = IEventSubscription_put_SubscriptionID()
        request["bstrSubscriptionID"] = bstrSubscriptionID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_SubscriptionName(){
        request = IEventSubscription_get_SubscriptionName()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

     func (self TYPE) put_SubscriptionName(bstrSubscriptionName interface{}){
        request = IEventSubscription_put_SubscriptionName()
        request["bstrSubscriptionName"] = bstrSubscriptionName
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_PublisherID(){
        request = IEventSubscription_get_PublisherID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_PublisherID(bstrPublisherID interface{}){
        request = IEventSubscription_put_PublisherID()
        request["bstrPublisherID"] = bstrPublisherID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_EventClassID(){
        request = IEventSubscription_get_EventClassID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_EventClassID(pbstrEventClassID interface{}){
        request = IEventSubscription_put_EventClassID()
        request["pbstrEventClassID"] = pbstrEventClassID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_MethodName(){
        request = IEventSubscription_get_MethodName()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_MethodName(bstrMethodName interface{}){
        request = IEventSubscription_put_MethodName()
        request["bstrMethodName"] = bstrMethodName
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_SubscriberCLSID(){
        request = IEventSubscription_get_SubscriberCLSID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_SubscriberCLSID(bstrSubscriberCLSID interface{}){
        request = IEventSubscription_put_SubscriberCLSID()
        request["bstrSubscriberCLSID"] = bstrSubscriberCLSID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_SubscriberInterface(){
        request = IEventSubscription_get_SubscriberInterface()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_SubscriberInterface(pSubscriberInterface interface{}){
        request = IEventSubscription_put_SubscriberInterface()
        request["pSubscriberInterface"] = pSubscriberInterface
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_PerUser(){
        request = IEventSubscription_get_PerUser()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_PerUser(fPerUser interface{}){
        request = IEventSubscription_put_PerUser()
        request["fPerUser"] = fPerUser
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_OwnerSID(){
        request = IEventSubscription_get_OwnerSID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_OwnerSID(bstrOwnerSID interface{}){
        request = IEventSubscription_put_OwnerSID()
        request["bstrOwnerSID"] = bstrOwnerSID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_Enabled(){
        request = IEventSubscription_get_Enabled()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_Enabled(fEnabled interface{}){
        request = IEventSubscription_put_Enabled()
        request["fEnabled"] = fEnabled
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_Description(){
        request = IEventSubscription_get_Description()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_Description(bstrDescription interface{}){
        request = IEventSubscription_put_Description()
        request["bstrDescription"] = bstrDescription
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_MachineName(){
        request = IEventSubscription_get_MachineName()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_MachineName(bstrMachineName interface{}){
        request = IEventSubscription_put_MachineName()
        request["bstrMachineName"] = bstrMachineName
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) GetPublisherProperty(){
        request = IEventSubscription_GetPublisherProperty()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) PutPublisherProperty(bstrPropertyName, propertyValue interface{}){
        request = IEventSubscription_PutPublisherProperty()
        request["bstrPropertyName"] = bstrPropertyName
        request["propertyValue"] = propertyValue
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) RemovePublisherProperty(bstrPropertyName interface{}){
        request = IEventSubscription_RemovePublisherProperty()
        request["bstrPropertyName"] = bstrPropertyName
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) GetPublisherPropertyCollection(){
        request = IEventSubscription_GetPublisherPropertyCollection()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) GetSubscriberProperty(){
        request = IEventSubscription_GetSubscriberProperty()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) PutSubscriberProperty(bstrPropertyName, propertyValue interface{}){
        request = IEventSubscription_PutSubscriberProperty()
        request["bstrPropertyName"] = bstrPropertyName
        request["propertyValue"] = propertyValue
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) RemoveSubscriberProperty(bstrPropertyName interface{}){
        request = IEventSubscription_RemoveSubscriberProperty()
        request["bstrPropertyName"] = bstrPropertyName
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) GetSubscriberPropertyCollection(){
        request = IEventSubscription_GetSubscriberPropertyCollection()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_InterfaceID(){
        request = IEventSubscription_get_InterfaceID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_InterfaceID(bstrInterfaceID interface{}){
        request = IEventSubscription_put_InterfaceID()
        request["bstrInterfaceID"] = bstrInterfaceID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

 type IEventSubscription2 struct { // IEventSubscription:
     func (self TYPE) __init__(interface interface{}){
        IEventSubscription.__init__(self,interface)
        self._iid = IID_IEventSubscription2

     func (self TYPE) get_FilterCriteria(){
        request = IEventSubscription2_get_FilterCriteria()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_FilterCriteria(bstrFilterCriteria interface{}){
        request = IEventSubscription2_put_FilterCriteria()
        request["bstrFilterCriteria"] = bstrFilterCriteria
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_SubscriberMoniker (){
        request = IEventSubscription2_get_SubscriberMoniker ()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_SubscriberMoniker(bstrMoniker interface{}){
        request = IEventSubscription2_put_SubscriberMoniker()
        request["bstrMoniker"] = bstrMoniker
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

 type IEventSubscription3 struct { // IEventSubscription2:
     func (self TYPE) __init__(interface interface{}){
        IEventSubscription2.__init__(self,interface)
        self._iid = IID_IEventSubscription3

     func (self TYPE) get_EventClassPartitionID(){
        request = IEventSubscription3_get_EventClassPartitionID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_EventClassPartitionID(bstrEventClassPartitionID interface{}){
        request = IEventSubscription3_put_EventClassPartitionID()
        request["bstrEventClassPartitionID"] = bstrEventClassPartitionID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_EventClassApplicationID(){
        request = IEventSubscription3_get_EventClassApplicationID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_EventClassApplicationID(bstrEventClassApplicationID interface{}){
        request = IEventSubscription3_put_EventClassApplicationID()
        request["bstrEventClassApplicationID"] = bstrEventClassApplicationID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_SubscriberPartitionID(){
        request = IEventSubscription3_get_SubscriberPartitionID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_SubscriberPartitionID(bstrSubscriberPartitionID interface{}){
        request = IEventSubscription3_put_SubscriberPartitionID()
        request["bstrSubscriberPartitionID"] = bstrSubscriberPartitionID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) get_SubscriberApplicationID(){
        request = IEventSubscription3_get_SubscriberApplicationID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

     func (self TYPE) put_SubscriberApplicationID(bstrSubscriberApplicationID interface{}){
        request = IEventSubscription3_put_SubscriberApplicationID()
        request["bstrSubscriberApplicationID"] = bstrSubscriberApplicationID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp


 type IEnumEventObject struct { // IDispatch:
     func (self TYPE) __init__(interface interface{}){
        IDispatch.__init__(self,interface)
        self._iid = IID_IEnumEventObject

     func (self TYPE) Clone(){
        request = IEnumEventObject_Clone()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return IEnumEventObject(INTERFACE(self.get_cinstance(), ''.join(resp["ppInterface"]["abData"]), self.get_ipidRemUnknown(), target = self.get_target()))

     func (self TYPE) Next(cReqElem interface{}){
        request = IEnumEventObject_Next()
        request["cReqElem"] = cReqElem
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        interfaces = list()
        for interface in resp["ppInterface"]:
            interfaces.append(IEventClass2(INTERFACE(self.get_cinstance(), ''.join(interface["abData"]), self.get_ipidRemUnknown(), target = self.get_target())))
        return interfaces

     func (self TYPE) Reset(){
        request = IEnumEventObject_Reset()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

     func (self TYPE) Skip(cSkipElem interface{}){
        request = IEnumEventObject_Skip()
        request["cSkipElem"] = cSkipElem
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

 type IEventObjectCollection struct { // IDispatch:
     func (self TYPE) __init__(interface interface{}){
        IDispatch.__init__(self,interface)
        self._iid = IID_IEventObjectCollection

     func (self TYPE) get__NewEnum(){
        request = IEventObjectCollection_get__NewEnum()
        resp = self.request(request, iid = self._iid , uuid = self.get_iPid())
        return IEnumEventObject(INTERFACE(self.get_cinstance(), ''.join(resp["ppEnum"]["abData"]), self.get_ipidRemUnknown(), target = self._get_target()))

     func (self TYPE) get_Item(objectID interface{}){
        request = IEventObjectCollection_get_Item()
        request["objectID"]["asData"] = objectID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

     func (self TYPE) get_NewEnum(){
        request = IEventObjectCollection_get_NewEnum()
        resp = self.request(request, iid = self._iid , uuid = self.get_iPid())
        return IEnumEventObject(INTERFACE(self.get_cinstance(), ''.join(resp["ppEnum"]["abData"]), self.get_ipidRemUnknown(), target = self.get_target()))

     func (self TYPE) get_Count(){
        request = IEventObjectCollection_get_Count()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

     func (self TYPE) Add(item, objectID interface{}){
        request = IEventObjectCollection_Add()
        request["item"] = item
        request["objectID"]["asData"] = objectID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

     func (self TYPE) Remove(objectID interface{}){
        request = IEventObjectCollection_Remove()
        request["objectID"]["asData"] = objectID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

 type IEventSystem struct { // IDispatch:
     func (self TYPE) __init__(interface interface{}){
        IDispatch.__init__(self,interface)
        self._iid = IID_IEventSystem

     func (self TYPE) Query(progID, queryCriteria interface{}){
        request = IEventSystem_Query()
        request["progID"]["asData"]=progID
        request["queryCriteria"]["asData"]=queryCriteria
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        iInterface = IDispatch(INTERFACE(self.get_cinstance(), ''.join(resp["ppInterface"]["abData"]), self.get_ipidRemUnknown(), target = self.get_target()))
        return IEventObjectCollection(iInterface.RemQueryInterface(1, (IID_IEventObjectCollection,)))

     func (self TYPE) Store(progID, pInterface interface{}){
        request = IEventSystem_Store()
        request["progID"]["asData"]=progID
        request["pInterface"] = pInterface
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

     func (self TYPE) Remove(progID, queryCriteria interface{}){
        request = IEventSystem_Remove()
        request["progID"]["asData"]=progID
        request["queryCriteria"] = queryCriteria
        resp = self.request(request, uuid = self.get_iPid())
        return resp

     func (self TYPE) get_EventObjectChangeEventClassID(){
        request = IEventSystem_get_EventObjectChangeEventClassID()
        resp = self.request(request, uuid = self.get_iPid())
        return resp

     func QueryS(self,progID, queryCriteria interface{}){
        request = IEventSystem_QueryS()
        request["progID"]["asData"]=progID
        request["queryCriteria"]["asData"]=queryCriteria
        resp = self.request(request, uuid = self.get_iPid())
        iInterface = IDispatch(INTERFACE(self.get_cinstance(), ''.join(resp["ppInterface"]["abData"]), self.get_ipidRemUnknown(), target = self.get_target()))
        return IEventObjectCollection(iInterface.RemQueryInterface(1, (IID_IEventObjectCollection,)))

     func RemoveS(self,progID, queryCriteria interface{}){
        request = IEventSystem_RemoveS()
        request["progID"]["asData"]=progID
        request["queryCriteria"]["asData"]=queryCriteria
        resp = self.request(request, uuid = self.get_iPid())
        return resp

 type IEventSystem2 struct { // IEventSystem:
     func (self TYPE) __init__(interface interface{}){
        IEventSystem.__init__(self,interface)
        self._iid = IID_IEventSystem2

     func (self TYPE) GetVersion(){
        request = IEventSystem2_GetVersion()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

     func (self TYPE) VerifyTransientSubscribers(){
        request = IEventSystem2_GetVersion()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

 type IEventSystemInitialize struct { // IRemUnknown:
     func (self TYPE) __init__(interface interface{}){
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IEventSystemInitialize

     func (self TYPE) SetCOMCatalogBehaviour(bRetainSubKeys interface{}){
        request = IEventSystem2_GetVersion()
        request["bRetainSubKeys"] = bRetainSubKeys
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp
