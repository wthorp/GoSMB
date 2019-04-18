// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Author: Alberto Solino (@agsolino)
//
// Description:
//   [MS-OAUT]: OLE Automation Protocol Implementation
//              This was used as a way to test the DCOM runtime. Further 
//              testing is needed to verify it is working as expected
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
import random
from struct import pack, unpack

from impacket import LOG
from impacket import hresult_errors
from impacket.dcerpc.v5.dcomrt import DCOMCALL, DCOMANSWER, IRemUnknown2, PMInterfacePointer, INTERFACE, \
    MInterfacePointer, MInterfacePointer_ARRAY, BYTE_ARRAY, PPMInterfacePointer
from impacket.dcerpc.v5.dtypes import LPWSTR, ULONG, DWORD, SHORT, GUID, USHORT, LONG, WSTR, BYTE, LONGLONG, FLOAT, \
    DOUBLE, HRESULT, PSHORT, PLONG, PLONGLONG, PFLOAT, PDOUBLE, PHRESULT, CHAR, ULONGLONG, INT, UINT, PCHAR, PUSHORT, \
    PULONG, PULONGLONG, PINT, PUINT, NULL
from impacket.dcerpc.v5.enum import Enum
from impacket.dcerpc.v5.ndr import NDRSTRUCT, NDRUniConformantArray, NDRPOINTER, NDRENUM, NDRUSHORT, NDRUNION, \
    NDRUniConformantVaryingArray, NDR
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.uuid import string_to_bin

 type DCERPCSessionError struct { // DCERPCException:
     func (self TYPE) __init__(error_string=nil, error_code=nil, packet=nil interface{}){
        DCERPCException.__init__(self, error_string, error_code, packet)

     func __str__( self  interface{}){
        if self.error_code in hresult_errors.ERROR_MESSAGES {
            error_msg_short = hresult_errors.ERROR_MESSAGES[self.error_code][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[self.error_code][1] 
            return 'OAUT SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        } else  {
            return 'OAUT SessionError: unknown error code: 0x%x' % (self.error_code)

//###############################################################################
// CONSTANTS
//###############################################################################
// 1.9 Standards Assignments
IID_IDispatch = string_to_bin("00020400-0000-0000-C000-000000000046")
IID_ITypeInfo = string_to_bin("00020401-0000-0000-C000-000000000046")
IID_ITypeComp = string_to_bin("00020403-0000-0000-C000-000000000046")
IID_NULL      = string_to_bin("00000000-0000-0000-0000-000000000000")

error_status_t = ULONG

LCID = DWORD
WORD = NDRUSHORT

// 2.2.2 IID
IID = GUID

// 2.2.3 LPOLESTR
LPOLESTR = LPWSTR
OLESTR = WSTR

// 2.2.4 REFIID
REFIID = IID

// 2.2.25 DATE
DATE = DOUBLE
 type PDATE struct { // NDRPOINTER:
    referent = (
        ('Data', DATE),
    }

// 2.2.27 VARIANT_BOOL
VARIANT_BOOL = USHORT

 type PVARIANT_BOOL struct { // NDRPOINTER:
    referent = (
        ('Data', VARIANT_BOOL),
    }

// 3.1.4.4 IDispatch::Invoke (Opnum 6)
// dwFlags
DISPATCH_METHOD         = 0x00000001
DISPATCH_PROPERTYGET    = 0x00000002
DISPATCH_PROPERTYPUT    = 0x00000004
DISPATCH_PROPERTYPUTREF = 0x00000008
DISPATCH_zeroVarResult  = 0x00020000
DISPATCH_zeroExcepInfo  = 0x00040000
DISPATCH_zeroArgErr     = 0x00080000

//###############################################################################
// STRUCTURES
//###############################################################################
// 2.2.26 DECIMAL
 type DECIMAL struct { // NDRSTRUCT: (
        ('wReserved',WORD),
        ('scale',BYTE),
        ('sign',BYTE),
        ('Hi32',ULONG),
        ('Lo64',ULONGLONG),
    }

 type PDECIMAL struct { // NDRPOINTER:
    referent = (
        ('Data', DECIMAL),
    }

// 2.2.7 VARIANT Type Constants
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
        VT_RECORD_OR_VT_BYREF   = VT_RECORD | VT_BYREF
        VT_UI1_OR_VT_BYREF      = VT_UI1 | VT_BYREF
        VT_I2_OR_VT_BYREF       = VT_I2 | VT_BYREF
        VT_I4_OR_VT_BYREF       = VT_I4 | VT_BYREF
        VT_I8_OR_VT_BYREF       = VT_I8 | VT_BYREF
        VT_R4_OR_VT_BYREF       = VT_R4 | VT_BYREF
        VT_R8_OR_VT_BYREF       = VT_R8 | VT_BYREF
        VT_BOOL_OR_VT_BYREF     = VT_BOOL | VT_BYREF
        VT_ERROR_OR_VT_BYREF    = VT_ERROR | VT_BYREF
        VT_CY_OR_VT_BYREF       = VT_CY | VT_BYREF
        VT_DATE_OR_VT_BYREF     = VT_DATE | VT_BYREF
        VT_BSTR_OR_VT_BYREF     = VT_BSTR | VT_BYREF
        VT_UNKNOWN_OR_VT_BYREF  = VT_UNKNOWN | VT_BYREF
        VT_DISPATCH_OR_VT_BYREF = VT_DISPATCH | VT_BYREF
        VT_ARRAY_OR_VT_BYREF    = VT_ARRAY | VT_BYREF
        VT_VARIANT_OR_VT_BYREF  = VT_VARIANT| VT_BYREF
        VT_I1_OR_VT_BYREF       = VT_I1 | VT_BYREF
        VT_UI2_OR_VT_BYREF      = VT_UI2 | VT_BYREF
        VT_UI4_OR_VT_BYREF      = VT_UI4 | VT_BYREF
        VT_UI8_OR_VT_BYREF      = VT_UI8 | VT_BYREF
        VT_INT_OR_VT_BYREF      = VT_INT | VT_BYREF
        VT_UINT_OR_VT_BYREF     = VT_UINT | VT_BYREF
        VT_DECIMAL_OR_VT_BYREF  = VT_DECIMAL | VT_BYREF

// 2.2.8 SAFEARRAY Feature Constants
 type SF_TYPE struct { // NDRENUM:
    // [v1_enum] type (
         Data uint32 // 
    }
     type enumItems struct { // Enum:
        SF_ERROR     = VARENUM.VT_ERROR
        SF_I1        = VARENUM.VT_I1
        SF_I2        = VARENUM.VT_I2
        SF_I4        = VARENUM.VT_I4
        SF_I8        = VARENUM.VT_I8
        SF_BSTR      = VARENUM.VT_BSTR
        SF_UNKNOWN   = VARENUM.VT_UNKNOWN
        SF_DISPATCH  = VARENUM.VT_DISPATCH
        SF_VARIANT   = VARENUM.VT_VARIANT
        SF_RECORD    = VARENUM.VT_RECORD
        SF_HAVEIID   = VARENUM.VT_UNKNOWN | 0x8000

// 2.2.10 CALLCONV Calling Convention Constants
 type CALLCONV struct { // NDRENUM:
    // [v1_enum] type (
         Data uint32 // 
    }
     type enumItems struct { // Enum:
        CC_CDECL   = 1
        CC_PASCAL  = 2
        CC_STDCALL = 4


// 2.2.12 FUNCKIND Function Access Constants
 type FUNCKIND struct { // NDRENUM:
    // [v1_enum] type (
         Data uint32 // 
    }
     type enumItems struct { // Enum:
        FUNC_PUREVIRTUAL = 1
        FUNC_STATIC      = 3
        FUNC_DISPATCH    = 4

// 2.2.14 INVOKEKIND Function Invocation Constants
 type INVOKEKIND struct { // NDRENUM:
    // [v1_enum] type (
         Data uint32 // 
    }
     type enumItems struct { // Enum:
        INVOKE_FUNC           = 1
        INVOKE_PROPERTYGET    = 2
        INVOKE_PROPERTYPUT    = 4
        INVOKE_PROPERTYPUTREF = 8

// 2.2.17 TYPEKIND Type Kind Constants
 type TYPEKIND struct { // NDRENUM:
    // [v1_enum] type (
         Data uint32 // 
    }
     type enumItems struct { // Enum:
        TKIND_ENUM      = 0
        TKIND_RECORD    = 1
        TKIND_MODULE    = 2
        TKIND_INTERFACE = 3
        TKIND_DISPATCH  = 4
        TKIND_COCLASS   = 5
        TKIND_ALIAS     = 6
        TKIND_UNION     = 7

// 2.2.23 BSTR
// 2.2.23.1 FLAGGED_WORD_BLOB
 type USHORT_ARRAY struct { // NDRUniConformantArray:
    item = "<H"

 type FLAGGED_WORD_BLOB struct { // NDRSTRUCT: (
        ('cBytes',ULONG),
        ('clSize',ULONG),
        ('asData',USHORT_ARRAY),
    }
     func (self TYPE) __setitem__(key, value interface{}){
        if key == 'asData' {
            value = value //+ '\x00'
            array = list()
            for letter in value:
                encoded = letter.encode("utf-16le")
                array.append(unpack('<H', encoded)[0])
            self.fields[key]["Data"] = array
            self.cBytes = len(value)*2
            self.clSize = len(value)
            self.data = nil        // force recompute
        } else  {
            return NDRSTRUCT.__setitem__(self, key, value)

     func (self TYPE) __getitem__(key interface{}){
        if key == 'asData' {
            value = ""
            for letter in self.fields["asData"]["Data"]:
                value += pack('<H', letter).decode("utf-16le")
            return value
        } else  {
            return NDRSTRUCT.__getitem__(self,key)

     func (self TYPE) dump(msg = nil, indent = 0 interface{}){
        if msg == nil { msg = self.__class__.__name__
        ind = " "*indent
        if msg != '' {
            print("%s" % (msg))
        value = ""
        print('%sasData: %s' % (ind,self.asData), end=' ')

// 2.2.23.2 BSTR Type Definition
 type BSTR struct { // NDRPOINTER:
    referent = (
        ('Data', FLAGGED_WORD_BLOB),
    }

 type PBSTR struct { // NDRPOINTER:
    referent = (
        ('Data', BSTR),
    }

// 2.2.24 CURRENCY
 type CURRENCY struct { // NDRSTRUCT: (
        ('int64', LONGLONG),
    }

 type PCURRENCY struct { // NDRPOINTER:
    referent = (
        ('Data', CURRENCY),
    }

// 2.2.28.2 BRECORD
// 2.2.28.2.1 _wireBRECORD
 type _wireBRECORD struct { // NDRSTRUCT: (
        ('fFlags', LONGLONG),
        ('clSize', LONGLONG),
        ('pRecInfo', MInterfacePointer),
        ('pRecord', BYTE_ARRAY),
    }

 type BRECORD struct { // NDRPOINTER:
    referent = (
        ('Data', _wireBRECORD),
    }

// 2.2.30 SAFEARRAY
// 2.2.30.1 SAFEARRAYBOUND
 type SAFEARRAYBOUND struct { // NDRSTRUCT: (
        ('cElements', ULONG),
        ('lLbound', LONG),
    }

 type PSAFEARRAYBOUND struct { // NDRPOINTER:
    referent = (
        ('Data', SAFEARRAYBOUND),
    }

// 2.2.30.2 SAFEARR_BSTR
 type BSTR_ARRAY struct { // NDRUniConformantArray:
    item = BSTR

 type PBSTR_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', BSTR_ARRAY),
    }

 type SAFEARR_BSTR struct { // NDRSTRUCT: (
        ('Size', ULONG),
        ('aBstr', PBSTR_ARRAY),
    }

// 2.2.30.3 SAFEARR_UNKNOWN
 type SAFEARR_UNKNOWN struct { // NDRSTRUCT: (
        ('Size', ULONG),
        ('apUnknown', MInterfacePointer_ARRAY),
    }

// 2.2.30.4 SAFEARR_DISPATCH
 type SAFEARR_DISPATCH struct { // NDRSTRUCT: (
        ('Size', ULONG),
        ('apDispatch', MInterfacePointer_ARRAY),
    }

// 2.2.30.6 SAFEARR_BRECORD
 type BRECORD_ARRAY struct { // NDRUniConformantArray:
    item = BRECORD

 type SAFEARR_BRECORD struct { // NDRSTRUCT: (
        ('Size', ULONG),
        ('aRecord', BRECORD_ARRAY),
    }

// 2.2.30.7 SAFEARR_HAVEIID
 type SAFEARR_HAVEIID struct { // NDRSTRUCT: (
        ('Size', ULONG),
        ('apUnknown', MInterfacePointer_ARRAY),
        ('iid', IID),
    }

// 2.2.30.8 Scalar-Sized Arrays
// 2.2.30.8.1 BYTE_SIZEDARR
 type BYTE_SIZEDARR struct { // NDRSTRUCT: (
        ('clSize', ULONG),
        ('pData', BYTE_ARRAY),
    }

// 2.2.30.8.2 WORD_SIZEDARR
 type WORD_ARRAY struct { // NDRUniConformantArray:
    item = "<H"

 type WORD_SIZEDARR struct { // NDRSTRUCT: (
        ('clSize', ULONG),
        ('pData', WORD_ARRAY),
    }

// 2.2.30.8.3 DWORD_SIZEDARR
 type DWORD_ARRAY struct { // NDRUniConformantArray:
    item = "<L"

 type DWORD_SIZEDARR struct { // NDRSTRUCT: (
        ('clSize', ULONG),
        ('pData', DWORD_ARRAY),
    }

// 2.2.30.8.4 HYPER_SIZEDARR
 type HYPER_ARRAY struct { // NDRUniConformantArray:
    item = "<Q"

 type HYPER_SIZEDARR struct { // NDRSTRUCT: (
        ('clSize', ULONG),
        ('pData', HYPER_ARRAY),
    }


// 2.2.36 HREFTYPE
HREFTYPE = DWORD

// 2.2.30.5 SAFEARR_VARIANT
 type VARIANT_ARRAY struct { // NDRUniConformantArray:
    // In order to avoid the lack of forward declarations in Python
    // I declare the item in the constructor
    //item = VARIANT
     func (self TYPE) __init__(data = nil, isNDR64 = false interface{}){
        NDRUniConformantArray.__init__(self, data, isNDR64)
        self.item = VARIANT

 type PVARIANT_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', VARIANT_ARRAY),
    }

 type PVARIANT struct { // NDRPOINTER:
    // In order to avoid the lack of forward declarations in Python
    // I declare the item in the constructor
    //referent = (
    //    ('Data', VARIANT),
    //)
     func (self TYPE) __init__(data = nil, isNDR64 = false interface{}){
        NDRPOINTER.__init__(self, data, isNDR64)
        self.referent = ( ('Data', VARIANT),)


 type SAFEARR_VARIANT struct { // NDRSTRUCT: (
        ('Size', ULONG),
        ('aVariant', VARIANT_ARRAY),
    }

// 2.2.30.9 SAFEARRAYUNION
 type SAFEARRAYUNION struct { // NDRUNION:
    commonHdr = (
        ('tag', ULONG),
    }
    union = {
        SF_TYPE.SF_BSTR     : ('BstrStr', SAFEARR_BSTR),
        SF_TYPE.SF_UNKNOWN  : ('UnknownStr', SAFEARR_UNKNOWN),
        SF_TYPE.SF_DISPATCH : ('DispatchStr', SAFEARR_DISPATCH),
        SF_TYPE.SF_VARIANT  : ('VariantStr', SAFEARR_VARIANT),
        SF_TYPE.SF_RECORD   : ('RecordStr', SAFEARR_BRECORD),
        SF_TYPE.SF_HAVEIID  : ('HaveIidStr', SAFEARR_HAVEIID),
        SF_TYPE.SF_I1       : ('ByteStr', BYTE_SIZEDARR),
        SF_TYPE.SF_I2       : ('WordStr', WORD_SIZEDARR),
        SF_TYPE.SF_I4       : ('LongStr', DWORD_SIZEDARR),
        SF_TYPE.SF_I8       : ('HyperStr', HYPER_SIZEDARR),
    }

// 2.2.30.10 SAFEARRAY
 type SAFEARRAYBOUND_ARRAY struct { // NDRUniConformantArray:
    item = SAFEARRAYBOUND

 type PSAFEARRAYBOUND_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SAFEARRAYBOUND_ARRAY),
    }

 type SAFEARRAY struct { // NDRSTRUCT: (
        ('cDims', USHORT),
        ('fFeatures', USHORT),
        ('cbElements', ULONG),
        ('cLocks', ULONG),
        ('uArrayStructs', SAFEARRAYUNION),
        ('rgsabound', SAFEARRAYBOUND_ARRAY),
    }

 type PSAFEARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SAFEARRAY),
    }

// 2.2.29 VARIANT
// 2.2.29.1 _wireVARIANT
 type EMPTY struct { // NDR:
    align = 0 (
    }

 type varUnion struct { // NDRUNION:
    commonHdr = (
        ('tag', ULONG),
    }
    union = {
        VARENUM.VT_I8                  : ('llVal', LONGLONG),
        VARENUM.VT_I4                  : ('lVal', LONG),
        VARENUM.VT_UI1                 : ('bVal', BYTE),
        VARENUM.VT_I2                  : ('iVal', SHORT),
        VARENUM.VT_R4                  : ('fltVal', FLOAT),
        VARENUM.VT_R8                  : ('dblVal', DOUBLE),
        VARENUM.VT_BOOL                : ('boolVal', VARIANT_BOOL),
        VARENUM.VT_ERROR               : ('scode', HRESULT),
        VARENUM.VT_CY                  : ('cyVal', CURRENCY),
        VARENUM.VT_DATE                : ('date', DATE),
        VARENUM.VT_BSTR                : ('bstrVal', BSTR),
        VARENUM.VT_UNKNOWN             : ('punkVal', PMInterfacePointer),
        VARENUM.VT_DISPATCH            : ('pdispVal', PMInterfacePointer),
        VARENUM.VT_ARRAY               : ('parray', SAFEARRAY),
        VARENUM.VT_RECORD              : ('brecVal', BRECORD),
        VARENUM.VT_RECORD_OR_VT_BYREF  : ('brecVal', BRECORD),
        VARENUM.VT_UI1_OR_VT_BYREF     : ('pbVal', BYTE),
        VARENUM.VT_I2_OR_VT_BYREF      : ('piVal', PSHORT),
        VARENUM.VT_I4_OR_VT_BYREF      : ('plVal', PLONG),
        VARENUM.VT_I8_OR_VT_BYREF      : ('pllVal', PLONGLONG),
        VARENUM.VT_R4_OR_VT_BYREF      : ('pfltVal', PFLOAT),
        VARENUM.VT_R8_OR_VT_BYREF      : ('pdblVal', PDOUBLE),
        VARENUM.VT_BOOL_OR_VT_BYREF    : ('pboolVal', PVARIANT_BOOL),
        VARENUM.VT_ERROR_OR_VT_BYREF   : ('pscode', PHRESULT),
        VARENUM.VT_CY_OR_VT_BYREF      : ('pcyVal', PCURRENCY),
        VARENUM.VT_DATE_OR_VT_BYREF    : ('pdate', PDATE),
        VARENUM.VT_BSTR_OR_VT_BYREF    : ('pbstrVal', PBSTR),
        VARENUM.VT_UNKNOWN_OR_VT_BYREF : ('ppunkVal', PPMInterfacePointer),
        VARENUM.VT_DISPATCH_OR_VT_BYREF: ('ppdispVal', PPMInterfacePointer),
        VARENUM.VT_ARRAY_OR_VT_BYREF   : ('pparray', PSAFEARRAY),
        VARENUM.VT_VARIANT_OR_VT_BYREF : ('pvarVal', PVARIANT),
        VARENUM.VT_I1                  : ('cVal', CHAR),
        VARENUM.VT_UI2                 : ('uiVal', USHORT),
        VARENUM.VT_UI4                 : ('ulVal', ULONG),
        VARENUM.VT_UI8                 : ('ullVal', ULONGLONG),
        VARENUM.VT_INT                 : ('intVal', INT),
        VARENUM.VT_UINT                : ('uintVal', UINT),
        VARENUM.VT_DECIMAL             : ('decVal', DECIMAL),
        VARENUM.VT_I1_OR_VT_BYREF      : ('pcVal', PCHAR),
        VARENUM.VT_UI2_OR_VT_BYREF     : ('puiVal', PUSHORT),
        VARENUM.VT_UI4_OR_VT_BYREF     : ('pulVal', PULONG),
        VARENUM.VT_UI8_OR_VT_BYREF     : ('pullVal', PULONGLONG),
        VARENUM.VT_INT_OR_VT_BYREF     : ('pintVal', PINT),
        VARENUM.VT_UINT_OR_VT_BYREF    : ('puintVal', PUINT),
        VARENUM.VT_DECIMAL_OR_VT_BYREF : ('pdecVal', PDECIMAL),
        VARENUM.VT_EMPTY               : ('empty', EMPTY),
        VARENUM.VT_NULL                : ('null', EMPTY),
    }

 type wireVARIANTStr struct { // NDRSTRUCT: (
        ('clSize',DWORD),
        ('rpcReserved',DWORD),
        ('vt',USHORT),
        ('wReserved1',USHORT),
        ('wReserved2',USHORT),
        ('wReserved3',USHORT),
        ('_varUnion',varUnion),
    }

     func (self TYPE) getAlignment(){
        return 8

 type VARIANT struct { // NDRPOINTER:
    referent = (
        ('Data', wireVARIANTStr),
    }

 type PVARIANT struct { // NDRPOINTER:
    referent = (
        ('Data', VARIANT),
    }

// 2.2.32 DISPID
DISPID = LONG

// 2.2.33 DISPPARAMS
 type DISPID_ARRAY struct { // NDRUniConformantArray:
    item = "<L"

 type PDISPID_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', DISPID_ARRAY),
    }

 type DISPPARAMS struct { // NDRSTRUCT: (
        ('rgvarg',PVARIANT_ARRAY),
        ('rgdispidNamedArgs', PDISPID_ARRAY),
        ('cArgs', UINT),
        ('cNamedArgs', UINT),
    }

// 2.2.34 EXCEPINFO
 type EXCEPINFO struct { // NDRSTRUCT: (
        ('wCode',WORD),
        ('wReserved', WORD),
        ('bstrSource', BSTR),
        ('bstrDescription', BSTR),
        ('bstrHelpFile', BSTR),
        ('dwHelpContext', DWORD),
        ('pvReserved', ULONG),
        ('pfnDeferredFillIn', ULONG),
        ('scode', HRESULT),
    }

// 2.2.35 MEMBERID
MEMBERID = DISPID

// 2.2.38 ARRAYDESC
 type ARRAYDESC struct { // NDRSTRUCT:
    // In order to avoid the lack of forward declarations in Python
    // I declare the item in the constructor
    // (
    //    ('tdescElem',TYPEDESC),
    //    ('cDims',USHORT),
    //    ('rgbounds',SAFEARRAYBOUND_ARRAY),
    //)
     func (self TYPE) __init__(data = nil, isNDR64 = false interface{}){
        NDRSTRUCT.__init__(self, data, isNDR64)
        self. (
            ('tdescElem',TYPEDESC),
            ('cDims',USHORT),
            ('rgbounds',SAFEARRAYBOUND_ARRAY),
        }

// 2.2.37 TYPEDESC
 type tdUnion struct { // NDRUNION:
    notAlign = true
    commonHdr = (
        ('tag', USHORT),
    }
    // In order to avoid the lack of forward declarations in Python
    // I declare the item in the constructor
    //union = {
    //    VARENUM.VT_PTR: ('lptdesc', tdUnion),
    //    VARENUM.VT_SAFEARRAY: ('lptdesc', tdUnion),
    //    VARENUM.VT_CARRAY: ('lpadesc', ARRAYDESC),
    //    VARENUM.VT_USERDEFINED: ('hreftype', HREFTYPE),
    //}
     func (self TYPE) __init__(data = nil, isNDR64=false, topLevel = false interface{}){
        NDRUNION.__init__(self,nil, isNDR64=isNDR64, topLevel=topLevel)
        self.union = {
            VARENUM.VT_PTR: ('lptdesc', PTYPEDESC),
            VARENUM.VT_SAFEARRAY: ('lptdesc', PTYPEDESC),
            VARENUM.VT_CARRAY: ('lpadesc', ARRAYDESC),
            VARENUM.VT_USERDEFINED: ('hreftype', HREFTYPE),
            'default': nil,
        }

 type TYPEDESC struct { // NDRSTRUCT: (
        ('vtType',tdUnion),
        ('vt', VARENUM),
    }

     func (self TYPE) getAlignment(){
        return 4

 type PTYPEDESC struct { // NDRPOINTER:
    referent = (
        ('Data', TYPEDESC),
    }
     func (self TYPE) __init__(data = nil, isNDR64=false, topLevel = false interface{}){
        ret = NDRPOINTER.__init__(self,nil, isNDR64=isNDR64, topLevel = false)
        // We're forcing the pointer not to be topLevel
        if data == nil {
            self.fields["ReferentID"] = random.randint(1,65535)
        } else  {
           self.fromString(data)


// 2.2.48 SCODE
SCODE = LONG

 type SCODE_ARRAY struct { // NDRUniConformantArray:
    item = SCODE

 type PSCODE_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SCODE_ARRAY),
    }

// 2.2.39 PARAMDESCEX
 type PARAMDESCEX struct { // NDRSTRUCT: (
        ('cBytes',ULONG),
        ('varDefaultValue',VARIANT),
    }

 type PPARAMDESCEX struct { // NDRPOINTER:
    referent = (
        ('Data', PARAMDESCEX),
    }


// 2.2.40 PARAMDESC
 type PARAMDESC struct { // NDRSTRUCT: (
        ('pparamdescex',PPARAMDESCEX),
        ('wParamFlags',USHORT),
    }

// 2.2.41 ELEMDESC
 type ELEMDESC struct { // NDRSTRUCT: (
        ('tdesc',TYPEDESC),
        ('paramdesc',PARAMDESC),
    }

 type ELEMDESC_ARRAY struct { // NDRUniConformantArray:
    item = ELEMDESC

 type PELEMDESC_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', ELEMDESC_ARRAY),
    }

// 2.2.42 FUNCDESC
 type FUNCDESC struct { // NDRSTRUCT: (
        ('memid',MEMBERID),
        ('lReserved1',PSCODE_ARRAY),
        ('lprgelemdescParam',PELEMDESC_ARRAY),
        ('funckind',FUNCKIND),
        ('invkind',INVOKEKIND),
        ('callconv',CALLCONV),
        ('cParams',SHORT),
        ('cParamsOpt',SHORT),
        ('oVft',SHORT),
        ('cReserved2',SHORT),
        ('elemdescFunc',ELEMDESC),
        ('wFuncFlags',WORD),
    }

 type LPFUNCDESC struct { // NDRPOINTER:
    referent = (
        ('Data', FUNCDESC),
    }
// 2.2.44 TYPEATTR
 type TYPEATTR struct { // NDRSTRUCT: (
        ('guid',GUID),
        ('lcid',LCID),
        ('dwReserved1',DWORD),
        ('dwReserved2',DWORD),
        ('dwReserved3',DWORD),
        ('lpstrReserved4',LPOLESTR),
        ('cbSizeInstance',ULONG),
        ('typeKind',TYPEKIND),
        ('cFuncs',WORD),
        ('cVars',WORD),
        ('cImplTypes',WORD),
        ('cbSizeVft',WORD),
        ('cbAlignment',WORD),
        ('wTypeFlags',WORD),
        ('wMajorVerNum',WORD),
        ('wMinorVerNum',WORD),
        ('tdescAlias',TYPEDESC),
        ('dwReserved5',DWORD),
        ('dwReserved6',WORD),
    }

 type PTYPEATTR struct { // NDRPOINTER:
    referent = (
        ('Data', TYPEATTR),
    }

 type BSTR_ARRAY_CV struct { // NDRUniConformantVaryingArray:
    item = BSTR

 type UINT_ARRAY struct { // NDRUniConformantArray:
    item = "<L"

 type OLESTR_ARRAY struct { // NDRUniConformantArray:
    item = LPOLESTR


//###############################################################################
// RPC CALLS
//###############################################################################
// 3.1.4.1 IDispatch::GetTypeInfoCount (Opnum 3)
 type IDispatch_GetTypeInfoCount struct { // DCOMCALL:
    opnum = 3 (
       ('pwszMachineName', LPWSTR),
    }

 type IDispatch_GetTypeInfoCountResponse struct { // DCOMANSWER: (
       ('pctinfo', ULONG),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.2 IDispatch::GetTypeInfo (Opnum 4)
 type IDispatch_GetTypeInfo struct { // DCOMCALL:
    opnum = 4 (
       ('iTInfo', ULONG),
       ('lcid', DWORD),
    }

 type IDispatch_GetTypeInfoResponse struct { // DCOMANSWER: (
       ('ppTInfo', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.3 IDispatch::GetIDsOfNames (Opnum 5)
 type IDispatch_GetIDsOfNames struct { // DCOMCALL:
    opnum = 5 (
       ('riid', REFIID),
       ('rgszNames', OLESTR_ARRAY),
       ('cNames', UINT),
       ('lcid', LCID),
    }

 type IDispatch_GetIDsOfNamesResponse struct { // DCOMANSWER: (
       ('rgDispId', DISPID_ARRAY),
       ('ErrorCode', error_status_t),
    }

// 3.1.4.4 IDispatch::Invoke (Opnum 6)
 type IDispatch_Invoke struct { // DCOMCALL:
    opnum = 6 (
       ('dispIdMember', DISPID),
       ('riid', REFIID),
       ('lcid', LCID),
       ('dwFlags', DWORD),
       ('pDispParams', DISPPARAMS),
       ('cVarRef', UINT),
       ('rgVarRefIdx', UINT_ARRAY),
       ('rgVarRef', VARIANT_ARRAY),
    }

 type IDispatch_InvokeResponse struct { // DCOMANSWER: (
       ('pVarResult', VARIANT),
       ('pExcepInfo', EXCEPINFO),
       ('pArgErr', UINT),
       ('ErrorCode', error_status_t),
    }

// 3.7.4.1 ITypeInfo::GetTypeAttr (Opnum 3)
 type ITypeInfo_GetTypeAttr struct { // DCOMCALL:
    opnum = 3 (
    }

 type ITypeInfo_GetTypeAttrResponse struct { // DCOMANSWER: (
       ('ppTypeAttr', PTYPEATTR),
       ('pReserved', DWORD),
       ('ErrorCode', error_status_t),
    }

// 3.7.4.2 ITypeInfo::GetTypeComp (Opnum 4)
 type ITypeInfo_GetTypeComp struct { // DCOMCALL:
    opnum = 4 (
    }

 type ITypeInfo_GetTypeCompResponse struct { // DCOMANSWER: (
       ('ppTComp', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    }

// 3.7.4.3 ITypeInfo::GetFuncDesc (Opnum 5)
 type ITypeInfo_GetFuncDesc struct { // DCOMCALL:
    opnum = 5 (
       ('index', UINT),
    }

 type ITypeInfo_GetFuncDescResponse struct { // DCOMANSWER: (
       ('ppFuncDesc', LPFUNCDESC),
       ('pReserved', DWORD),
       ('ErrorCode', error_status_t),
    }

// 3.7.4.5 ITypeInfo::GetNames (Opnum 7)
 type ITypeInfo_GetNames struct { // DCOMCALL:
    opnum = 7 (
       ('memid', MEMBERID),
       ('cMaxNames', UINT),
    }

 type ITypeInfo_GetNamesResponse struct { // DCOMANSWER: (
       ('rgBstrNames', BSTR_ARRAY_CV),
       ('pcNames', UINT),
       ('ErrorCode', error_status_t),
    }

// 3.7.4.8 ITypeInfo::GetDocumentation (Opnum 12)
 type ITypeInfo_GetDocumentation struct { // DCOMCALL:
    opnum = 12 (
       ('memid', MEMBERID),
       ('refPtrFlags', DWORD),
    }

 type ITypeInfo_GetDocumentationResponse struct { // DCOMANSWER: (
       ('pBstrName', BSTR),
       ('pBstrDocString', BSTR),
       ('pdwHelpContext', DWORD),
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
// 4.8.5 Enumerating All Methods in an Interface
// INPUT: IDispatch pointer from the automation server
// CALL IDispatch::GetTypeInfoCount and OBTAIN pcTInfo
// COMMENT see Section 3.1.4.1 for information on pcTInfo i
// IF pcTInfo = 0 THEN
//     PRINT Automation Server does not support type information for this object
// ELSE
//     CALL IDispatch::GetTypeInfo with correct LocaleID and OBTAIN ITypeInfo pointer
//     CALL ITypeInfo::GetDocumentation(MEMBERID_NIL, 1, &BstrName, NULL, NULL, NULL)
//     PRINT Name of the Interface is BstrName
//     CALL ITypeInfo::GetTypeAttr and OBTAIN TYPEATTR pointer
//
//     FOR X = 0 to TYPEATTR:: cFuncs -1
//         CALL ITypeInfo::GetFuncDesc with X and OBTAIN FUNCDESC pointer
//         CALL ITypeInfo::GetNames with FUNCDESC::memid and appropriate values for
//             rgBstrNames, cMaxNames and pcNames
//         COMMENT see Section 3.7.4.5 for more information regarding the parameters
//                 to ITypeinfo::GetNames
//         IF pcNames > 0 THEN
//             PRINT Name of the method is rgBstrNames[0]
//             PRINT Parameters to above method are following
//             FOR Y = 1 to pcNames -1
//                 PRINT rgBstrNames[Y]
//             END FOR
//         END IF
//     END FOR i
// ENDIF
 func enumerateMethods(iInterface interface{}){
    methods = dict()
    typeInfoCount = iInterface.GetTypeInfoCount()
    if typeInfoCount["pctinfo"] == 0 {
        LOG.error("Automation Server does not support type information for this object")
        return {}
    iTypeInfo = iInterface.GetTypeInfo()
    iTypeAttr = iTypeInfo.GetTypeAttr()
    for x in range(iTypeAttr["ppTypeAttr"]["cFuncs"]):
        funcDesc = iTypeInfo.GetFuncDesc(x)
        names = iTypeInfo.GetNames(funcDesc["ppFuncDesc"]["memid"], 255)
        print(names["rgBstrNames"][0]["asData"])
        funcDesc.dump()
        print('='*80)
        if names["pcNames"] > 0 {
            name = names["rgBstrNames"][0]["asData"]
            methods[name] = {}
            for param in range(1, names["pcNames"]):
                methods[name][names["rgBstrNames"][param]["asData"]] = ""
        if funcDesc["ppFuncDesc"]["elemdescFunc"] != NULL {
            methods[name]["ret"] = funcDesc["ppFuncDesc"]["elemdescFunc"]["tdesc"]["vt"]

    return methods

 func checkNullString(string interface{}){
    if string == NULL {
        return string

    if string[-1:] != '\x00' {
        return string + '\x00'
    } else  {
        return string

 type ITypeComp struct { // IRemUnknown2:
     func (self TYPE) __init__(interface interface{}){
        IRemUnknown2.__init__(self,interface)
        self._iid = IID_ITypeComp

 type ITypeInfo struct { // IRemUnknown2:
     func (self TYPE) __init__(interface interface{}){
        IRemUnknown2.__init__(self,interface)
        self._iid = IID_ITypeInfo

     func (self TYPE) GetTypeAttr(){
        request = ITypeInfo_GetTypeAttr()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

     func (self TYPE) GetTypeComp(){
        request = ITypeInfo_GetTypeComp()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return ITypeComp(INTERFACE(self.get_cinstance(), ''.join(resp["ppTComp"]["abData"]), self.get_ipidRemUnknown(), target = self.get_target()))

     func (self TYPE) GetFuncDesc(index interface{}){
        request = ITypeInfo_GetFuncDesc()
        request["index"] = index
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

     func (self TYPE) GetNames(memid, cMaxNames=10 interface{}){
        request = ITypeInfo_GetNames()
        request["memid"] = memid
        request["cMaxNames"] = cMaxNames
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

     func (self TYPE) GetDocumentation(memid, refPtrFlags=15 interface{}){
        request = ITypeInfo_GetDocumentation()
        request["memid"] = memid
        request["refPtrFlags"] = refPtrFlags
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp


 type IDispatch struct { // IRemUnknown2:
     func (self TYPE) __init__(interface interface{}){
        IRemUnknown2.__init__(self,interface)
        self._iid = IID_IDispatch

     func (self TYPE) GetTypeInfoCount(){
        request = IDispatch_GetTypeInfoCount()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

     func (self TYPE) GetTypeInfo(){
        request = IDispatch_GetTypeInfo()
        request["iTInfo"] = 0
        request["lcid"] = 0
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return ITypeInfo(INTERFACE(self.get_cinstance(), ''.join(resp["ppTInfo"]["abData"]), self.get_ipidRemUnknown(), target = self.get_target()))

     func (self TYPE) GetIDsOfNames(rgszNames, lcid = 0 interface{}){
        request = IDispatch_GetIDsOfNames()
        request["riid"] = IID_NULL
        for name in rgszNames:
            tmpName = LPOLESTR()
            tmpName["Data"] = checkNullString(name)
            request["rgszNames"].append(tmpName)
        request["cNames"] = len(rgszNames)
        request["lcid"] = lcid
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        IDs = list()
        for id in resp["rgDispId"]:
            IDs.append(id)

        return IDs

     func (self TYPE) Invoke(dispIdMember, lcid, dwFlags, pDispParams, cVarRef, rgVarRefIdx, rgVarRef interface{}){
        request = IDispatch_Invoke()
        request["dispIdMember"] = dispIdMember
        request["riid"] = IID_NULL
        request["lcid"] = lcid
        request["dwFlags"] = dwFlags
        request["pDispParams"] = pDispParams
        request["cVarRef"] = cVarRef
        request["rgVarRefIdx"] = rgVarRefIdx
        request["rgVarRef"] = rgVarRefIdx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp
