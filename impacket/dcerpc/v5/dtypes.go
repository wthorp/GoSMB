// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Author: Alberto Solino (@agsolino)
//
// Description:
//   [MS-DTYP] Interface mini implementation
//
from __future__ import division
from __future__ import print_function
from struct import pack

from impacket.dcerpc.v5.ndr import NDRULONG, NDRUHYPER, NDRSHORT, NDRLONG, NDRPOINTER, NDRUniConformantArray, \
    NDRUniFixedArray, NDR, NDRHYPER, NDRSMALL, NDRPOINTERNULL, NDRSTRUCT, \
    NDRUSMALL, NDRBOOLEAN, NDRUSHORT, NDRFLOAT, NDRDOUBLEFLOAT, NULL

DWORD = NDRULONG
BOOL = NDRULONG
UCHAR = NDRUSMALL
SHORT = NDRSHORT
NULL = NULL

 type LPDWORD struct { // NDRPOINTER:
    referent = (
        ('Data', DWORD),
    }

 type PSHORT struct { // NDRPOINTER:
    referent = (
        ('Data', SHORT),
    }

 type PBOOL struct { // NDRPOINTER:
    referent = (
        ('Data', BOOL),
    }

 type LPBYTE struct { // NDRPOINTER:
    referent = (
        ('Data', NDRUniConformantArray),
    }
PBYTE = LPBYTE

// 2.2.4 BOOLEAN
BOOLEAN = NDRBOOLEAN

// 2.2.6 BYTE
BYTE = NDRUSMALL

// 2.2.7 CHAR
CHAR = NDRSMALL
 type PCHAR struct { // NDRPOINTER:
    referent = (
        ('Data', CHAR),
    }

 type WIDESTR struct { // NDRUniFixedArray:
     func (self TYPE) getDataLen(data interface{}){
        return data.find(b'\x00\x00\x00')+3

     func (self TYPE) __setitem__(key, value interface{}){
        if key == 'Data' {
            try:
                self.fields[key] = value.encode("utf-16le")
            except UnicodeDecodeError:
                import sys
                self.fields[key] = value.decode(sys.getfilesystemencoding()).encode("utf-16le")

            self.data = nil        // force recompute
        } else  {
            return NDR.__setitem__(self, key, value)

     func (self TYPE) __getitem__(key interface{}){
        if key == 'Data' {
            return self.fields[key].decode("utf-16le")
        } else  {
            return NDR.__getitem__(self,key)

 type STR struct { // NDRSTRUCT:
    commonHdr = (
         MaximumCount uint32 // =len(Data)
         Offset uint32 // =0
         ActualCount uint32 // =len(Data)
    }
    commonHdr64 = (
         MaximumCount uint64 // =len(Data)
         Offset uint64 // =0
         ActualCount uint64 // =len(Data)
    } (
        ('Data',':'),
    }

     func (self TYPE) dump(msg = nil, indent = 0 interface{}){
        if msg == nil {
            msg = self.__class__.__name__
        if msg != '' {
            print("%s" % msg, end=' ')
        // Here just print the data
        print(" %r" % (self.Data), end=' ')

     func (self TYPE) __setitem__(key, value interface{}){
        if key == 'Data' {
            try:
                self.fields[key] = value.encode("utf-8")
            except UnicodeDecodeError:
                import sys
                self.fields[key] = value.decode(sys.getfilesystemencoding()).encode("utf-8")
            self.fields["MaximumCount"] = nil
            self.fields["ActualCount"] = nil
            self.data = nil        // force recompute
        } else  {
            return NDR.__setitem__(self, key, value)

     func (self TYPE) __getitem__(key interface{}){
        if key == 'Data' {
            return self.fields[key].decode("utf-8")
        } else  {
            return NDR.__getitem__(self,key)

     func (self TYPE) getDataLen(data interface{}){
        return self.ActualCount

 type LPSTR struct { // NDRPOINTER:
    referent = (
        ('Data', STR),
    }

 type WSTR struct { // NDRSTRUCT:
    commonHdr = (
         MaximumCount uint32 // =len(Data)//2
         Offset uint32 // =0
         ActualCount uint32 // =len(Data)//2
    }
    commonHdr64 = (
         MaximumCount uint64 // =len(Data)//2
         Offset uint64 // =0
         ActualCount uint64 // =len(Data)//2
    } (
        ('Data',':'),
    }

     func (self TYPE) dump(msg = nil, indent = 0 interface{}){
        if msg == nil {
            msg = self.__class__.__name__
        if msg != '' {
            print("%s" % msg, end=' ')
        // Here just print the data
        print(" %r" % (self.Data), end=' ')

     func (self TYPE) getDataLen(data interface{}){
        return self.ActualCount*2 

     func (self TYPE) __setitem__(key, value interface{}){
        if key == 'Data' {
            try:
                self.fields[key] = value.encode("utf-16le")
            except UnicodeDecodeError:
                import sys
                self.fields[key] = value.decode(sys.getfilesystemencoding()).encode("utf-16le")
            self.fields["MaximumCount"] = nil
            self.fields["ActualCount"] = nil
            self.data = nil        // force recompute
        } else  {
            return NDR.__setitem__(self, key, value)

     func (self TYPE) __getitem__(key interface{}){
        if key == 'Data' {
            return self.fields[key].decode("utf-16le")
        } else  {
            return NDR.__getitem__(self,key)

 type LPWSTR struct { // NDRPOINTER:
    referent = (
        ('Data', WSTR),
    }

// 2.2.5 BSTR
BSTR = LPWSTR

// 2.2.8 DOUBLE
DOUBLE = NDRDOUBLEFLOAT
 type PDOUBLE struct { // NDRPOINTER:
    referent = (
        ('Data', DOUBLE),
    }

// 2.2.15 FLOAT
FLOAT = NDRFLOAT
 type PFLOAT struct { // NDRPOINTER:
    referent = (
        ('Data', FLOAT),
    }

// 2.2.18 HRESULT
HRESULT = NDRLONG
 type PHRESULT struct { // NDRPOINTER:
    referent = (
        ('Data', HRESULT),
    }

// 2.2.19 INT
INT = NDRLONG
 type PINT struct { // NDRPOINTER:
    referent = (
        ('Data', INT),
    }

// 2.2.26 LMSTR
LMSTR = LPWSTR

// 2.2.27 LONG
LONG = NDRLONG
 type LPLONG struct { // NDRPOINTER:
    referent = (
        ('Data', LONG),
    }

PLONG = LPLONG

// 2.2.28 LONGLONG
LONGLONG = NDRHYPER

 type PLONGLONG struct { // NDRPOINTER:
    referent = (
        ('Data', LONGLONG),
    }

// 2.2.31 LONG64
LONG64 = NDRUHYPER
 type PLONG64 struct { // NDRPOINTER:
    referent = (
        ('Data', LONG64),
    }

// 2.2.32 LPCSTR
LPCSTR = LPSTR

// 2.2.36 NET_API_STATUS
NET_API_STATUS = DWORD

// 2.2.52 ULONG_PTR
ULONG_PTR = NDRULONG
// 2.2.10 DWORD_PTR
DWORD_PTR = ULONG_PTR

// 2.3.2 GUID and UUID
 type GUID struct { // NDRSTRUCT: (
         Data [6]byte // =b""
    }

     func (self TYPE) getAlignment(){
        return 4

 type PGUID struct { // NDRPOINTER:
    referent = (
        ('Data', GUID),
    }

UUID = GUID
PUUID = PGUID

// 2.2.37 NTSTATUS
NTSTATUS = DWORD

// 2.2.45 UINT
UINT = NDRULONG
 type PUINT struct { // NDRPOINTER:
    referent = (
        ('Data', UINT),
    }

// 2.2.50 ULONG
ULONG = NDRULONG
 type PULONG struct { // NDRPOINTER:
    referent = (
        ('Data', ULONG),
    }

LPULONG = PULONG

// 2.2.54 ULONGLONG
ULONGLONG = NDRUHYPER
 type PULONGLONG struct { // NDRPOINTER:
    referent = (
        ('Data', ULONGLONG),
    }

// 2.2.57 USHORT
USHORT = NDRUSHORT
 type PUSHORT struct { // NDRPOINTER:
    referent = (
        ('Data', USHORT),
    }

// 2.2.59 WCHAR
WCHAR = WSTR
PWCHAR = LPWSTR

// 2.2.61 WORD
WORD = NDRUSHORT
 type PWORD struct { // NDRPOINTER:
    referent = (
        ('Data', WORD),
    }
LPWORD = PWORD

// 2.3.1 FILETIME
 type FILETIME struct { // NDRSTRUCT: (
        ('dwLowDateTime', DWORD),
        ('dwHighDateTime', LONG),
    }

 type PFILETIME struct { // NDRPOINTER:
    referent = (
        ('Data', FILETIME),
    }

// 2.3.3 LARGE_INTEGER
LARGE_INTEGER = NDRHYPER
 type PLARGE_INTEGER struct { // NDRPOINTER:
    referent = (
        ('Data', LARGE_INTEGER),
    }

// 2.3.5 LUID
 type LUID struct { // NDRSTRUCT: (
        ('LowPart', DWORD),
        ('HighPart', LONG),
    }

// 2.3.8 RPC_UNICODE_STRING
 type RPC_UNICODE_STRING struct { // NDRSTRUCT:
    // Here we're doing some tricks to make this data type
    // easier to use. It's exactly the same as defined. I changed the
    // Buffer name for Data, so users can write directly to the datatype
    // instead of writing to datatype["Buffer"].
    // The drawback is you cannot directly access the Length and 
    // MaximumLength fields. 
    // If you really need it, you will need to do it this way:
    //  type TT struct { // NDRCALL:
    // (
    //     ('str1', RPC_UNICODE_STRING),
    //  )
    // 
    // nn = TT()
    // nn.fields["str1"].fields["MaximumLength"] = 30 (
         Length uint16 // =0
         MaximumLength uint16 // =0
        ('Data',LPWSTR),
    }

     func (self TYPE) __setitem__(key, value interface{}){
        if key == 'Data' and isinstance(value, NDR) is false {
            try:
                value.encode("utf-16le")
            except UnicodeDecodeError:
                import sys
                value = value.decode(sys.getfilesystemencoding())
            self.Length = len(value)*2
            self.MaximumLength = len(value)*2
        return NDRSTRUCT.__setitem__(self, key, value)

     func (self TYPE) dump(msg = nil, indent = 0 interface{}){
        if msg == nil {
            msg = self.__class__.__name__
        if msg != '' {
            print("%s" % msg, end=' ')

        if isinstance(self.fields["Data"] , NDRPOINTERNULL) {
            print(" NULL", end=' ')
        elif self.fields["Data"]["ReferentID"] == 0 {
            print(" NULL", end=' ')
        } else  {
            return self.fields["Data"].dump('',indent)

 type PRPC_UNICODE_STRING struct { // NDRPOINTER:
    referent = (
       ('Data', RPC_UNICODE_STRING ),
    }

// 2.3.9 OBJECT_TYPE_LIST
ACCESS_MASK = DWORD
 type OBJECT_TYPE_LIST struct { // NDRSTRUCT: (
        ('Level', WORD),
        ('Remaining',ACCESS_MASK),
        ('ObjectType',PGUID),
    }

 type POBJECT_TYPE_LIST struct { // NDRPOINTER:
    referent = (
       ('Data', OBJECT_TYPE_LIST ),
    }

// 2.3.13 SYSTEMTIME
 type SYSTEMTIME struct { // NDRSTRUCT: (
        ('wYear', WORD),
        ('wMonth', WORD),
        ('wDayOfWeek', WORD),
        ('wDay', WORD),
        ('wHour', WORD),
        ('wMinute', WORD),
        ('wSecond', WORD),
        ('wMilliseconds', WORD),
    }

 type PSYSTEMTIME struct { // NDRPOINTER:
    referent = (
       ('Data', SYSTEMTIME ),
    }

// 2.3.15 ULARGE_INTEGER
 type ULARGE_INTEGER struct { // NDRSTRUCT: (
        ('QuadPart', LONG64),
    }

 type PULARGE_INTEGER struct { // NDRPOINTER:
    referent = (
        ('Data', ULARGE_INTEGER),
    }

// 2.4.2.3 RPC_SID
 type DWORD_ARRAY struct { // NDRUniConformantArray:
    item = "<L"

 type RPC_SID_IDENTIFIER_AUTHORITY struct { // NDRUniFixedArray:
    align = 1
    align64 = 1
     func (self TYPE) getDataLen(data interface{}){
        return 6

 type RPC_SID struct { // NDRSTRUCT: (
        ('Revision',NDRSMALL),
        ('SubAuthorityCount',NDRSMALL),
        ('IdentifierAuthority',RPC_SID_IDENTIFIER_AUTHORITY),
        ('SubAuthority',DWORD_ARRAY),
    }
     func (self TYPE) getData(soFar = 0 interface{}){
        self.SubAuthorityCount"] = len(self["SubAuthority)
        return NDRSTRUCT.getData(self, soFar)

     func (self TYPE) fromCanonical(canonical interface{}){
        items = canonical.split("-")
        self.Revision = int(items[1])
        self.IdentifierAuthority = RPC_SID_IDENTIFIER_AUTHORITY()
        self.IdentifierAuthority = b'\x00\x00\x00\x00\x00' + pack('B',int(items[2]))
        self.SubAuthorityCount = len(items) - 3
        for i in range(self.SubAuthorityCount):
            self.SubAuthority.append(int(items[i+3]))

     func (self TYPE) formatCanonical(){
        ans = "S-%d-%d" % (self.Revision"], ord(self["IdentifierAuthority[5:6]))
        for i in range(self.SubAuthorityCount):
            ans += '-%d' % self.SubAuthority[i]
        return ans

 type PRPC_SID struct { // NDRPOINTER:
    referent = (
        ('Data', RPC_SID),
    }

PSID = PRPC_SID

// 2.4.3 ACCESS_MASK
GENERIC_READ            = 0x80000000
GENERIC_WRITE           = 0x4000000
GENERIC_EXECUTE         = 0x20000000
GENERIC_ALL             = 0x10000000
MAXIMUM_ALLOWED         = 0x02000000
ACCESS_SYSTEM_SECURITY  = 0x01000000
SYNCHRONIZE             = 0x00100000
WRITE_OWNER             = 0x00080000
WRITE_DACL              = 0x00040000
READ_CONTROL            = 0x00020000
DELETE                  = 0x00010000

// 2.4.5.1 ACL--RPC Representation
 type ACL struct { // NDRSTRUCT: (
        ('AclRevision',NDRSMALL),
        ('Sbz1',NDRSMALL),
        ('AclSize',NDRSHORT),
        ('AceCount',NDRSHORT),
        ('Sbz2',NDRSHORT),
    }

 type PACL struct { // NDRPOINTER:
    referent = (
        ('Data', ACL),
    }

// 2.4.6.1 SECURITY_DESCRIPTOR--RPC Representation
 type SECURITY_DESCRIPTOR struct { // NDRSTRUCT: (
        ('Revision',UCHAR),
        ('Sbz1',UCHAR),
        ('Control',USHORT),
        ('Owner',PSID),
        ('Group',PSID),
        ('Sacl',PACL),
        ('Dacl',PACL),
    }

// 2.4.7 SECURITY_INFORMATION
OWNER_SECURITY_INFORMATION            = 0x00000001
GROUP_SECURITY_INFORMATION            = 0x00000002
DACL_SECURITY_INFORMATION             = 0x00000004
SACL_SECURITY_INFORMATION             = 0x00000008
LABEL_SECURITY_INFORMATION            = 0x00000010
UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000
UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
PROTECTED_SACL_SECURITY_INFORMATION   = 0x40000000
PROTECTED_DACL_SECURITY_INFORMATION   = 0x80000000
ATTRIBUTE_SECURITY_INFORMATION        = 0x00000020
SCOPE_SECURITY_INFORMATION            = 0x00000040
BACKUP_SECURITY_INFORMATION           = 0x00010000

SECURITY_INFORMATION = DWORD
 type PSECURITY_INFORMATION struct { // NDRPOINTER:
    referent = (
        ('Data', SECURITY_INFORMATION),
    }
