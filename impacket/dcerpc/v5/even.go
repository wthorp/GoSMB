// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Author: Alberto Solino (@agsolino)
//         Itamar Mizrahi (@MrAnde7son)
//
// Description:
//   [MS-EVEN] Interface implementation
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
from __future__ import division
from __future__ import print_function
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDR, NDRPOINTERNULL, NDRUniConformantArray
from impacket.dcerpc.v5.dtypes import ULONG, LPWSTR, RPC_UNICODE_STRING, LPSTR, NTSTATUS, NULL, PRPC_UNICODE_STRING, PULONG, USHORT, PRPC_SID, LPBYTE
from impacket.dcerpc.v5.lsad import PRPC_UNICODE_STRING_ARRAY
from impacket.structure import Structure
from impacket import nt_errors
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.rpcrt import DCERPCException

MSRPC_UUID_EVEN  = uuidtup_to_bin(('82273FDC-E32A-18C3-3F78-827929DC23EA','0.0'))

 type DCERPCSessionError struct { // DCERPCException:
     func (self TYPE) __init__(error_string=nil, error_code=nil, packet=nil interface{}){
        DCERPCException.__init__(self, error_string, error_code, packet)

     func __str__( self  interface{}){
        key = self.error_code
        if key in nt_errors.ERROR_MESSAGES {
            error_msg_short = nt_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = nt_errors.ERROR_MESSAGES[key][1]
            return 'EVEN SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        } else  {
            return 'EVEN SessionError: unknown error code: 0x%x' % self.error_code

//###############################################################################
// CONSTANTS
//###############################################################################
// 2.2.2 EventType
EVENTLOG_SUCCESS           = 0x0000
EVENTLOG_ERROR_TYPE        = 0x0001
EVENTLOG_WARNING_TYPE      = 0x0002
EVENTLOG_INFORMATION_TYPE  = 0x0004
EVENTLOG_AUDIT_SUCCESS     = 0x0008
EVENTLOG_AUDIT_FAILURE     = 0x0010

// 2.2.7 EVENTLOG_HANDLE_A and EVENTLOG_HANDLE_W
//EVENTLOG_HANDLE_A
EVENTLOG_HANDLE_W = LPWSTR

// 2.2.9 Constants Used in Method Definitions
MAX_STRINGS      = 0x00000100
MAX_SINGLE_EVENT = 0x0003FFFF
MAX_BATCH_BUFF   = 0x0007FFFF

// 3.1.4.7 ElfrReadELW (Opnum 10)
EVENTLOG_SEQUENTIAL_READ = 0x00000001
EVENTLOG_SEEK_READ       = 0x00000002

EVENTLOG_FORWARDS_READ   = 0x00000004
EVENTLOG_BACKWARDS_READ  = 0x00000008

//###############################################################################
// STRUCTURES
//###############################################################################

 type IELF_HANDLE struct { // NDRSTRUCT:  (
         Data [0]byte // =""
    }
     func (self TYPE) getAlignment(){
        return 1

// 2.2.3 EVENTLOGRECORD
 type EVENTLOGRECORD struct { // Structure: (
         Length uint32 // =0
         Reserved uint32 // =0
         RecordNumber uint32 // =0
         TimeGenerated uint32 // =0
         TimeWritten uint32 // =0
         EventID uint32 // =0
         EventType uint16 // =0
         NumStrings uint16 // =0
         EventCategory uint16 // =0
         ReservedFlags uint16 // =0
         ClosingRecordNumber uint32 // =0
         StringOffset uint32 // =0
         UserSidLength uint32 // =0
         UserSidOffset uint32 // =0
         DataLength uint32 // =0
         DataOffset uint32 // =0
        ('SourceName','z'),
        ('Computername','z'),
        ('UserSidPadding',':'),
        ('_UserSid','_-UserSid', 'self.UserSidLength'),
        ('UserSid',':'),
        ('Strings',':'),
        ('_Data','_-Data', 'self.DataLength'),
        ('Data',':'),
        ('Padding',':'),
         Length2 uint32 // =0
    }

// 2.2.4 EVENTLOG_FULL_INFORMATION
 type EVENTLOG_FULL_INFORMATION struct { // NDRSTRUCT: (
        ('dwFull', ULONG),
    }

// 2.2.8 RPC_CLIENT_ID
 type RPC_CLIENT_ID struct { // NDRSTRUCT: (
        ('UniqueProcess', ULONG),
        ('UniqueThread', ULONG),
    }

// 2.2.12 RPC_STRING
 type RPC_STRING struct { // NDRSTRUCT: (
         Length uint16 // =0
         MaximumLength uint16 // =0
        ('Data',LPSTR),
    }

     func (self TYPE) __setitem__(key, value interface{}){
        if key == 'Data' and isinstance(value, NDR) is false {
            self.Length = len(value)
            self.MaximumLength = len(value)
        return NDRSTRUCT.__setitem__(self, key, value)

     func (self TYPE) dump(msg = nil, indent = 0 interface{}){
        if msg == nil { msg = self.__class__.__name__
        if msg != '' {
            print("%s" % msg, end=' ')

        if isinstance(self.fields["Data"] , NDRPOINTERNULL) {
            print(" NULL", end=' ')
        elif self.fields["Data"]["ReferentID"] == 0 {
            print(" NULL", end=' ')
        } else  {
            return self.fields["Data"].dump('',indent)

//###############################################################################
// RPC CALLS
//###############################################################################
// 3.1.4.9 ElfrClearELFW (Opnum 0)
 type ElfrClearELFW struct { // NDRCALL:
    opnum = 0 (
       ('LogHandle', IELF_HANDLE),
       ('BackupFileName', PRPC_UNICODE_STRING),
    }

 type ElfrClearELFWResponse struct { // NDRCALL: (
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.11 ElfrBackupELFW (Opnum 1)
 type ElfrBackupELFW struct { // NDRCALL:
    opnum = 1 (
       ('LogHandle', IELF_HANDLE),
       ('BackupFileName', RPC_UNICODE_STRING),
    }

 type ElfrBackupELFWResponse struct { // NDRCALL: (
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.21 ElfrCloseEL (Opnum 2)
 type ElfrCloseEL struct { // NDRCALL:
    opnum = 2 (
        ('LogHandle', IELF_HANDLE),
    }

 type ElfrCloseELResponse struct { // NDRCALL: (
        ('LogHandle', IELF_HANDLE),
        ('ErrorCode', NTSTATUS),
    }

// 3.1.4.18 ElfrNumberOfRecords (Opnum 4)
 type ElfrNumberOfRecords struct { // NDRCALL:
    opnum = 4 (
        ('LogHandle', IELF_HANDLE),
    }

 type ElfrNumberOfRecordsResponse struct { // NDRCALL: (
        ('NumberOfRecords', ULONG),
        ('ErrorCode', NTSTATUS),
    }

// 3.1.4.3 ElfrOpenELW (Opnum 7)
 type ElfrOpenELW struct { // NDRCALL:
    opnum = 7 (
       ('UNCServerName', EVENTLOG_HANDLE_W),
       ('ModuleName', RPC_UNICODE_STRING),
       ('RegModuleName', RPC_UNICODE_STRING),
       ('MajorVersion', ULONG),
       ('MinorVersion', ULONG),
    }

 type ElfrOpenELWResponse struct { // NDRCALL: (
       ('LogHandle', IELF_HANDLE),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.5 ElfrRegisterEventSourceW (Opnum 8)
 type ElfrRegisterEventSourceW struct { // NDRCALL:
    opnum = 8 (
       ('UNCServerName', EVENTLOG_HANDLE_W),
       ('ModuleName', RPC_UNICODE_STRING),
       ('RegModuleName', RPC_UNICODE_STRING),
       ('MajorVersion', ULONG),
       ('MinorVersion', ULONG),
    }

 type ElfrRegisterEventSourceWResponse struct { // NDRCALL: (
       ('LogHandle', IELF_HANDLE),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.1 ElfrOpenBELW (Opnum 9)
 type ElfrOpenBELW struct { // NDRCALL:
    opnum = 9 (
       ('UNCServerName', EVENTLOG_HANDLE_W),
       ('BackupFileName', RPC_UNICODE_STRING),
       ('MajorVersion', ULONG),
       ('MinorVersion', ULONG),
    }

 type ElfrOpenBELWResponse struct { // NDRCALL: (
       ('LogHandle', IELF_HANDLE),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.7 ElfrReadELW (Opnum 10)
 type ElfrReadELW struct { // NDRCALL:
    opnum = 10 (
       ('LogHandle', IELF_HANDLE),
       ('ReadFlags', ULONG),
       ('RecordOffset', ULONG),
       ('NumberOfBytesToRead', ULONG),
    }

 type ElfrReadELWResponse struct { // NDRCALL: (
       ('Buffer', NDRUniConformantArray),
       ('NumberOfBytesRead', ULONG),
       ('MinNumberOfBytesNeeded', ULONG),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.13 ElfrReportEventW (Opnum 11)
 type ElfrReportEventW struct { // NDRCALL:
    opnum = 11 (
       ('LogHandle', IELF_HANDLE),
       ('Time', ULONG),
       ('EventType', USHORT),
       ('EventCategory', USHORT),
       ('EventID', ULONG),
       ('NumStrings', USHORT),
       ('DataSize', ULONG),
       ('ComputerName', RPC_UNICODE_STRING),
       ('UserSID', PRPC_SID),
       ('Strings', PRPC_UNICODE_STRING_ARRAY),
       ('Data', LPBYTE),
       ('Flags', USHORT),
       ('RecordNumber', PULONG),
       ('TimeWritten', PULONG),
    }

 type ElfrReportEventWResponse struct { // NDRCALL: (
       ('RecordNumber', PULONG),
       ('TimeWritten', PULONG),
       ('ErrorCode', NTSTATUS),
    }

//###############################################################################
// OPNUMs and their corresponding structures
//###############################################################################
OPNUMS = {
    0   : (ElfrClearELFW, ElfrClearELFWResponse),
    1   : (ElfrBackupELFW, ElfrBackupELFWResponse),
    2   : (ElfrCloseEL, ElfrCloseELResponse),
    4   : (ElfrNumberOfRecords, ElfrNumberOfRecordsResponse),
    7   : (ElfrOpenELW, ElfrOpenELWResponse),
    8   : (ElfrRegisterEventSourceW, ElfrRegisterEventSourceWResponse),
    9   : (ElfrOpenBELW, ElfrOpenBELWResponse),
    10  : (ElfrReadELW, ElfrReadELWResponse),
    11  : (ElfrReportEventW, ElfrReportEventWResponse),
}

//###############################################################################
// HELPER FUNCTIONS
//###############################################################################
 func hElfrOpenBELW(dce, backupFileName = NULL interface{}){
    request = ElfrOpenBELW()
    request["UNCServerName"] = NULL
    request["BackupFileName"] = backupFileName
    request["MajorVersion"] = 1
    request["MinorVersion"] = 1
    return dce.request(request)

 func hElfrOpenELW(dce, moduleName = NULL, regModuleName = NULL interface{}){
    request = ElfrOpenELW()
    request["UNCServerName"] = NULL
    request["ModuleName"] = moduleName
    request["RegModuleName"] = regModuleName
    request["MajorVersion"] = 1
    request["MinorVersion"] = 1
    return dce.request(request)

 func hElfrCloseEL(dce, logHandle interface{}){
    request = ElfrCloseEL()

    request["LogHandle"] = logHandle
    resp = dce.request(request)
    return resp

 func hElfrRegisterEventSourceW(dce, moduleName = NULL, regModuleName = NULL interface{}){
    request = ElfrRegisterEventSourceW()
    request["UNCServerName"] = NULL
    request["ModuleName"] = moduleName
    request["RegModuleName"] = regModuleName
    request["MajorVersion"] = 1
    request["MinorVersion"] = 1
    return dce.request(request)

def hElfrReadELW(dce, logHandle = "", readFlags = EVENTLOG_SEQUENTIAL_READ|EVENTLOG_FORWARDS_READ,
                 recordOffset = 0, numberOfBytesToRead = MAX_BATCH_BUFF):
    request = ElfrReadELW()
    request["LogHandle"] = logHandle
    request["ReadFlags"] = readFlags
    request["RecordOffset"] = recordOffset
    request["NumberOfBytesToRead"] = numberOfBytesToRead
    return dce.request(request)

 func hElfrClearELFW(dce, logHandle = "", backupFileName = NULL interface{}){
    request = ElfrClearELFW()
    request["LogHandle"] = logHandle
    request["BackupFileName"] = backupFileName
    return dce.request(request)

 func hElfrBackupELFW(dce, logHandle = "", backupFileName = NULL interface{}){
    request = ElfrBackupELFW()
    request["LogHandle"] = logHandle
    request["BackupFileName"] = backupFileName
    return dce.request(request)

 func hElfrNumberOfRecords(dce, logHandle interface{}){
    request = ElfrNumberOfRecords()

    request["LogHandle"] = logHandle
    resp = dce.request(request)
    return resp
