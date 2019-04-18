// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
// Copyright (c) 2017 @MrAnde7son
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Author: Itamar (@MrAnde7son)
//
// Description:
//   Initial [MS-EVEN6] Interface implementation
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
from impacket import system_errors
from impacket.dcerpc.v5.dtypes import WSTR, DWORD, LPWSTR, ULONG, LARGE_INTEGER, WORD, BYTE
from impacket.dcerpc.v5.ndr import NDRCALL, NDRPOINTER, NDRUniConformantArray, NDRUniVaryingArray, NDRSTRUCT
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_EVEN6 = uuidtup_to_bin(('F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C', '1.0'))

 type DCERPCSessionError struct { // DCERPCException:
     func (self TYPE) __init__(error_string=nil, error_code=nil, packet=nil interface{}){
        DCERPCException.__init__(self, error_string, error_code, packet)

     func (self TYPE) __str__(){
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES {
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'EVEN6 SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        } else  {
            return 'EVEN6 SessionError: unknown error code: 0x%x' % self.error_code

//###############################################################################
// CONSTANTS
//###############################################################################

// Evt Path Flags
EvtQueryChannelName = 0x00000001
EvtQueryFilePath = 0x00000002
EvtReadOldestToNewest = 0x00000100
EvtReadNewestToOldest = 0x00000200

//###############################################################################
// STRUCTURES
//###############################################################################

 type CONTEXT_HANDLE_LOG_HANDLE struct { // NDRSTRUCT:
    align = 1 (
         Data [0]byte // =""
    }

 type PCONTEXT_HANDLE_LOG_HANDLE struct { // NDRPOINTER:
    referent = (
        ('Data', CONTEXT_HANDLE_LOG_HANDLE),
    }

 type CONTEXT_HANDLE_LOG_QUERY struct { // NDRSTRUCT:
    align = 1 (
         Data [0]byte // =""
    }

 type PCONTEXT_HANDLE_LOG_QUERY struct { // NDRPOINTER:
    referent = (
        ('Data', CONTEXT_HANDLE_LOG_QUERY),
    }

 type LPPCONTEXT_HANDLE_LOG_QUERY struct { // NDRPOINTER:
    referent = (
        ('Data', PCONTEXT_HANDLE_LOG_QUERY),
    }

 type CONTEXT_HANDLE_OPERATION_CONTROL struct { // NDRSTRUCT:
    align = 1 (
         Data [0]byte // =""
    }

 type PCONTEXT_HANDLE_OPERATION_CONTROL struct { // NDRPOINTER:
    referent = (
        ('Data', CONTEXT_HANDLE_OPERATION_CONTROL),
    }

// 2.2.11 EvtRpcQueryChannelInfo
 type EvtRpcQueryChannelInfo struct { // NDRSTRUCT: (
        ('Name', LPWSTR),
        ('Status', DWORD),
    }

 type EvtRpcQueryChannelInfoArray struct { // NDRUniVaryingArray:
    item = EvtRpcQueryChannelInfo

 type LPEvtRpcQueryChannelInfoArray struct { // NDRPOINTER:
    referent = (
        ('Data', EvtRpcQueryChannelInfoArray)
    }

 type RPC_INFO struct { // NDRSTRUCT: (
        ('Error', DWORD),
        ('SubError', DWORD),
        ('SubErrorParam', DWORD),
    }

 type PRPC_INFO struct { // NDRPOINTER:
    referent = (
        ('Data', RPC_INFO)
    }

 type WSTR_ARRAY struct { // NDRUniVaryingArray:
    item = WSTR

 type DWORD_ARRAY struct { // NDRUniVaryingArray:
    item = DWORD

 type LPDWORD_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', DWORD_ARRAY)
    }

 type BYTE_ARRAY struct { // NDRUniVaryingArray:
    item = "c"

 type CBYTE_ARRAY struct { // NDRUniVaryingArray:
    item = BYTE

 type CDWORD_ARRAY struct { // NDRUniConformantArray:
    item = DWORD

 type LPBYTE_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', CBYTE_ARRAY)
    }

 type ULONG_ARRAY struct { // NDRUniVaryingArray:
    item = ULONG

// 2.3.1 EVENT_DESCRIPTOR
 type EVENT_DESCRIPTOR struct { // NDRSTRUCT: (
        ('Id', WORD),
        ('Version', BYTE),
        ('Channel', BYTE),
        ('LevelSeverity', BYTE),
        ('Opcode', BYTE),
        ('Task', WORD),
        ('Keyword', ULONG),
    }

 type BOOKMARK struct { // NDRSTRUCT: (
        ('BookmarkSize', DWORD),
         HeaderSize uint32 // =0x18
        ('ChannelSize', DWORD),
        ('CurrentChannel', DWORD),
        ('ReadDirection', DWORD),
        ('RecordIdsOffset', DWORD),
        ('LogRecordNumbers', ULONG_ARRAY),
    }


//2.2.17 RESULT_SET
 type RESULT_SET struct { // NDRSTRUCT: (
        ('TotalSize', DWORD),
        ('HeaderSize', DWORD),
        ('EventOffset', DWORD),
        ('BookmarkOffset', DWORD),
        ('BinXmlSize', DWORD),
        ('EventData', BYTE_ARRAY),
        // NumberOfSubqueryIDs uint32 // =0
        //('SubqueryIDs', BYTE_ARRAY),
        //('BookMarkData', BOOKMARK),
    }

//###############################################################################
// RPC CALLS
//###############################################################################

 type EvtRpcRegisterLogQuery struct { // NDRCALL:
    opnum = 5 (
        ('Path', LPWSTR),
        ('Query', WSTR),
        ('Flags', DWORD),
    }

 type EvtRpcRegisterLogQueryResponse struct { // NDRCALL: (
        ('Handle', CONTEXT_HANDLE_LOG_QUERY),
        ('OpControl', CONTEXT_HANDLE_OPERATION_CONTROL),
        ('QueryChannelInfoSize', DWORD),
        ('QueryChannelInfo', EvtRpcQueryChannelInfoArray),
        ('Error', RPC_INFO),
        }

 type EvtRpcQueryNext struct { // NDRCALL:
    opnum = 11 (
        ('LogQuery', CONTEXT_HANDLE_LOG_QUERY),
        ('NumRequestedRecords', DWORD),
        ('TimeOutEnd', DWORD),
        ('Flags', DWORD),
    }

 type EvtRpcQueryNextResponse struct { // NDRCALL: (
        ('NumActualRecords', DWORD),
        ('EventDataIndices', DWORD_ARRAY),
        ('EventDataSizes', DWORD_ARRAY),
        ('ResultBufferSize', DWORD),
        ('ResultBuffer', BYTE_ARRAY),
        ('ErrorCode', ULONG),
    }

 type EvtRpcQuerySeek struct { // NDRCALL:
    opnum = 12 (
        ('LogQuery', CONTEXT_HANDLE_LOG_QUERY),
        ('Pos', LARGE_INTEGER),
        ('BookmarkXML', LPWSTR),
        ('Flags', DWORD),
    }

 type EvtRpcQuerySeekResponse struct { // NDRCALL: (
        ('Error', RPC_INFO),
    }

 type EvtRpcClose struct { // NDRCALL:
    opnum = 13 (
        ("Handle", CONTEXT_HANDLE_LOG_HANDLE),
    }

 type EvtRpcCloseResponse struct { // NDRCALL: (
        ("Handle", PCONTEXT_HANDLE_LOG_HANDLE),
        ('ErrorCode', ULONG),
    }

 type EvtRpcOpenLogHandle struct { // NDRCALL:
    opnum = 17 (
        ('Channel', WSTR),
        ('Flags', DWORD),
    }

 type EvtRpcOpenLogHandleResponse struct { // NDRCALL: (
        ('Handle', PCONTEXT_HANDLE_LOG_HANDLE),
        ('Error', RPC_INFO),
    }

 type EvtRpcGetChannelList struct { // NDRCALL:
    opnum = 19 (
        ('Flags', DWORD),
    }

 type EvtRpcGetChannelListResponse struct { // NDRCALL: (
        ('NumChannelPaths', DWORD),
        ('ChannelPaths', WSTR_ARRAY),
        ('ErrorCode', ULONG),
    }

//###############################################################################
// OPNUMs and their corresponding structures
//###############################################################################

OPNUMS = {
    5   : (EvtRpcRegisterLogQuery, EvtRpcRegisterLogQueryResponse),
    11  : (EvtRpcQueryNext,  EvtRpcQueryNextResponse),
    12  : (EvtRpcQuerySeek, EvtRpcQuerySeekResponse),
    13  : (EvtRpcClose, EvtRpcCloseResponse),
    17  : (EvtRpcOpenLogHandle, EvtRpcOpenLogHandle),
    19  : (EvtRpcGetChannelList, EvtRpcGetChannelListResponse),
}

//###############################################################################
// HELPER FUNCTIONS
//###############################################################################

 func hEvtRpcRegisterLogQuery(dce, path, flags, query='*\x00' interface{}){
    request = EvtRpcRegisterLogQuery()

    request["Path"] = path
    request["Query"] = query
    request["Flags"] = flags
    resp = dce.request(request)
    return resp

 func hEvtRpcQueryNext(dce, handle, numRequestedRecords, timeOutEnd=1000 interface{}){
    request = EvtRpcQueryNext()

    request["LogQuery"] = handle
    request["NumRequestedRecords"] = numRequestedRecords
    request["TimeOutEnd"] = timeOutEnd
    request["Flags"] = 0
    status = system_errors.ERROR_MORE_DATA
    resp = dce.request(request)
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCException as e:
            if str(e).find("ERROR_NO_MORE_ITEMS") < 0 {
                raise
            elif str(e).find("ERROR_TIMEOUT") < 0 {
                raise
            resp = e.get_packet()
        return resp

 func hEvtRpcClose(dce, handle interface{}){
    request = EvtRpcClose()
    request["Handle"] = handle
    resp = dce.request(request)
    return resp

 func hEvtRpcOpenLogHandle(dce, channel, flags interface{}){
    request = EvtRpcOpenLogHandle()

    request["Channel"] = channel
    request["Flags"] = flags
    return dce.request(request)

 func hEvtRpcGetChannelList(dce interface{}){
    request = EvtRpcGetChannelList()

    request["Flags"] = 0
    resp = dce.request(request)
    return resp
