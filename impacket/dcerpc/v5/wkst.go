// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Author: Alberto Solino (@agsolino)
//
// Description:
//   [MS-WKST] Interface implementation
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
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRENUM, NDRUNION, NDRUniConformantArray, NDRUniFixedArray, \
    NDRPOINTER
from impacket.dcerpc.v5.dtypes import NULL, WSTR, ULONG, LPWSTR, LONG, LARGE_INTEGER, WIDESTR, RPC_UNICODE_STRING, \
    LPULONG, LPLONG
from impacket import system_errors
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.enum import Enum
from impacket.dcerpc.v5.rpcrt import DCERPCException

MSRPC_UUID_WKST   = uuidtup_to_bin(('6BFFD098-A112-3610-9833-46C3F87E345A', '1.0'))

 type DCERPCSessionError struct { // DCERPCException:
     func (self TYPE) __init__(error_string=nil, error_code=nil, packet=nil interface{}){
        DCERPCException.__init__(self, error_string, error_code, packet)

     func __str__( self  interface{}){
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES {
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1] 
            return 'WKST SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        } else  {
            return 'WKST SessionError: unknown error code: 0x%x' % self.error_code

//###############################################################################
// CONSTANTS
//###############################################################################

// 2.2.1.1 JOIN_MAX_PASSWORD_LENGTH
JOIN_MAX_PASSWORD_LENGTH = 256

// 2.2.1.2 JOIN_OBFUSCATOR_LENGTH
JOIN_OBFUSCATOR_LENGTH = 8

// 2.2.1.3 MAX_PREFERRED_LENGTH
MAX_PREFERRED_LENGTH = 0xffffffff

// 2.2.5.22 USE_INFO_1
USE_OK       = 0x00000000
USE_PAUSED   = 0x00000001
USE_SESSLOST = 0x00000002
USE_NETERR   = 0x00000003
USE_CONN     = 0x00000004
USE_RECONN   = 0x00000005

USE_WILDCARD = 0xFFFFFFFF
USE_DISKDEV  = 0x00000000
USE_SPOOLDEV = 0x00000001
USE_CHARDEV  = 0x00000002
USE_IPC      = 0x00000003

// 3.2.4.9 NetrUseDel (Opnum 10)
// Force Level
USE_NOFORCE       = 0x00000000
USE_FORCE         = 0x00000001
USE_LOTS_OF_FORCE = 0x00000002

// 3.2.4.13 NetrJoinDomain2 (Opnum 22)
// Options
NETSETUP_JOIN_DOMAIN           = 0x00000001
NETSETUP_ACCT_CREATE           = 0x00000002
NETSETUP_ACCT_DELETE           = 0x00000004
NETSETUP_DOMAIN_JOIN_IF_JOINED = 0x00000020
NETSETUP_JOIN_UNSECURE         = 0x00000040
NETSETUP_MACHINE_PWD_PASSED    = 0x00000080
NETSETUP_DEFER_SPN_SET         = 0x00000100
NETSETUP_JOIN_DC_ACCOUNT       = 0x00000200
NETSETUP_JOIN_WITH_NEW_NAME    = 0x00000400
NETSETUP_INSTALL_INVOCATION    = 0x00040000

// 3.2.4.14 NetrUnjoinDomain2 (Opnum 23)
// Options
NETSETUP_ACCT_DELETE              = 0x00000004
NETSETUP_IGNORE_UNSUPPORTED_FLAGS = 0x10000000

// 3.2.4.15 NetrRenameMachineInDomain2 (Opnum 24)
// Options
NETSETUP_ACCT_CREATE           = 0x00000002
NETSETUP_DNS_NAME_CHANGES_ONLY = 0x00001000

//###############################################################################
// STRUCTURES
//###############################################################################

// 2.2.2.1 WKSSVC_IDENTIFY_HANDLE
 type WKSSVC_IDENTIFY_HANDLE struct { // NDRSTRUCT:  (
        ('Data', WSTR),
    }

 type LPWKSSVC_IDENTIFY_HANDLE struct { // NDRPOINTER:
    referent = (
        ('Data', WKSSVC_IDENTIFY_HANDLE),
    }

// 2.2.2.2 WKSSVC_IMPERSONATE_HANDLE
 type WKSSVC_IMPERSONATE_HANDLE struct { // NDRSTRUCT:  (
        ('Data',WSTR),
    }

 type LPWKSSVC_IMPERSONATE_HANDLE struct { // NDRPOINTER:
    referent = (
        ('Data', WKSSVC_IMPERSONATE_HANDLE),
    }

// 2.2.3.1 NETSETUP_JOIN_STATUS
 type NETSETUP_JOIN_STATUS struct { // NDRENUM:
     type enumItems struct { // Enum:
        NetSetupUnknownStatus = 1
        NetSetupUnjoined      = 2
        NetSetupWorkgroupName = 3
        NetSetupDomainName    = 4

// 2.2.3.2 NETSETUP_NAME_TYPE
 type NETSETUP_NAME_TYPE struct { // NDRENUM:
     type enumItems struct { // Enum:
        NetSetupUnknown           = 0
        NetSetupMachine           = 1
        NetSetupWorkgroup         = 2
        NetSetupDomain            = 3
        NetSetupNonExistentDomain = 4
        NetSetupDnsMachine        = 5

// 2.2.3.3 NET_COMPUTER_NAME_TYPE
 type NET_COMPUTER_NAME_TYPE struct { // NDRENUM:
     type enumItems struct { // Enum:
        NetPrimaryComputerName    = 0
        NetAlternateComputerNames = 1
        NetAllComputerNames       = 2
        NetComputerNameTypeMax    = 3

// 2.2.5.1 WKSTA_INFO_100
 type WKSTA_INFO_100 struct { // NDRSTRUCT: (
        ('wki100_platform_id', ULONG),
        ('wki100_computername', LPWSTR),
        ('wki100_langroup', LPWSTR),
        ('wki100_ver_major', ULONG),
        ('wki100_ver_minor', ULONG),
    }

 type LPWKSTA_INFO_100 struct { // NDRPOINTER:
    referent = (
        ('Data', WKSTA_INFO_100),
    }

// 2.2.5.2 WKSTA_INFO_101
 type WKSTA_INFO_101 struct { // NDRSTRUCT: (
        ('wki101_platform_id', ULONG),
        ('wki101_computername', LPWSTR),
        ('wki101_langroup', LPWSTR),
        ('wki101_ver_major', ULONG),
        ('wki101_ver_minor', ULONG),
        ('wki101_lanroot', LPWSTR),
    }

 type LPWKSTA_INFO_101 struct { // NDRPOINTER:
    referent = (
        ('Data', WKSTA_INFO_101),
    }

// 2.2.5.3 WKSTA_INFO_102
 type WKSTA_INFO_102 struct { // NDRSTRUCT: (
        ('wki102_platform_id', ULONG),
        ('wki102_computername', LPWSTR),
        ('wki102_langroup', LPWSTR),
        ('wki102_ver_major', ULONG),
        ('wki102_ver_minor', ULONG),
        ('wki102_lanroot', LPWSTR),
        ('wki102_logged_on_users', ULONG),
    }

 type LPWKSTA_INFO_102 struct { // NDRPOINTER:
    referent = (
        ('Data', WKSTA_INFO_102),
    }

// 2.2.5.4 WKSTA_INFO_502
 type WKSTA_INFO_502 struct { // NDRSTRUCT: (
        ('wki502_char_wait', ULONG),
        ('wki502_collection_time', ULONG),
        ('wki502_maximum_collection_count', ULONG),
        ('wki502_keep_conn', ULONG),
        ('wki502_max_cmds', ULONG),
        ('wki502_sess_timeout', ULONG),
        ('wki502_siz_char_buf', ULONG),
        ('wki502_max_threads', ULONG),
        ('wki502_lock_quota', ULONG),
        ('wki502_lock_increment', ULONG),
        ('wki502_lock_maximum', ULONG),
        ('wki502_pipe_increment', ULONG),
        ('wki502_pipe_maximum', ULONG),
        ('wki502_cache_file_timeout', ULONG),
        ('wki502_dormant_file_limit', ULONG),
        ('wki502_read_ahead_throughput', ULONG),
        ('wki502_num_mailslot_buffers', ULONG),
        ('wki502_num_srv_announce_buffers', ULONG),
        ('wki502_max_illegal_datagram_events', ULONG),
        ('wki502_illegal_datagram_event_reset_frequency', ULONG),
        ('wki502_log_election_packets', LONG),
        ('wki502_use_opportunistic_locking', LONG),
        ('wki502_use_unlock_behind', LONG),
        ('wki502_use_close_behind', LONG),
        ('wki502_buf_named_pipes', LONG),
        ('wki502_use_lock_read_unlock', LONG),
        ('wki502_utilize_nt_caching', LONG),
        ('wki502_use_raw_read', LONG),
        ('wki502_use_raw_write', LONG),
        ('wki502_use_write_raw_data', LONG),
        ('wki502_use_encryption', LONG),
        ('wki502_buf_files_deny_write', LONG),
        ('wki502_buf_read_only_files', LONG),
        ('wki502_force_core_create_mode', LONG),
        ('wki502_use_512_byte_max_transfer', LONG),
    }

 type LPWKSTA_INFO_502 struct { // NDRPOINTER:
    referent = (
        ('Data', WKSTA_INFO_502),
    }

// 2.2.5.5 WKSTA_INFO_1013
 type WKSTA_INFO_1013 struct { // NDRSTRUCT: (
        ('wki1013_keep_conn', ULONG),
    }

 type LPWKSTA_INFO_1013 struct { // NDRPOINTER:
    referent = (
        ('Data', WKSTA_INFO_1013),
    }

// 2.2.5.6 WKSTA_INFO_1018
 type WKSTA_INFO_1018 struct { // NDRSTRUCT: (
        ('wki1018_sess_timeout', ULONG),
    }

 type LPWKSTA_INFO_1018 struct { // NDRPOINTER:
    referent = (
        ('Data', WKSTA_INFO_1018),
    }

// 2.2.5.7 WKSTA_INFO_1046
 type WKSTA_INFO_1046 struct { // NDRSTRUCT: (
        ('wki1046_dormant_file_limit', ULONG),
    }

 type LPWKSTA_INFO_1046 struct { // NDRPOINTER:
    referent = (
        ('Data', WKSTA_INFO_1046),
    }

// 2.2.4.1 WKSTA_INFO
 type WKSTA_INFO struct { // NDRUNION:
    commonHdr = (
        ('tag', ULONG),
    }
    union = {
        100: ('WkstaInfo100', LPWKSTA_INFO_100),
        101: ('WkstaInfo101', LPWKSTA_INFO_101),
        102: ('WkstaInfo102', LPWKSTA_INFO_102),
        502: ('WkstaInfo502', LPWKSTA_INFO_502),
        1013: ('WkstaInfo1013', LPWKSTA_INFO_1013),
        1018: ('WkstaInfo1018', LPWKSTA_INFO_1018),
        1046: ('WkstaInfo1046', LPWKSTA_INFO_1046),
    }

 type LPWKSTA_INFO struct { // NDRPOINTER:
    referent = (
        ('Data', WKSTA_INFO),
    }

// 2.2.5.8 WKSTA_TRANSPORT_INFO_0
 type WKSTA_TRANSPORT_INFO_0 struct { // NDRSTRUCT: (
        ('wkti0_quality_of_service', ULONG),
        ('wkti0_number_of_vcs', ULONG),
        ('wkti0_transport_name', LPWSTR),
        ('wkti0_transport_address', LPWSTR),
        ('wkti0_wan_ish', ULONG),
    }

// 2.2.5.9 WKSTA_USER_INFO_0
 type WKSTA_USER_INFO_0 struct { // NDRSTRUCT: (
        ('wkui0_username', LPWSTR),
    }

// 2.2.5.10 WKSTA_USER_INFO_1
 type WKSTA_USER_INFO_1 struct { // NDRSTRUCT: (
        ('wkui1_username', LPWSTR),
        ('wkui1_logon_domain', LPWSTR),
        ('wkui1_oth_domains', LPWSTR),
        ('wkui1_logon_server', LPWSTR),
    }

// 2.2.5.11 STAT_WORKSTATION_0
 type STAT_WORKSTATION_0 struct { // NDRSTRUCT: (
        ('StatisticsStartTime', LARGE_INTEGER),
        ('BytesReceived', LARGE_INTEGER),
        ('SmbsReceived', LARGE_INTEGER),
        ('PagingReadBytesRequested', LARGE_INTEGER),
        ('NonPagingReadBytesRequested', LARGE_INTEGER),
        ('CacheReadBytesRequested', LARGE_INTEGER),
        ('NetworkReadBytesRequested', LARGE_INTEGER),
        ('BytesTransmitted', LARGE_INTEGER),
        ('SmbsTransmitted', LARGE_INTEGER),
        ('PagingWriteBytesRequested', LARGE_INTEGER),
        ('NonPagingWriteBytesRequested', LARGE_INTEGER),
        ('CacheWriteBytesRequested', LARGE_INTEGER),
        ('NetworkWriteBytesRequested', LARGE_INTEGER),
        ('InitiallyFailedOperations', ULONG),
        ('FailedCompletionOperations', ULONG),
        ('ReadOperations', ULONG),
        ('RandomReadOperations', ULONG),
        ('ReadSmbs', ULONG),
        ('LargeReadSmbs', ULONG),
        ('SmallReadSmbs', ULONG),
        ('WriteOperations', ULONG),
        ('RandomWriteOperations', ULONG),
        ('WriteSmbs', ULONG),
        ('LargeWriteSmbs', ULONG),
        ('SmallWriteSmbs', ULONG),
        ('RawReadsDenied', ULONG),
        ('RawWritesDenied', ULONG),
        ('NetworkErrors', ULONG),
        ('Sessions', ULONG),
        ('FailedSessions', ULONG),
        ('Reconnects', ULONG),
        ('CoreConnects', ULONG),
        ('Lanman20Connects', ULONG),
        ('Lanman21Connects', ULONG),
        ('LanmanNtConnects', ULONG),
        ('ServerDisconnects', ULONG),
        ('HungSessions', ULONG),
        ('UseCount', ULONG),
        ('FailedUseCount', ULONG),
        ('CurrentCommands', ULONG),
    }

 type LPSTAT_WORKSTATION_0 struct { // NDRPOINTER:
    referent = (
        ('Data', STAT_WORKSTATION_0),
    }

// 2.2.5.12 WKSTA_USER_INFO_0_CONTAINER
 type WKSTA_USER_INFO_0_ARRAY struct { // NDRUniConformantArray:
    item = WKSTA_USER_INFO_0

 type LPWKSTA_USER_INFO_0_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', WKSTA_USER_INFO_0_ARRAY),
    }

 type WKSTA_USER_INFO_0_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', ULONG),
        ('Buffer', LPWKSTA_USER_INFO_0_ARRAY),
    }

 type LPWKSTA_USER_INFO_0_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', WKSTA_USER_INFO_0_CONTAINER),
    }

// 2.2.5.13 WKSTA_USER_INFO_1_CONTAINER
 type WKSTA_USER_INFO_1_ARRAY struct { // NDRUniConformantArray:
    item = WKSTA_USER_INFO_1

 type LPWKSTA_USER_INFO_1_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', WKSTA_USER_INFO_1_ARRAY),
    }

 type WKSTA_USER_INFO_1_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', ULONG),
        ('Buffer', LPWKSTA_USER_INFO_1_ARRAY),
    }

 type LPWKSTA_USER_INFO_1_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', WKSTA_USER_INFO_1_CONTAINER),
    }

// 2.2.5.14 WKSTA_USER_ENUM_STRUCT
 type WKSTA_USER_ENUM_UNION struct { // NDRUNION:
    commonHdr = (
        ('tag', ULONG),
    }

    union = {
        0: ('Level0', LPWKSTA_USER_INFO_0_CONTAINER),
        1: ('Level1', LPWKSTA_USER_INFO_1_CONTAINER),
    }

 type WKSTA_USER_ENUM_STRUCT struct { // NDRSTRUCT: (
        ('Level', ULONG),
        ('WkstaUserInfo', WKSTA_USER_ENUM_UNION),
    }


// 2.2.5.15 WKSTA_TRANSPORT_INFO_0_CONTAINER
 type WKSTA_TRANSPORT_INFO_0_ARRAY struct { // NDRUniConformantArray:
    item = WKSTA_TRANSPORT_INFO_0

 type LPWKSTA_TRANSPORT_INFO_0_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', WKSTA_TRANSPORT_INFO_0_ARRAY),
    }

 type WKSTA_TRANSPORT_INFO_0_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', ULONG),
        ('Buffer', LPWKSTA_TRANSPORT_INFO_0_ARRAY),
    }

 type LPWKSTA_TRANSPORT_INFO_0_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', WKSTA_TRANSPORT_INFO_0_CONTAINER),
    }

// 2.2.5.16 WKSTA_TRANSPORT_ENUM_STRUCT
 type WKSTA_TRANSPORT_ENUM_UNION struct { // NDRUNION:
    commonHdr = (
        ('tag', ULONG),
    }

    union = {
        0: ('Level0', LPWKSTA_TRANSPORT_INFO_0_CONTAINER),
    }

 type WKSTA_TRANSPORT_ENUM_STRUCT struct { // NDRSTRUCT: (
        ('Level', ULONG),
        ('WkstaTransportInfo', WKSTA_TRANSPORT_ENUM_UNION),
    }

// 2.2.5.17 JOINPR_USER_PASSWORD
 type WCHAR_ARRAY struct { // WIDESTR:
     func (self TYPE) getDataLen(data interface{}){
        return JOIN_MAX_PASSWORD_LENGTH

 type CHAR_ARRAY struct { // NDRUniFixedArray:
     func (self TYPE) getDataLen(data interface{}){
        return JOIN_OBFUSCATOR_LENGTH

 type JOINPR_USER_PASSWORD struct { // NDRSTRUCT: (
        ('Obfuscator', CHAR_ARRAY),
        ('Buffer', WCHAR_ARRAY),
    }

// 2.2.5.18 JOINPR_ENCRYPTED_USER_PASSWORD
 type JOINPR_ENCRYPTED_USER_PASSWORD struct { // NDRSTRUCT: (
         Buffer [4]byte // =b""
    }
     func (self TYPE) getAlignment(){
        return 1

 type PJOINPR_ENCRYPTED_USER_PASSWORD struct { // NDRPOINTER:
    referent = (
        ('Data', JOINPR_ENCRYPTED_USER_PASSWORD),
    }

// 2.2.5.19 UNICODE_STRING
UNICODE_STRING = WSTR
 type PUNICODE_STRING struct { // NDRPOINTER:
    referent = (
        ('Data', UNICODE_STRING),
    }

// 2.2.5.20 NET_COMPUTER_NAME_ARRAY
 type UNICODE_STRING_ARRAY struct { // NDRUniConformantArray:
    item = RPC_UNICODE_STRING

 type PUNICODE_STRING_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', UNICODE_STRING_ARRAY),
    }

 type NET_COMPUTER_NAME_ARRAY struct { // NDRSTRUCT: (
        ('EntriesRead', ULONG),
        ('ComputerNames', PUNICODE_STRING_ARRAY),
    }

 type PNET_COMPUTER_NAME_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', NET_COMPUTER_NAME_ARRAY), 
    }

// 2.2.5.21 USE_INFO_0
 type USE_INFO_0 struct { // NDRSTRUCT: (
        ('ui0_local', LPWSTR),
        ('ui0_remote', LPWSTR),
    }

 type LPUSE_INFO_0 struct { // NDRPOINTER:
    referent = (
        ('Data', USE_INFO_0),
    }

// 2.2.5.22 USE_INFO_1
 type USE_INFO_1 struct { // NDRSTRUCT: (
        ('ui1_local', LPWSTR),
        ('ui1_remote', LPWSTR),
        ('ui1_password', LPWSTR),
        ('ui1_status', ULONG),
        ('ui1_asg_type', ULONG),
        ('ui1_refcount', ULONG),
        ('ui1_usecount', ULONG),
    }

 type LPUSE_INFO_1 struct { // NDRPOINTER:
    referent = (
        ('Data', USE_INFO_1),
    }

// 2.2.5.23 USE_INFO_2
 type USE_INFO_2 struct { // NDRSTRUCT: (
        ('ui2_useinfo', USE_INFO_1),
        ('ui2_username', LPWSTR),
        ('ui2_domainname', LPWSTR),
    }

 type LPUSE_INFO_2 struct { // NDRPOINTER:
    referent = (
        ('Data', USE_INFO_2),
    }

// 2.2.5.24 USE_INFO_3
 type USE_INFO_3 struct { // NDRSTRUCT: (
        ('ui3_ui2', USE_INFO_2),
        ('ui3_flags', ULONG),
    }

 type LPUSE_INFO_3 struct { // NDRPOINTER:
    referent = (
        ('Data', USE_INFO_3),
    }

// 2.2.4.2 USE_INFO
 type USE_INFO struct { // NDRUNION:
    commonHdr = (
        ('tag', ULONG),
    }

    union = {
        0: ('UseInfo0', LPUSE_INFO_0),
        1: ('UseInfo1', LPUSE_INFO_1),
        2: ('UseInfo2', LPUSE_INFO_2),
        3: ('UseInfo3', LPUSE_INFO_3),
    }

// 2.2.5.25 USE_INFO_0_CONTAINER
 type USE_INFO_0_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', ULONG),
        ('Buffer', LPUSE_INFO_0),
    }

 type LPUSE_INFO_0_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', USE_INFO_0_CONTAINER),
    }

// 2.2.5.26 USE_INFO_1_CONTAINER
 type USE_INFO_1_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', ULONG),
        ('Buffer', LPUSE_INFO_1),
    }

 type LPUSE_INFO_1_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', USE_INFO_1_CONTAINER),
    }

// 2.2.5.27 USE_INFO_2_CONTAINER
 type USE_INFO_2_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', ULONG),
        ('Buffer', LPUSE_INFO_2),
    }

 type LPUSE_INFO_2_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', USE_INFO_2_CONTAINER),
    }

// 2.2.5.28 USE_ENUM_STRUCT
 type USE_ENUM_UNION struct { // NDRUNION:
    commonHdr = (
        ('tag', ULONG),
    }

    union = {
        0: ('Level0', LPUSE_INFO_0_CONTAINER),
        1: ('Level1', LPUSE_INFO_1_CONTAINER),
        2: ('Level2', LPUSE_INFO_2_CONTAINER),
    }

 type USE_ENUM_STRUCT struct { // NDRSTRUCT: (
        ('Level', ULONG),
        ('UseInfo', USE_ENUM_UNION),
    }

//###############################################################################
// RPC CALLS
//###############################################################################

// 3.2.4.1 NetrWkstaGetInfo (Opnum 0)
 type NetrWkstaGetInfo struct { // NDRCALL:
    opnum = 0 (
       ('ServerName', LPWKSSVC_IDENTIFY_HANDLE),
       ('Level', ULONG),
    }

 type NetrWkstaGetInfoResponse struct { // NDRCALL: (
       ('WkstaInfo',WKSTA_INFO),
       ('ErrorCode',ULONG),
    }

// 3.2.4.2 NetrWkstaSetInfo (Opnum 1)
 type NetrWkstaSetInfo struct { // NDRCALL:
    opnum = 1 (
       ('ServerName', LPWKSSVC_IDENTIFY_HANDLE),
       ('Level', ULONG),
       ('WkstaInfo',WKSTA_INFO),
       ('ErrorParameter',LPULONG),
    }

 type NetrWkstaSetInfoResponse struct { // NDRCALL: (
       ('ErrorParameter',LPULONG),
       ('ErrorCode',ULONG),
    }

// 3.2.4.3 NetrWkstaUserEnum (Opnum 2)
 type NetrWkstaUserEnum struct { // NDRCALL:
    opnum = 2 (
       ('ServerName', LPWKSSVC_IDENTIFY_HANDLE),
       ('UserInfo', WKSTA_USER_ENUM_STRUCT),
       ('PreferredMaximumLength', ULONG),
       ('ResumeHandle', LPULONG),
    }

 type NetrWkstaUserEnumResponse struct { // NDRCALL: (
       ('UserInfo',WKSTA_USER_ENUM_STRUCT),
       ('TotalEntries',ULONG),
       ('ResumeHandle',ULONG),
       ('ErrorCode',ULONG),
    }

// 3.2.4.4 NetrWkstaTransportEnum (Opnum 5)
 type NetrWkstaTransportEnum struct { // NDRCALL:
    opnum = 5 (
       ('ServerName', LPWKSSVC_IDENTIFY_HANDLE),
       ('TransportInfo', WKSTA_TRANSPORT_ENUM_STRUCT),
       ('PreferredMaximumLength', ULONG),
       ('ResumeHandle', LPULONG),
    }

 type NetrWkstaTransportEnumResponse struct { // NDRCALL: (
       ('TransportInfo',WKSTA_TRANSPORT_ENUM_STRUCT),
       ('TotalEntries',ULONG),
       ('ResumeHandle',ULONG),
       ('ErrorCode',ULONG),
    }

// 3.2.4.5 NetrWkstaTransportAdd (Opnum 6)
 type NetrWkstaTransportAdd struct { // NDRCALL:
    opnum = 6 (
       ('ServerName', LPWKSSVC_IDENTIFY_HANDLE),
       ('Level', ULONG),
       ('TransportInfo',WKSTA_TRANSPORT_INFO_0),
       ('ErrorParameter',LPULONG),
    }

 type NetrWkstaTransportAddResponse struct { // NDRCALL: (
       ('ErrorParameter',LPULONG),
       ('ErrorCode',ULONG),
    }

// 3.2.4.7 NetrUseAdd (Opnum 8)
 type NetrUseAdd struct { // NDRCALL:
    opnum = 8 (
       ('ServerName', LPWKSSVC_IMPERSONATE_HANDLE),
       ('Level', ULONG),
       ('InfoStruct',USE_INFO),
       ('ErrorParameter',LPULONG),
    }

 type NetrUseAddResponse struct { // NDRCALL: (
       ('ErrorParameter',LPULONG),
       ('ErrorCode',ULONG),
    }

// 3.2.4.8 NetrUseGetInfo (Opnum 9)
 type NetrUseGetInfo struct { // NDRCALL:
    opnum = 9 (
       ('ServerName', LPWKSSVC_IMPERSONATE_HANDLE),
       ('UseName', WSTR),
       ('Level',ULONG),
    }

 type NetrUseGetInfoResponse struct { // NDRCALL: (
       ('InfoStruct',USE_INFO),
       ('ErrorCode',ULONG),
    }

// 3.2.4.9 NetrUseDel (Opnum 10)
 type NetrUseDel struct { // NDRCALL:
    opnum = 10 (
       ('ServerName', LPWKSSVC_IMPERSONATE_HANDLE),
       ('UseName', WSTR),
       ('ForceLevel',ULONG),
    }

 type NetrUseDelResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.2.4.10 NetrUseEnum (Opnum 11)
 type NetrUseEnum struct { // NDRCALL:
    opnum = 11 (
       ('ServerName', LPWKSSVC_IMPERSONATE_HANDLE),
       ('InfoStruct', USE_ENUM_STRUCT),
       ('PreferredMaximumLength',ULONG),
       ('ResumeHandle',LPULONG),
    }

 type NetrUseEnumResponse struct { // NDRCALL: (
       ('InfoStruct',USE_ENUM_STRUCT),
       ('TotalEntries',ULONG),
       ('ResumeHandle',LPULONG),
       ('ErrorCode',ULONG),
    }

// 3.2.4.11 NetrWorkstationStatisticsGet (Opnum 13)
 type NetrWorkstationStatisticsGet struct { // NDRCALL:
    opnum = 13 (
       ('ServerName', LPWKSSVC_IDENTIFY_HANDLE),
       ('ServiceName', LPWSTR),
       ('Level',ULONG),
       ('Options',ULONG),
    }

 type NetrWorkstationStatisticsGetResponse struct { // NDRCALL: (
       ('Buffer',LPSTAT_WORKSTATION_0),
       ('ErrorCode',ULONG),
    }

// 3.2.4.12 NetrGetJoinInformation (Opnum 20)
 type NetrGetJoinInformation struct { // NDRCALL:
    opnum = 20 (
       ('ServerName', LPWKSSVC_IMPERSONATE_HANDLE),
       ('NameBuffer', LPWSTR),
    }

 type NetrGetJoinInformationResponse struct { // NDRCALL: (
       ('NameBuffer',LPWSTR),
       ('BufferType',NETSETUP_JOIN_STATUS),
       ('ErrorCode',ULONG),
    }

// 3.2.4.13 NetrJoinDomain2 (Opnum 22)
 type NetrJoinDomain2 struct { // NDRCALL:
    opnum = 22 (
       ('ServerName', LPWSTR),
       ('DomainNameParam', WSTR),
       ('MachineAccountOU', LPWSTR),
       ('AccountName', LPWSTR),
       ('Password', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('Options', ULONG),
    }

 type NetrJoinDomain2Response struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.2.4.14 NetrUnjoinDomain2 (Opnum 23)
 type NetrUnjoinDomain2 struct { // NDRCALL:
    opnum = 23 (
       ('ServerName', LPWSTR),
       ('AccountName', LPWSTR),
       ('Password', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('Options', ULONG),
    }

 type NetrUnjoinDomain2Response struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.2.4.15 NetrRenameMachineInDomain2 (Opnum 24)
 type NetrRenameMachineInDomain2 struct { // NDRCALL:
    opnum = 24 (
       ('ServerName', LPWSTR),
       ('MachineName', LPWSTR),
       ('AccountName', LPWSTR),
       ('Password', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('Options', ULONG),
    }

 type NetrRenameMachineInDomain2Response struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.2.4.16 NetrValidateName2 (Opnum 25)
 type NetrValidateName2 struct { // NDRCALL:
    opnum = 25 (
       ('ServerName', LPWSTR),
       ('NameToValidate', WSTR),
       ('AccountName', LPWSTR),
       ('Password', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('NameType', NETSETUP_NAME_TYPE),
    }

 type NetrValidateName2Response struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.2.4.17 NetrGetJoinableOUs2 (Opnum 26)
 type NetrGetJoinableOUs2 struct { // NDRCALL:
    opnum = 26 (
       ('ServerName', LPWSTR),
       ('DomainNameParam', WSTR),
       ('AccountName', LPWSTR),
       ('Password', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('OUCount', ULONG),
    }

 type NetrGetJoinableOUs2Response struct { // NDRCALL: (
       ('OUCount', LPLONG),
       ('OUs',PUNICODE_STRING_ARRAY),
       ('ErrorCode',ULONG),
    }

// 3.2.4.18 NetrAddAlternateComputerName (Opnum 27)
 type NetrAddAlternateComputerName struct { // NDRCALL:
    opnum = 27 (
       ('ServerName', LPWSTR),
       ('AlternateName', LPWSTR),
       ('DomainAccount', LPWSTR),
       ('EncryptedPassword', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('Reserved', ULONG),
    }

 type NetrAddAlternateComputerNameResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.2.4.19 NetrRemoveAlternateComputerName (Opnum 28)
 type NetrRemoveAlternateComputerName struct { // NDRCALL:
    opnum = 28 (
       ('ServerName', LPWSTR),
       ('AlternateName', LPWSTR),
       ('DomainAccount', LPWSTR),
       ('EncryptedPassword', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('Reserved', ULONG),
    }

 type NetrRemoveAlternateComputerNameResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.2.4.20 NetrSetPrimaryComputerName (Opnum 29)
 type NetrSetPrimaryComputerName struct { // NDRCALL:
    opnum = 29 (
       ('ServerName', LPWSTR),
       ('PrimaryName', LPWSTR),
       ('DomainAccount', LPWSTR),
       ('EncryptedPassword', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('Reserved', ULONG),
    }

 type NetrSetPrimaryComputerNameResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.2.4.21 NetrEnumerateComputerNames (Opnum 30)
 type NetrEnumerateComputerNames struct { // NDRCALL:
    opnum = 30 (
       ('ServerName', LPWKSSVC_IMPERSONATE_HANDLE),
       ('NameType', NET_COMPUTER_NAME_TYPE),
       ('Reserved', ULONG),
    }

 type NetrEnumerateComputerNamesResponse struct { // NDRCALL: (
       ('ComputerNames',PNET_COMPUTER_NAME_ARRAY),
       ('ErrorCode',ULONG),
    }

//###############################################################################
// OPNUMs and their corresponding structures
//###############################################################################
OPNUMS = {
 0 : (NetrWkstaGetInfo, NetrWkstaGetInfoResponse),
 1 : (NetrWkstaSetInfo, NetrWkstaSetInfoResponse),
 2 : (NetrWkstaUserEnum, NetrWkstaUserEnumResponse),
 5 : (NetrWkstaTransportEnum, NetrWkstaTransportEnumResponse),
 6 : (NetrWkstaTransportAdd, NetrWkstaTransportAddResponse),
// 7 : (NetrWkstaTransportDel, NetrWkstaTransportDelResponse),
 8 : (NetrUseAdd, NetrUseAddResponse),
 9 : (NetrUseGetInfo, NetrUseGetInfoResponse),
10 : (NetrUseDel, NetrUseDelResponse),
11 : (NetrUseEnum, NetrUseEnumResponse),
13 : (NetrWorkstationStatisticsGet, NetrWorkstationStatisticsGetResponse),
20 : (NetrGetJoinInformation, NetrGetJoinInformationResponse),
22 : (NetrJoinDomain2, NetrJoinDomain2Response),
23 : (NetrUnjoinDomain2, NetrUnjoinDomain2Response),
24 : (NetrRenameMachineInDomain2, NetrRenameMachineInDomain2Response),
25 : (NetrValidateName2, NetrValidateName2Response),
26 : (NetrGetJoinableOUs2, NetrGetJoinableOUs2Response),
27 : (NetrAddAlternateComputerName, NetrAddAlternateComputerNameResponse),
28 : (NetrRemoveAlternateComputerName, NetrRemoveAlternateComputerNameResponse),
29 : (NetrSetPrimaryComputerName, NetrSetPrimaryComputerNameResponse),
30 : (NetrEnumerateComputerNames, NetrEnumerateComputerNamesResponse),
}

//###############################################################################
// HELPER FUNCTIONS
//###############################################################################
 func checkNullString(string interface{}){
    if string == NULL {
        return string

    if string[-1:] != '\x00' {
        return string + '\x00'
    } else  {
        return string

 func hNetrWkstaGetInfo(dce, level interface{}){
    request = NetrWkstaGetInfo()
    request["ServerName"] = "\x00"*10
    request["Level"] = level
    return dce.request(request)

 func hNetrWkstaUserEnum(dce, level, preferredMaximumLength=0xffffffff interface{}){
    request = NetrWkstaUserEnum()
    request["ServerName"] = "\x00"*10
    request["UserInfo"]["Level"] = level
    request["UserInfo"]["WkstaUserInfo"]["tag"] = level
    request["PreferredMaximumLength"] = preferredMaximumLength
    return dce.request(request)

 func hNetrWkstaTransportEnum(dce, level, resumeHandle = 0, preferredMaximumLength = 0xffffffff interface{}){
    request = NetrWkstaTransportEnum()
    request["ServerName"] = "\x00"*10
    request["TransportInfo"]["Level"] = level
    request["TransportInfo"]["WkstaTransportInfo"]["tag"] = level
    request["ResumeHandle"] = resumeHandle
    request["PreferredMaximumLength"] = preferredMaximumLength
    return dce.request(request)

 func hNetrWkstaSetInfo(dce, level, wkstInfo interface{}){
    request = NetrWkstaSetInfo()
    request["ServerName"] = "\x00"*10
    request["Level"] = level
    request["WkstaInfo"]["tag"] = level
    request["WkstaInfo"]['WkstaInfo%d'% level] = wkstInfo
    return dce.request(request)

 func hNetrWorkstationStatisticsGet(dce, serviceName, level, options interface{}){
    request = NetrWorkstationStatisticsGet()
    request["ServerName"] = "\x00"*10
    request["ServiceName"] = serviceName
    request["Level"] = level
    request["Options"] = options
    return dce.request(request)

 func hNetrGetJoinInformation(dce, nameBuffer interface{}){
    request = NetrGetJoinInformation()
    request["ServerName"] = "\x00"*10
    request["NameBuffer"] = nameBuffer
    return dce.request(request)

 func hNetrJoinDomain2(dce, domainNameParam, machineAccountOU, accountName, password, options interface{}){
    request = NetrJoinDomain2()
    request["ServerName"] = "\x00"*10
    request["DomainNameParam"] = checkNullString(domainNameParam)
    request["MachineAccountOU"] = checkNullString(machineAccountOU)
    request["AccountName"] = checkNullString(accountName)
    if password == NULL {
        request["Password"] = NULL
    } else  {
        request["Password"]["Buffer"] = password
    request["Options"] = options
    return dce.request(request)

 func hNetrUnjoinDomain2(dce, accountName, password, options interface{}){
    request = NetrUnjoinDomain2()
    request["ServerName"] = "\x00"*10
    request["AccountName"] = checkNullString(accountName)
    if password == NULL {
        request["Password"] = NULL
    } else  {
        request["Password"]["Buffer"] = password
    request["Options"] = options
    return dce.request(request)

 func hNetrRenameMachineInDomain2(dce, machineName, accountName, password, options interface{}){
    request = NetrRenameMachineInDomain2()
    request["ServerName"] = "\x00"*10
    request["MachineName"] = checkNullString(machineName)
    request["AccountName"] = checkNullString(accountName)
    if password == NULL {
        request["Password"] = NULL
    } else  {
        request["Password"]["Buffer"] = password
    request["Options"] = options
    return dce.request(request)

 func hNetrValidateName2(dce, nameToValidate, accountName, password, nameType interface{}){
    request = NetrValidateName2()
    request["ServerName"] = "\x00"*10
    request["NameToValidate"] = checkNullString(nameToValidate)
    request["AccountName"] = checkNullString(accountName)
    if password == NULL {
        request["Password"] = NULL
    } else  {
        request["Password"]["Buffer"] = password
    request["NameType"] = nameType
    return dce.request(request)

 func hNetrGetJoinableOUs2(dce, domainNameParam, accountName, password, OUCount interface{}){
    request = NetrGetJoinableOUs2()
    request["ServerName"] = "\x00"*10
    request["DomainNameParam"] = checkNullString(domainNameParam)
    request["AccountName"] = checkNullString(accountName)
    if password == NULL {
        request["Password"] = NULL
    } else  {
        request["Password"]["Buffer"] = password
    request["OUCount"] = OUCount
    return dce.request(request)

 func hNetrAddAlternateComputerName(dce, alternateName, domainAccount, encryptedPassword interface{}){
    request = NetrAddAlternateComputerName()
    request["ServerName"] = "\x00"*10
    request["AlternateName"] = checkNullString(alternateName)
    request["DomainAccount"] = checkNullString(domainAccount)
    if encryptedPassword == NULL {
        request["EncryptedPassword"] = NULL
    } else  {
        request["EncryptedPassword"]["Buffer"] = encryptedPassword
    return dce.request(request)

 func hNetrRemoveAlternateComputerName(dce, alternateName, domainAccount, encryptedPassword interface{}){
    request = NetrRemoveAlternateComputerName()
    request["ServerName"] = "\x00"*10
    request["AlternateName"] = checkNullString(alternateName)
    request["DomainAccount"] = checkNullString(domainAccount)
    if encryptedPassword == NULL {
        request["EncryptedPassword"] = NULL
    } else  {
        request["EncryptedPassword"]["Buffer"] = encryptedPassword
    return dce.request(request)

 func hNetrSetPrimaryComputerName(dce, primaryName, domainAccount, encryptedPassword interface{}){
    request = NetrSetPrimaryComputerName()
    request["ServerName"] = "\x00"*10
    request["PrimaryName"] = checkNullString(primaryName)
    request["DomainAccount"] = checkNullString(domainAccount)
    if encryptedPassword == NULL {
        request["EncryptedPassword"] = NULL
    } else  {
        request["EncryptedPassword"]["Buffer"] = encryptedPassword
    return dce.request(request)

 func hNetrEnumerateComputerNames(dce, nameType interface{}){
    request = NetrEnumerateComputerNames()
    request["ServerName"] = "\x00"*10
    request["NameType"] = nameType
    return dce.request(request)

 func hNetrUseAdd(dce, level, infoStruct interface{}){
    request = NetrUseAdd()
    request["ServerName"] = "\x00"*10
    request["Level"] = level
    request["InfoStruct"]["tag"] = level
    request["InfoStruct"]['UseInfo%d' % level] = infoStruct
    return dce.request(request)

 func hNetrUseEnum(dce, level, resumeHandle = 0, preferredMaximumLength = 0xffffffff interface{}){
    request = NetrUseEnum()
    request["ServerName"] = "\x00"*10
    request["InfoStruct"]["Level"] = level
    request["InfoStruct"]["UseInfo"]["tag"] = level
    request["InfoStruct"]["UseInfo"]['Level%d'%level]["Buffer"] = NULL
    request["PreferredMaximumLength"] = preferredMaximumLength
    request["ResumeHandle"] = resumeHandle
    return dce.request(request)

 func hNetrUseGetInfo(dce, useName, level interface{}){
    request = NetrUseGetInfo()
    request["ServerName"] = "\x00"*10
    request["UseName"] = checkNullString(useName)
    request["Level"] = level
    return dce.request(request)

 func hNetrUseDel(dce, useName, forceLevel=USE_LOTS_OF_FORCE interface{}){
    request = NetrUseDel()
    request["ServerName"] = "\x00"*10
    request["UseName"] = checkNullString(useName)
    request["ForceLevel"] = forceLevel
    return dce.request(request)
