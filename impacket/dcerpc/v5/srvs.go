// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Author: Alberto Solino (@agsolino)
//
// Description:
//   [MS-SRVS] Interface implementation
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
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.ndr import NDRCALL, NDR, NDRSTRUCT, NDRUNION, NDRPOINTER, NDRUniConformantArray, \
    NDRUniFixedArray, NDRBOOLEAN, NDRUniConformantVaryingArray, PNDRUniConformantArray
from impacket.dcerpc.v5.dtypes import NULL, DWORD, LPWSTR, LPBYTE, LMSTR, ULONG, GUID, LPLONG, WSTR, \
    SECURITY_INFORMATION, WCHAR
from impacket import system_errors
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_SRVS  = uuidtup_to_bin(('4B324FC8-1670-01D3-1278-5A47BF6EE188', '3.0'))

 type DCERPCSessionError struct { // DCERPCException:
     func (self TYPE) __init__(error_string=nil, error_code=nil, packet=nil interface{}){
        DCERPCException.__init__(self, error_string, error_code, packet)

     func __str__( self  interface{}){
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES {
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1] 
            return 'SRVS SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        } else  {
            return 'SRVS SessionError: unknown error code: 0x%x' % self.error_code

//###############################################################################
// CONSTANTS
//###############################################################################
// 2.2.1.1 SRVSVC_HANDLE
SRVSVC_HANDLE = WCHAR

 type PSRVSVC_HANDLE struct { // NDRPOINTER:
    referent = (
        ('Data', SRVSVC_HANDLE),
    }

// 2.2.1.2 SHARE_DEL_HANDLE
 type SHARE_DEL_HANDLE struct { // NDRSTRUCT:
    align = 1  (
         Data [0]byte // =""
    }

// 2.2.1.3 PSHARE_DEL_HANDLE
 type PSHARE_DEL_HANDLE struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_DEL_HANDLE),
    }

// 2.2.2.2 MAX_PREFERRED_LENGTH
MAX_PREFERRED_LENGTH = -1

// 2.2.2.3 Session User Flags
SESS_GUEST        = 0x00000001
SESS_NOENCRYPTION = 0x00000002

// 2.2.2.4 Share Types
STYPE_DISKTREE     = 0x00000000
STYPE_PRINTQ       = 0x00000001
STYPE_DEVICE       = 0x00000002
STYPE_IPC          = 0x00000003
STYPE_CLUSTER_FS   = 0x02000000
STYPE_CLUSTER_SOFS = 0x04000000
STYPE_CLUSTER_DFS  = 0x08000000

STYPE_SPECIAL      = 0x80000000
STYPE_TEMPORARY    = 0x40000000

// 2.2.2.5 Client-Side Caching (CSC) States
CSC_CACHE_MANUAL_REINT = 0x00
CSC_CACHE_AUTO_REINT   = 0x10
CSC_CACHE_VDO          = 0x20
CSC_CACHE_NONE         = 0x30

// 2.2.2.6 Platform IDs
PLATFORM_ID_DOS = 300
PLATFORM_ID_OS2 = 400
PLATFORM_ID_NT  = 500
PLATFORM_ID_OSF = 600
PLATFORM_ID_VMS = 700

// 2.2.2.7 Software Type Flags
SV_TYPE_WORKSTATION       = 0x00000001
SV_TYPE_SERVER            = 0x00000002
SV_TYPE_SQLSERVER         = 0x00000004
SV_TYPE_DOMAIN_CTRL       = 0x00000008
SV_TYPE_DOMAIN_BAKCTRL    = 0x00000010
SV_TYPE_TIME_SOURCE       = 0x00000020
SV_TYPE_AFP               = 0x00000040
SV_TYPE_NOVELL            = 0x00000080
SV_TYPE_DOMAIN_MEMBER     = 0x00000100
SV_TYPE_LOCAL_LIST_ONLY   = 0x40000000
SV_TYPE_PRINTQ_SERVER     = 0x00000200
SV_TYPE_DIALIN_SERVER     = 0x00000400
SV_TYPE_XENIX_SERVER      = 0x00000800
SV_TYPE_SERVER_MFPN       = 0x00004000
SV_TYPE_NT                = 0x00001000
SV_TYPE_WFW               = 0x00002000
SV_TYPE_SERVER_NT         = 0x00008000
SV_TYPE_POTENTIAL_BROWSER = 0x00010000
SV_TYPE_BACKUP_BROWSER    = 0x00020000
SV_TYPE_MASTER_BROWSER    = 0x00040000
SV_TYPE_DOMAIN_MASTER     = 0x00080000
SV_TYPE_DOMAIN_ENUM       = 0x80000000
SV_TYPE_WINDOWS           = 0x00400000
SV_TYPE_ALL               = 0xFFFFFFFF
SV_TYPE_TERMINALSERVER    = 0x02000000
SV_TYPE_CLUSTER_NT        = 0x10000000
SV_TYPE_CLUSTER_VS_NT     = 0x04000000

// 2.2.2.8 Name Types
NAMETYPE_USER          = 1
NAMETYPE_PASSWORD      = 2
NAMETYPE_GROUP         = 3
NAMETYPE_COMPUTER      = 4
NAMETYPE_EVENT         = 5
NAMETYPE_DOMAIN        = 6
NAMETYPE_SERVICE       = 7
NAMETYPE_NET           = 8
NAMETYPE_SHARE         = 9
NAMETYPE_MESSAGE       = 10
NAMETYPE_MESSAGEDEST   = 11
NAMETYPE_SHAREPASSWORD = 12
NAMETYPE_WORKGROUP     = 13

// 2.2.2.9 Path Types
ITYPE_UNC_COMPNAME     = 4144
ITYPE_UNC_WC           = 4145
ITYPE_UNC              = 4096
ITYPE_UNC_WC_PATH      = 4097
ITYPE_UNC_SYS_SEM      = 6400
ITYPE_UNC_SYS_SHMEM    = 6656
ITYPE_UNC_SYS_MSLOT    = 6144
ITYPE_UNC_SYS_PIPE     = 6912
ITYPE_UNC_SYS_QUEUE    = 7680
ITYPE_PATH_ABSND       = 8194
ITYPE_PATH_ABSD        = 8198
ITYPE_PATH_RELND       = 8192
ITYPE_PATH_RELD        = 8196
ITYPE_PATH_ABSND_WC    = 8195
ITYPE_PATH_ABSD_WC     = 8199
ITYPE_PATH_RELND_WC    = 8193
ITYPE_PATH_RELD_WC     = 8197
ITYPE_PATH_SYS_SEM     = 10498
ITYPE_PATH_SYS_SHMEM   = 10754
ITYPE_PATH_SYS_MSLOT   = 10242
ITYPE_PATH_SYS_PIPE    = 11010
ITYPE_PATH_SYS_COMM    = 11266
ITYPE_PATH_SYS_PRINT   = 11522
ITYPE_PATH_SYS_QUEUE   = 11778
ITYPE_PATH_SYS_SEM_M   = 43266
ITYPE_PATH_SYS_SHMEM_M = 43522
ITYPE_PATH_SYS_MSLOT_M = 43010
ITYPE_PATH_SYS_PIPE_M  = 43778
ITYPE_PATH_SYS_COMM_M  = 44034
ITYPE_PATH_SYS_PRINT_M = 44290
ITYPE_PATH_SYS_QUEUE_M = 44546
ITYPE_DEVICE_DISK      = 16384
ITYPE_DEVICE_LPT       = 16400
ITYPE_DEVICE_COM       = 16416
ITYPE_DEVICE_CON       = 16448
ITYPE_DEVICE_NUL       = 16464

// 2.2.2.11 SHARE_INFO Parameter Error Codes

SHARE_NETNAME_PARMNUM      = 1
SHARE_TYPE_PARMNUM         = 3
SHARE_REMARK_PARMNUM       = 4
SHARE_PERMISSIONS_PARMNUM  = 5
SHARE_MAX_USES_PARMNUM     = 6
SHARE_CURRENT_USES_PARMNUM = 7
SHARE_PATH_PARMNUM         = 8
SHARE_PASSWD_PARMNUM       = 9
SHARE_FILE_SD_PARMNUM      = 501

// 2.2.2.12 SERVER_INFO Parameter Error Codes
SV_PLATFORM_ID_PARMNUM             = 101
SV_NAME_PARMNUM                    = 102
SV_VERSION_MAJOR_PARMNUM           = 103
SV_VERSION_MINOR_PARMNUM           = 104
SV_TYPE_PARMNUM                    = 105
SV_COMMENT_PARMNUM                 = 5
SV_USERS_PARMNUM                   = 107
SV_DISC_PARMNUM                    = 10
SV_HIDDEN_PARMNUM                  = 16
SV_ANNOUNCE_PARMNUM                = 17
SV_ANNDELTA_PARMNUM                = 18
SV_USERPATH_PARMNUM                = 112
SV_SESSOPENS_PARMNUM               = 501
SV_SESSVCS_PARMNUM                 = 502
SV_OPENSEARCH_PARMNUM              = 503
SV_SIZREQBUF_PARMNUM               = 504
SV_INITWORKITEMS_PARMNUM           = 505
SV_MAXWORKITEMS_PARMNUM            = 506
SV_RAWWORKITEMS_PARMNUM            = 507
SV_IRPSTACKSIZE_PARMNUM            = 508
SV_MAXRAWBUFLEN_PARMNUM            = 509
SV_SESSUSERS_PARMNUM               = 510
SV_SESSCONNS_PARMNUM               = 511
SV_MAXNONPAGEDMEMORYUSAGE_PARMNUM  = 512
SV_MAXPAGEDMEMORYUSAGE_PARMNUM     = 513
SV_ENABLESOFTCOMPAT_PARMNUM        = 514
SV_ENABLEFORCEDLOGOFF_PARMNUM      = 515
SV_TIMESOURCE_PARMNUM              = 516
SV_ACCEPTDOWNLEVELAPIS_PARMNUM     = 517
SV_LMANNOUNCE_PARMNUM              = 518
SV_DOMAIN_PARMNUM                  = 519
SV_MAXCOPYREADLEN_PARMNUM          = 520
SV_MAXCOPYWRITELEN_PARMNUM         = 521
SV_MINKEEPSEARCH_PARMNUM           = 522
SV_MAXKEEPSEARCH_PARMNUM           = 523
SV_MINKEEPCOMPLSEARCH_PARMNUM      = 524
SV_MAXKEEPCOMPLSEARCH_PARMNUM      = 525
SV_THREADCOUNTADD_PARMNUM          = 526
SV_NUMBLOCKTHREADS_PARMNUM         = 527
SV_SCAVTIMEOUT_PARMNUM             = 528
SV_MINRCVQUEUE_PARMNUM             = 529
SV_MINFREEWORKITEMS_PARMNUM        = 530
SV_XACTMEMSIZE_PARMNUM             = 531
SV_THREADPRIORITY_PARMNUM          = 532
SV_MAXMPXCT_PARMNUM                = 533
SV_OPLOCKBREAKWAIT_PARMNUM         = 534
SV_OPLOCKBREAKRESPONSEWAIT_PARMNUM = 535
SV_ENABLEOPLOCKS_PARMNUM           = 536
SV_ENABLEOPLOCKFORCECLOSE_PARMNUM  = 537
SV_ENABLEFCBOPENS_PARMNUM          = 538
SV_ENABLERAW_PARMNUM               = 539
SV_ENABLESHAREDNETDRIVES_PARMNUM   = 540
SV_MINFREECONNECTIONS_PARMNUM      = 541
SV_MAXFREECONNECTIONS_PARMNUM      = 542
SV_INITSESSTABLE_PARMNUM           = 543
SV_INITCONNTABLE_PARMNUM           = 544
SV_INITFILETABLE_PARMNUM           = 545
SV_INITSEARCHTABLE_PARMNUM         = 546
SV_ALERTSCHEDULE_PARMNUM           = 547
SV_ERRORTHRESHOLD_PARMNUM          = 548
SV_NETWORKERRORTHRESHOLD_PARMNUM   = 549
SV_DISKSPACETHRESHOLD_PARMNUM      = 550
SV_MAXLINKDELAY_PARMNUM            = 552
SV_MINLINKTHROUGHPUT_PARMNUM       = 553
SV_LINKINFOVALIDTIME_PARMNUM       = 554
SV_SCAVQOSINFOUPDATETIME_PARMNUM   = 555
SV_MAXWORKITEMIDLETIME_PARMNUM     = 556

// 2.2.2.13 DFS Entry Flags
PKT_ENTRY_TYPE_CAIRO          = 0x0001
PKT_ENTRY_TYPE_MACHINE        = 0x0002
PKT_ENTRY_TYPE_NONCAIRO       = 0x0004
PKT_ENTRY_TYPE_LEAFONLY       = 0x0008
PKT_ENTRY_TYPE_OUTSIDE_MY_DOM = 0x0010
PKT_ENTRY_TYPE_INSITE_ONLY    = 0x0020
PKT_ENTRY_TYPE_REFERRAL_SVC   = 0x0080
PKT_ENTRY_TYPE_PERMANENT      = 0x0100
PKT_ENTRY_TYPE_LOCAL          = 0x0400
PKT_ENTRY_TYPE_LOCAL_XPOINT   = 0x0800
PKT_ENTRY_TYPE_MACH_SHARE     = 0x1000
PKT_ENTRY_TYPE_OFFLINE        = 0x2000

// 2.2.4.7 FILE_INFO_3 
// fi3_permissions
PERM_FILE_READ   = 0x00000001
PERM_FILE_WRITE  = 0x00000002
PERM_FILE_CREATE = 0x00000004
ACCESS_EXEC      = 0x00000008
ACCESS_DELETE    = 0x00000010
ACCESS_ATRIB     = 0x00000020
ACCESS_PERM      = 0x00000040

// 2.2.4.29 SHARE_INFO_1005
// shi1005_flags
SHI1005_FLAGS_DFS                         = 0x00000001
SHI1005_FLAGS_DFS_ROOT                    = 0x00000002
CSC_MASK                                  = 0x00000030
SHI1005_FLAGS_RESTRICT_EXCLUSIVE_OPENS    = 0x00000100
SHI1005_FLAGS_FORCE_SHARED_DELETE         = 0x00000200
SHI1005_FLAGS_ALLOW_NAMESPACE_CACHING     = 0x00000400
SHI1005_FLAGS_ACCESS_BASED_DIRECTORY_ENUM = 0x00000800
SHI1005_FLAGS_FORCE_LEVELII_OPLOCK        = 0x00001000
SHI1005_FLAGS_ENABLE_HASH                 = 0x00002000
SHI1005_FLAGS_ENABLE_CA                   = 0x00004000
SHI1005_FLAGS_ENCRYPT_DATA                = 0x00008000

// 2.2.4.43 SERVER_INFO_103
// sv103_capabilities
SRV_SUPPORT_HASH_GENERATION = 0x0001
SRV_HASH_GENERATION_ACTIVE  = 0x0002

// 2.2.4.96 SERVER_TRANSPORT_INFO_3
// svti3_flags
SVTI2_REMAP_PIPE_NAMES = 0x00000002
SVTI2_SCOPED_NAME      = 0x00000004

// 2.2.4.109 DFS_SITENAME_INFO
// SiteFlags
DFS_SITE_PRIMARY = 0x00000001

// 3.1.4.42 NetrDfsFixLocalVolume (Opnum 51)
// ServiceType
DFS_SERVICE_TYPE_MASTER     = 0x00000001
DFS_SERVICE_TYPE_READONLY   = 0x00000002
DFS_SERVICE_TYPE_LOCAL      = 0x00000004
DFS_SERVICE_TYPE_REFERRAL   = 0x00000008
DFS_SERVICE_TYPE_ACTIVE     = 0x000000010
DFS_SERVICE_TYPE_DOWN_LEVEL = 0x000000020
DFS_SERVICE_TYPE_COSTLIER   = 0x000000040
DFS_SERVICE_TYPE_OFFLINE    = 0x000000080

// CreateDisposition
FILE_SUPERSEDE = 0x00000000
FILE_OPEN      = 0x00000001
FILE_CREATE    = 0x00000002

//###############################################################################
// STRUCTURES
//###############################################################################
// 2.2.4.1 CONNECTION_INFO_0
 type CONNECTION_INFO_0 struct { // NDRSTRUCT: (
        ('coni0_id', DWORD),
    }

 type CONNECTION_INFO_0_ARRAY struct { // NDRUniConformantArray:
    item = CONNECTION_INFO_0

 type LPCONNECTION_INFO_0_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', CONNECTION_INFO_0_ARRAY),
    }

// 2.2.4.2 CONNECTION_INFO_1
 type CONNECTION_INFO_1 struct { // NDRSTRUCT: (
        ('coni1_id', DWORD),
        ('coni1_type', DWORD),
        ('coni1_num_opens', DWORD),
        ('coni1_num_users', DWORD),
        ('coni1_time', DWORD),
        ('coni1_username', LPWSTR),
        ('coni1_netname', LPWSTR),
    }

 type CONNECTION_INFO_1_ARRAY struct { // NDRUniConformantArray:
    item = CONNECTION_INFO_1

 type LPCONNECTION_INFO_1_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', CONNECTION_INFO_1_ARRAY),
    }

// 2.2.4.3 CONNECT_INFO_0_CONTAINER
 type CONNECT_INFO_0_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', DWORD),
        ('Buffer', LPCONNECTION_INFO_0_ARRAY),
    }

 type LPCONNECT_INFO_0_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', CONNECT_INFO_0_CONTAINER),
    }

// 2.2.4.4 CONNECT_INFO_1_CONTAINER
 type CONNECT_INFO_1_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', DWORD),
        ('Buffer', LPCONNECTION_INFO_1_ARRAY),
    }

 type LPCONNECT_INFO_1_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', CONNECT_INFO_1_CONTAINER),
    }

// 2.2.3.1 CONNECT_ENUM_UNION
 type CONNECT_ENUM_UNION struct { // NDRUNION:
    commonHdr = (
        ('tag', DWORD),
    }

    union = {
        0: ('Level0', LPCONNECT_INFO_0_CONTAINER),
        1: ('Level1', LPCONNECT_INFO_1_CONTAINER),
    }

// 2.2.4.5 CONNECT_ENUM_STRUCT
 type CONNECT_ENUM_STRUCT struct { // NDRSTRUCT: (
        ('Level', DWORD),
        ('ConnectInfo', CONNECT_ENUM_UNION),
    }

// 2.2.4.6 FILE_INFO_2
 type FILE_INFO_2 struct { // NDRSTRUCT: (
        ('fi2_id', DWORD),
    }

 type LPFILE_INFO_2 struct { // NDRPOINTER:
    referent = (
        ('Data', FILE_INFO_2),
    }

 type FILE_INFO_2_ARRAY struct { // NDRUniConformantArray:
    item = FILE_INFO_2

 type LPFILE_INFO_2_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', FILE_INFO_2_ARRAY),
    }

// 2.2.4.7 FILE_INFO_3
 type FILE_INFO_3 struct { // NDRSTRUCT: (
        ('fi3_id', DWORD),
        ('fi3_permissions', DWORD),
        ('fi3_num_locks', DWORD),
        ('fi3_path_name', LPWSTR),
        ('fi3_username', LPWSTR),
    }

 type LPFILE_INFO_3 struct { // NDRPOINTER:
    referent = (
        ('Data', FILE_INFO_3),
    }

 type FILE_INFO_3_ARRAY struct { // NDRUniConformantArray:
    item = FILE_INFO_3

 type LPFILE_INFO_3_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', FILE_INFO_3_ARRAY),
    }

// 2.2.4.8 FILE_INFO_2_CONTAINER
 type FILE_INFO_2_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', DWORD),
        ('Buffer', LPFILE_INFO_2_ARRAY),
    }

 type LPFILE_INFO_2_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', FILE_INFO_2_CONTAINER),
    }

// 2.2.4.9 FILE_INFO_3_CONTAINER
 type FILE_INFO_3_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', DWORD),
        ('Buffer', LPFILE_INFO_3_ARRAY),
    }

 type LPFILE_INFO_3_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', FILE_INFO_3_CONTAINER),
    }

// 2.2.3.2 FILE_ENUM_UNION
 type FILE_ENUM_UNION struct { // NDRUNION:
    commonHdr = (
        ('tag', DWORD),
    }

    union = {
        2: ('Level2', LPFILE_INFO_2_CONTAINER),
        3: ('Level3', LPFILE_INFO_3_CONTAINER),
    }

// 2.2.4.10 FILE_ENUM_STRUCT
 type FILE_ENUM_STRUCT struct { // NDRSTRUCT: (
        ('Level', DWORD),
        ('FileInfo', FILE_ENUM_UNION),
    }

// 2.2.4.11 SESSION_INFO_0
 type SESSION_INFO_0 struct { // NDRSTRUCT: (
        ('sesi0_cname', LPWSTR),
    }

 type LPSESSION_INFO_0 struct { // NDRPOINTER:
    referent = (
        ('Data', SESSION_INFO_0),
    }

 type SESSION_INFO_0_ARRAY struct { // NDRUniConformantArray:
    item = SESSION_INFO_0

 type LPSESSION_INFO_0_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SESSION_INFO_0_ARRAY),
    }

// 2.2.4.12 SESSION_INFO_1
 type SESSION_INFO_1 struct { // NDRSTRUCT: (
        ('sesi1_cname', LPWSTR),
        ('sesi1_username', LPWSTR),
        ('sesi1_num_opens', DWORD),
        ('sesi1_time', DWORD),
        ('sesi1_idle_time', DWORD),
        ('sesi1_user_flags', DWORD),
    }

 type LPSESSION_INFO_1 struct { // NDRPOINTER:
    referent = (
        ('Data', SESSION_INFO_1),
    }

 type SESSION_INFO_1_ARRAY struct { // NDRUniConformantArray:
    item = SESSION_INFO_1

 type LPSESSION_INFO_1_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SESSION_INFO_1_ARRAY),
    }

// 2.2.4.13 SESSION_INFO_2
 type SESSION_INFO_2 struct { // NDRSTRUCT: (
        ('sesi2_cname', LPWSTR),
        ('sesi2_username', LPWSTR),
        ('sesi2_num_opens', DWORD),
        ('sesi2_time', DWORD),
        ('sesi2_idle_time', DWORD),
        ('sesi2_user_flags', DWORD),
        ('sesi2_cltype_name', LPWSTR),
    }

 type LPSESSION_INFO_2 struct { // NDRPOINTER:
    referent = (
        ('Data', SESSION_INFO_2),
    }

 type SESSION_INFO_2_ARRAY struct { // NDRUniConformantArray:
    item = SESSION_INFO_2

 type LPSESSION_INFO_2_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SESSION_INFO_2_ARRAY),
    }

// 2.2.4.14 SESSION_INFO_10
 type SESSION_INFO_10 struct { // NDRSTRUCT: (
        ('sesi10_cname', LPWSTR),
        ('sesi10_username', LPWSTR),
        ('sesi10_time', DWORD),
        ('sesi10_idle_time', DWORD),
    }

 type LPSESSION_INFO_10 struct { // NDRPOINTER:
    referent = (
        ('Data', SESSION_INFO_10),
    }

 type SESSION_INFO_10_ARRAY struct { // NDRUniConformantArray:
    item = SESSION_INFO_10

 type LPSESSION_INFO_10_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SESSION_INFO_10_ARRAY),
    }

// 2.2.4.15 SESSION_INFO_502
 type SESSION_INFO_502 struct { // NDRSTRUCT: (
        ('sesi502_cname', LPWSTR),
        ('sesi502_username', LPWSTR),
        ('sesi502_num_opens', DWORD),
        ('sesi502_time', DWORD),
        ('sesi502_idle_time', DWORD),
        ('sesi502_user_flags', DWORD),
        ('sesi502_cltype_name', LPWSTR),
        ('sesi502_transport', LPWSTR),
    }

 type LPSESSION_INFO_502 struct { // NDRPOINTER:
    referent = (
        ('Data', SESSION_INFO_502),
    }

 type SESSION_INFO_502_ARRAY struct { // NDRUniConformantArray:
    item = SESSION_INFO_502

 type LPSESSION_INFO_502_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SESSION_INFO_502_ARRAY),
    }

// 2.2.4.16 SESSION_INFO_0_CONTAINER
 type SESSION_INFO_0_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', DWORD),
        ('Buffer', LPSESSION_INFO_0_ARRAY),
    }

 type LPSESSION_INFO_0_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', SESSION_INFO_0_CONTAINER),
    }

// 2.2.4.17 SESSION_INFO_1_CONTAINER
 type SESSION_INFO_1_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', DWORD),
        ('Buffer', LPSESSION_INFO_1_ARRAY),
    }

 type LPSESSION_INFO_1_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', SESSION_INFO_1_CONTAINER),
    }

// 2.2.4.18 SESSION_INFO_2_CONTAINER
 type SESSION_INFO_2_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', DWORD),
        ('Buffer', LPSESSION_INFO_2_ARRAY),
    }

 type LPSESSION_INFO_2_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', SESSION_INFO_2_CONTAINER),
    }

// 2.2.4.19 SESSION_INFO_10_CONTAINER
 type SESSION_INFO_10_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', DWORD),
        ('Buffer', LPSESSION_INFO_10_ARRAY),
    }

 type LPSESSION_INFO_10_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', SESSION_INFO_10_CONTAINER),
    }

// 2.2.4.20 SESSION_INFO_502_CONTAINER
 type SESSION_INFO_502_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', DWORD),
        ('Buffer', LPSESSION_INFO_502_ARRAY),
    }

 type LPSESSION_INFO_502_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', SESSION_INFO_502_CONTAINER),
    }

// 2.2.3.4 SESSION_ENUM_UNION
 type SESSION_ENUM_UNION struct { // NDRUNION:
    commonHdr = (
        ('tag', DWORD),
    }

    union = {
        0: ('Level0', LPSESSION_INFO_0_CONTAINER),
        1: ('Level1', LPSESSION_INFO_1_CONTAINER),
        2: ('Level2', LPSESSION_INFO_2_CONTAINER),
        10: ('Level10', LPSESSION_INFO_10_CONTAINER),
        502: ('Level502', LPSESSION_INFO_502_CONTAINER),
    }

// 2.2.4.21 SESSION_ENUM_STRUCT
 type SESSION_ENUM_STRUCT struct { // NDRSTRUCT: (
        ('Level', DWORD),
        ('SessionInfo', SESSION_ENUM_UNION),
    }

// 2.2.4.22 SHARE_INFO_0
 type SHARE_INFO_0 struct { // NDRSTRUCT: (
        ('shi0_netname', LPWSTR),
    }

 type LPSHARE_INFO_0 struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_0),
    }

 type SHARE_INFO_0_ARRAY struct { // NDRUniConformantArray:
    item = SHARE_INFO_0

 type LPSHARE_INFO_0_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_0_ARRAY),
    }

// 2.2.4.23 SHARE_INFO_1
 type SHARE_INFO_1 struct { // NDRSTRUCT: (
        ('shi1_netname', LPWSTR),
        ('shi1_type', DWORD),
        ('shi1_remark', LPWSTR),
    }

 type LPSHARE_INFO_1 struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_1),
    }

 type SHARE_INFO_1_ARRAY struct { // NDRUniConformantArray:
    item = SHARE_INFO_1

 type LPSHARE_INFO_1_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_1_ARRAY),
    }

// 2.2.4.24 SHARE_INFO_2
 type SHARE_INFO_2 struct { // NDRSTRUCT: (
        ('shi2_netname', LPWSTR),
        ('shi2_type', DWORD),
        ('shi2_remark', LPWSTR),
        ('shi2_permissions', DWORD),
        ('shi2_max_uses', DWORD),
        ('shi2_current_uses', DWORD),
        ('shi2_path', LPWSTR),
        ('shi2_passwd', LPWSTR),
    }

 type LPSHARE_INFO_2 struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_2),
    }

 type SHARE_INFO_2_ARRAY struct { // NDRUniConformantArray:
    item = SHARE_INFO_2

 type LPSHARE_INFO_2_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_2_ARRAY),
    }

// 2.2.4.25 SHARE_INFO_501
 type SHARE_INFO_501 struct { // NDRSTRUCT: (
        ('shi501_netname', LPWSTR),
        ('shi501_type', DWORD),
        ('shi501_remark', LPWSTR),
        ('shi501_flags', DWORD),
    }

 type LPSHARE_INFO_501 struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_501),
    }

 type SHARE_INFO_501_ARRAY struct { // NDRUniConformantArray:
    item = SHARE_INFO_501

 type LPSHARE_INFO_501_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_501_ARRAY),
    }

// 2.2.4.26 SHARE_INFO_502_I
 type SHARE_INFO_502 struct { // NDRSTRUCT: (
        ('shi502_netname', LPWSTR),
        ('shi502_type', DWORD),
        ('shi502_remark', LPWSTR),
        ('shi502_permissions', DWORD),
        ('shi502_max_uses', DWORD),
        ('shi502_current_uses', DWORD),
        ('shi502_path', LPWSTR),
        ('shi502_passwd', LPWSTR),
        ('shi502_reserved', DWORD),
        ('shi502_security_descriptor', LPBYTE),
    }

 type LPSHARE_INFO_502 struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_502),
    }

 type SHARE_INFO_502_ARRAY struct { // NDRUniConformantArray:
    item = SHARE_INFO_502

 type LPSHARE_INFO_502_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_502_ARRAY),
    }

// 2.2.4.27 SHARE_INFO_503_I
 type SHARE_INFO_503 struct { // NDRSTRUCT: (
        ('shi503_netname', LPWSTR),
        ('shi503_type', DWORD),
        ('shi503_remark', LPWSTR),
        ('shi503_permissions', DWORD),
        ('shi503_max_uses', DWORD),
        ('shi503_current_uses', DWORD),
        ('shi503_path', LPWSTR),
        ('shi503_passwd', LPWSTR),
        ('shi503_servername', LPWSTR),
        ('shi503_reserved', DWORD),
        ('shi503_security_descriptor', LPBYTE),
    }

 type LPSHARE_INFO_503 struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_503),
    }

 type SHARE_INFO_503_ARRAY struct { // NDRUniConformantArray:
    item = SHARE_INFO_503

 type LPSHARE_INFO_503_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_503_ARRAY),
    }

// 2.2.4.28 SHARE_INFO_1004
 type SHARE_INFO_1004 struct { // NDRSTRUCT: (
        ('shi1004_remark', LPWSTR),
    }

 type LPSHARE_INFO_1004 struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_1004),
    }

 type SHARE_INFO_1004_ARRAY struct { // NDRUniConformantArray:
    item = SHARE_INFO_1004

 type LPSHARE_INFO_1004_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_1004_ARRAY),
    }

// 2.2.4.29 SHARE_INFO_1005
 type SHARE_INFO_1005 struct { // NDRSTRUCT: (
        ('shi1005_flags', DWORD),
    }

 type LPSHARE_INFO_1005 struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_1005),
    }

 type SHARE_INFO_1005_ARRAY struct { // NDRUniConformantArray:
    item = SHARE_INFO_1004

 type LPSHARE_INFO_1005_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_1005_ARRAY),
    }

// 2.2.4.30 SHARE_INFO_1006
 type SHARE_INFO_1006 struct { // NDRSTRUCT: (
        ('shi1006_max_uses', DWORD),
    }

 type LPSHARE_INFO_1006 struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_1006),
    }

 type SHARE_INFO_1006_ARRAY struct { // NDRUniConformantArray:
    item = SHARE_INFO_1006

 type LPSHARE_INFO_1006_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_1006_ARRAY),
    }

// 2.2.4.31 SHARE_INFO_1501_I
 type SHARE_INFO_1501 struct { // NDRSTRUCT: (
        ('shi1501_reserved', DWORD),
        ('shi1501_security_descriptor', NDRUniConformantArray),
    }

 type LPSHARE_INFO_1501 struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_1501),
    }

 type SHARE_INFO_1501_ARRAY struct { // NDRUniConformantArray:
    item = SHARE_INFO_1501

 type LPSHARE_INFO_1501_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_1501_ARRAY),
    }

// 2.2.4.32 SHARE_INFO_0_CONTAINER
 type SHARE_INFO_0_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', DWORD),
        ('Buffer', LPSHARE_INFO_0_ARRAY),
    }

 type LPSHARE_INFO_0_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_0_CONTAINER),
    }

// 2.2.4.33 SHARE_INFO_1_CONTAINER
 type SHARE_INFO_1_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', DWORD),
        ('Buffer', LPSHARE_INFO_1_ARRAY),
    }

 type LPSHARE_INFO_1_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_1_CONTAINER),
    }

// 2.2.4.34 SHARE_INFO_2_CONTAINER
 type SHARE_INFO_2_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', DWORD),
        ('Buffer', LPSHARE_INFO_2_ARRAY),
    }

 type LPSHARE_INFO_2_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_2_CONTAINER),
    }

// 2.2.4.35 SHARE_INFO_501_CONTAINER
 type SHARE_INFO_501_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', DWORD),
        ('Buffer', LPSHARE_INFO_501_ARRAY),
    }

 type LPSHARE_INFO_501_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_501_CONTAINER),
    }

// 2.2.4.36 SHARE_INFO_502_CONTAINER
 type SHARE_INFO_502_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', DWORD),
        ('Buffer', LPSHARE_INFO_502_ARRAY),
    }

 type LPSHARE_INFO_502_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_502_CONTAINER),
    }

// 2.2.4.37 SHARE_INFO_503_CONTAINER
 type SHARE_INFO_503_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', DWORD),
        ('Buffer', LPSHARE_INFO_503_ARRAY),
    }

 type LPSHARE_INFO_503_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', SHARE_INFO_503_CONTAINER),
    }

// 2.2.3.5 SHARE_ENUM_UNION
 type SHARE_ENUM_UNION struct { // NDRUNION:
    commonHdr = (
        ('tag', DWORD),
    }

    union = {
        0: ('Level0', LPSHARE_INFO_0_CONTAINER),
        1: ('Level1', LPSHARE_INFO_1_CONTAINER),
        2: ('Level2', LPSHARE_INFO_2_CONTAINER),
        501: ('Level501', LPSHARE_INFO_501_CONTAINER),
        502: ('Level502', LPSHARE_INFO_502_CONTAINER),
        503: ('Level503', LPSHARE_INFO_503_CONTAINER),
    }

// 2.2.4.38 SHARE_ENUM_STRUCT
 type SHARE_ENUM_STRUCT struct { // NDRSTRUCT: (
        ('Level', DWORD),
        ('ShareInfo', SHARE_ENUM_UNION),
    }

// 2.2.4.39 STAT_SERVER_0
 type STAT_SERVER_0 struct { // NDRSTRUCT: (
        ('sts0_start', DWORD),
        ('sts0_fopens', DWORD),
        ('sts0_devopens', DWORD),
        ('sts0_jobsqueued', DWORD),
        ('sts0_sopens', DWORD),
        ('sts0_stimedout', DWORD),
        ('sts0_serrorout', DWORD),
        ('sts0_pwerrors', DWORD),
        ('sts0_permerrors', DWORD),
        ('sts0_syserrors', DWORD),
        ('sts0_bytessent_low', DWORD),
        ('sts0_bytessent_high', DWORD),
        ('sts0_bytesrcvd_low', DWORD),
        ('sts0_bytesrcvd_high', DWORD),
        ('sts0_avresponse', DWORD),
        ('sts0_reqbufneed', DWORD),
        ('sts0_bigbufneed', DWORD),
    }

 type LPSTAT_SERVER_0 struct { // NDRPOINTER:
    referent = (
        ('Data', STAT_SERVER_0),
    }

// 2.2.4.40 SERVER_INFO_100
 type SERVER_INFO_100 struct { // NDRSTRUCT: (
        ('sv100_platform_id', DWORD),
        ('sv100_name', LPWSTR),
    }

 type LPSERVER_INFO_100 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_100),
    }

// 2.2.4.41 SERVER_INFO_101
 type SERVER_INFO_101 struct { // NDRSTRUCT: (
        ('sv101_platform_id', DWORD),
        ('sv101_name', LPWSTR),
        ('sv101_version_major', DWORD),
        ('sv101_version_minor', DWORD),
        ('sv101_type', DWORD),
        ('sv101_comment', LPWSTR),
    }

 type LPSERVER_INFO_101 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_101),
    }

// 2.2.4.42 SERVER_INFO_102
 type SERVER_INFO_102 struct { // NDRSTRUCT: (
        ('sv102_platform_id', DWORD),
        ('sv102_name', LPWSTR),
        ('sv102_version_major', DWORD),
        ('sv102_version_minor', DWORD),
        ('sv102_type', DWORD),
        ('sv102_comment', LPWSTR),
        ('sv102_users', DWORD),
        ('sv102_disc', DWORD),
        ('sv102_hidden', DWORD),
        ('sv102_announce', DWORD),
        ('sv102_anndelta', DWORD),
        ('sv102_licenses', DWORD),
        ('sv102_userpath', LPWSTR),
    }

 type LPSERVER_INFO_102 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_102),
    }

// 2.2.4.43 SERVER_INFO_103
 type SERVER_INFO_103 struct { // NDRSTRUCT: (
        ('sv103_platform_id', DWORD),
        ('sv103_name', LPWSTR),
        ('sv103_version_major', DWORD),
        ('sv103_version_minor', DWORD),
        ('sv103_type', DWORD),
        ('sv103_comment', LPWSTR),
        ('sv103_users', DWORD),
        ('sv103_disc', DWORD),
        ('sv103_hidden', DWORD),
        ('sv103_announce', DWORD),
        ('sv103_anndelta', DWORD),
        ('sv103_licenses', DWORD),
        ('sv103_userpath', LPWSTR),
        ('sv103_capabilities', DWORD),
    }

 type LPSERVER_INFO_103 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_103),
    }

// 2.2.4.44 SERVER_INFO_502
 type SERVER_INFO_502 struct { // NDRSTRUCT: (
        ('sv502_sessopens', DWORD),
        ('sv502_sessvcs', DWORD),
        ('sv502_opensearch', DWORD),
        ('sv502_sizreqbuf', DWORD),
        ('sv502_initworkitems', DWORD),
        ('sv502_maxworkitems', DWORD),
        ('sv502_rawworkitems', DWORD),
        ('sv502_irpstacksize', DWORD),
        ('sv502_maxrawbuflen', DWORD),
        ('sv502_sessusers', DWORD),
        ('sv502_sessconns', DWORD),
        ('sv502_maxpagedmemoryusage', DWORD),
        ('sv502_maxnonpagedmemoryusage', DWORD),
        ('sv502_enablesoftcompat', DWORD),
        ('sv502_enableforcedlogoff', DWORD),
        ('sv502_timesource', DWORD),
        ('sv502_acceptdownlevelapis', DWORD),
        ('sv502_lmannounce', DWORD),
    }

 type LPSERVER_INFO_502 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_502),
    }

// 2.2.4.45 SERVER_INFO_503
 type SERVER_INFO_503 struct { // NDRSTRUCT: (
        ('sv503_sessopens', DWORD),
        ('sv503_sessvcs', DWORD),
        ('sv503_opensearch', DWORD),
        ('sv503_sizreqbuf', DWORD),
        ('sv503_initworkitems', DWORD),
        ('sv503_maxworkitems', DWORD),
        ('sv503_rawworkitems', DWORD),
        ('sv503_irpstacksize', DWORD),
        ('sv503_maxrawbuflen', DWORD),
        ('sv503_sessusers', DWORD),
        ('sv503_sessconns', DWORD),
        ('sv503_maxpagedmemoryusage', DWORD),
        ('sv503_maxnonpagedmemoryusage', DWORD),
        ('sv503_enablesoftcompat', DWORD),
        ('sv503_enableforcedlogoff', DWORD),
        ('sv503_timesource', DWORD),
        ('sv503_acceptdownlevelapis', DWORD),
        ('sv503_lmannounce', DWORD),
        ('sv503_domain', LPWSTR),
        ('sv503_maxcopyreadlen', DWORD),
        ('sv503_maxcopywritelen', DWORD),
        ('sv503_minkeepsearch', DWORD),
        ('sv503_maxkeepsearch', DWORD),
        ('sv503_minkeepcomplsearch', DWORD),
        ('sv503_maxkeepcomplsearch', DWORD),
        ('sv503_threadcountadd', DWORD),
        ('sv503_numblockthreads', DWORD),
        ('sv503_scavtimeout', DWORD),
        ('sv503_minrcvqueue', DWORD),
        ('sv503_minfreeworkitems', DWORD),
        ('sv503_xactmemsize', DWORD),
        ('sv503_threadpriority', DWORD),
        ('sv503_maxmpxct', DWORD),
        ('sv503_oplockbreakwait', DWORD),
        ('sv503_oplockbreakresponsewait', DWORD),
        ('sv503_enableoplocks', DWORD),
        ('sv503_enableoplockforceclose', DWORD),
        ('sv503_enablefcbopens', DWORD),
        ('sv503_enableraw', DWORD),
        ('sv503_enablesharednetdrives', DWORD),
        ('sv503_minfreeconnections', DWORD),
        ('sv503_maxfreeconnections', DWORD),
    }

 type LPSERVER_INFO_503 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_503),
    }

// 2.2.4.46 SERVER_INFO_599
 type SERVER_INFO_599 struct { // NDRSTRUCT: (
        ('sv599_sessopens', DWORD),
        ('sv599_sessvcs', DWORD),
        ('sv599_opensearch', DWORD),
        ('sv599_sizreqbuf', DWORD),
        ('sv599_initworkitems', DWORD),
        ('sv599_maxworkitems', DWORD),
        ('sv599_rawworkitems', DWORD),
        ('sv599_irpstacksize', DWORD),
        ('sv599_maxrawbuflen', DWORD),
        ('sv599_sessusers', DWORD),
        ('sv599_sessconns', DWORD),
        ('sv599_maxpagedmemoryusage', DWORD),
        ('sv599_maxnonpagedmemoryusage', DWORD),
        ('sv599_enablesoftcompat', DWORD),
        ('sv599_enableforcedlogoff', DWORD),
        ('sv599_timesource', DWORD),
        ('sv599_acceptdownlevelapis', DWORD),
        ('sv599_lmannounce', DWORD),
        ('sv599_domain', LPWSTR),
        ('sv599_maxcopyreadlen', DWORD),
        ('sv599_maxcopywritelen', DWORD),
        ('sv599_minkeepsearch', DWORD),
        ('sv599_maxkeepsearch', DWORD),
        ('sv599_minkeepcomplsearch', DWORD),
        ('sv599_maxkeepcomplsearch', DWORD),
        ('sv599_threadcountadd', DWORD),
        ('sv599_numblockthreads', DWORD),
        ('sv599_scavtimeout', DWORD),
        ('sv599_minrcvqueue', DWORD),
        ('sv599_minfreeworkitems', DWORD),
        ('sv599_xactmemsize', DWORD),
        ('sv599_threadpriority', DWORD),
        ('sv599_maxmpxct', DWORD),
        ('sv599_oplockbreakwait', DWORD),
        ('sv599_oplockbreakresponsewait', DWORD),
        ('sv599_enableoplocks', DWORD),
        ('sv599_enableoplockforceclose', DWORD),
        ('sv599_enablefcbopens', DWORD),
        ('sv599_enableraw', DWORD),
        ('sv599_enablesharednetdrives', DWORD),
        ('sv599_minfreeconnections', DWORD),
        ('sv599_maxfreeconnections', DWORD),
        ('sv599_initsesstable', DWORD),
        ('sv599_initconntable', DWORD),
        ('sv599_initfiletable', DWORD),
        ('sv599_initsearchtable', DWORD),
        ('sv599_alertschedule', DWORD),
        ('sv599_errorthreshold', DWORD),
        ('sv599_networkerrorthreshold', DWORD),
        ('sv599_diskspacethreshold', DWORD),
        ('sv599_reserved', DWORD),
        ('sv599_maxlinkdelay', DWORD),
        ('sv599_minlinkthroughput', DWORD),
        ('sv599_linkinfovalidtime', DWORD),
        ('sv599_scavqosinfoupdatetime', DWORD),
        ('sv599_maxworkitemidletime', DWORD),
    }

 type LPSERVER_INFO_599 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_599),
    }

// 2.2.4.47 SERVER_INFO_1005
 type SERVER_INFO_1005 struct { // NDRSTRUCT: (
        ('sv1005_comment', LPWSTR),
    }

 type LPSERVER_INFO_1005 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1005),
    }

// 2.2.4.48 SERVER_INFO_1107
 type SERVER_INFO_1107 struct { // NDRSTRUCT: (
        ('sv1107_users', DWORD),
    }

 type LPSERVER_INFO_1107 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1107),
    }

// 2.2.4.49 SERVER_INFO_1010
 type SERVER_INFO_1010 struct { // NDRSTRUCT: (
        ('sv1010_disc', DWORD),
    }

 type LPSERVER_INFO_1010 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1010),
    }

// 2.2.4.50 SERVER_INFO_1016
 type SERVER_INFO_1016 struct { // NDRSTRUCT: (
        ('sv1016_hidden', DWORD),
    }

 type LPSERVER_INFO_1016 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1016),
    }

// 2.2.4.51 SERVER_INFO_1017
 type SERVER_INFO_1017 struct { // NDRSTRUCT: (
        ('sv1017_announce', DWORD),
    }

 type LPSERVER_INFO_1017 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1017),
    }

// 2.2.4.52 SERVER_INFO_1018
 type SERVER_INFO_1018 struct { // NDRSTRUCT: (
        ('sv1018_anndelta', DWORD),
    }

 type LPSERVER_INFO_1018 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1018),
    }

// 2.2.4.53 SERVER_INFO_1501
 type SERVER_INFO_1501 struct { // NDRSTRUCT: (
        ('sv1501_sessopens', DWORD),
    }

 type LPSERVER_INFO_1501 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1501),
    }

// 2.2.4.54 SERVER_INFO_1502
 type SERVER_INFO_1502 struct { // NDRSTRUCT: (
        ('sv1502_sessvcs', DWORD),
    }

 type LPSERVER_INFO_1502 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1502),
    }

// 2.2.4.55 SERVER_INFO_1503
 type SERVER_INFO_1503 struct { // NDRSTRUCT: (
        ('sv1503_opensearch', DWORD),
    }

 type LPSERVER_INFO_1503 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1503),
    }

// 2.2.4.56 SERVER_INFO_1506
 type SERVER_INFO_1506 struct { // NDRSTRUCT: (
        ('sv1506_maxworkitems', DWORD),
    }

 type LPSERVER_INFO_1506 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1506),
    }

// 2.2.4.57 SERVER_INFO_1510
 type SERVER_INFO_1510 struct { // NDRSTRUCT: (
        ('sv1510_sessusers', DWORD),
    }

 type LPSERVER_INFO_1510 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1510),
    }

// 2.2.4.58 SERVER_INFO_1511
 type SERVER_INFO_1511 struct { // NDRSTRUCT: (
        ('sv1511_sessconns', DWORD),
    }

 type LPSERVER_INFO_1511 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1511),
    }

// 2.2.4.59 SERVER_INFO_1512
 type SERVER_INFO_1512 struct { // NDRSTRUCT: (
        ('sv1512_maxnonpagedmemoryusage', DWORD),
    }

 type LPSERVER_INFO_1512 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1512),
    }

// 2.2.4.60 SERVER_INFO_1513
 type SERVER_INFO_1513 struct { // NDRSTRUCT: (
        ('sv1513_maxpagedmemoryusage', DWORD),
    }

 type LPSERVER_INFO_1513 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1513),
    }

// 2.2.4.61 SERVER_INFO_1514
 type SERVER_INFO_1514 struct { // NDRSTRUCT: (
        ('sv1514_enablesoftcompat', DWORD),
    }

 type LPSERVER_INFO_1514 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1514),
    }

// 2.2.4.62 SERVER_INFO_1515
 type SERVER_INFO_1515 struct { // NDRSTRUCT: (
        ('sv1515_enableforcedlogoff', DWORD),
    }

 type LPSERVER_INFO_1515 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1515),
    }

// 2.2.4.63 SERVER_INFO_1516
 type SERVER_INFO_1516 struct { // NDRSTRUCT: (
        ('sv1516_timesource', DWORD),
    }

 type LPSERVER_INFO_1516 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1516),
    }

// 2.2.4.64 SERVER_INFO_1518
 type SERVER_INFO_1518 struct { // NDRSTRUCT: (
        ('sv1518_lmannounce', DWORD),
    }

 type LPSERVER_INFO_1518 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1518),
    }

// 2.2.4.65 SERVER_INFO_1523
 type SERVER_INFO_1523 struct { // NDRSTRUCT: (
        ('sv1523_maxkeepsearch', DWORD),
    }

 type LPSERVER_INFO_1523 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1523),
    }

// 2.2.4.66 SERVER_INFO_1528
 type SERVER_INFO_1528 struct { // NDRSTRUCT: (
        ('sv1528_scavtimeout', DWORD),
    }

 type LPSERVER_INFO_1528 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1528),
    }

// 2.2.4.67 SERVER_INFO_1529
 type SERVER_INFO_1529 struct { // NDRSTRUCT: (
        ('sv1529_minrcvqueue', DWORD),
    }

 type LPSERVER_INFO_1529 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1529),
    }

// 2.2.4.68 SERVER_INFO_1530
 type SERVER_INFO_1530 struct { // NDRSTRUCT: (
        ('sv1530_minfreeworkitems', DWORD),
    }

 type LPSERVER_INFO_1530 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1530),
    }

// 2.2.4.69 SERVER_INFO_1533
 type SERVER_INFO_1533 struct { // NDRSTRUCT: (
        ('sv1533_maxmpxct', DWORD),
    }

 type LPSERVER_INFO_1533 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1533),
    }

// 2.2.4.70 SERVER_INFO_1534
 type SERVER_INFO_1534 struct { // NDRSTRUCT: (
        ('sv1534_oplockbreakwait', DWORD),
    }

 type LPSERVER_INFO_1534 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1534),
    }

// 2.2.4.71 SERVER_INFO_1535
 type SERVER_INFO_1535 struct { // NDRSTRUCT: (
        ('sv1535_oplockbreakresponsewait', DWORD),
    }

 type LPSERVER_INFO_1535 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1535),
    }

// 2.2.4.72 SERVER_INFO_1536
 type SERVER_INFO_1536 struct { // NDRSTRUCT: (
        ('sv1536_enableoplocks', DWORD),
    }

 type LPSERVER_INFO_1536 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1536),
    }

// 2.2.4.73 SERVER_INFO_1538
 type SERVER_INFO_1538 struct { // NDRSTRUCT: (
        ('sv1538_enablefcbopens', DWORD),
    }

 type LPSERVER_INFO_1538 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1538),
    }

// 2.2.4.74 SERVER_INFO_1539
 type SERVER_INFO_1539 struct { // NDRSTRUCT: (
        ('sv1539_enableraw', DWORD),
    }

 type LPSERVER_INFO_1539 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1539),
    }

// 2.2.4.75 SERVER_INFO_1540
 type SERVER_INFO_1540 struct { // NDRSTRUCT: (
        ('sv1540_enablesharednetdrives', DWORD),
    }

 type LPSERVER_INFO_1540 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1540),
    }

// 2.2.4.76 SERVER_INFO_1541
 type SERVER_INFO_1541 struct { // NDRSTRUCT: (
        ('sv1541_minfreeconnections', DWORD),
    }

 type LPSERVER_INFO_1541 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1541),
    }

// 2.2.4.77 SERVER_INFO_1542
 type SERVER_INFO_1542 struct { // NDRSTRUCT: (
        ('sv1542_maxfreeconnections', DWORD),
    }

 type LPSERVER_INFO_1542 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1542),
    }

// 2.2.4.78 SERVER_INFO_1543
 type SERVER_INFO_1543 struct { // NDRSTRUCT: (
        ('sv1543_initsesstable', DWORD),
    }

 type LPSERVER_INFO_1543 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1543),
    }

// 2.2.4.79 SERVER_INFO_1544
 type SERVER_INFO_1544 struct { // NDRSTRUCT: (
        ('sv1544_initconntable', DWORD),
    }

 type LPSERVER_INFO_1544 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1544),
    }

// 2.2.4.80 SERVER_INFO_1545
 type SERVER_INFO_1545 struct { // NDRSTRUCT: (
        ('sv1545_initfiletable', DWORD),
    }

 type LPSERVER_INFO_1545 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1545),
    }

// 2.2.4.81 SERVER_INFO_1546
 type SERVER_INFO_1546 struct { // NDRSTRUCT: (
        ('sv1546_initsearchtable', DWORD),
    }

 type LPSERVER_INFO_1546 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1546),
    }

// 2.2.4.82 SERVER_INFO_1547
 type SERVER_INFO_1547 struct { // NDRSTRUCT: (
        ('sv1547_alertschedule', DWORD),
    }

 type LPSERVER_INFO_1547 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1547),
    }

// 2.2.4.83 SERVER_INFO_1548
 type SERVER_INFO_1548 struct { // NDRSTRUCT: (
        ('sv1548_errorthreshold', DWORD),
    }

 type LPSERVER_INFO_1548 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1548),
    }

// 2.2.4.84 SERVER_INFO_1549
 type SERVER_INFO_1549 struct { // NDRSTRUCT: (
        ('sv1549_networkerrorthreshold', DWORD),
    }

 type LPSERVER_INFO_1549 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1549),
    }

// 2.2.4.85 SERVER_INFO_1550
 type SERVER_INFO_1550 struct { // NDRSTRUCT: (
        ('sv1550_diskspacethreshold', DWORD),
    }

 type LPSERVER_INFO_1550 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1550),
    }

// 2.2.4.86 SERVER_INFO_1552
 type SERVER_INFO_1552 struct { // NDRSTRUCT: (
        ('sv1552_maxlinkdelay', DWORD),
    }

 type LPSERVER_INFO_1552 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1552),
    }

// 2.2.4.87 SERVER_INFO_1553
 type SERVER_INFO_1553 struct { // NDRSTRUCT: (
        ('sv1553_minlinkthroughput', DWORD),
    }

 type LPSERVER_INFO_1553 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1553),
    }

// 2.2.4.88 SERVER_INFO_1554
 type SERVER_INFO_1554 struct { // NDRSTRUCT: (
        ('sv1554_linkinfovalidtime', DWORD),
    }

 type LPSERVER_INFO_1554 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1554),
    }

// 2.2.4.89 SERVER_INFO_1555
 type SERVER_INFO_1555 struct { // NDRSTRUCT: (
        ('sv1555_scavqosinfoupdatetime', DWORD),
    }

 type LPSERVER_INFO_1555 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1555),
    }

// 2.2.4.90 SERVER_INFO_1556
 type SERVER_INFO_1556 struct { // NDRSTRUCT: (
        ('sv1556_maxworkitemidletime', DWORD),
    }

 type LPSERVER_INFO_1556 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_INFO_1556),
    }

// 2.2.4.91 DISK_INFO
 type WCHAR_ARRAY struct { // NDRSTRUCT:
    commonHdr = (
         Offset uint32 // =0
         ActualCount uint32 // =len(Data)//2
    }
    commonHdr64 = (
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

     func (self TYPE) __setitem__(key, value interface{}){
        if key == 'Data' {
            try:
                self.fields[key] = value.encode("utf-16le")
            except UnicodeDecodeError:
                import sys
                self.fields[key] = value.decode(sys.getfilesystemencoding()).encode("utf-16le")
            self.fields["ActualCount"] = nil
            self.data = nil        // force recompute
        } else  {
            return NDR.__setitem__(self, key, value)

     func (self TYPE) __getitem__(key interface{}){
        if key == 'Data' {
            return self.fields[key].decode("utf-16le")
        } else  {
            return NDR.__getitem__(self,key)

     func (self TYPE) getDataLen(data interface{}){
        return self.ActualCount*2 


 type DISK_INFO struct { // NDRSTRUCT: (
        ('Disk', WCHAR_ARRAY),
    }

 type LPDISK_INFO struct { // NDRPOINTER:
    referent = (
        ('Data', DISK_INFO),
    }

 type DISK_INFO_ARRAY struct { // NDRUniConformantVaryingArray:
    item = DISK_INFO

 type LPDISK_INFO_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', DISK_INFO_ARRAY),
    }

// 2.2.4.92 DISK_ENUM_CONTAINER
 type DISK_ENUM_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', DWORD),
        ('Buffer', LPDISK_INFO_ARRAY),
    }

 type LPDISK_ENUM_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', DISK_ENUM_CONTAINER),
    }

// 2.2.4.93 SERVER_TRANSPORT_INFO_0
 type SERVER_TRANSPORT_INFO_0 struct { // NDRSTRUCT: (
        ('svti0_numberofvcs', DWORD),
        ('svti0_transportname', LPWSTR),
        ('svti0_transportaddress', PNDRUniConformantArray),
        ('svti0_transportaddresslength', DWORD),
        ('svti0_networkaddress', LPWSTR),
    }

 type LPSERVER_TRANSPORT_INFO_0 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_TRANSPORT_INFO_0),
    }

 type SERVER_TRANSPORT_INFO_0_ARRAY struct { // NDRUniConformantArray:
    item = SERVER_TRANSPORT_INFO_0

 type LPSERVER_TRANSPORT_INFO_0_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_TRANSPORT_INFO_0_ARRAY),
    }

// 2.2.4.94 SERVER_TRANSPORT_INFO_1
 type SERVER_TRANSPORT_INFO_1 struct { // NDRSTRUCT: (
        ('svti1_numberofvcs', DWORD),
        ('svti1_transportname', LPWSTR),
        ('svti1_transportaddress', PNDRUniConformantArray),
        ('svti1_transportaddresslength', DWORD),
        ('svti1_networkaddress', LPWSTR),
        ('svti1_domain', LPWSTR),
    }

 type LPSERVER_TRANSPORT_INFO_1 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_TRANSPORT_INFO_1),
    }

 type SERVER_TRANSPORT_INFO_1_ARRAY struct { // NDRUniConformantArray:
    item = SERVER_TRANSPORT_INFO_1

 type LPSERVER_TRANSPORT_INFO_1_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_TRANSPORT_INFO_1_ARRAY),
    }

// 2.2.4.95 SERVER_TRANSPORT_INFO_2
 type SERVER_TRANSPORT_INFO_2 struct { // NDRSTRUCT: (
        ('svti2_numberofvcs', DWORD),
        ('svti2_transportname', LPWSTR),
        ('svti2_transportaddress', PNDRUniConformantArray),
        ('svti2_transportaddresslength', DWORD),
        ('svti2_networkaddress', LPWSTR),
        ('svti2_domain', LPWSTR),
        ('svti2_flags', DWORD),
    }

 type LPSERVER_TRANSPORT_INFO_2 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_TRANSPORT_INFO_2),
    }

 type SERVER_TRANSPORT_INFO_2_ARRAY struct { // NDRUniConformantArray:
    item = SERVER_TRANSPORT_INFO_2

 type LPSERVER_TRANSPORT_INFO_2_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_TRANSPORT_INFO_2_ARRAY),
    }

// 2.2.4.96 SERVER_TRANSPORT_INFO_3
 type PASSWORD_ARRAY struct { // NDRUniFixedArray:
     func (self TYPE) getDataLen(data interface{}){
        return 256

 type SERVER_TRANSPORT_INFO_3 struct { // NDRSTRUCT: (
        ('svti3_numberofvcs', DWORD),
        ('svti3_transportname', LPWSTR),
        ('svti3_transportaddress', PNDRUniConformantArray),
        ('svti3_transportaddresslength', DWORD),
        ('svti3_networkaddress', LPWSTR),
        ('svti3_domain', LPWSTR),
        ('svti3_flags', DWORD),
        ('svti3_passwordlength', DWORD),
        ('svti3_password', PASSWORD_ARRAY),
    }

 type LPSERVER_TRANSPORT_INFO_3 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_TRANSPORT_INFO_3),
    }

 type SERVER_TRANSPORT_INFO_3_ARRAY struct { // NDRUniConformantArray:
    item = SERVER_TRANSPORT_INFO_3

 type LPSERVER_TRANSPORT_INFO_3_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_TRANSPORT_INFO_3_ARRAY),
    }

// 2.2.4.97 SERVER_XPORT_INFO_0_CONTAINER
 type SERVER_XPORT_INFO_0_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', DWORD),
        ('Buffer', LPSERVER_TRANSPORT_INFO_0_ARRAY),
    }

 type LPSERVER_XPORT_INFO_0_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_XPORT_INFO_0_CONTAINER),
    }

// 2.2.4.98 SERVER_XPORT_INFO_1_CONTAINER
 type SERVER_XPORT_INFO_1_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', DWORD),
        ('Buffer', LPSERVER_TRANSPORT_INFO_1_ARRAY),
    }

 type LPSERVER_XPORT_INFO_1_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_XPORT_INFO_1_CONTAINER),
    }

// 2.2.4.99 SERVER_XPORT_INFO_2_CONTAINER
 type SERVER_XPORT_INFO_2_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', DWORD),
        ('Buffer', LPSERVER_TRANSPORT_INFO_2_ARRAY),
    }

 type LPSERVER_XPORT_INFO_2_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_XPORT_INFO_2_CONTAINER),
    }

// 2.2.4.100 SERVER_XPORT_INFO_3_CONTAINER
 type SERVER_XPORT_INFO_3_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', DWORD),
        ('Buffer', LPSERVER_TRANSPORT_INFO_3_ARRAY),
    }

 type LPSERVER_XPORT_INFO_3_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_XPORT_INFO_3_CONTAINER),
    }

// 2.2.3.8 SERVER_XPORT_ENUM_UNION
 type SERVER_XPORT_ENUM_UNION struct { // NDRUNION:
    commonHdr = (
        ('tag', DWORD),
    }

    union = {
        0: ('Level0', LPSERVER_XPORT_INFO_0_CONTAINER),
        1: ('Level1', LPSERVER_XPORT_INFO_1_CONTAINER),
        2: ('Level2', LPSERVER_XPORT_INFO_2_CONTAINER),
        3: ('Level3', LPSERVER_XPORT_INFO_3_CONTAINER),
    }

// 2.2.4.101 SERVER_XPORT_ENUM_STRUCT
 type SERVER_XPORT_ENUM_STRUCT struct { // NDRSTRUCT: (
        ('Level', DWORD),
        ('XportInfo', SERVER_XPORT_ENUM_UNION),
    }

// 2.2.4.102 SERVER_ALIAS_INFO_0
 type SERVER_ALIAS_INFO_0 struct { // NDRSTRUCT: (
        ('srvai0_alias', LMSTR),
        ('srvai0_target', LMSTR),
        ('srvai0_default', NDRBOOLEAN),
        ('srvai0_reserved', ULONG),
    }

 type LPSERVER_ALIAS_INFO_0 struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_ALIAS_INFO_0),
    }

 type SERVER_ALIAS_INFO_0_ARRAY struct { // NDRUniConformantArray:
    item = SERVER_ALIAS_INFO_0

 type LPSERVER_ALIAS_INFO_0_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_ALIAS_INFO_0_ARRAY),
    }

// 2.2.4.103 SERVER_ALIAS_INFO_0_CONTAINER
 type SERVER_ALIAS_INFO_0_CONTAINER struct { // NDRSTRUCT: (
        ('EntriesRead', DWORD),
        ('Buffer', LPSERVER_ALIAS_INFO_0_ARRAY),
    }

 type LPSERVER_ALIAS_INFO_0_CONTAINER struct { // NDRPOINTER:
    referent = (
        ('Data', SERVER_ALIAS_INFO_0_CONTAINER),
    }

// 2.2.4.104 SERVER_ALIAS_ENUM_STRUCT
 type SERVER_ALIAS_ENUM_UNION struct { // NDRUNION:
    commonHdr = (
        ('tag', DWORD),
    }

    union = {
        0: ('Level0', LPSERVER_ALIAS_INFO_0_CONTAINER),
    }

 type SERVER_ALIAS_ENUM_STRUCT struct { // NDRSTRUCT: (
        ('Level', DWORD),
        ('ServerAliasInfo', SERVER_ALIAS_ENUM_UNION),
    }

// 2.2.4.105 TIME_OF_DAY_INFO
 type TIME_OF_DAY_INFO struct { // NDRSTRUCT: (
        ('tod_elapsedt', DWORD),
        ('tod_msecs', DWORD),
        ('tod_hours', DWORD),
        ('tod_mins', DWORD),
        ('tod_secs', DWORD),
        ('tod_hunds', DWORD),
        ('tod_timezone', DWORD),
        ('tod_tinterval', DWORD),
        ('tod_day', DWORD),
        ('tod_month', DWORD),
        ('tod_year', DWORD),
        ('tod_weekday', DWORD),
    }

 type LPTIME_OF_DAY_INFO struct { // NDRPOINTER:
    referent = (
        ('Data', TIME_OF_DAY_INFO),
    }

// 2.2.4.106 ADT_SECURITY_DESCRIPTOR
 type ADT_SECURITY_DESCRIPTOR struct { // NDRSTRUCT: (
        ('Length', DWORD),
        ('Buffer', PNDRUniConformantArray),
    }

 type PADT_SECURITY_DESCRIPTOR struct { // NDRPOINTER:
    referent = (
        ('Data', ADT_SECURITY_DESCRIPTOR),
    }

// 2.2.4.107 NET_DFS_ENTRY_ID
 type NET_DFS_ENTRY_ID struct { // NDRSTRUCT: (
        ('Uid', GUID),
        ('Prefix', LPWSTR),
    }

 type NET_DFS_ENTRY_ID_ARRAY struct { // NDRUniConformantArray:
    item = NET_DFS_ENTRY_ID

 type LPNET_DFS_ENTRY_ID_ARRAY struct { // NDRPOINTER:
     referent = (
         ('Data', NET_DFS_ENTRY_ID_ARRAY),
     }

// 2.2.4.108 NET_DFS_ENTRY_ID_CONTAINER
 type NET_DFS_ENTRY_ID_CONTAINER struct { // NDRSTRUCT: (
        ('Count', DWORD),
        ('Buffer', LPNET_DFS_ENTRY_ID_ARRAY),
    }

// 2.2.4.109 DFS_SITENAME_INFO
 type DFS_SITENAME_INFO struct { // NDRSTRUCT: (
        ('SiteFlags', DWORD),
        ('SiteName', LPWSTR),
    }

// 2.2.4.110 DFS_SITELIST_INFO
 type DFS_SITENAME_INFO_ARRAY struct { // NDRUniConformantArray:
    item = DFS_SITENAME_INFO

 type DFS_SITELIST_INFO struct { // NDRSTRUCT: (
        ('cSites', DWORD),
        ('Site', DFS_SITENAME_INFO_ARRAY),
    }

 type LPDFS_SITELIST_INFO struct { // NDRPOINTER:
    referent = (
        ('Data', DFS_SITELIST_INFO),
    }

// 2.2.3 Unions
// 2.2.3.3 FILE_INFO
 type FILE_INFO struct { // NDRUNION:
    commonHdr = (
        ('tag', DWORD),
    }

    union = {
        2: ('FileInfo2', LPFILE_INFO_2),
        3: ('FileInfo3', LPFILE_INFO_3),
    }

// 2.2.3.6 SHARE_INFO
 type SHARE_INFO struct { // NDRUNION:
    commonHdr = (
        ('tag', DWORD),
    }

    union = {
        0: ('ShareInfo0', LPSHARE_INFO_0),
        1: ('ShareInfo1', LPSHARE_INFO_1),
        2: ('ShareInfo2', LPSHARE_INFO_2),
        502: ('ShareInfo502', LPSHARE_INFO_502),
        1004: ('ShareInfo1004', LPSHARE_INFO_1004),
        1006: ('ShareInfo1006', LPSHARE_INFO_1006),
        1501: ('ShareInfo1501', LPSHARE_INFO_1501),
        1005: ('ShareInfo1005', LPSHARE_INFO_1005),
        501: ('ShareInfo501', LPSHARE_INFO_501),
        503: ('ShareInfo503', LPSHARE_INFO_503),
    }

// 2.2.3.7 SERVER_INFO
 type SERVER_INFO struct { // NDRUNION:
    commonHdr = (
        ('tag', DWORD),
    }

    union = {
        100: ('ServerInfo100', LPSERVER_INFO_100),
        101: ('ServerInfo101', LPSERVER_INFO_101),
        102: ('ServerInfo102', LPSERVER_INFO_102),
        103: ('ServerInfo103', LPSERVER_INFO_103),
        502: ('ServerInfo502', LPSERVER_INFO_502),
        503: ('ServerInfo503', LPSERVER_INFO_503),
        599: ('ServerInfo599', LPSERVER_INFO_599),
        1005: ('ServerInfo1005', LPSERVER_INFO_1005),
        1107: ('ServerInfo1107', LPSERVER_INFO_1107),
        1010: ('ServerInfo1010', LPSERVER_INFO_1010),
        1016: ('ServerInfo1016', LPSERVER_INFO_1016),
        1017: ('ServerInfo1017', LPSERVER_INFO_1017),
        1018: ('ServerInfo1018', LPSERVER_INFO_1018),
        1501: ('ServerInfo1501', LPSERVER_INFO_1501),
        1502: ('ServerInfo1502', LPSERVER_INFO_1502),
        1503: ('ServerInfo1503', LPSERVER_INFO_1503),
        1506: ('ServerInfo1506', LPSERVER_INFO_1506),
        1510: ('ServerInfo1510', LPSERVER_INFO_1510),
        1511: ('ServerInfo1511', LPSERVER_INFO_1511),
        1512: ('ServerInfo1512', LPSERVER_INFO_1512),
        1513: ('ServerInfo1513', LPSERVER_INFO_1513),
        1514: ('ServerInfo1514', LPSERVER_INFO_1514),
        1515: ('ServerInfo1515', LPSERVER_INFO_1515),
        1516: ('ServerInfo1516', LPSERVER_INFO_1516),
        1518: ('ServerInfo1518', LPSERVER_INFO_1518),
        1523: ('ServerInfo1523', LPSERVER_INFO_1523),
        1528: ('ServerInfo1528', LPSERVER_INFO_1528),
        1529: ('ServerInfo1529', LPSERVER_INFO_1529),
        1530: ('ServerInfo1530', LPSERVER_INFO_1530),
        1533: ('ServerInfo1533', LPSERVER_INFO_1533),
        1534: ('ServerInfo1534', LPSERVER_INFO_1534),
        1535: ('ServerInfo1535', LPSERVER_INFO_1535),
        1536: ('ServerInfo1536', LPSERVER_INFO_1536),
        1538: ('ServerInfo1538', LPSERVER_INFO_1538),
        1539: ('ServerInfo1539', LPSERVER_INFO_1539),
        1540: ('ServerInfo1540', LPSERVER_INFO_1540),
        1541: ('ServerInfo1541', LPSERVER_INFO_1541),
        1542: ('ServerInfo1542', LPSERVER_INFO_1542),
        1543: ('ServerInfo1543', LPSERVER_INFO_1543),
        1544: ('ServerInfo1544', LPSERVER_INFO_1544),
        1545: ('ServerInfo1545', LPSERVER_INFO_1545),
        1546: ('ServerInfo1546', LPSERVER_INFO_1546),
        1547: ('ServerInfo1547', LPSERVER_INFO_1547),
        1548: ('ServerInfo1548', LPSERVER_INFO_1548),
        1549: ('ServerInfo1549', LPSERVER_INFO_1549),
        1550: ('ServerInfo1550', LPSERVER_INFO_1550),
        1552: ('ServerInfo1552', LPSERVER_INFO_1552),
        1553: ('ServerInfo1553', LPSERVER_INFO_1553),
        1554: ('ServerInfo1554', LPSERVER_INFO_1554),
        1555: ('ServerInfo1555', LPSERVER_INFO_1555),
        1556: ('ServerInfo1556', LPSERVER_INFO_1556),
    }

// 2.2.3.9 TRANSPORT_INFO
 type TRANSPORT_INFO struct { // NDRUNION:
    commonHdr = (
        ('tag', DWORD),
    }

    union = {
        0: ('Transport0', SERVER_TRANSPORT_INFO_0),
        1: ('Transport1', SERVER_TRANSPORT_INFO_1),
        2: ('Transport2', SERVER_TRANSPORT_INFO_2),
        3: ('Transport3', SERVER_TRANSPORT_INFO_3),
    }

// 2.2.3.10 SERVER_ALIAS_INFO
 type SERVER_ALIAS_INFO struct { // NDRUNION:
    commonHdr = (
        ('tag', DWORD),
    }

    union = {
        0: ('ServerAliasInfo0', LPSERVER_ALIAS_INFO_0),
    }


//###############################################################################
// RPC CALLS
//###############################################################################
// 3.1.4.1 NetrConnectionEnum (Opnum 8)
 type NetrConnectionEnum struct { // NDRCALL:
    opnum = 8 (
       ('ServerName', PSRVSVC_HANDLE),
       ('Qualifier', LPWSTR),
       ('InfoStruct', CONNECT_ENUM_STRUCT),
       ('PreferedMaximumLength', DWORD),
       ('ResumeHandle', LPLONG),
    }

 type NetrConnectionEnumResponse struct { // NDRCALL: (
       ('InfoStruct',CONNECT_ENUM_STRUCT),
       ('TotalEntries',DWORD),
       ('ResumeHandle',LPLONG),
       ('ErrorCode',ULONG),
    }

// 3.1.4.2 NetrFileEnum (Opnum 9)
 type NetrFileEnum struct { // NDRCALL:
    opnum = 9 (
       ('ServerName', PSRVSVC_HANDLE),
       ('BasePath', LPWSTR),
       ('UserName', LPWSTR),
       ('InfoStruct', FILE_ENUM_STRUCT),
       ('PreferedMaximumLength', DWORD),
       ('ResumeHandle', LPLONG),
    }

 type NetrFileEnumResponse struct { // NDRCALL: (
       ('InfoStruct',FILE_ENUM_STRUCT),
       ('TotalEntries',DWORD),
       ('ResumeHandle',LPLONG),
       ('ErrorCode',ULONG),
    }

// 3.1.4.3 NetrFileGetInfo (Opnum 10)
 type NetrFileGetInfo struct { // NDRCALL:
    opnum = 10 (
       ('ServerName', PSRVSVC_HANDLE),
       ('FileId', DWORD),
       ('Level', DWORD),
    }

 type NetrFileGetInfoResponse struct { // NDRCALL: (
       ('InfoStruct',FILE_INFO),
       ('ErrorCode',ULONG),
    }

// 3.1.4.4 NetrFileClose (Opnum 11)
 type NetrFileClose struct { // NDRCALL:
    opnum = 11 (
       ('ServerName', PSRVSVC_HANDLE),
       ('FileId', DWORD),
    }

 type NetrFileCloseResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.1.4.5 NetrSessionEnum (Opnum 12)
 type NetrSessionEnum struct { // NDRCALL:
    opnum = 12 (
       ('ServerName', PSRVSVC_HANDLE),
       ('ClientName', LPWSTR),
       ('UserName', LPWSTR),
       ('InfoStruct', SESSION_ENUM_STRUCT),
       ('PreferedMaximumLength', DWORD),
       ('ResumeHandle', LPLONG),
    }

 type NetrSessionEnumResponse struct { // NDRCALL: (
       ('InfoStruct',SESSION_ENUM_STRUCT),
       ('TotalEntries',DWORD),
       ('ResumeHandle',LPLONG),
       ('ErrorCode',ULONG),
    }

// 3.1.4.6 NetrSessionDel (Opnum 13)
 type NetrSessionDel struct { // NDRCALL:
    opnum = 13 (
       ('ServerName', PSRVSVC_HANDLE),
       ('ClientName', LPWSTR),
       ('UserName', LPWSTR),
    }

 type NetrSessionDelResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.1.4.7 NetrShareAdd (Opnum 14)
 type NetrShareAdd struct { // NDRCALL:
    opnum = 14 (
       ('ServerName', PSRVSVC_HANDLE),
       ('Level', DWORD),
       ('InfoStruct', SHARE_INFO),
       ('ParmErr', LPLONG),
    }

 type NetrShareAddResponse struct { // NDRCALL: (
       ('ParmErr', LPLONG),
       ('ErrorCode',ULONG),
    }

// 3.1.4.8 NetrShareEnum (Opnum 15)
 type NetrShareEnum struct { // NDRCALL:
    opnum = 15 (
       ('ServerName', PSRVSVC_HANDLE),
       ('InfoStruct', SHARE_ENUM_STRUCT),
       ('PreferedMaximumLength', DWORD),
       ('ResumeHandle', LPLONG),
    }

 type NetrShareEnumResponse struct { // NDRCALL: (
       ('InfoStruct', SHARE_ENUM_STRUCT),
       ('TotalEntries',DWORD),
       ('ResumeHandle',LPLONG),
       ('ErrorCode',ULONG),
    }

// 3.1.4.9 NetrShareEnumSticky (Opnum 36)
 type NetrShareEnumSticky struct { // NDRCALL:
    opnum = 36 (
       ('ServerName', PSRVSVC_HANDLE),
       ('InfoStruct', SHARE_ENUM_STRUCT),
       ('PreferedMaximumLength', DWORD),
       ('ResumeHandle', LPLONG),
    }

 type NetrShareEnumStickyResponse struct { // NDRCALL: (
       ('InfoStruct', SHARE_ENUM_STRUCT),
       ('TotalEntries',DWORD),
       ('ResumeHandle',LPLONG),
       ('ErrorCode',ULONG),
    }

// 3.1.4.10 NetrShareGetInfo (Opnum 16)
 type NetrShareGetInfo struct { // NDRCALL:
    opnum = 16 (
       ('ServerName', PSRVSVC_HANDLE),
       ('NetName', WSTR),
       ('Level', DWORD),
    }

 type NetrShareGetInfoResponse struct { // NDRCALL: (
       ('InfoStruct', SHARE_INFO),
       ('ErrorCode',ULONG),
    }

// 3.1.4.11 NetrShareSetInfo (Opnum 17)
 type NetrShareSetInfo struct { // NDRCALL:
    opnum = 17 (
       ('ServerName', PSRVSVC_HANDLE),
       ('NetName', WSTR),
       ('Level', DWORD),
       ('ShareInfo', SHARE_INFO),
       ('ParmErr', LPLONG),
    }

 type NetrShareSetInfoResponse struct { // NDRCALL: (
       ('ParmErr', LPLONG),
       ('ErrorCode',ULONG),
    }

// 3.1.4.12 NetrShareDel (Opnum 18)
 type NetrShareDel struct { // NDRCALL:
    opnum = 18 (
       ('ServerName', PSRVSVC_HANDLE),
       ('NetName', WSTR),
       ('Reserved', DWORD),
    }

 type NetrShareDelResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.1.4.13 NetrShareDelSticky (Opnum 19)
 type NetrShareDelSticky struct { // NDRCALL:
    opnum = 19 (
       ('ServerName', PSRVSVC_HANDLE),
       ('NetName', WSTR),
       ('Reserved', DWORD),
    }

 type NetrShareDelStickyResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.1.4.14 NetrShareDelStart (Opnum 37)
 type NetrShareDelStart struct { // NDRCALL:
    opnum = 37 (
       ('ServerName', PSRVSVC_HANDLE),
       ('NetName', WSTR),
       ('Reserved', DWORD),
    }

 type NetrShareDelStartResponse struct { // NDRCALL: (
       ('ContextHandle',SHARE_DEL_HANDLE),
       ('ErrorCode',ULONG),
    }

// 3.1.4.15 NetrShareDelCommit (Opnum 38)
 type NetrShareDelCommit struct { // NDRCALL:
    opnum = 38 (
       ('ContextHandle',SHARE_DEL_HANDLE),
    }

 type NetrShareDelCommitResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.1.4.16 NetrShareCheck (Opnum 20)
 type NetrShareCheck struct { // NDRCALL:
    opnum = 20 (
       ('ServerName', PSRVSVC_HANDLE),
       ('Device', WSTR),
    }

 type NetrShareCheckResponse struct { // NDRCALL: (
       ('Type',DWORD),
       ('ErrorCode',ULONG),
    }

// 3.1.4.17 NetrServerGetInfo (Opnum 21)
 type NetrServerGetInfo struct { // NDRCALL:
    opnum = 21 (
       ('ServerName', PSRVSVC_HANDLE),
       ('Level', DWORD),
    }

 type NetrServerGetInfoResponse struct { // NDRCALL: (
       ('InfoStruct', SERVER_INFO),
       ('ErrorCode',ULONG),
    }

// 3.1.4.18 NetrServerSetInfo (Opnum 22)
 type NetrServerSetInfo struct { // NDRCALL:
    opnum = 22 (
       ('ServerName', PSRVSVC_HANDLE),
       ('Level', DWORD),
       ('InfoStruct', SERVER_INFO),
    }

 type NetrServerSetInfoResponse struct { // NDRCALL: (
       ('ParmErr', LPLONG),
       ('ErrorCode',ULONG),
    }

// 3.1.4.19 NetrServerDiskEnum (Opnum 23)
 type NetrServerDiskEnum struct { // NDRCALL:
    opnum = 23 (
       ('ServerName', PSRVSVC_HANDLE),
       ('Level', DWORD),
       ('DiskInfoStruct', DISK_ENUM_CONTAINER),
       ('PreferedMaximumLength', DWORD),
       ('ResumeHandle', LPLONG),
    }

 type NetrServerDiskEnumResponse struct { // NDRCALL: (
       ('DiskInfoStruct', DISK_ENUM_CONTAINER),
       ('TotalEntries', DWORD),
       ('ResumeHandle', LPLONG),
       ('ErrorCode',ULONG),
    }

// 3.1.4.20 NetrServerStatisticsGet (Opnum 24)
 type NetrServerStatisticsGet struct { // NDRCALL:
    opnum = 24 (
       ('ServerName', PSRVSVC_HANDLE),
       ('Service', LPWSTR),
       ('Level', DWORD),
       ('Options', DWORD),
    }

 type NetrServerStatisticsGetResponse struct { // NDRCALL: (
       ('InfoStruct', LPSTAT_SERVER_0),
       ('ErrorCode',ULONG),
    }

// 3.1.4.21 NetrRemoteTOD (Opnum 28)
 type NetrRemoteTOD struct { // NDRCALL:
    opnum = 28 (
       ('ServerName', PSRVSVC_HANDLE),
    }

 type NetrRemoteTODResponse struct { // NDRCALL: (
       ('BufferPtr', LPTIME_OF_DAY_INFO),
       ('ErrorCode',ULONG),
    }

// 3.1.4.22 NetrServerTransportAdd (Opnum 25)
 type NetrServerTransportAdd struct { // NDRCALL:
    opnum = 25 (
       ('ServerName', PSRVSVC_HANDLE),
       ('Level', DWORD),
       ('Buffer', SERVER_TRANSPORT_INFO_0),
    }

 type NetrServerTransportAddResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.1.4.23 NetrServerTransportAddEx (Opnum 41)
 type NetrServerTransportAddEx struct { // NDRCALL:
    opnum = 41 (
       ('ServerName', PSRVSVC_HANDLE),
       ('Level', DWORD),
       ('Buffer', TRANSPORT_INFO),
    }

 type NetrServerTransportAddExResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.1.4.24 NetrServerTransportEnum (Opnum 26)
 type NetrServerTransportEnum struct { // NDRCALL:
    opnum = 26 (
       ('ServerName', PSRVSVC_HANDLE),
       ('InfoStruct', SERVER_XPORT_ENUM_STRUCT),
       ('PreferedMaximumLength', DWORD),
       ('ResumeHandle', LPLONG),
    }

 type NetrServerTransportEnumResponse struct { // NDRCALL: (
       ('InfoStruct', SERVER_XPORT_ENUM_STRUCT),
       ('TotalEntries', DWORD),
       ('ResumeHandle', LPLONG),
       ('ErrorCode',ULONG),
    }

// 3.1.4.25 NetrServerTransportDel (Opnum 27)
 type NetrServerTransportDel struct { // NDRCALL:
    opnum = 27 (
       ('ServerName', PSRVSVC_HANDLE),
       ('Level', DWORD),
       ('Buffer', SERVER_TRANSPORT_INFO_0),
    }

 type NetrServerTransportDelResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.1.4.26 NetrServerTransportDelEx (Opnum 53)
 type NetrServerTransportDelEx struct { // NDRCALL:
    opnum = 53 (
       ('ServerName', PSRVSVC_HANDLE),
       ('Level', DWORD),
       ('Buffer', TRANSPORT_INFO),
    }

 type NetrServerTransportDelExResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.1.4.27 NetrpGetFileSecurity (Opnum 39)
 type NetrpGetFileSecurity struct { // NDRCALL:
    opnum = 39 (
       ('ServerName', PSRVSVC_HANDLE),
       ('ShareName', LPWSTR),
       ('lpFileName', WSTR),
       ('RequestedInformation', SECURITY_INFORMATION),
    }

 type NetrpGetFileSecurityResponse struct { // NDRCALL: (
       ('SecurityDescriptor', PADT_SECURITY_DESCRIPTOR),
       ('ErrorCode',ULONG),
    }

// 3.1.4.28 NetrpSetFileSecurity (Opnum 40)
 type NetrpSetFileSecurity struct { // NDRCALL:
    opnum = 40 (
       ('ServerName', PSRVSVC_HANDLE),
       ('ShareName', LPWSTR),
       ('lpFileName', WSTR),
       ('SecurityInformation', SECURITY_INFORMATION),
       ('SecurityDescriptor', ADT_SECURITY_DESCRIPTOR),
    }

 type NetrpSetFileSecurityResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.1.4.29 NetprPathType (Opnum 30)
 type NetprPathType struct { // NDRCALL:
    opnum = 30 (
       ('ServerName', PSRVSVC_HANDLE),
       ('PathName', WSTR),
       ('Flags', DWORD),
    }

 type NetprPathTypeResponse struct { // NDRCALL: (
       ('PathType', DWORD),
       ('ErrorCode',ULONG),
    }

// 3.1.4.30 NetprPathCanonicalize (Opnum 31)
 type NetprPathCanonicalize struct { // NDRCALL:
    opnum = 31 (
       ('ServerName', PSRVSVC_HANDLE),
       ('PathName', WSTR),
       ('OutbufLen', DWORD),
       ('Prefix', WSTR),
       ('PathType', DWORD),
       ('Flags', DWORD),
    }

 type NetprPathCanonicalizeResponse struct { // NDRCALL: (
       ('Outbuf', NDRUniConformantArray),
       ('PathType', DWORD),
       ('ErrorCode',ULONG),
    }

// 3.1.4.31 NetprPathCompare (Opnum 32)
 type NetprPathCompare struct { // NDRCALL:
    opnum = 32 (
       ('ServerName', PSRVSVC_HANDLE),
       ('PathName1', WSTR),
       ('PathName2', WSTR),
       ('PathType', DWORD),
       ('Flags', DWORD),
    }

 type NetprPathCompareResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.1.4.32 NetprNameValidate (Opnum 33)
 type NetprNameValidate struct { // NDRCALL:
    opnum = 33 (
       ('ServerName', PSRVSVC_HANDLE),
       ('Name', WSTR),
       ('NameType', DWORD),
       ('Flags', DWORD),
    }

 type NetprNameValidateResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.1.4.33 NetprNameCanonicalize (Opnum 34)
 type NetprNameCanonicalize struct { // NDRCALL:
    opnum = 34 (
       ('ServerName', PSRVSVC_HANDLE),
       ('Name', WSTR),
       ('OutbufLen', DWORD),
       ('NameType', DWORD),
       ('Flags', DWORD),
    }

 type NetprNameCanonicalizeResponse struct { // NDRCALL: (
       ('Outbuf', NDRUniConformantArray),
       ('NameType', DWORD),
       ('ErrorCode',ULONG),
    }

// 3.1.4.34 NetprNameCompare (Opnum 35)
 type NetprNameCompare struct { // NDRCALL:
    opnum = 35 (
       ('ServerName', PSRVSVC_HANDLE),
       ('Name1', WSTR),
       ('Name2', WSTR),
       ('NameType', DWORD),
       ('Flags', DWORD),
    }

 type NetprNameCompareResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.1.4.35 NetrDfsGetVersion (Opnum 43)
 type NetrDfsGetVersion struct { // NDRCALL:
    opnum = 43 (
       ('ServerName', PSRVSVC_HANDLE),
    }

 type NetrDfsGetVersionResponse struct { // NDRCALL: (
       ('Version', DWORD),
       ('ErrorCode',ULONG),
    }

// 3.1.4.36 NetrDfsCreateLocalPartition (Opnum 44)
 type NetrDfsCreateLocalPartition struct { // NDRCALL:
    opnum = 44 (
       ('ServerName', PSRVSVC_HANDLE),
       ('ShareName', WSTR),
       ('EntryUid', GUID),
       ('EntryPrefix', WSTR),
       ('ShortName', WSTR),
       ('RelationInfo', NET_DFS_ENTRY_ID_CONTAINER),
       ('Force', DWORD),
    }

 type NetrDfsCreateLocalPartitionResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.1.4.37 NetrDfsDeleteLocalPartition (Opnum 45)
 type NetrDfsDeleteLocalPartition struct { // NDRCALL:
    opnum = 45 (
       ('ServerName', PSRVSVC_HANDLE),
       ('Uid', GUID),
       ('Prefix', WSTR),
    }

 type NetrDfsDeleteLocalPartitionResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.1.4.38 NetrDfsSetLocalVolumeState (Opnum 46)
 type NetrDfsSetLocalVolumeState struct { // NDRCALL:
    opnum = 46 (
       ('ServerName', PSRVSVC_HANDLE),
       ('Uid', GUID),
       ('Prefix', WSTR),
       ('State', DWORD),
    }

 type NetrDfsSetLocalVolumeStateResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.1.4.39 NetrDfsCreateExitPoint (Opnum 48)
 type NetrDfsCreateExitPoint struct { // NDRCALL:
    opnum = 48 (
       ('ServerName', PSRVSVC_HANDLE),
       ('Uid', GUID),
       ('Prefix', WSTR),
       ('Type', DWORD),
       ('ShortPrefixLen', DWORD),
    }

 type NetrDfsCreateExitPointResponse struct { // NDRCALL: (
       ('ShortPrefix',WCHAR_ARRAY),
       ('ErrorCode',ULONG),
    }

// 3.1.4.40 NetrDfsModifyPrefix (Opnum 50)
 type NetrDfsModifyPrefix struct { // NDRCALL:
    opnum = 50 (
       ('ServerName', PSRVSVC_HANDLE),
       ('Uid', GUID),
       ('Prefix', WSTR),
    }

 type NetrDfsModifyPrefixResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.1.4.41 NetrDfsDeleteExitPoint (Opnum 49)
 type NetrDfsDeleteExitPoint struct { // NDRCALL:
    opnum = 49 (
       ('ServerName', PSRVSVC_HANDLE),
       ('Uid', GUID),
       ('Prefix', WSTR),
       ('Type', DWORD),
    }

 type NetrDfsDeleteExitPointResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.1.4.42 NetrDfsFixLocalVolume (Opnum 51)
 type NetrDfsFixLocalVolume struct { // NDRCALL:
    opnum = 51 (
       ('ServerName', PSRVSVC_HANDLE),
       ('VolumeName', WSTR),
       ('EntryType', DWORD),
       ('ServiceType', DWORD),
       ('StgId', WSTR),
       ('EntryUid', GUID),
       ('EntryPrefix', WSTR),
       ('RelationInfo', NET_DFS_ENTRY_ID_CONTAINER),
       ('CreateDisposition', DWORD),
    }

 type NetrDfsFixLocalVolumeResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.1.4.43 NetrDfsManagerReportSiteInfo (Opnum 52)
 type NetrDfsManagerReportSiteInfo struct { // NDRCALL:
    opnum = 52 (
       ('ServerName', PSRVSVC_HANDLE),
       ('ppSiteInfo', LPDFS_SITELIST_INFO),
    }

 type NetrDfsManagerReportSiteInfoResponse struct { // NDRCALL: (
       ('ppSiteInfo', LPDFS_SITELIST_INFO),
       ('ErrorCode',ULONG),
    }

// 3.1.4.44 NetrServerAliasAdd (Opnum 54)
 type NetrServerAliasAdd struct { // NDRCALL:
    opnum = 54 (
       ('ServerName', PSRVSVC_HANDLE),
       ('Level', DWORD),
       ('InfoStruct', SERVER_ALIAS_INFO),
    }

 type NetrServerAliasAddResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.1.4.45 NetrServerAliasEnum (Opnum 55)
 type NetrServerAliasEnum struct { // NDRCALL:
    opnum = 55 (
       ('ServerName', PSRVSVC_HANDLE),
       ('InfoStruct', SERVER_ALIAS_ENUM_STRUCT),
       ('PreferedMaximumLength', DWORD),
       ('ResumeHandle', LPLONG),
    }

 type NetrServerAliasEnumResponse struct { // NDRCALL: (
       ('InfoStruct',SERVER_ALIAS_ENUM_STRUCT),
       ('TotalEntries',DWORD),
       ('ResumeHandle',LPLONG),
       ('ErrorCode',ULONG),
    }

// 3.1.4.46 NetrServerAliasDel (Opnum 56)
 type NetrServerAliasDel struct { // NDRCALL:
    opnum = 56 (
       ('ServerName', PSRVSVC_HANDLE),
       ('Level', DWORD),
       ('InfoStruct', SERVER_ALIAS_INFO),
    }

 type NetrServerAliasDelResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

// 3.1.4.47 NetrShareDelEx (Opnum 57)
 type NetrShareDelEx struct { // NDRCALL:
    opnum = 57 (
       ('ServerName', PSRVSVC_HANDLE),
       ('Level', DWORD),
       ('ShareInfo', SHARE_INFO),
    }

 type NetrShareDelExResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

//###############################################################################
// OPNUMs and their corresponding structures
//###############################################################################
OPNUMS = {
 8 : (NetrConnectionEnum, NetrConnectionEnumResponse),
 9 : (NetrFileEnum, NetrFileEnumResponse),
10 : (NetrFileGetInfo, NetrFileGetInfoResponse),
11 : (NetrFileClose, NetrFileCloseResponse),
12 : (NetrSessionEnum, NetrSessionEnumResponse),
13 : (NetrSessionDel, NetrSessionDelResponse),
14 : (NetrShareAdd, NetrShareAddResponse),
15 : (NetrShareEnum, NetrShareEnumResponse),
16 : (NetrShareGetInfo, NetrShareGetInfoResponse),
17 : (NetrShareSetInfo, NetrShareSetInfoResponse),
18 : (NetrShareDel, NetrShareDelResponse),
19 : (NetrShareDelSticky, NetrShareDelStickyResponse),
20 : (NetrShareCheck, NetrShareCheckResponse),
21 : (NetrServerGetInfo, NetrServerGetInfoResponse),
22 : (NetrServerSetInfo, NetrServerSetInfoResponse),
23 : (NetrServerDiskEnum, NetrServerDiskEnumResponse),
24 : (NetrServerStatisticsGet, NetrServerStatisticsGetResponse),
25 : (NetrServerTransportAdd, NetrServerTransportAddResponse),
26 : (NetrServerTransportEnum, NetrServerTransportEnumResponse),
27 : (NetrServerTransportDel, NetrServerTransportDelResponse),
28 : (NetrRemoteTOD, NetrRemoteTODResponse),
30 : (NetprPathType, NetprPathTypeResponse),
31 : (NetprPathCanonicalize, NetprPathCanonicalizeResponse),
32 : (NetprPathCompare, NetprPathCompareResponse),
33 : (NetprNameValidate, NetprNameValidateResponse),
34 : (NetprNameCanonicalize, NetprNameCanonicalizeResponse),
35 : (NetprNameCompare, NetprNameCompareResponse),
36 : (NetrShareEnumSticky, NetrShareEnumStickyResponse),
37 : (NetrShareDelStart, NetrShareDelStartResponse),
38 : (NetrShareDelCommit, NetrShareDelCommitResponse),
39 : (NetrpGetFileSecurity, NetrpGetFileSecurityResponse),
40 : (NetrpSetFileSecurity, NetrpSetFileSecurityResponse),
41 : (NetrServerTransportAddEx, NetrServerTransportAddExResponse),
43 : (NetrDfsGetVersion, NetrDfsGetVersionResponse),
44 : (NetrDfsCreateLocalPartition, NetrDfsCreateLocalPartitionResponse),
45 : (NetrDfsDeleteLocalPartition, NetrDfsDeleteLocalPartitionResponse),
46 : (NetrDfsSetLocalVolumeState, NetrDfsSetLocalVolumeStateResponse),
48 : (NetrDfsCreateExitPoint, NetrDfsCreateExitPointResponse),
49 : (NetrDfsDeleteExitPoint, NetrDfsDeleteExitPointResponse),
50 : (NetrDfsModifyPrefix, NetrDfsModifyPrefixResponse),
51 : (NetrDfsFixLocalVolume, NetrDfsFixLocalVolumeResponse),
52 : (NetrDfsManagerReportSiteInfo, NetrDfsManagerReportSiteInfoResponse),
53 : (NetrServerTransportDelEx, NetrServerTransportDelExResponse),
54 : (NetrServerAliasAdd, NetrServerAliasAddResponse),
55 : (NetrServerAliasEnum, NetrServerAliasEnumResponse),
56 : (NetrServerAliasDel, NetrServerAliasDelResponse),
57 : (NetrShareDelEx, NetrShareDelExResponse),
}

//###############################################################################
// HELPER FUNCTIONS
//###############################################################################
 func hNetrConnectionEnum(dce, qualifier, level, resumeHandle = 0, preferedMaximumLength = 0xffffffff interface{}){
    request = NetrConnectionEnum()
    request["ServerName"] = NULL
    request["Qualifier"] = qualifier 
    request["InfoStruct"]["Level"] = level
    request["InfoStruct"]["ConnectInfo"]["tag"] = level
    request["PreferedMaximumLength"] = preferedMaximumLength
    request["ResumeHandle"] = resumeHandle
    return dce.request(request)

 func hNetrFileEnum(dce, basePath, userName, level, resumeHandle = 0, preferedMaximumLength = 0xffffffff interface{}){
    request = NetrFileEnum()
    request["ServerName"] = NULL
    request["BasePath"] = basePath
    request["UserName"] = userName
    request["InfoStruct"]["Level"] = level
    request["InfoStruct"]["FileInfo"]["tag"] = level
    request["PreferedMaximumLength"] = preferedMaximumLength
    request["ResumeHandle"] = resumeHandle
    return dce.request(request)

 func hNetrFileGetInfo(dce, fileId, level interface{}){
    request = NetrFileGetInfo()
    request["ServerName"] = NULL
    request["FileId"] = fileId
    request["Level"] = level
    return dce.request(request)

 func hNetrFileClose(dce, fileId interface{}){
    request = NetrFileClose()
    request["ServerName"] = NULL
    request["FileId"] = fileId
    return dce.request(request)

 func hNetrSessionEnum(dce, clientName, userName, level, resumeHandle = 0, preferedMaximumLength = 0xffffffff interface{}){
    request = NetrSessionEnum()
    request["ServerName"] = NULL
    request["ClientName"] = clientName
    request["UserName"] = userName
    request["InfoStruct"]["Level"] = level
    request["InfoStruct"]["SessionInfo"]["tag"] = level
    request["InfoStruct"]["SessionInfo"]['Level%d'%level]["Buffer"] = NULL
    request["PreferedMaximumLength"] = preferedMaximumLength
    request["ResumeHandle"] = resumeHandle

    return dce.request(request)

 func hNetrSessionDel(dce, clientName, userName interface{}){
    request = NetrSessionDel()
    request["ServerName"] = NULL
    request["ClientName"] = clientName
    request["UserName"] = userName
    return dce.request(request)

 func hNetrShareAdd(dce, level, infoStruct interface{}){
    request = NetrShareAdd()
    request["ServerName"] = NULL
    request["Level"] = level
    request["InfoStruct"]["tag"] = level
    request["InfoStruct"]['ShareInfo%d'%level] = infoStruct
    return dce.request(request)

 func hNetrShareDel(dce, netName interface{}){
    request = NetrShareDel()
    request["ServerName"] = NULL
    request["NetName"] = netName
    return dce.request(request)

 func hNetrShareEnum(dce, level, resumeHandle = 0, preferedMaximumLength = 0xffffffff interface{}){
    request = NetrShareEnum()
    request["ServerName"] = "\x00"
    request["PreferedMaximumLength"] = preferedMaximumLength
    request["ResumeHandle"] = resumeHandle
    request["InfoStruct"]["Level"] = level
    request["InfoStruct"]["ShareInfo"]["tag"] = level
    request["InfoStruct"]["ShareInfo"]['Level%d'%level]["Buffer"] = NULL

    return dce.request(request)

 func hNetrShareEnumSticky(dce, level, resumeHandle = 0, preferedMaximumLength = 0xffffffff interface{}){
    request = NetrShareEnumSticky()
    request["ServerName"] = NULL
    request["PreferedMaximumLength"] = preferedMaximumLength
    request["ResumeHandle"] = resumeHandle
    request["InfoStruct"]["Level"] = level
    request["InfoStruct"]["ShareInfo"]["tag"] = level
    request["InfoStruct"]["ShareInfo"]['Level%d'%level]["Buffer"] = NULL

    return dce.request(request)

 func hNetrShareGetInfo(dce, netName, level interface{}){
    request = NetrShareGetInfo()
    request["ServerName"] = NULL
    request["NetName"] = netName
    request["Level"] = level
    return dce.request(request)

 func hNetrShareSetInfo(dce, netName, level, shareInfo interface{}){
    request = NetrShareSetInfo()
    request["ServerName"] = NULL
    request["NetName"] = netName
    request["Level"] = level
    request["ShareInfo"]["tag"] = level
    request["ShareInfo"]['ShareInfo%d'%level] = shareInfo

    return dce.request(request)

 func hNetrShareDelSticky(dce, netName interface{}){
    request = NetrShareDelSticky()
    request["ServerName"] = NULL
    request["NetName"] = netName
    return dce.request(request)

// Sacala la h a estos 2, y tira todos los test cases juntos
 func hNetrShareDelStart(dce, netName interface{}){
    request = NetrShareDelStart()
    request["ServerName"] = NULL
    request["NetName"] = netName
    return dce.request(request)

 func hNetrShareDelCommit(dce, contextHandle interface{}){
    request = NetrShareDelCommit()
    request["ContextHandle"] = contextHandle
    return dce.request(request)

 func hNetrShareCheck(dce, device interface{}){
    request = NetrShareCheck()
    request["ServerName"] = NULL
    request["Device"] = device
    return dce.request(request)

 func hNetrServerGetInfo(dce, level interface{}){
    request = NetrServerGetInfo()
    request["ServerName"] = NULL
    request["Level"] = level
    return dce.request(request)

 func hNetrServerDiskEnum(dce, level, resumeHandle = 0, preferedMaximumLength = 0xffffffff interface{}){
    request = NetrServerDiskEnum()
    request["ServerName"] = NULL
    request["PreferedMaximumLength"] = preferedMaximumLength
    request["ResumeHandle"] = resumeHandle
    request["Level"] = level
    request["DiskInfoStruct"]["Buffer"] = NULL
    return dce.request(request)

 func hNetrServerStatisticsGet(dce, service, level, options interface{}){
    request = NetrServerStatisticsGet()
    request["ServerName"] = NULL
    request["Service"] = service
    request["Level"] = level
    request["Options"] = options
    return dce.request(request)

 func hNetrRemoteTOD(dce interface{}){
    request = NetrRemoteTOD()
    request["ServerName"] = NULL
    return dce.request(request)

 func hNetrServerTransportEnum(dce, level, resumeHandle = 0, preferedMaximumLength = 0xffffffff interface{}){
    request = NetrServerTransportEnum()
    request["ServerName"] = NULL
    request["PreferedMaximumLength"] = preferedMaximumLength
    request["ResumeHandle"] = resumeHandle
    request["InfoStruct"]["Level"] = level
    request["InfoStruct"]["XportInfo"]["tag"] = level
    request["InfoStruct"]["XportInfo"]['Level%d' % level]["Buffer"] = NULL
    return dce.request(request)

 func hNetrpGetFileSecurity(dce, shareName, lpFileName, requestedInformation interface{}){
    request = NetrpGetFileSecurity()
    request["ServerName"] = NULL
    request["ShareName"] = shareName
    request["lpFileName"] = lpFileName
    request["RequestedInformation"] = requestedInformation
    retVal = dce.request(request)
    return b''.join(retVal["SecurityDescriptor"]["Buffer"])

 func hNetrpSetFileSecurity(dce, shareName, lpFileName, securityInformation, securityDescriptor interface{}){
    request = NetrpSetFileSecurity()
    request["ServerName"] = NULL
    request["ShareName"] = shareName
    request["lpFileName"] = lpFileName
    request["SecurityInformation"] = securityInformation
    request["SecurityDescriptor"]["Length"] = len(securityDescriptor)
    request["SecurityDescriptor"]["Buffer"] = list(securityDescriptor)
    return dce.request(request)

 func hNetprPathType(dce, pathName, flags interface{}){
    request = NetprPathType()
    request["ServerName"] = NULL
    request["PathName"] = pathName
    request["Flags"] = flags
    return dce.request(request)

 func hNetprPathCanonicalize(dce, pathName, prefix, outbufLen=50, pathType=0, flags=0 interface{}){
    request = NetprPathCanonicalize()
    request["ServerName"] = NULL
    request["PathName"] = pathName
    request["OutbufLen"] = outbufLen
    request["Prefix"] = prefix
    request["PathType"] = pathType
    request["Flags"] = flags
    return dce.request(request)

 func hNetprPathCompare(dce, pathName1, pathName2, pathType=0, flags=0 interface{}){
    request = NetprPathCompare()
    request["ServerName"] = NULL
    request["PathName1"] = pathName1
    request["PathName2"] = pathName2
    request["PathType"] = pathType
    request["Flags"] = flags
    return dce.request(request)

 func hNetprNameValidate(dce, name, nameType, flags=0 interface{}){
    request = NetprNameValidate()
    request["ServerName"] = NULL
    request["Name"] = name
    request["NameType"] = nameType
    request["Flags"] = flags
    return dce.request(request)

 func hNetprNameCanonicalize(dce, name, outbufLen=50, nameType=0, flags=0 interface{}){
    request = NetprNameCanonicalize()
    request["ServerName"] = NULL
    request["Name"] = name
    request["OutbufLen"] = outbufLen
    request["NameType"] = nameType
    request["Flags"] = flags
    return dce.request(request)

 func hNetprNameCompare(dce, name1, name2, nameType=0, flags=0 interface{}){
    request = NetprNameCompare()
    request["ServerName"] = NULL
    request["Name1"] = name1
    request["Name2"] = name2
    request["NameType"] = nameType
    request["Flags"] = flags
    return dce.request(request)

 func hNetrDfsGetVersion(dce interface{}){
    request = NetrDfsGetVersion()
    request["ServerName"] = NULL
    return dce.request(request)

 func hNetrServerAliasAdd(dce, level, aliasInfo interface{}){
    request = NetrServerAliasAdd()
    request["ServerName"] = NULL
    request["Level"] = level
    request["InfoStruct"]["tag"] = level
    request["InfoStruct"]['ServerAliasInfo%d'%level] = aliasInfo
    return dce.request(request)

 func hNetrServerAliasDel(dce, level, aliasInfo interface{}){
    request = NetrServerAliasDel()
    request["ServerName"] = NULL
    request["Level"] = level
    request["InfoStruct"]["tag"] = level
    request["InfoStruct"]['ServerAliasInfo%d'%level] = aliasInfo
    return dce.request(request)

 func hNetrServerAliasEnum(dce, level, resumeHandle = 0, preferedMaximumLength = 0xffffffff interface{}){
    request = NetrServerAliasEnum()
    request["ServerName"] = NULL
    request["InfoStruct"]["Level"] = level
    request["InfoStruct"]["ServerAliasInfo"]["tag"] = level
    request["InfoStruct"]["ServerAliasInfo"]['Level%d' % level]["Buffer"] = NULL
    request["PreferedMaximumLength"] = preferedMaximumLength
    request["ResumeHandle"] = resumeHandle
    return dce.request(request)
