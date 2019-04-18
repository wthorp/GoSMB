// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Author: Alberto Solino (@agsolino)
//
// Description:
//   SMB 2 and 3 Protocol Structures and constants [MS-SMB2]
//
from __future__ import division
from __future__ import print_function

from impacket.structure import Structure

// Constants

// SMB Packet
SMB2_PACKET_SIZE     = 64

// SMB Commands
SMB2_NEGOTIATE       = 0x0000 //
SMB2_SESSION_SETUP   = 0x0001 //
SMB2_LOGOFF          = 0x0002 //
SMB2_TREE_CONNECT    = 0x0003 //
SMB2_TREE_DISCONNECT = 0x0004 //
SMB2_CREATE          = 0x0005 //
SMB2_CLOSE           = 0x0006 //
SMB2_FLUSH           = 0x0007 //
SMB2_READ            = 0x0008 //
SMB2_WRITE           = 0x0009 //
SMB2_LOCK            = 0x000A //
SMB2_IOCTL           = 0x000B //
SMB2_CANCEL          = 0x000C //
SMB2_ECHO            = 0x000D //
SMB2_QUERY_DIRECTORY = 0x000E //
SMB2_CHANGE_NOTIFY   = 0x000F
SMB2_QUERY_INFO      = 0x0010 //
SMB2_SET_INFO        = 0x0011
SMB2_OPLOCK_BREAK    = 0x0012

// SMB Flags
SMB2_FLAGS_SERVER_TO_REDIR    = 0x00000001
SMB2_FLAGS_ASYNC_COMMAND      = 0x00000002
SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004
SMB2_FLAGS_SIGNED             = 0x00000008
SMB2_FLAGS_DFS_OPERATIONS     = 0x10000000
SMB2_FLAGS_REPLAY_OPERATION   = 0x80000000

// SMB Error SymLink Flags
SYMLINK_FLAG_ABSOLUTE         = 0x0
SYMLINK_FLAG_RELATIVE         = 0x1

// SMB2_NEGOTIATE
// Security Modes
SMB2_NEGOTIATE_SIGNING_ENABLED  = 0x1
SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x2

// Capabilities
SMB2_GLOBAL_CAP_DFS                = 0x01
SMB2_GLOBAL_CAP_LEASING            = 0x02
SMB2_GLOBAL_CAP_LARGE_MTU          = 0x04
SMB2_GLOBAL_CAP_MULTI_CHANNEL      = 0x08
SMB2_GLOBAL_CAP_PERSISTENT_HANDLES = 0x10
SMB2_GLOBAL_CAP_DIRECTORY_LEASING  = 0x20
SMB2_GLOBAL_CAP_ENCRYPTION         = 0x40

// Dialects
SMB2_DIALECT_002      = 0x0202 
SMB2_DIALECT_21       = 0x0210 
SMB2_DIALECT_30       = 0x0300 
SMB2_DIALECT_302      = 0x0302  //SMB 3.0.2
SMB2_DIALECT_311      = 0x0311  //SMB 3.1.1
SMB2_DIALECT_WILDCARD = 0x02FF 

// SMB2_SESSION_SETUP
// Flags
SMB2_SESSION_FLAG_BINDING        = 0x01
SMB2_SESSION_FLAG_IS_GUEST       = 0x01
SMB2_SESSION_FLAG_IS_NULL        = 0x02
SMB2_SESSION_FLAG_ENCRYPT_DATA   = 0x04

// SMB2_TREE_CONNECT 
// Types
SMB2_SHARE_TYPE_DISK   = 0x1
SMB2_SHARE_TYPE_PIPE   = 0x2
SMB2_SHARE_TYPE_PRINT  = 0x3

// Share Flags
SMB2_SHAREFLAG_MANUAL_CACHING              = 0x00000000
SMB2_SHAREFLAG_AUTO_CACHING                = 0x00000010
SMB2_SHAREFLAG_VDO_CACHING                 = 0x00000020
SMB2_SHAREFLAG_NO_CACHING                  = 0x00000030
SMB2_SHAREFLAG_DFS                         = 0x00000001
SMB2_SHAREFLAG_DFS_ROOT                    = 0x00000002
SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS    = 0x00000100
SMB2_SHAREFLAG_FORCE_SHARED_DELETE         = 0x00000200
SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING     = 0x00000400
SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM = 0x00000800
SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK        = 0x00001000
SMB2_SHAREFLAG_ENABLE_HASH_V1              = 0x00002000
SMB2_SHAREFLAG_ENABLE_HASH_V2              = 0x00004000
SMB2_SHAREFLAG_ENCRYPT_DATA                = 0x00008000

// Capabilities
SMB2_SHARE_CAP_DFS                         = 0x00000008
SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY     = 0x00000010
SMB2_SHARE_CAP_SCALEOUT                    = 0x00000020
SMB2_SHARE_CAP_CLUSTER                     = 0x00000040

// SMB_CREATE 
// Oplocks
SMB2_OPLOCK_LEVEL_NONE       = 0x00
SMB2_OPLOCK_LEVEL_II         = 0x01
SMB2_OPLOCK_LEVEL_EXCLUSIVE  = 0x08
SMB2_OPLOCK_LEVEL_BATCH      = 0x09
SMB2_OPLOCK_LEVEL_LEASE      = 0xFF

// Impersonation Level
SMB2_IL_ANONYMOUS       = 0x00000000
SMB2_IL_IDENTIFICATION  = 0x00000001
SMB2_IL_IMPERSONATION   = 0x00000002
SMB2_IL_DELEGATE        = 0x00000003

// File Attributes
FILE_ATTRIBUTE_ARCHIVE             = 0x00000020
FILE_ATTRIBUTE_COMPRESSED          = 0x00000800
FILE_ATTRIBUTE_DIRECTORY           = 0x00000010
FILE_ATTRIBUTE_ENCRYPTED           = 0x00004000
FILE_ATTRIBUTE_HIDDEN              = 0x00000002
FILE_ATTRIBUTE_NORMAL              = 0x00000080
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000
FILE_ATTRIBUTE_OFFLINE             = 0x00001000
FILE_ATTRIBUTE_READONLY            = 0x00000001
FILE_ATTRIBUTE_REPARSE_POINT       = 0x00000400
FILE_ATTRIBUTE_SPARSE_FILE         = 0x00000200
FILE_ATTRIBUTE_SYSTEM              = 0x00000004
FILE_ATTRIBUTE_TEMPORARY           = 0x00000100
FILE_ATTRIBUTE_INTEGRITY_STREAM    = 0x00000800
FILE_ATTRIBUTE_NO_SCRUB_DATA       = 0x00020000

// Share Access
FILE_SHARE_READ         = 0x00000001
FILE_SHARE_WRITE        = 0x00000002
FILE_SHARE_DELETE       = 0x00000004

// Create Disposition
FILE_SUPERSEDE          = 0x00000000 
FILE_OPEN               = 0x00000001
FILE_CREATE             = 0x00000002
FILE_OPEN_IF            = 0x00000003
FILE_OVERWRITE          = 0x00000004
FILE_OVERWRITE_IF       = 0x00000005

// Create Options
FILE_DIRECTORY_FILE            = 0x00000001
FILE_WRITE_THROUGH             = 0x00000002
FILE_SEQUENTIAL_ONLY           = 0x00000004
FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008
FILE_SYNCHRONOUS_IO_ALERT      = 0x00000010
FILE_SYNCHRONOUS_IO_NONALERT   = 0x00000020
FILE_NON_DIRECTORY_FILE        = 0x00000040
FILE_COMPLETE_IF_OPLOCKED      = 0x00000100
FILE_NO_EA_KNOWLEDGE           = 0x00000200
FILE_RANDOM_ACCESS             = 0x00000800
FILE_DELETE_ON_CLOSE           = 0x00001000
FILE_OPEN_BY_FILE_ID           = 0x00002000
FILE_OPEN_FOR_BACKUP_INTENT    = 0x00004000
FILE_NO_COMPRESSION            = 0x00008000
FILE_RESERVE_OPFILTER          = 0x00100000
FILE_OPEN_REPARSE_POINT        = 0x00200000 
FILE_OPEN_NO_RECALL            = 0x00400000
FILE_OPEN_FOR_FREE_SPACE_QUERY = 0x00800000

// File Access Mask / Desired Access
FILE_READ_DATA         = 0x00000001
FILE_WRITE_DATA        = 0x00000002
FILE_APPEND_DATA       = 0x00000004
FILE_READ_EA           = 0x00000008
FILE_WRITE_EA          = 0x00000010
FILE_EXECUTE           = 0x00000020
FILE_READ_ATTRIBUTES   = 0x00000080
FILE_WRITE_ATTRIBUTES  = 0x00000100
DELETE                 = 0x00010000
READ_CONTROL           = 0x00020000
WRITE_DAC              = 0x00040000
WRITE_OWNER            = 0x00080000
SYNCHRONIZE            = 0x00100000
ACCESS_SYSTEM_SECURITY = 0x01000000
MAXIMUM_ALLOWED        = 0x02000000
GENERIC_ALL            = 0x10000000
GENERIC_EXECUTE        = 0x20000000
GENERIC_WRITE          = 0x40000000
GENERIC_READ           = 0x80000000

// Directory Access Mask 
FILE_LIST_DIRECTORY    = 0x00000001
FILE_ADD_FILE          = 0x00000002
FILE_ADD_SUBDIRECTORY  = 0x00000004
FILE_TRAVERSE          = 0x00000020
FILE_DELETE_CHILD      = 0x00000040

// Create Contexts
SMB2_CREATE_EA_BUFFER                     = 0x45787441 
SMB2_CREATE_SD_BUFFER                     = 0x53656344
SMB2_CREATE_DURABLE_HANDLE_REQUEST        = 0x44486e51 
SMB2_CREATE_DURABLE_HANDLE_RECONNECT      = 0x44486e43 
SMB2_CREATE_ALLOCATION_SIZE               = 0x416c5369 
SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST  = 0x4d784163 
SMB2_CREATE_TIMEWARP_TOKEN                = 0x54577270 
SMB2_CREATE_QUERY_ON_DISK_ID              = 0x51466964 
SMB2_CREATE_REQUEST                       = 0x52714c73 
SMB2_CREATE_REQUEST_LEASE_V2              = 0x52714c73 
SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2     = 0x44483251 
SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2   = 0x44483243 
SMB2_CREATE_APP_INSTANCE_ID               = 0x45BCA66AEFA7F74A9008FA462E144D74 

// Flags
SMB2_CREATE_FLAG_REPARSEPOINT  = 0x1
FILE_NEED_EA                   = 0x80

// CreateAction
FILE_SUPERSEDED    = 0x00000000
FILE_OPENED        = 0x00000001
FILE_CREATED       = 0x00000002
FILE_OVERWRITTEN   = 0x00000003

// SMB2_CREATE_REQUEST_LEASE states
SMB2_LEASE_NONE            = 0x00
SMB2_LEASE_READ_CACHING    = 0x01
SMB2_LEASE_HANDLE_CACHING  = 0x02
SMB2_LEASE_WRITE_CACHING   = 0x04

// SMB2_CREATE_REQUEST_LEASE_V2 Flags
SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET = 0x4

// SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2 Flags
SMB2_DHANDLE_FLAG_PERSISTENT = 0x02
 
// SMB2_CLOSE
// Flags
SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB  = 0x0001

// SMB2_READ
// Channel
SMB2_CHANNEL_NONE     = 0x00
SMB2_CHANNEL_RDMA_V1  = 0x01

// SMB2_WRITE
// Flags
SMB2_WRITEFLAG_WRITE_THROUGH = 0x01

// Lease Break Notification
SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED  = 0x01

// SMB_LOCK
// Flags
SMB2_LOCKFLAG_SHARED_LOCK       = 0x01
SMB2_LOCKFLAG_EXCLUSIVE_LOCK    = 0x02
SMB2_LOCKFLAG_UNLOCK            = 0x04
SMB2_LOCKFLAG_FAIL_IMMEDIATELY  = 0x10

// SMB IOCTL
// Control Codes
FSCTL_DFS_GET_REFERRALS              = 0x00060194
FSCTL_PIPE_PEEK                      = 0x0011400C
FSCTL_PIPE_WAIT                      = 0x00110018
FSCTL_PIPE_TRANSCEIVE                = 0x0011C017
FSCTL_SRV_COPYCHUNK                  = 0x001440F2
FSCTL_SRV_ENUMERATE_SNAPSHOTS        = 0x00144064
FSCTL_SRV_REQUEST_RESUME_KEY         = 0x00140078
FSCTL_SRV_READ_HASH                  = 0x001441bb
FSCTL_SRV_COPYCHUNK_WRITE            = 0x001480F2
FSCTL_LMR_REQUEST_RESILIENCY         = 0x001401D4
FSCTL_QUERY_NETWORK_INTERFACE_INFO   = 0x001401FC
FSCTL_SET_REPARSE_POINT              = 0x000900A4
FSCTL_DELETE_REPARSE_POINT           = 0x000900AC
FSCTL_DFS_GET_REFERRALS_EX           = 0x000601B0
FSCTL_FILE_LEVEL_TRIM                = 0x00098208
FSCTL_VALIDATE_NEGOTIATE_INFO        = 0x00140204

// Flags
SMB2_0_IOCTL_IS_FSCTL  = 0x1

// SRV_READ_HASH
// Type
SRV_HASH_TYPE_PEER_DIST  = 0x01

// Version
SRV_HASH_VER_1  = 0x1
SRV_HASH_VER_2  = 0x2

// Retrieval Type
SRV_HASH_RETRIEVE_HASH_BASED  = 0x01
SRV_HASH_RETRIEVE_FILE_BASED  = 0x02

// NETWORK_INTERFACE_INFO
// Capabilities
RSS_CAPABLE  = 0x01
RDMA_CAPABLE = 0x02

// SMB2_QUERY_DIRECTORIES
// Information Class 
FILE_DIRECTORY_INFORMATION         = 0x01
FILE_FULL_DIRECTORY_INFORMATION    = 0x02
FILEID_FULL_DIRECTORY_INFORMATION  = 0x26
FILE_BOTH_DIRECTORY_INFORMATION    = 0x03
FILEID_BOTH_DIRECTORY_INFORMATION  = 0x25
FILENAMES_INFORMATION              = 0x0C

// Flags
SMB2_RESTART_SCANS        = 0x01
SMB2_RETURN_SINGLE_ENTRY  = 0x02
SMB2_INDEX_SPECIFIED      = 0x04
SMB2_REOPEN               = 0x10

// SMB2_CHANGE_NOTIFY
// Flags
SMB2_WATCH_TREE  = 0x01

// Filters
FILE_NOTIFY_CHANGE_FILE_NAME     = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME      = 0x00000002
FILE_NOTIFY_CHANGE_ATTRIBUTES    = 0x00000004
FILE_NOTIFY_CHANGE_SIZE          = 0x00000008
FILE_NOTIFY_CHANGE_LAST_WRITE    = 0x00000010
FILE_NOTIFY_CHANGE_LAST_ACCESS   = 0x00000020
FILE_NOTIFY_CHANGE_CREATION      = 0x00000040
FILE_NOTIFY_CHANGE_EA            = 0x00000080
FILE_NOTIFY_CHANGE_SECURITY      = 0x00000100
FILE_NOTIFY_CHANGE_STREAM_NAME   = 0x00000200
FILE_NOTIFY_CHANGE_STREAM_SIZE   = 0x00000400
FILE_NOTIFY_CHANGE_STREAM_WRITE  = 0x00000800

// FILE_NOTIFY_INFORMATION
// Actions
FILE_ACTION_ADDED            = 0x00000001
FILE_ACTION_REMOVED          = 0x00000002
FILE_ACTION_MODIFIED         = 0x00000003
FILE_ACTION_RENAMED_OLD_NAME = 0x00000004 
FILE_ACTION_RENAMED_NEW_NAME = 0x00000005

// SMB2_QUERY_INFO
// InfoTypes
SMB2_0_INFO_FILE        = 0x01
SMB2_0_INFO_FILESYSTEM  = 0x02
SMB2_0_INFO_SECURITY    = 0x03
SMB2_0_INFO_QUOTA       = 0x04

// File Information Classes
SMB2_SEC_INFO_00                      = 0
SMB2_FILE_ACCESS_INFO                 = 8
SMB2_FILE_ALIGNMENT_INFO              = 17
SMB2_FILE_ALL_INFO                    = 18
SMB2_FILE_ALLOCATION_INFO             = 19
SMB2_FILE_ALTERNATE_NAME_INFO         = 21
SMB2_ATTRIBUTE_TAG_INFO               = 35
SMB2_FILE_BASIC_INFO                  = 4
SMB2_FILE_BOTH_DIRECTORY_INFO         = 3
SMB2_FILE_COMPRESSION_INFO            = 28
SMB2_FILE_DIRECTORY_INFO              = 1
SMB2_FILE_DISPOSITION_INFO            = 13
SMB2_FILE_EA_INFO                     = 7
SMB2_FILE_END_OF_FILE_INFO            = 20
SMB2_FULL_DIRECTORY_INFO              = 2
SMB2_FULL_EA_INFO                     = 15
SMB2_FILE_HARDLINK_INFO               = 46
SMB2_FILE_ID_BOTH_DIRECTORY_INFO      = 37
SMB2_FILE_ID_FULL_DIRECTORY_INFO      = 38
SMB2_FILE_ID_GLOBAL_TX_DIRECTORY_INFO = 50
SMB2_FILE_INTERNAL_INFO               = 6
SMB2_FILE_LINK_INFO                   = 11
SMB2_FILE_MAILSLOT_QUERY_INFO         = 26
SMB2_FILE_MAILSLOT_SET_INFO           = 27
SMB2_FILE_MODE_INFO                   = 16
SMB2_FILE_MOVE_CLUSTER_INFO           = 31
SMB2_FILE_NAME_INFO                   = 9
SMB2_FILE_NAMES_INFO                  = 12
SMB2_FILE_NETWORK_OPEN_INFO           = 34
SMB2_FILE_NORMALIZED_NAME_INFO        = 48
SMB2_FILE_OBJECT_ID_INFO              = 29
SMB2_FILE_PIPE_INFO                   = 23
SMB2_FILE_PIPE_LOCAL_INFO             = 24
SMB2_FILE_PIPE_REMOTE_INFO            = 25
SMB2_FILE_POSITION_INFO               = 14
SMB2_FILE_QUOTA_INFO                  = 32
SMB2_FILE_RENAME_INFO                 = 10
SMB2_FILE_REPARSE_POINT_INFO          = 33
SMB2_FILE_SFIO_RESERVE_INFO           = 44
SMB2_FILE_SHORT_NAME_INFO             = 45
SMB2_FILE_STANDARD_INFO               = 5
SMB2_FILE_STANDARD_LINK_INFO          = 54
SMB2_FILE_STREAM_INFO                 = 22
SMB2_FILE_TRACKING_INFO               = 36
SMB2_FILE_VALID_DATA_LENGTH_INFO      = 39

// File System Information Classes
SMB2_FILESYSTEM_VOLUME_INFO           = 1
SMB2_FILESYSTEM_LABEL_INFO            = 2
SMB2_FILESYSTEM_SIZE_INFO             = 3
SMB2_FILESYSTEM_DEVICE_INFO           = 4
SMB2_FILESYSTEM_ATTRIBUTE_INFO        = 5
SMB2_FILESYSTEM_CONTROL_INFO          = 6
SMB2_FILESYSTEM_FULL_SIZE_INFO        = 7
SMB2_FILESYSTEM_OBJECT_ID_INFO        = 8
SMB2_FILESYSTEM_DRIVER_PATH_INFO      = 9
SMB2_FILESYSTEM_SECTOR_SIZE_INFO      = 11

// Additional information
OWNER_SECURITY_INFORMATION  = 0x00000001
GROUP_SECURITY_INFORMATION  = 0x00000002
DACL_SECURITY_INFORMATION   = 0x00000004
SACL_SECURITY_INFORMATION   = 0x00000008
LABEL_SECURITY_INFORMATION  = 0x00000010

// Flags
SL_RESTART_SCAN         = 0x00000001
SL_RETURN_SINGLE_ENTRY  = 0x00000002
SL_INDEX_SPECIFIED      = 0x00000004

// TRANSFORM_HEADER
SMB2_ENCRYPTION_AES128_CCM = 0x0001
SMB2_ENCRYPTION_AES128_GCM = 0x0002


// STRUCtures
// Represents a SMB2/3 Packet
 type SMBPacketBase struct { // Structure:
     func addCommand(self,command interface{}){
        // Pad to 8 bytes and put the offset of another SMBPacket
        raise Exception("Implement This!")

     func (self TYPE) isValidAnswer(status interface{}){
        if self.Status != status {
            from . import smb3
            raise smb3.SessionError(self.Status, self)
        return true

     func (self TYPE) __init__(data = nil interface{}){
        Structure.__init__(self,data)
        if data == nil {
            self.TreeID = 0


 type SMB2PacketAsync struct { // SMBPacketBase: (
        ('ProtocolID','"\xfeSMB'),
         StructureSize uint16 // =64
         CreditCharge uint16 // =0
         Status uint32 // =0
         Command uint16 // =0
         CreditRequestResponse uint16 // =0
         Flags uint32 // =0
         NextCommand uint32 // =0
         MessageID uint64 // =0
         AsyncID uint64 // =0
         SessionID uint64 // =0
         Signature [6]byte // =""
        ('Data',':=""'),
    }

 type SMB3PacketAsync struct { // SMBPacketBase: (
        ('ProtocolID','"\xfeSMB'),
         StructureSize uint16 // =64
         CreditCharge uint16 // =0
         ChannelSequence uint16 // =0
         Reserved uint16 // =0
         Command uint16 // =0
         CreditRequestResponse uint16 // =0
         Flags uint32 // =0
         NextCommand uint32 // =0
         MessageID uint64 // =0
         AsyncID uint64 // =0
         SessionID uint64 // =0
         Signature [6]byte // =""
        ('Data',':=""'),
    }

 type SMB2Packet struct { // SMBPacketBase: (
        ('ProtocolID','"\xfeSMB'),
         StructureSize uint16 // =64
         CreditCharge uint16 // =0
         Status uint32 // =0
         Command uint16 // =0
         CreditRequestResponse uint16 // =0
         Flags uint32 // =0
         NextCommand uint32 // =0
         MessageID uint64 // =0
         Reserved uint32 // =0
         TreeID uint32 // =0
         SessionID uint64 // =0
         Signature [6]byte // =""
        ('Data',':=""'),
    }

 type SMB3Packet struct { // SMBPacketBase: (
        ('ProtocolID','"\xfeSMB'),
         StructureSize uint16 // =64
         CreditCharge uint16 // =0
         ChannelSequence uint16 // =0
         Reserved uint16 // =0
         Command uint16 // =0
         CreditRequestResponse uint16 // =0
         Flags uint32 // =0
         NextCommand uint32 // =0
         MessageID uint64 // =0
         Reserved uint32 // =0
         TreeID uint32 // =0
         SessionID uint64 // =0
         Signature [6]byte // =""
        ('Data',':=""'),
    }

 type SMB2Error struct { // Structure: (
         StructureSize uint16 // =9
         Reserved uint16 // =0
         ByteCount uint32 // =0
        ('_ErrorData','_-ErrorData','self.ByteCount'),
        ('ErrorData','"\xff'),
    }

 type SMB2ErrorSymbolicLink struct { // Structure: (
         SymLinkLength uint32 // =0
         SymLinkErrorTag uint32 // =0
         ReparseTag uint32 // =0
         ReparseDataLenght uint16 // =0
         UnparsedPathLength uint16 // =0
         SubstituteNameOffset uint16 // =0
         SubstituteNameLength uint16 // =0
         PrintNameOffset uint16 // =0
         PrintNameLength uint16 // =0
         Flags uint32 // =0
        ('PathBuffer',':'),
    }

// SMB2_NEGOTIATE
 type SMB2Negotiate struct { // Structure: (
         StructureSize uint16 // =36
         DialectCount uint16 // =0
         SecurityMode uint16 // =0
         Reserved uint16 // =0
         Capabilities uint32 // =0
         ClientGuid [6]byte // =""
         ClientStartTime uint64 // =0
        ('Dialects','*<H'),
    }

 type SMB2Negotiate_Response struct { // Structure: (
         StructureSize uint16 // =65
         SecurityMode uint16 // =0
         DialectRevision uint16 // =0
         Reserved uint16 // =0
         ServerGuid [6]byte // =""
         Capabilities uint32 // =0
         MaxTransactSize uint32 // =0
         MaxReadSize uint32 // =0
         MaxWriteSize uint32 // =0
         SystemTime uint64 // =0
         ServerStartTime uint64 // =0
         SecurityBufferOffset uint16 // =0
         SecurityBufferLength uint16 // =0
         Reserved2 uint32 // =0
        ('_AlignPad','_-AlignPad','self.SecurityBufferOffset"] - (64 + self["StructureSize - 1)'),
        ('AlignPad',':=""'),
        ('_Buffer','_-Buffer','self.SecurityBufferLength'),
        ('Buffer',':'),
    }

// SMB2_SESSION_SETUP 
 type SMB2SessionSetup struct { // Structure:
    SIZE = 24 (
         StructureSize uint16 // =25
         Flags byte // =0
         SecurityMode byte // =0
         Capabilities uint32 // =0
         Channel uint32 // =0
         SecurityBufferOffset uint16 // =(self.SIZE + 64 + len(self.AlignPad))
         SecurityBufferLength uint16 // =0
         PreviousSessionId uint64 // =0
        ('_AlignPad','_-AlignPad','self.SecurityBufferOffset"] - (64 + self["StructureSize - 1)'),
        ('AlignPad',':=""'),
        ('_Buffer','_-Buffer','self.SecurityBufferLength'),
        ('Buffer',':'),
    }

     func (self TYPE) __init__(data = nil interface{}){
        Structure.__init__(self,data)
        if data == nil {
            self.AlignPad = ""

     func (self TYPE) getData(){
        //self.AlignPad = "\x00" * ((8 - ((24 + SMB2_PACKET_SIZE) & 7)) & 7)
        //self.SecurityBufferOffset"] = 24 + SMB2_PACKET_SIZE +len(self["AlignPad) 
        //self.SecurityBufferLength"] += len(self["AlignPad)
        return Structure.getData(self)
        

 type SMB2SessionSetup_Response struct { // Structure: (
         StructureSize uint16 // =9
         SessionFlags uint16 // =0
         SecurityBufferOffset uint16 // =0
         SecurityBufferLength uint16 // =0
        ('_AlignPad','_-AlignPad','self.SecurityBufferOffset"] - (64 + self["StructureSize - 1)'),
        ('AlignPad',':=""'),
        ('_Buffer','_-Buffer','self.SecurityBufferLength'),
        ('Buffer',':'),
    }

// SMB2_LOGOFF
 type SMB2Logoff struct { // Structure: (
         StructureSize uint16 // =4
         Reserved uint16 // =0
    } 


 type SMB2Logoff_Response struct { // Structure: (
         StructureSize uint16 // =4
         Reserved uint16 // =0
    }

// SMB2_TREE_CONNECT
 type SMB2TreeConnect struct { // Structure:
    SIZE = 8 (
         StructureSize uint16 // =9
         Reserved uint16 // =0
         PathOffset uint16 // =(self.SIZE + 64 + len(self.AlignPad))
         PathLength uint16 // =0
        ('_AlignPad','_-AlignPad','self.PathOffset - (64 + self.SIZE - 1)'),
        ('AlignPad',':=""'),
        ('_Buffer','_-Buffer','self.PathLength'),
        ('Buffer',':'),
    }
     func (self TYPE) __init__(data = nil interface{}){
        Structure.__init__(self,data)
        if data == nil {
            self.AlignPad = ""

 type SMB2TreeConnect_Response struct { // Structure: (
         StructureSize uint16 // =16
         ShareType byte // =0
         Reserved byte // =0
         ShareFlags uint32 // =0
         Capabilities uint32 // =0
         MaximalAccess uint32 // =0
    }

// SMB2_TREE_DISCONNECT
 type SMB2TreeDisconnect struct { // Structure: (
         StructureSize uint16 // =4
         Reserved uint16 // =0
    }

 type SMB2TreeDisconnect_Response struct { // Structure: (
         StructureSize uint16 // =4
         Reserved uint16 // =0
    }

// SMB2_CREATE
 type SMB2Create struct { // Structure:
    SIZE = 56 (
         StructureSize uint16 // =57
         SecurityFlags byte // =0
         RequestedOplockLevel byte // =0
         ImpersonationLevel uint32 // =0
         SmbCreateFlags uint64 // =0
         Reserved uint64 // =0
         DesiredAccess uint32 // =0
         FileAttributes uint32 // =0
         ShareAccess uint32 // =0
         CreateDisposition uint32 // =0
         CreateOptions uint32 // =0
         NameOffset uint16 // =(self.SIZE + 64 + len(self.AlignPad))
         NameLength uint16 // =0
         CreateContextsOffset uint32 // =0
         CreateContextsLength uint32 // =0
        ('_AlignPad','_-AlignPad','self.NameOffset"] - (64 + self["StructureSize - 1)'),
        ('AlignPad',':=""'),
        ('_Buffer','_-Buffer','self.CreateContextsLength"]+self["NameLength'),
        ('Buffer',':'),
    }
     func (self TYPE) __init__(data = nil interface{}){
        Structure.__init__(self,data)
        if data == nil {
            self.AlignPad = ""

 type SMB2CreateContext struct { // Structure: (
          Next uint32 // =0
          NameOffset uint16 // =0
          NameLength uint16 // =0
          Reserved uint16 // =0
          DataOffset uint16 // =0
          DataLength uint32 // =0
         ('_Buffer','_-Buffer','self.DataLength"]+self["NameLength'),
         ('Buffer',':'),
     }

 type SMB2_FILEID struct { // Structure: (
         Persistent uint64 // =0
         Volatile uint64 // =0
    }

 type SMB2Create_Response struct { // Structure: (
         StructureSize uint16 // =89
         OplockLevel byte // =0
         Flags byte // =0
         CreateAction uint32 // =0
         CreationTime uint64 // =0
         LastAccessTime uint64 // =0
         LastWriteTime uint64 // =0
         ChangeTime uint64 // =0
         AllocationSize uint64 // =0
         EndOfFile uint64 // =0
         FileAttributes uint32 // =0
         Reserved2 uint32 // =0
        ('FileID',':',SMB2_FILEID),
         CreateContextsOffset uint32 // =0
         CreateContextsLength uint32 // =0
        ('_AlignPad','_-AlignPad','self.CreateContextsOffset"] - (64 + self["StructureSize - 1)'),
        ('AlignPad',':=""'),
        ('_Buffer','_-Buffer','self.CreateContextsLength'),
        ('Buffer',':'),
    }

 type FILE_FULL_EA_INFORMATION struct { // Structure: (
         NextEntryOffset uint32 // =0
         Flags byte // =0
         EaNameLength byte // =0
         EaValueLength uint16 // =0
        ('_EaName','_-EaName','self.EaNameLength'),
        ('EaName',':'),
        ('_EaValue','_-EaValue','self.EaValue'),
        ('EaValue',':'),
    }


 type SMB2_CREATE_DURABLE_HANDLE_RECONNECT struct { // Structure: (
        ('Data',':',SMB2_FILEID),
    }

 type SMB2_CREATE_DURABLE_HANDLE_REQUEST struct { // Structure: (
         DurableRequest [6]byte // =""
    }

 type SMB2_CREATE_DURABLE_HANDLE_RESPONSE struct { // Structure: (
         Reserved uint64 // =0
    }

 type SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST struct { // Structure: (
         Timestamp uint64 // =0
    }

 type SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE struct { // Structure: (
         QueryStatus uint32 // =0
         MaximalAccess uint32 // =0
    }

 type SMB2_CREATE_ALLOCATION_SIZE struct { // Structure: (
         AllocationSize uint64 // =0
    }

 type SMB2_CREATE_TIMEWARP_TOKEN struct { // Structure: (
         AllocationSize uint64 // =0
    }

 type SMB2_CREATE_REQUEST_LEASE struct { // Structure: (
         LeaseKey [6]byte // =""
         LeaseState uint32 // =0
         LeaseFlags uint32 // =0
         LeaseDuration uint64 // =0
    }

SMB2_CREATE_RESPONSE_LEASE = SMB2_CREATE_REQUEST_LEASE

 type SMB2_CREATE_REQUEST_LEASE_V2 struct { // Structure: (
         LeaseKey [6]byte // =""
         LeaseState uint32 // =0
         Flags uint32 // =0
         LeaseDuration uint64 // =0
         ParentLeaseKey [6]byte // =""
         Epoch uint16 // =0
         Reserved uint16 // =0
    }

SMB2_CREATE_RESPONSE_LEASE_V2 = SMB2_CREATE_REQUEST_LEASE_V2

 type SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2 struct { // Structure: (
         Timeout uint32 // =0
         Flags uint32 // =0
         Reserved [8]byte // =""
         CreateGuid [6]byte // =""
    }

 type SMB2_CREATE_DURABLE_HANDLE_RESPONSE_V2 struct { // Structure: (
         Timeout uint32 // =0
         Flags uint32 // =0
    }

 type SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2 struct { // Structure: (
        ('FileID',':', SMB2_FILEID),
         CreateGuid [6]byte // =""
         Flags uint32 // =0
    }

 type SMB2_CREATE_APP_INSTANCE_ID struct { // Structure: (
         StructureSize uint16 // =0
         Reserved uint16 // =0
         AppInstanceId [6]byte // =""
    }

 type SMB2_CREATE_QUERY_ON_DISK_ID struct { // Structure: (
         DiskIDBuffer [2]byte // =""
    }

// Todo: Add Classes for
//SMB2_CREATE_SD_BUFFER                    

// SMB2_CLOSE
 type SMB2Close struct { // Structure: (
         StructureSize uint16 // =24
         Flags uint16 // =0
         Reserved uint32 // =0
        ('FileID',':', SMB2_FILEID),
    }

 type SMB2Close_Response struct { // Structure: (
         StructureSize uint16 // =60
         Flags uint16 // =0
         Reserved uint32 // =0
         CreationTime uint64 // =0
         LastAccessTime uint64 // =0
         LastWriteTime uint64 // =0
         ChangeTime uint64 // =0
         AllocationSize uint64 // =0
         EndofFile uint64 // =0
         FileAttributes uint32 // =0
    }

// SMB2_FLUSH
 type SMB2Flush struct { // Structure: (
         StructureSize uint16 // =24
         Reserved1 uint16 // =0
         Reserved2 uint32 // =0
        ('FileID',':',SMB2_FILEID),
    }

 type SMB2Flush_Response struct { // Structure: (
         StructureSize uint16 // =4
         Reserved uint16 // =0
    }

// SMB2_READ
 type SMB2Read struct { // Structure:
    SIZE = 48 (
         StructureSize uint16 // =49
         Padding byte // =0
         Reserved byte // =0
         Length uint32 // =0
         Offset uint64 // =0
        ('FileID',':',SMB2_FILEID),
         MinimumCount uint32 // =0
         Channel uint32 // =0
         RemainingBytes uint32 // =0
         ReadChannelInfoOffset uint16 // =0
         ReadChannelInfoLength uint16 // =0
        ('_AlignPad','_-AlignPad','self.ReadChannelInfoOffset"] - (64 + self["StructureSize - 1)'),
        ('AlignPad',':=""'),
        ('_Buffer','_-Buffer','self.ReadChannelInfoLength'),
        ('Buffer',':="0"'),
    }
     func (self TYPE) __init__(data = nil interface{}){
        Structure.__init__(self,data)
        if data == nil {
            self.AlignPad = ""


 type SMB2Read_Response struct { // Structure: (
         StructureSize uint16 // =17
         DataOffset byte // =0
         Reserved byte // =0
         DataLength uint32 // =0
         DataRemaining uint32 // =0
         Reserved2 uint32 // =0
        ('_AlignPad','_-AlignPad','self.DataOffset"] - (64 + self["StructureSize - 1)'),
        ('AlignPad',':=""'),
        ('_Buffer','_-Buffer','self.DataLength'),
        ('Buffer',':'),
    }

// SMB2_WRITE
 type SMB2Write struct { // Structure:
    SIZE = 48 (
         StructureSize uint16 // =49
         DataOffset uint16 // =(self.SIZE + 64 + len(self.AlignPad))
         Length uint32 // =0
         Offset uint64 // =0
        ('FileID',':',SMB2_FILEID),
         Channel uint32 // =0
         RemainingBytes uint32 // =0
         WriteChannelInfoOffset uint16 // =0
         WriteChannelInfoLength uint16 // =0
        ('_AlignPad','_-AlignPad','self.DataOffset"] + self["WriteChannelInfoOffset"] - (64 + self["StructureSize - 1)'),
        ('AlignPad',':=""'),
         Flags uint32 // =0
        ('_Buffer','_-Buffer','self.Length"]+self["WriteChannelInfoLength'),
        ('Buffer',':'),
    }
     func (self TYPE) __init__(data = nil interface{}){
        Structure.__init__(self,data)
        if data == nil {
            self.AlignPad = ""


 type SMB2Write_Response struct { // Structure: (
         StructureSize uint16 // =17
         Reserved uint16 // =0
         Count uint32 // =0
         Remaining uint32 // =0
         WriteChannelInfoOffset uint16 // =0
         WriteChannelInfoLength uint16 // =0
    }

 type SMB2OplockBreakNotification struct { // Structure: (
         StructureSize uint16 // =24
         OplockLevel byte // =0
         Reserved byte // =0
         Reserved2 uint32 // =0
        ('FileID',':',SMB2_FILEID),
    }

SMB2OplockBreakAcknowledgment = SMB2OplockBreakNotification
SMB2OplockBreakResponse       = SMB2OplockBreakNotification

 type SMB2LeaseBreakNotification struct { // Structure: (
         StructureSize uint16 // =44
         NewEpoch uint16 // =0
         Flags uint32 // =0
         LeaseKey [6]byte // =""
         CurrentLeaseState uint32 // =0
         NewLeaseState uint32 // =0
         BreakReason uint32 // =0
         AccessMaskHint uint32 // =0
         ShareMaskHint uint32 // =0
    }

 type SMB2LeaseBreakAcknowledgement struct { // Structure: (
         StructureSize uint16 // =36
         Reserved uint16 // =0
         Flags uint32 // =0
         LeaseKey [6]byte // =""
         LeaseState uint32 // =0
         LeaseDuration uint64 // =0
    }

SMB2LeaseBreakResponse = SMB2LeaseBreakAcknowledgement

// SMB2_LOCK
 type SMB2_LOCK_ELEMENT struct { // Structure: (
         Offset uint64 // =0
         Length uint64 // =0
         Flags uint32 // =0
         Reserved uint32 // =0
    }

 type SMB2Lock struct { // Structure: (
         StructureSize uint16 // =48
         LockCount uint16 // =0
         LockSequence uint32 // =0
        ('FileID',':',SMB2_FILEID),
        ('_Locks','_-Locks','self.LockCount*24'),
        ('Locks',':'),
    }

 type SMB2Lock_Response struct { // Structure: (
         StructureSize uint16 // =4
         Reserved uint16 // =0
    }


// SMB2_ECHO
 type SMB2Echo struct { // Structure: (
         StructureSize uint16 // =4
         Reserved uint16 // =0
    }

SMB2Echo_Response = SMB2Echo

// SMB2_CANCEL`
 type SMB2Cancel struct { // Structure: (
         StructureSize uint16 // =4
         Reserved uint16 // =0
    }

// SMB2_IOCTL
 type SMB2Ioctl struct { // Structure:
    SIZE = 56 (
         StructureSize uint16 // =57
         Reserved uint16 // =0
         CtlCode uint32 // =0
        ('FileID',':',SMB2_FILEID),
         InputOffset uint32 // =(self.SIZE + 64 + len(self.AlignPad))
         InputCount uint32 // =0
         MaxInputResponse uint32 // =0
         OutputOffset uint32 // =(self.SIZE + 64 + len(self.AlignPad"]) + self["InputCount)
         OutputCount uint32 // =0
         MaxOutputResponse uint32 // =0
         Flags uint32 // =0
         Reserved2 uint32 // =0
        //('_AlignPad','_-AlignPad','self.InputOffset"] + self["OutputOffset"] - (64 + self["StructureSize - 1)'),
        //('AlignPad',':=""'),
        ('_Buffer','_-Buffer','self.InputCount"]+self["OutputCount'),
        ('Buffer',':'),
    }
     func (self TYPE) __init__(data = nil interface{}){
        Structure.__init__(self,data)
        if data == nil {
            self.AlignPad = ""

 type FSCTL_PIPE_WAIT_STRUCTURE struct { // Structure: (
         Timeout int64 // =0
         NameLength uint32 // =0
         TimeoutSpecified byte // =0
         Padding byte // =0
        ('_Name','_-Name','self.NameLength'),
        ('Name',':'),
    }

 type SRV_COPYCHUNK_COPY struct { // Structure: (
         SourceKey [4]byte // =""
         ChunkCount uint32 // =0
         Reserved uint32 // =0
        ('_Chunks','_-Chunks', 'self.ChunkCount*len(SRV_COPYCHUNK)'),
        ('Chunks',':'),
    }

 type SRV_COPYCHUNK struct { // Structure: (
         SourceOffset uint64 // =0
         TargetOffset uint64 // =0
         Length uint32 // =0
         Reserved uint32 // =0
    }

 type SRV_COPYCHUNK_RESPONSE struct { // Structure: (
         ChunksWritten uint32 // =0
         ChunkBytesWritten uint32 // =0
         TotalBytesWritten uint32 // =0
    }

 type SRV_READ_HASH struct { // Structure: (
         HashType uint32 // =0
         HashVersion uint32 // =0
         HashRetrievalType uint32 // =0
         Length uint32 // =0
         Offset uint64 // =0
    }

 type NETWORK_RESILIENCY_REQUEST struct { // Structure: (
         Timeout uint32 // =0
         Reserved uint32 // =0
    } 

 type VALIDATE_NEGOTIATE_INFO struct { // Structure: (
         Capabilities uint32 // =0
         Guid [6]byte // =""
         SecurityMode uint16 // =0
        // DialectCount uint16 // =0
         Dialects uint16 // *<H
    }

 type VALIDATE_NEGOTIATE_INFO_RESPONSE struct { // Structure: (
         Capabilities uint32 // =0
         Guid [6]byte // =""
         SecurityMode uint16 // =0
         Dialect uint16 // 
    }

 type SRV_SNAPSHOT_ARRAY struct { // Structure: (
         NumberOfSnapShots uint32 // =0
         NumberOfSnapShotsReturned uint32 // =0
         SnapShotArraySize uint32 // =0
        ('_SnapShots','_-SnapShots','self.SnapShotArraySize'),
        ('SnapShots',':'),
    }

 type SRV_REQUEST_RESUME_KEY struct { // Structure: (
         ResumeKey [4]byte // =""
         ContextLength uint32 // =0
        ('_Context','_-Context','self.ContextLength'),
        ('Context',':'),
    }

 type HASH_HEADER struct { // Structure: (
         HashType uint32 // =0
         HashVersion uint32 // =0
         SourceFileChangeTime uint64 // =0
         SourceFileSize uint64 // =0
         HashBlobLength uint32 // =0
         HashBlobOffset uint32 // =0
         Dirty uint16 // =0
         SourceFileNameLength uint32 // =0
        ('_SourceFileName','_-SourceFileName','self.SourceFileNameLength',),
        ('SourceFileName',':'),
    }

 type SRV_HASH_RETRIEVE_HASH_BASED struct { // Structure: (
         Offset uint64 // =0
         BufferLength uint32 // =0
         Reserved uint32 // =0
        ('_Buffer','_-Buffer','self.BufferLength'),
        ('Buffer',':'),
    }

 type SRV_HASH_RETRIEVE_FILE_BASED struct { // Structure: (
         FileDataOffset uint64 // =0
         FileDataLength uint64 // =0
         BufferLength uint32 // =0
         Reserved uint32 // =0
        ('_Buffer','_-Buffer','self.BufferLength'),
        ('Buffer',':'),
    }

 type NETWORK_INTERFACE_INFO struct { // Structure: (
         Next uint32 // =0
         IfIndex uint32 // =0
         Capability uint32 // =0
         Reserved uint32 // =0
         LinkSpeed uint64 // =0
         SockAddr_Storage [8]byte // =""
    }

 type MOUNT_POINT_REPARSE_DATA_STRUCTURE struct { // Structure: (
         ReparseTag uint32 // =0xA0000003
         ReparseDataLen uint16 // =len(self.PathBuffer) + 8
         Reserved uint16 // =0
         SubstituteNameOffset uint16 // =0
         SubstituteNameLength uint16 // =0
         PrintNameOffset uint16 // =0
         PrintNameLength uint16 // =0
        ("PathBuffer", ":")
    }

 type MOUNT_POINT_REPARSE_GUID_DATA_STRUCTURE struct { // Structure: (
         ReparseTag uint32 // =0xA0000003
         ReparseDataLen uint16 // =len(self.DataBuffer)
         Reserved uint16 // =0
         ReparseGuid [6]byte // =''
        ("DataBuffer", ":")
    }

 type SMB2Ioctl_Response struct { // Structure: (
         StructureSize uint16 // =49
         Reserved uint16 // =0
         CtlCode uint32 // =0
        ('FileID',':',SMB2_FILEID),
         InputOffset uint32 // =0
         InputCount uint32 // =0
         OutputOffset uint32 // =0
         OutputCount uint32 // =0
         Flags uint32 // =0
         Reserved2 uint32 // =0
        ('_AlignPad','_-AlignPad','self.OutputOffset"] - (64 + self["StructureSize - 1)'),
        ('AlignPad',':=""'),
        ('_Buffer','_-Buffer','self.InputCount"]+self["OutputCount'),
        ('Buffer',':'),
    }

// SMB2_QUERY_DIRECTORY
 type SMB2QueryDirectory struct { // Structure:
    SIZE = 32 (
         StructureSize uint16 // =33
         FileInformationClass byte // =0
         Flags byte // =0
         FileIndex uint32 // =0
        ('FileID',':',SMB2_FILEID),
         FileNameOffset uint16 // =(self.SIZE + 64 + len(self.AlignPad))
         FileNameLength uint16 // =0
         OutputBufferLength uint32 // =0
        ('_AlignPad','_-AlignPad','self.FileNameOffset"] - (64 + self["StructureSize - 1)'),
        ('AlignPad',':=""'),
        ('_Buffer','_-Buffer','self.FileNameLength'),
        ('Buffer',':'),
    }
     func (self TYPE) __init__(data = nil interface{}){
        Structure.__init__(self,data)
        if data == nil {
            self.AlignPad = ""

 type SMB2QueryDirectory_Response struct { // Structure: (
         StructureSize uint16 // =9
         OutputBufferOffset uint16 // =0
         OutputBufferLength uint32 // =0
        ('_AlignPad','_-AlignPad','self.OutputBufferOffset"] - (64 + self["StructureSize - 1)'),
        ('AlignPad',':=""'),
        ('_Buffer','_-Buffer','self.OutputBufferLength'),
        ('Buffer',':'),
    }

// SMB2_CHANGE_NOTIFY
 type SMB2ChangeNotify struct { // Structure: (
         StructureSize uint16 // =32
         Flags uint16 // =0
         OutputBufferLength uint32 // =0
        ('FileID',':',SMB2_FILEID),
         CompletionFilter uint32 // =0
         Reserved uint32 // =0
    }

 type SMB2ChangeNotify_Response struct { // Structure: (
         StructureSize uint16 // =9
         OutputBufferOffset uint16 // =0
         OutputBufferLength uint32 // =0
        ('_AlignPad','_-AlignPad','self.OutputBufferOffset"] - (64 + self["StructureSize - 1)'),
        ('AlignPad',':=""'),
        ('_Buffer','_-Buffer','self.OutputBufferLength'),
        ('Buffer',':'),
    }

 type FILE_NOTIFY_INFORMATION struct { // Structure: (
         NextEntryOffset uint32 // =0
         Action uint32 // =0
         FileNameLength uint32 // =0
        ('_FileName','_-FileName','self.FileNameLength',),
        ('FileName',':'),
    }

// SMB2_QUERY_INFO
 type SMB2QueryInfo struct { // Structure:
    SIZE = 40 (
        StructureSize uint16 // =41
        InfoType byte // =0
        FileInfoClass byte // =0
        OutputBufferLength uint32 // =0
        InputBufferOffset uint16 // =(self.SIZE + 64 + len(self.AlignPad))
        Reserved uint16 // =0
        InputBufferLength uint32 // =0
        AdditionalInformation uint32 // =0
        Flags uint32 // =0
       ('FileID',':',SMB2_FILEID),
       ('_AlignPad','_-AlignPad','self.InputBufferOffset"] - (64 + self["StructureSize - 1)'),
       ('AlignPad',':=""'),
       ('_Buffer','_-Buffer','self.InputBufferLength'),
       ('Buffer',':'),
    }
     func (self TYPE) __init__(data = nil interface{}){
        Structure.__init__(self,data)
        if data == nil {
            self.AlignPad = ""


 type SMB2_QUERY_QUOTA_INFO struct { // Structure: (
         ReturnSingle byte // =0
         RestartScan byte // =0
         Reserved uint16 // =0
         SidListLength uint32 // =0
         StartSidLength uint32 // =0
         StartSidOffset uint32 // =0
        // ToDo: Check 2.2.37.1 here
        ('SidBuffer',':'),
    }

 type SMB2QueryInfo_Response struct { // Structure: (
        StructureSize uint16 // =9
        OutputBufferOffset uint16 // =0
        OutputBufferLength uint32 // =0
       ('_AlignPad','_-AlignPad','self.OutputBufferOffset"] - (64 + self["StructureSize - 1)'),
       ('AlignPad',':=""'),
       ('_Buffer','_-Buffer','self.OutputBufferLength'),
       ('Buffer',':'),
   }

// SMB2_SET_INFO
 type SMB2SetInfo struct { // Structure:
    SIZE = 32 (
        StructureSize uint16 // =33
        InfoType byte // =0
        FileInfoClass byte // =0
        BufferLength uint32 // =0
        BufferOffset uint16 // =(self.SIZE + 64 + len(self.AlignPad))
        Reserved uint16 // =0
        AdditionalInformation uint32 // =0
       ('FileID',':',SMB2_FILEID),
       ('_AlignPad','_-AlignPad','self.BufferOffset"] - (64 + self["StructureSize - 1)'),
       ('AlignPad',':=""'),
       ('_Buffer','_-Buffer','self.BufferLength'),
       ('Buffer',':'),
    }
     func (self TYPE) __init__(data = nil interface{}){
        Structure.__init__(self,data)
        if data == nil {
            self.AlignPad = ""

 type SMB2SetInfo_Response struct { // Structure: (
        StructureSize uint16 // =2
    }

 type FILE_RENAME_INFORMATION_TYPE_2 struct { // Structure: (
         ReplaceIfExists byte // =0
         Reserved [7]byte // =""
         RootDirectory uint64 // =0
         FileNameLength uint32 // =0
        ('_FileName','_-FileName','self.FileNameLength'),
        ('FileName',':'),
    }

 type SMB2_TRANSFORM_HEADER struct { // Structure: (
        ('ProtocolID','"\xfdSMB'),
         Signature [6]byte // =""
         Nonce [6]byte // =""
         OriginalMessageSize uint32 // =0
         Reserved uint16 // =0
         EncryptionAlgorithm uint16 // =0
         SessionID uint64 // =0
    }

// SMB2_FILE_INTERNAL_INFO
 type FileInternalInformation struct { // Structure: (
         IndexNumber int64 // =0
    }

// SMB2_SEC_INFO_00       
 type FileSecInformation struct { // Structure: (
         Revision int16 // =1
         Type int16 // =0
         OffsetToOwner uint32 // =0
         OffsetToGroup uint32 // =0
         OffsetToSACL uint32 // =0
         OffsetToDACL uint32 // =0
    }
