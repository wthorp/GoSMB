// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Author: Alberto Solino (@agsolino)
//
// Description:
//   [MS-DHCPM] Interface implementation
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
from impacket import system_errors
from impacket.dcerpc.v5.dtypes import LPWSTR, ULONG, NULL, DWORD, BOOL, BYTE, LPDWORD, WORD
from impacket.dcerpc.v5.ndr import NDRCALL, NDRUniConformantArray, NDRPOINTER, NDRSTRUCT, NDRENUM, NDRUNION
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.enum import Enum
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_DHCPSRV = uuidtup_to_bin(('6BFFD098-A112-3610-9833-46C3F874532D', '1.0'))
MSRPC_UUID_DHCPSRV2 = uuidtup_to_bin(('5B821720-F63B-11D0-AAD2-00C04FC324DB', '1.0'))


 type DCERPCSessionError struct { // DCERPCException:
    ERROR_MESSAGES = {
        0x00004E2D: ("ERROR_DHCP_JET_ERROR", "An error occurred while accessing the DHCP server database."),
        0x00004E25: ("ERROR_DHCP_SUBNET_NOT_PRESENT", "The specified IPv4 subnet does not exist."),
        0x00004E54: ("ERROR_DHCP_SUBNET_EXISTS", "The IPv4 scope parameters are incorrect. Either the IPv4 scope already"
                                                 " exists, corresponding to the SubnetAddress and SubnetMask members of "
                                                 "the structure DHCP_SUBNET_INFO (section 2.2.1.2.8), or there is a "
                                                 "range overlap of IPv4 addresses between those associated with the "
                                                 "SubnetAddress and SubnetMask fields of the new IPv4 scope and the "
                                                 "subnet address and mask of an already existing IPv4 scope"),

    }
     func (self TYPE) __init__(error_string=nil, error_code=nil, packet=nil interface{}){
        DCERPCException.__init__(self, error_string, error_code, packet)

     func (self TYPE) __str__(){
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES {
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'DHCPM SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        elif key in self.ERROR_MESSAGES {
            error_msg_short = self.ERROR_MESSAGES[key][0]
            error_msg_verbose = self.ERROR_MESSAGES[key][1]
            return 'DHCPM SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        } else  {
            return 'DHCPM SessionError: unknown error code: 0x%x' % self.error_code

//###############################################################################
// CONSTANTS
//###############################################################################
DHCP_SRV_HANDLE = LPWSTR
DHCP_IP_ADDRESS = DWORD
DHCP_IP_MASK = DWORD
DHCP_OPTION_ID = DWORD

// DHCP enumeratiom flags
DHCP_FLAGS_OPTION_DEFAULT = 0x00000000
DHCP_FLAGS_OPTION_IS_VENDOR = 0x00000003

// Errors
ERROR_DHCP_JET_ERROR = 0x00004E2D
ERROR_DHCP_SUBNET_NOT_PRESENT = 0x00004E25
ERROR_DHCP_SUBNET_EXISTS = 0x00004E54
//###############################################################################
// STRUCTURES
//###############################################################################
// 2.2.1.1.3 DHCP_SEARCH_INFO_TYPE
 type DHCP_SEARCH_INFO_TYPE struct { // NDRENUM:
     type enumItems struct { // Enum:
        DhcpClientIpAddress       = 0
        DhcpClientHardwareAddress = 1
        DhcpClientName            = 2

// 2.2.1.1.11 QuarantineStatus
 type QuarantineStatus struct { // NDRENUM:
     type enumItems struct { // Enum:
        NOQUARANTINE        = 0
        RESTRICTEDACCESS    = 1
        DROPPACKET          = 2
        PROBATION           = 3
        EXEMPT              = 4
        DEFAULTQUARSETTING  = 5
        NOQUARINFO          = 6

// 2.2.1.2.7 DHCP_HOST_INFO
 type DHCP_HOST_INFO struct { // NDRSTRUCT: (
        ('IpAddress', DHCP_IP_ADDRESS),
        ('NetBiosName', LPWSTR),
        ('HostName', LPWSTR),
    }

// 2.2.1.2.9 DHCP_BINARY_DATA
 type BYTE_ARRAY struct { // NDRUniConformantArray:
    item = "c"

 type PBYTE_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', BYTE_ARRAY),
    }

 type DHCP_BINARY_DATA struct { // NDRSTRUCT: (
        ('DataLength', DWORD),
        ('Data_', PBYTE_ARRAY),
    }

DHCP_CLIENT_UID = DHCP_BINARY_DATA

// 2.2.1.2.11 DATE_TIME
 type DATE_TIME struct { // NDRSTRUCT: (
        ('dwLowDateTime', DWORD),
        ('dwHighDateTime', DWORD),
    }

// 2.2.1.2.19 DHCP_CLIENT_INFO_VQ
 type DHCP_CLIENT_INFO_VQ struct { // NDRSTRUCT: (
        ('ClientIpAddress', DHCP_IP_ADDRESS),
        ('SubnetMask', DHCP_IP_MASK),
        ('ClientHardwareAddress', DHCP_CLIENT_UID),
        ('ClientName', LPWSTR),
        ('ClientComment', LPWSTR),
        ('ClientLeaseExpires', DATE_TIME),
        ('OwnerHost', DHCP_HOST_INFO),
        ('bClientType', BYTE),
        ('AddressState', BYTE),
        ('Status', QuarantineStatus),
        ('ProbationEnds', DATE_TIME),
        ('QuarantineCapable', BOOL),
    }

 type DHCP_CLIENT_SEARCH_UNION struct { // NDRUNION:
    union = {
        DHCP_SEARCH_INFO_TYPE.DhcpClientIpAddress:       ('ClientIpAddress', DHCP_IP_ADDRESS),
        DHCP_SEARCH_INFO_TYPE.DhcpClientHardwareAddress: ('ClientHardwareAddress', DHCP_CLIENT_UID),
        DHCP_SEARCH_INFO_TYPE.DhcpClientName:            ('ClientName', LPWSTR),
    }

 type DHCP_SEARCH_INFO struct { // NDRSTRUCT: (
        ('SearchType', DHCP_SEARCH_INFO_TYPE),
        ('SearchInfo', DHCP_CLIENT_SEARCH_UNION),
    }

// 2.2.1.2.14 DHCP_CLIENT_INFO_V4
 type DHCP_CLIENT_INFO_V4 struct { // NDRSTRUCT: (
        ('ClientIpAddress', DHCP_IP_ADDRESS),
        ('SubnetMask', DHCP_IP_MASK),
        ('ClientHardwareAddress', DHCP_CLIENT_UID),
        ('ClientName', LPWSTR),
        ('ClientComment', LPWSTR),
        ('ClientLeaseExpires', DATE_TIME),
        ('OwnerHost', DHCP_HOST_INFO),
        ('bClientType', BYTE),
    }

 type DHCP_CLIENT_INFO_V5 struct { // NDRSTRUCT: (
        ('ClientIpAddress', DHCP_IP_ADDRESS),
        ('SubnetMask', DHCP_IP_MASK),
        ('ClientHardwareAddress', DHCP_CLIENT_UID),
        ('ClientName', LPWSTR),
        ('ClientComment', LPWSTR),
        ('ClientLeaseExpires', DATE_TIME),
        ('OwnerHost', DHCP_HOST_INFO),
        ('bClientType', BYTE),
        ('AddressState', BYTE),
    }

 type LPDHCP_CLIENT_INFO_V4 struct { // NDRPOINTER:
    referent = (
        ('Data', DHCP_CLIENT_INFO_V4),
    }

 type LPDHCP_CLIENT_INFO_V5 struct { // NDRPOINTER:
    referent = (
        ('Data', DHCP_CLIENT_INFO_V5),
    }

// 2.2.1.2.115 DHCP_CLIENT_INFO_PB
 type DHCP_CLIENT_INFO_PB struct { // NDRSTRUCT: (
        ('ClientIpAddress', DHCP_IP_ADDRESS),
        ('SubnetMask', DHCP_IP_MASK),
        ('ClientHardwareAddress', DHCP_CLIENT_UID),
        ('ClientName', LPWSTR),
        ('ClientComment', LPWSTR),
        ('ClientLeaseExpires', DATE_TIME),
        ('OwnerHost', DHCP_HOST_INFO),
        ('bClientType', BYTE),
        ('AddressState', BYTE),
        ('Status', QuarantineStatus),
        ('ProbationEnds', DATE_TIME),
        ('QuarantineCapable', BOOL),
        ('FilterStatus', DWORD),
        ('PolicyName', LPWSTR),
    }

 type LPDHCP_CLIENT_INFO_PB struct { // NDRPOINTER:
    referent = (
        ('Data', DHCP_CLIENT_INFO_PB),
    }

 type LPDHCP_CLIENT_INFO_VQ struct { // NDRPOINTER:
    referent = (
        ('Data', DHCP_CLIENT_INFO_VQ),
    }

 type DHCP_CLIENT_INFO_VQ_ARRAY struct { // NDRUniConformantArray:
    item = LPDHCP_CLIENT_INFO_VQ

 type LPDHCP_CLIENT_INFO_VQ_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', DHCP_CLIENT_INFO_VQ_ARRAY),
    }

 type DHCP_CLIENT_INFO_ARRAY_VQ struct { // NDRSTRUCT: (
        ('NumElements', DWORD),
        ('Clients', LPDHCP_CLIENT_INFO_VQ_ARRAY),
    }

 type LPDHCP_CLIENT_INFO_ARRAY_VQ struct { // NDRPOINTER:
    referent = (
        ('Data', DHCP_CLIENT_INFO_ARRAY_VQ),
    }

 type DHCP_CLIENT_INFO_V4_ARRAY struct { // NDRUniConformantArray:
    item = LPDHCP_CLIENT_INFO_V4

 type DHCP_CLIENT_INFO_V5_ARRAY struct { // NDRUniConformantArray:
    item = LPDHCP_CLIENT_INFO_V5

 type LPDHCP_CLIENT_INFO_V4_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', DHCP_CLIENT_INFO_V4_ARRAY),
    }

 type LPDHCP_CLIENT_INFO_V5_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', DHCP_CLIENT_INFO_V5_ARRAY),
    }

 type DHCP_CLIENT_INFO_ARRAY_V4 struct { // NDRSTRUCT: (
        ('NumElements', DWORD),
        ('Clients', LPDHCP_CLIENT_INFO_V4_ARRAY),
    }

 type DHCP_CLIENT_INFO_ARRAY_V5 struct { // NDRSTRUCT: (
        ('NumElements', DWORD),
        ('Clients', LPDHCP_CLIENT_INFO_V4_ARRAY),
    }

 type LPDHCP_CLIENT_INFO_ARRAY_V5 struct { // NDRPOINTER:
    referent = (
        ('Data', DHCP_CLIENT_INFO_ARRAY_V5),
    }

 type LPDHCP_CLIENT_INFO_ARRAY_V4 struct { // NDRPOINTER:
    referent = (
        ('Data', DHCP_CLIENT_INFO_ARRAY_V4),
    }

 type DHCP_IP_ADDRESS_ARRAY struct { // NDRUniConformantArray:
    item = DHCP_IP_ADDRESS

 type LPDHCP_IP_ADDRESS_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', DHCP_IP_ADDRESS_ARRAY),
    }

 type DHCP_IP_ARRAY struct { // NDRSTRUCT: (
        ('NumElements', DWORD),
        ('Elements', LPDHCP_IP_ADDRESS_ARRAY),
    }

 type DHCP_SUBNET_STATE struct { // NDRENUM:
     type enumItems struct { // Enum:
        DhcpSubnetEnabled           = 0
        DhcpSubnetDisabled          = 1
        DhcpSubnetEnabledSwitched   = 2
        DhcpSubnetDisabledSwitched  = 3
        DhcpSubnetInvalidState      = 4

 type DHCP_SUBNET_INFO struct { // NDRSTRUCT: (
        ('SubnetAddress', DHCP_IP_ADDRESS),
        ('SubnetMask', DHCP_IP_MASK),
        ('SubnetName', LPWSTR),
        ('SubnetComment', LPWSTR),
        ('PrimaryHost', DHCP_HOST_INFO),
        ('SubnetState', DHCP_SUBNET_STATE),
    }

 type LPDHCP_SUBNET_INFO struct { // NDRPOINTER:
    referent = (
        ('Data', DHCP_SUBNET_INFO),
    }

 type DHCP_OPTION_SCOPE_TYPE struct { // NDRENUM:
     type enumItems struct { // Enum:
        DhcpDefaultOptions  = 0
        DhcpGlobalOptions   = 1
        DhcpSubnetOptions   = 2
        DhcpReservedOptions = 3
        DhcpMScopeOptions   = 4

 type DHCP_RESERVED_SCOPE struct { // NDRSTRUCT: (
        ('ReservedIpAddress', DHCP_IP_ADDRESS),
        ('ReservedIpSubnetAddress', DHCP_IP_ADDRESS),
    }

 type DHCP_OPTION_SCOPE_UNION struct { // NDRUNION:
    union = {
        DHCP_OPTION_SCOPE_TYPE.DhcpDefaultOptions   : (),
        DHCP_OPTION_SCOPE_TYPE.DhcpGlobalOptions    : (),
        DHCP_OPTION_SCOPE_TYPE.DhcpSubnetOptions    : ('SubnetScopeInfo', DHCP_IP_ADDRESS),
        DHCP_OPTION_SCOPE_TYPE.DhcpReservedOptions  : ('ReservedScopeInfo', DHCP_RESERVED_SCOPE),
        DHCP_OPTION_SCOPE_TYPE.DhcpMScopeOptions    : ('MScopeInfo', LPWSTR),
    }

 type DHCP_OPTION_SCOPE_INFO struct { // NDRSTRUCT: (
        ('ScopeType', DHCP_OPTION_SCOPE_TYPE),
        ('ScopeInfo', DHCP_OPTION_SCOPE_UNION),
    }

 type LPDHCP_OPTION_SCOPE_INFO struct { // NDRPOINTER:
    referent = (
        ('Data', DHCP_OPTION_SCOPE_INFO)
    }

 type DWORD_DWORD struct { // NDRSTRUCT: (
        ('DWord1', DWORD),
        ('DWord2', DWORD),
    }

 type DHCP_BOOTP_IP_RANGE struct { // NDRSTRUCT: (
        ('StartAddress', DHCP_IP_ADDRESS),
        ('EndAddress', DHCP_IP_ADDRESS),
        ('BootpAllocated', ULONG),
        ('MaxBootpAllowed', DHCP_IP_ADDRESS),
        ('MaxBootpAllowed', ULONG ),
    }

 type DHCP_IP_RESERVATION_V4 struct { // NDRSTRUCT: (
        ('ReservedIpAddress', DHCP_IP_ADDRESS),
        ('ReservedForClient', DHCP_CLIENT_UID),
        ('bAllowedClientTypes', BYTE),
    }

 type DHCP_IP_RANGE struct { // NDRSTRUCT: (
        ('StartAddress', DHCP_IP_ADDRESS),
        ('EndAddress', DHCP_IP_ADDRESS),
    }

 type DHCP_IP_CLUSTER struct { // NDRSTRUCT: (
        ('ClusterAddress', DHCP_IP_ADDRESS),
        ('ClusterMask', DWORD),
    }

 type DHCP_SUBNET_ELEMENT_TYPE struct { // NDRENUM:
     type enumItems struct { // Enum:
        DhcpIpRanges           = 0
        DhcpSecondaryHosts     = 1
        DhcpReservedIps        = 2
        DhcpExcludedIpRanges   = 3
        DhcpIpUsedClusters     = 4
        DhcpIpRangesDhcpOnly   = 5
        DhcpIpRangesDhcpBootp  = 6
        DhcpIpRangesBootpOnly  = 7

 type DHCP_SUBNET_ELEMENT_UNION_V5 struct { // NDRUNION:
    union = {
        DHCP_SUBNET_ELEMENT_TYPE.DhcpIpRanges           : ('IpRange', DHCP_BOOTP_IP_RANGE),
        DHCP_SUBNET_ELEMENT_TYPE.DhcpSecondaryHosts     : ('SecondaryHost', DHCP_HOST_INFO),
        DHCP_SUBNET_ELEMENT_TYPE.DhcpReservedIps        : ('ReservedIp', DHCP_IP_RESERVATION_V4),
        DHCP_SUBNET_ELEMENT_TYPE.DhcpExcludedIpRanges   : ('ExcludeIpRange', DHCP_IP_RANGE),
        DHCP_SUBNET_ELEMENT_TYPE.DhcpIpUsedClusters     : ('IpUsedCluster', DHCP_IP_CLUSTER),
    }

 type DHCP_SUBNET_ELEMENT_DATA_V5 struct { // NDRSTRUCT: (
        ('ElementType', DHCP_SUBNET_ELEMENT_TYPE),
        ('Element', DHCP_SUBNET_ELEMENT_UNION_V5),
    }

 type LPDHCP_SUBNET_ELEMENT_DATA_V5 struct { // NDRUniConformantArray:
    item = DHCP_SUBNET_ELEMENT_DATA_V5

 type DHCP_SUBNET_ELEMENT_INFO_ARRAY_V5 struct { // NDRSTRUCT: (
        ('NumElements', DWORD),
        ('Elements', LPDHCP_SUBNET_ELEMENT_DATA_V5),
    }

 type LPDHCP_SUBNET_ELEMENT_INFO_ARRAY_V5 struct { // NDRPOINTER:
    referent = (
        ('Data', DHCP_SUBNET_ELEMENT_INFO_ARRAY_V5)
    }

 type DHCP_OPTION_DATA_TYPE struct { // NDRENUM:
     type enumItems struct { // Enum:
        DhcpByteOption              = 0
        DhcpWordOption              = 1
        DhcpDWordOption             = 2
        DhcpDWordDWordOption        = 3
        DhcpIpAddressOption         = 4
        DhcpStringDataOption        = 5
        DhcpBinaryDataOption        = 6
        DhcpEncapsulatedDataOption  = 7
        DhcpIpv6AddressOption       = 8

 type DHCP_OPTION_ELEMENT_UNION struct { // NDRUNION:
    commonHdr = (
        ('tag', DHCP_OPTION_DATA_TYPE),
    }
    union = {
        DHCP_OPTION_DATA_TYPE.DhcpByteOption            : ('ByteOption', BYTE),
        DHCP_OPTION_DATA_TYPE.DhcpWordOption            : ('WordOption', WORD),
        DHCP_OPTION_DATA_TYPE.DhcpDWordOption           : ('DWordOption', DWORD),
        DHCP_OPTION_DATA_TYPE.DhcpDWordDWordOption      : ('DWordDWordOption', DWORD_DWORD),
        DHCP_OPTION_DATA_TYPE.DhcpIpAddressOption       : ('IpAddressOption', DHCP_IP_ADDRESS),
        DHCP_OPTION_DATA_TYPE.DhcpStringDataOption      : ('StringDataOption', LPWSTR),
        DHCP_OPTION_DATA_TYPE.DhcpBinaryDataOption      : ('BinaryDataOption', DHCP_BINARY_DATA),
        DHCP_OPTION_DATA_TYPE.DhcpEncapsulatedDataOption: ('EncapsulatedDataOption', DHCP_BINARY_DATA),
        DHCP_OPTION_DATA_TYPE.DhcpIpv6AddressOption     : ('Ipv6AddressDataOption', LPWSTR),
    }

 type DHCP_OPTION_DATA_ELEMENT struct { // NDRSTRUCT: (
        ('OptionType', DHCP_OPTION_DATA_TYPE),
        ('Element', DHCP_OPTION_ELEMENT_UNION),
    }

 type DHCP_OPTION_DATA_ELEMENT_ARRAY2 struct { // NDRUniConformantArray:
    item = DHCP_OPTION_DATA_ELEMENT

 type LPDHCP_OPTION_DATA_ELEMENT struct { // NDRPOINTER:
    referent = (
        ('Data', DHCP_OPTION_DATA_ELEMENT_ARRAY2),
    }

 type DHCP_OPTION_DATA struct { // NDRSTRUCT: (
        ('NumElements', DWORD),
        ('Elements', LPDHCP_OPTION_DATA_ELEMENT),
    }

 type DHCP_OPTION_VALUE struct { // NDRSTRUCT: (
        ('OptionID', DHCP_OPTION_ID),
        ('Value', DHCP_OPTION_DATA),
    }

 type PDHCP_OPTION_VALUE struct { // NDRPOINTER:
    referent = (
        ('Data', DHCP_OPTION_VALUE),
    }

 type DHCP_OPTION_VALUE_ARRAY2 struct { // NDRUniConformantArray:
    item = DHCP_OPTION_VALUE

 type LPDHCP_OPTION_VALUE struct { // NDRPOINTER:
    referent = (
        ('Data', DHCP_OPTION_VALUE_ARRAY2),
    }

 type DHCP_OPTION_VALUE_ARRAY struct { // NDRSTRUCT: (
        ('NumElements', DWORD),
        ('Values', LPDHCP_OPTION_VALUE),
    }

 type LPDHCP_OPTION_VALUE_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', DHCP_OPTION_VALUE_ARRAY),
    }

 type DHCP_ALL_OPTION_VALUES struct { // NDRSTRUCT: (
        ('ClassName', LPWSTR),
        ('VendorName', LPWSTR),
        ('IsVendor', BOOL),
        ('OptionsArray', LPDHCP_OPTION_VALUE_ARRAY),
    }

 type OPTION_VALUES_ARRAY struct { // NDRUniConformantArray:
    item = DHCP_ALL_OPTION_VALUES

 type LPOPTION_VALUES_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', OPTION_VALUES_ARRAY),
    }

 type DHCP_ALL_OPTIONS_VALUES struct { // NDRSTRUCT: (
        ('Flags', DWORD),
        ('NumElements', DWORD),
        ('Options', LPOPTION_VALUES_ARRAY),
    }

 type LPDHCP_ALL_OPTION_VALUES struct { // NDRPOINTER:
    referent = (
        ('Data', DHCP_ALL_OPTIONS_VALUES),
    }

//###############################################################################
// RPC CALLS
//###############################################################################
// Interface dhcpsrv
 type DhcpGetSubnetInfo struct { // NDRCALL:
    opnum = 2 (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('SubnetAddress', DHCP_IP_ADDRESS),
    }

 type DhcpGetSubnetInfoResponse struct { // NDRCALL: (
        ('SubnetInfo', LPDHCP_SUBNET_INFO),
        ('ErrorCode', ULONG),
    }

 type DhcpEnumSubnets struct { // NDRCALL:
    opnum = 3 (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('ResumeHandle', LPDWORD),
        ('PreferredMaximum', DWORD),
    }

 type DhcpEnumSubnetsResponse struct { // NDRCALL: (
        ('ResumeHandle', LPDWORD),
        ('EnumInfo', DHCP_IP_ARRAY),
        ('EnumRead', DWORD),
        ('EnumTotal', DWORD),
        ('ErrorCode', ULONG),
    }

 type DhcpGetOptionValue struct { // NDRCALL:
    opnum = 13 (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('OptionID', DHCP_OPTION_ID),
        ('ScopeInfo', DHCP_OPTION_SCOPE_INFO),
    }

 type DhcpGetOptionValueResponse struct { // NDRCALL: (
        ('OptionValue', PDHCP_OPTION_VALUE),
        ('ErrorCode', ULONG),
    }

 type DhcpEnumOptionValues struct { // NDRCALL:
    opnum = 14 (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('ScopeInfo', DHCP_OPTION_SCOPE_INFO),
        ('ResumeHandle', LPDWORD),
        ('PreferredMaximum', DWORD),
    }

 type DhcpEnumOptionValuesResponse struct { // NDRCALL: (
        ('ResumeHandle', DWORD),
        ('OptionValues', LPDHCP_OPTION_VALUE_ARRAY),
        ('OptionsRead', DWORD),
        ('OptionsTotal', DWORD),
        ('ErrorCode', ULONG),
    }

 type DhcpGetClientInfoV4 struct { // NDRCALL:
    opnum = 34 (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('SearchInfo', DHCP_SEARCH_INFO),
    }

 type DhcpGetClientInfoV4Response struct { // NDRCALL: (
        ('ClientInfo', LPDHCP_CLIENT_INFO_V4),
        ('ErrorCode', ULONG),
    }

 type DhcpEnumSubnetClientsV4 struct { // NDRCALL:
    opnum = 35 (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('SubnetAddress', DHCP_IP_ADDRESS),
        ('ResumeHandle', DWORD),
        ('PreferredMaximum', DWORD),
    }

 type DhcpEnumSubnetClientsV4Response struct { // NDRCALL: (
        ('ResumeHandle', LPDWORD),
        ('ClientInfo', LPDHCP_CLIENT_INFO_ARRAY_V4),
        ('ClientsRead', DWORD),
        ('ClientsTotal', DWORD),
        ('ErrorCode', ULONG),
    }

// Interface dhcpsrv2

 type DhcpEnumSubnetClientsV5 struct { // NDRCALL:
    opnum = 0 (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('SubnetAddress', DHCP_IP_ADDRESS),
        ('ResumeHandle', LPDWORD),
        ('PreferredMaximum', DWORD),
    }

 type DhcpEnumSubnetClientsV5Response struct { // NDRCALL: (
        ('ResumeHandle', DWORD),
        ('ClientsInfo', LPDHCP_CLIENT_INFO_ARRAY_V5),
        ('ClientsRead', DWORD),
        ('ClientsTotal', DWORD),
    }

 type DhcpGetOptionValueV5 struct { // NDRCALL:
    opnum = 21 (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('Flags', DWORD),
        ('OptionID', DHCP_OPTION_ID),
        ('ClassName', LPWSTR),
        ('VendorName', LPWSTR),
        ('ScopeInfo', DHCP_OPTION_SCOPE_INFO),
    }

 type DhcpGetOptionValueV5Response struct { // NDRCALL: (
        ('OptionValue', PDHCP_OPTION_VALUE),
        ('ErrorCode', ULONG),
    }

 type DhcpEnumOptionValuesV5 struct { // NDRCALL:
    opnum = 22 (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('Flags', DWORD),
        ('ClassName', LPWSTR),
        ('VendorName', LPWSTR),
        ('ScopeInfo', DHCP_OPTION_SCOPE_INFO),
        ('ResumeHandle', LPDWORD),
        ('PreferredMaximum', DWORD),
    }

 type DhcpEnumOptionValuesV5Response struct { // NDRCALL: (
        ('ResumeHandle', DWORD),
        ('OptionValues', LPDHCP_OPTION_VALUE_ARRAY),
        ('OptionsRead', DWORD),
        ('OptionsTotal', DWORD),
        ('ErrorCode', ULONG),
    }

 type DhcpGetAllOptionValues struct { // NDRCALL:
    opnum = 30 (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('Flags', DWORD),
        ('ScopeInfo', DHCP_OPTION_SCOPE_INFO),
    }

 type DhcpGetAllOptionValuesResponse struct { // NDRCALL: (
        ('Values', LPDHCP_ALL_OPTION_VALUES),
        ('ErrorCode', ULONG),
    }

 type DhcpEnumSubnetElementsV5 struct { // NDRCALL:
    opnum = 38 (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('SubnetAddress', DHCP_IP_ADDRESS),
        ('EnumElementType', DHCP_SUBNET_ELEMENT_TYPE),
        ('ResumeHandle', LPDWORD),
        ('PreferredMaximum', DWORD),
    }

 type DhcpEnumSubnetElementsV5Response struct { // NDRCALL: (
        ('ResumeHandle', DWORD),
        ('EnumElementInfo', LPDHCP_SUBNET_ELEMENT_INFO_ARRAY_V5),
        ('ElementsRead', DWORD),
        ('ElementsTotal', DWORD),
        ('ErrorCode', ULONG),
    }

 type DhcpEnumSubnetClientsVQ struct { // NDRCALL:
    opnum = 47 (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('SubnetAddress', DHCP_IP_ADDRESS),
        ('ResumeHandle', LPDWORD),
        ('PreferredMaximum', DWORD),
    }

 type DhcpEnumSubnetClientsVQResponse struct { // NDRCALL: (
        ('ResumeHandle', LPDWORD),
        ('ClientInfo', LPDHCP_CLIENT_INFO_ARRAY_VQ),
        ('ClientsRead', DWORD),
        ('ClientsTotal', DWORD),
        ('ErrorCode', ULONG),
    }

 type DhcpV4GetClientInfo struct { // NDRCALL:
    opnum = 123 (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('SearchInfo', DHCP_SEARCH_INFO),
    }

 type DhcpV4GetClientInfoResponse struct { // NDRCALL: (
        ('ClientInfo', LPDHCP_CLIENT_INFO_PB),
        ('ErrorCode', ULONG),
    }

//###############################################################################
// OPNUMs and their corresponding structures
//###############################################################################
OPNUMS = {
    0: (DhcpEnumSubnetClientsV5, DhcpEnumSubnetClientsV5Response),
    2: (DhcpGetSubnetInfo, DhcpGetSubnetInfoResponse),
    3: (DhcpEnumSubnets, DhcpEnumSubnetsResponse),
    13: (DhcpGetOptionValue, DhcpGetOptionValueResponse),
    14: (DhcpEnumOptionValues, DhcpEnumOptionValuesResponse),
    21: (DhcpGetOptionValueV5, DhcpGetOptionValueV5Response),
    22: (DhcpEnumOptionValuesV5, DhcpEnumOptionValuesV5Response),
    30: (DhcpGetAllOptionValues, DhcpGetAllOptionValuesResponse),
    34: (DhcpGetClientInfoV4, DhcpGetClientInfoV4Response),
    35: (DhcpEnumSubnetClientsV4, DhcpEnumSubnetClientsV4Response),
    38: (DhcpEnumSubnetElementsV5, DhcpEnumSubnetElementsV5Response),
    47: (DhcpEnumSubnetClientsVQ, DhcpEnumSubnetClientsVQResponse),
    123: (DhcpV4GetClientInfo, DhcpV4GetClientInfoResponse),
}


//###############################################################################
// HELPER FUNCTIONS
//###############################################################################
 func hDhcpGetClientInfoV4(dce, searchType, searchValue interface{}){
    request = DhcpGetClientInfoV4()

    request["ServerIpAddress"] = NULL
    request["SearchInfo"]["SearchType"] = searchType
    request["SearchInfo"]["SearchInfo"]["tag"] = searchType
    if searchType == DHCP_SEARCH_INFO_TYPE.DhcpClientIpAddress {
        request["SearchInfo"]["SearchInfo"]["ClientIpAddress"] = searchValue
    elif searchType == DHCP_SEARCH_INFO_TYPE.DhcpClientHardwareAddress {
        // This should be a DHCP_BINARY_DATA
        request["SearchInfo"]["SearchInfo"]["ClientHardwareAddress"] = searchValue
    } else  {
        request["SearchInfo"]["SearchInfo"]["ClientName"] = searchValue

    return dce.request(request)

 func hDhcpGetSubnetInfo(dce, subnetaddress interface{}){
    request = DhcpGetSubnetInfo()

    request["ServerIpAddress"] = NULL
    request["SubnetAddress"] = subnetaddress
    resp = dce.request(request)

    return resp

 func hDhcpGetOptionValue(dce, optionID, scopetype=DHCP_OPTION_SCOPE_TYPE.DhcpDefaultOptions, options=NULL interface{}){
    request = DhcpGetOptionValue()

    request["ServerIpAddress"] = NULL
    request["OptionID"] = optionID
    request["ScopeInfo"]["ScopeType"] = scopetype
    if scopetype != DHCP_OPTION_SCOPE_TYPE.DhcpDefaultOptions and scopetype != DHCP_OPTION_SCOPE_TYPE.DhcpGlobalOptions {
        request["ScopeInfo"]["ScopeInfo"]["tag"] = scopetype
    if scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpSubnetOptions {
        request["ScopeInfo"]["ScopeInfo"]["SubnetScopeInfo"] = options
    elif scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpReservedOptions {
        request["ScopeInfo"]["ScopeInfo"]["ReservedScopeInfo"] = options
    elif scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpMScopeOptions {
        request["ScopeInfo"]["ScopeInfo"]["MScopeInfo"] = options

    status = system_errors.ERROR_MORE_DATA
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCException as e:
            if str(e).find("ERROR_NO_MORE_ITEMS") < 0 {
                raise
            resp = e.get_packet()
        return resp

def hDhcpEnumOptionValues(dce, scopetype=DHCP_OPTION_SCOPE_TYPE.DhcpDefaultOptions, options=NULL,
                          preferredMaximum=0xffffffff):
    request = DhcpEnumOptionValues()

    request["ServerIpAddress"] = NULL
    request["ScopeInfo"]["ScopeType"] = scopetype
    if scopetype != DHCP_OPTION_SCOPE_TYPE.DhcpDefaultOptions and scopetype != DHCP_OPTION_SCOPE_TYPE.DhcpGlobalOptions {
        request["ScopeInfo"]["ScopeInfo"]["tag"] = scopetype
    if scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpSubnetOptions {
        request["ScopeInfo"]["ScopeInfo"]["SubnetScopeInfo"] = options
    elif scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpReservedOptions {
        request["ScopeInfo"]["ScopeInfo"]["ReservedScopeInfo"] = options
    elif scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpMScopeOptions {
        request["ScopeInfo"]["ScopeInfo"]["MScopeInfo"] = options
    request["ResumeHandle"] = NULL
    request["PreferredMaximum"] = preferredMaximum

    status = system_errors.ERROR_MORE_DATA
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCException as e:
            if str(e).find("ERROR_NO_MORE_ITEMS") < 0 {
                raise
            resp = e.get_packet()
        return resp

def hDhcpEnumOptionValuesV5(dce, flags=DHCP_FLAGS_OPTION_DEFAULT, classname=NULL, vendorname=NULL,
                            scopetype=DHCP_OPTION_SCOPE_TYPE.DhcpDefaultOptions, options=NULL,
                            preferredMaximum=0xffffffff):
    request = DhcpEnumOptionValuesV5()

    request["ServerIpAddress"] = NULL
    request["Flags"] = flags
    request["ClassName"] = classname
    request["VendorName"] = vendorname
    request["ScopeInfo"]["ScopeType"] = scopetype
    request["ScopeInfo"]["ScopeInfo"]["tag"] = scopetype
    if scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpSubnetOptions {
        request["ScopeInfo"]["ScopeInfo"]["SubnetScopeInfo"] = options
    elif scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpReservedOptions {
        request["ScopeInfo"]["ScopeInfo"]["ReservedScopeInfo"] = options
    elif scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpMScopeOptions {
        request["ScopeInfo"]["ScopeInfo"]["MScopeInfo"] = options
    request["ResumeHandle"] = NULL
    request["PreferredMaximum"] = preferredMaximum

    status = system_errors.ERROR_MORE_DATA
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCException as e:
            if str(e).find("ERROR_NO_MORE_ITEMS") < 0 {
                raise
            resp = e.get_packet()
        return resp

def hDhcpGetOptionValueV5(dce, option_id, flags=DHCP_FLAGS_OPTION_DEFAULT, classname=NULL, vendorname=NULL,
                            scopetype=DHCP_OPTION_SCOPE_TYPE.DhcpDefaultOptions, options=NULL):
    request = DhcpGetOptionValueV5()

    request["ServerIpAddress"] = NULL
    request["Flags"] = flags
    request["OptionID"] = option_id
    request["ClassName"] = classname
    request["VendorName"] = vendorname
    request["ScopeInfo"]["ScopeType"] = scopetype
    request["ScopeInfo"]["ScopeInfo"]["tag"] = scopetype
    if scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpSubnetOptions {
        request["ScopeInfo"]["ScopeInfo"]["SubnetScopeInfo"] = options
    elif scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpReservedOptions {
        request["ScopeInfo"]["ScopeInfo"]["ReservedScopeInfo"] = options
    elif scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpMScopeOptions {
        request["ScopeInfo"]["ScopeInfo"]["MScopeInfo"] = options

    status = system_errors.ERROR_MORE_DATA
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCException as e:
            if str(e).find("ERROR_NO_MORE_ITEMS") < 0 {
                raise
            resp = e.get_packet()
        return resp

 func hDhcpGetAllOptionValues(dce, scopetype=DHCP_OPTION_SCOPE_TYPE.DhcpDefaultOptions, options=NULL interface{}){
    request = DhcpGetAllOptionValues()

    request["ServerIpAddress"] = NULL
    request["Flags"] = NULL
    request["ScopeInfo"]["ScopeType"] = scopetype
    request["ScopeInfo"]["ScopeInfo"]["tag"] = scopetype
    if scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpSubnetOptions {
        request["ScopeInfo"]["ScopeInfo"]["SubnetScopeInfo"] = options
    elif scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpReservedOptions {
        request["ScopeInfo"]["ScopeInfo"]["ReservedScopeInfo"] = options
    elif scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpMScopeOptions {
        request["ScopeInfo"]["ScopeInfo"]["MScopeInfo"] = options

    status = system_errors.ERROR_MORE_DATA
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCException as e:
            if str(e).find("ERROR_NO_MORE_ITEMS") < 0 {
                raise
            resp = e.get_packet()
        return resp

 func hDhcpEnumSubnets(dce, preferredMaximum=0xffffffff interface{}){
    request = DhcpEnumSubnets()

    request["ServerIpAddress"] = NULL
    request["ResumeHandle"] = NULL
    request["PreferredMaximum"] = preferredMaximum
    status = system_errors.ERROR_MORE_DATA
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCException as e:
            if str(e).find("STATUS_MORE_ENTRIES") < 0 {
                raise
            resp = e.get_packet()
        return resp

 func hDhcpEnumSubnetClientsVQ(dce, preferredMaximum=0xffffffff interface{}){
    request = DhcpEnumSubnetClientsVQ()

    request["ServerIpAddress"] = NULL
    request["SubnetAddress"] = NULL
    request["ResumeHandle"] = NULL
    request["PreferredMaximum"] = preferredMaximum
    status = system_errors.ERROR_MORE_DATA
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCException as e:
            if str(e).find("STATUS_MORE_ENTRIES") < 0 {
                raise
            resp = e.get_packet()
        return resp

 func hDhcpEnumSubnetClientsV4(dce, preferredMaximum=0xffffffff interface{}){
    request = DhcpEnumSubnetClientsV4()

    request["ServerIpAddress"] = NULL
    request["SubnetAddress"] = NULL
    request["ResumeHandle"] = NULL
    request["PreferredMaximum"] = preferredMaximum
    status = system_errors.ERROR_MORE_DATA
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCException as e:
            if str(e).find("STATUS_MORE_ENTRIES") < 0 {
                raise
            resp = e.get_packet()
        return resp

 func hDhcpEnumSubnetClientsV5(dce, subnetAddress=0, preferredMaximum=0xffffffff interface{}){
    request = DhcpEnumSubnetClientsV5()

    request["ServerIpAddress"] = NULL
    request["SubnetAddress"] = subnetAddress
    request["ResumeHandle"] = NULL
    request["PreferredMaximum"] = preferredMaximum
    status = system_errors.ERROR_MORE_DATA
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCSessionError as e:
            if str(e).find("STATUS_MORE_ENTRIES") < 0 {
                raise
            resp = e.get_packet()
        return resp

 func hDhcpEnumSubnetElementsV5(dce, subnet_address, element_type=DHCP_SUBNET_ELEMENT_TYPE.DhcpIpRanges, preferredMaximum=0xffffffff interface{}){
    request = DhcpEnumSubnetElementsV5()

    request["ServerIpAddress"] = NULL
    request["SubnetAddress"] = subnet_address
    request["EnumElementType"] = element_type
    request["ResumeHandle"] = NULL
    request["PreferredMaximum"] = preferredMaximum

    status = system_errors.ERROR_MORE_DATA
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCException as e:
            if str(e).find("ERROR_NO_MORE_ITEMS") < 0 {
                raise
            resp = e.get_packet()
        return resp
