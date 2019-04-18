// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Author: Alberto Solino (@agsolino)
//
// Description:
//   [MS-NRPC] Interface implementation
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
from struct import pack
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRENUM, NDRUNION, NDRPOINTER, NDRUniConformantArray, \
    NDRUniFixedArray, NDRUniConformantVaryingArray
from impacket.dcerpc.v5.dtypes import WSTR, LPWSTR, DWORD, ULONG, USHORT, PGUID, NTSTATUS, NULL, LONG, UCHAR, PRPC_SID, \
    GUID, RPC_UNICODE_STRING, SECURITY_INFORMATION, LPULONG
from impacket import system_errors, nt_errors
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.enum import Enum
from impacket.dcerpc.v5.samr import OLD_LARGE_INTEGER
from impacket.dcerpc.v5.lsad import PLSA_FOREST_TRUST_INFORMATION
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.structure import Structure
from impacket import ntlm, crypto, LOG
import hmac
import hashlib
try:
    from Cryptodome.Cipher import DES, AES, ARC4
except ImportError:
    LOG.critical("Warning: You don't have any crypto installed. You need pycryptodomex")
    LOG.critical("See https://pypi.org/project/pycryptodomex/")

MSRPC_UUID_NRPC = uuidtup_to_bin(('12345678-1234-ABCD-EF00-01234567CFFB', '1.0'))

 type DCERPCSessionError struct { // DCERPCException:
     func (self TYPE) __init__(error_string=nil, error_code=nil, packet=nil interface{}){
        DCERPCException.__init__(self, error_string, error_code, packet)

     func __str__( self  interface{}){
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES {
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1] 
            return 'NRPC SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        elif key in nt_errors.ERROR_MESSAGES {
            error_msg_short = nt_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = nt_errors.ERROR_MESSAGES[key][1] 
            return 'NRPC SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        } else  {
            return 'NRPC SessionError: unknown error code: 0x%x' % (self.error_code)

//###############################################################################
// CONSTANTS
//###############################################################################
// 2.2.1.2.5 NL_DNS_NAME_INFO
// Type
NlDnsLdapAtSite       = 22
NlDnsGcAtSite         = 25
NlDnsDsaCname         = 28
NlDnsKdcAtSite        = 30
NlDnsDcAtSite         = 32
NlDnsRfc1510KdcAtSite = 34
NlDnsGenericGcAtSite  = 36

// DnsDomainInfoType
NlDnsDomainName      = 1
NlDnsDomainNameAlias = 2
NlDnsForestName      = 3
NlDnsForestNameAlias = 4
NlDnsNdncDomainName  = 5
NlDnsRecordName      = 6

// 2.2.1.3.15 NL_OSVERSIONINFO_V1
// wSuiteMask
VER_SUITE_BACKOFFICE               = 0x00000004
VER_SUITE_BLADE                    = 0x00000400
VER_SUITE_COMPUTE_SERVER           = 0x00004000
VER_SUITE_DATACENTER               = 0x00000080
VER_SUITE_ENTERPRISE               = 0x00000002
VER_SUITE_EMBEDDEDNT               = 0x00000040
VER_SUITE_PERSONAL                 = 0x00000200
VER_SUITE_SINGLEUSERTS             = 0x00000100
VER_SUITE_SMALLBUSINESS            = 0x00000001
VER_SUITE_SMALLBUSINESS_RESTRICTED = 0x00000020
VER_SUITE_STORAGE_SERVER           = 0x00002000
VER_SUITE_TERMINAL                 = 0x00000010

// wProductType
VER_NT_DOMAIN_CONTROLLER = 0x00000002
VER_NT_SERVER            = 0x00000003
VER_NT_WORKSTATION       = 0x00000001

// 2.2.1.4.18 NETLOGON Specific Access Masks
NETLOGON_UAS_LOGON_ACCESS  = 0x0001
NETLOGON_UAS_LOGOFF_ACCESS = 0x0002
NETLOGON_CONTROL_ACCESS    = 0x0004
NETLOGON_QUERY_ACCESS      = 0x0008
NETLOGON_SERVICE_ACCESS    = 0x0010
NETLOGON_FTINFO_ACCESS     = 0x0020
NETLOGON_WKSTA_RPC_ACCESS  = 0x0040

// 3.5.4.9.1 NetrLogonControl2Ex (Opnum 18)
// FunctionCode
NETLOGON_CONTROL_QUERY             = 0x00000001
NETLOGON_CONTROL_REPLICATE         = 0x00000002
NETLOGON_CONTROL_SYNCHRONIZE       = 0x00000003
NETLOGON_CONTROL_PDC_REPLICATE     = 0x00000004
NETLOGON_CONTROL_REDISCOVER        = 0x00000005
NETLOGON_CONTROL_TC_QUERY          = 0x00000006
NETLOGON_CONTROL_TRANSPORT_NOTIFY  = 0x00000007
NETLOGON_CONTROL_FIND_USER         = 0x00000008
NETLOGON_CONTROL_CHANGE_PASSWORD   = 0x00000009
NETLOGON_CONTROL_TC_VERIFY         = 0x0000000A
NETLOGON_CONTROL_FORCE_DNS_REG     = 0x0000000B
NETLOGON_CONTROL_QUERY_DNS_REG     = 0x0000000C
NETLOGON_CONTROL_BACKUP_CHANGE_LOG = 0x0000FFFC
NETLOGON_CONTROL_TRUNCATE_LOG      = 0x0000FFFD
NETLOGON_CONTROL_SET_DBFLAG        = 0x0000FFFE
NETLOGON_CONTROL_BREAKPOINT        = 0x0000FFFF

//###############################################################################
// STRUCTURES
//###############################################################################
// 3.5.4.1 RPC Binding Handles for Netlogon Methods
LOGONSRV_HANDLE = WSTR
PLOGONSRV_HANDLE = LPWSTR

// 2.2.1.1.1 CYPHER_BLOCK
 type CYPHER_BLOCK struct { // NDRSTRUCT: (
         Data [8]byte // =b""
    }
     func (self TYPE) getAlignment(){
        return 1

NET_API_STATUS = DWORD

// 2.2.1.1.2 STRING
from impacket.dcerpc.v5.lsad import STRING

// 2.2.1.1.3 LM_OWF_PASSWORD
 type CYPHER_BLOCK_ARRAY struct { // NDRUniFixedArray:
     func (self TYPE) getDataLen(data interface{}){
        return len(CYPHER_BLOCK())*2

 type LM_OWF_PASSWORD struct { // NDRSTRUCT: (
        ('Data', CYPHER_BLOCK_ARRAY),
    }

// 2.2.1.1.4 NT_OWF_PASSWORD
NT_OWF_PASSWORD = LM_OWF_PASSWORD
ENCRYPTED_NT_OWF_PASSWORD = NT_OWF_PASSWORD

// 2.2.1.3.4 NETLOGON_CREDENTIAL
 type UCHAR_FIXED_ARRAY struct { // NDRUniFixedArray:
    align = 1
     func (self TYPE) getDataLen(data interface{}){
        return len(CYPHER_BLOCK())

 type NETLOGON_CREDENTIAL struct { // NDRSTRUCT: (
        ('Data',UCHAR_FIXED_ARRAY),
    }
     func (self TYPE) getAlignment(){
        return 1

// 2.2.1.1.5 NETLOGON_AUTHENTICATOR
 type NETLOGON_AUTHENTICATOR struct { // NDRSTRUCT: (
        ('Credential', NETLOGON_CREDENTIAL),
        ('Timestamp', DWORD),
    }

 type PNETLOGON_AUTHENTICATOR struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_AUTHENTICATOR),
    }

// 2.2.1.2.1 DOMAIN_CONTROLLER_INFOW
 type DOMAIN_CONTROLLER_INFOW struct { // NDRSTRUCT: (
        ('DomainControllerName', LPWSTR),
        ('DomainControllerAddress', LPWSTR),
        ('DomainControllerAddressType', ULONG),
        ('DomainGuid', GUID),
        ('DomainName', LPWSTR),
        ('DnsForestName', LPWSTR),
        ('Flags', ULONG),
        ('DcSiteName', LPWSTR),
        ('ClientSiteName', LPWSTR),
    }

 type PDOMAIN_CONTROLLER_INFOW struct { // NDRPOINTER:
    referent = (
        ('Data', DOMAIN_CONTROLLER_INFOW),
    }

// 2.2.1.2.2 NL_SITE_NAME_ARRAY
 type RPC_UNICODE_STRING_ARRAY struct { // NDRUniConformantArray:
    item = RPC_UNICODE_STRING

 type PRPC_UNICODE_STRING_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', RPC_UNICODE_STRING_ARRAY),
    }

 type NL_SITE_NAME_ARRAY struct { // NDRSTRUCT: (
        ('EntryCount', ULONG),
        ('SiteNames', PRPC_UNICODE_STRING_ARRAY),
    }

 type PNL_SITE_NAME_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', NL_SITE_NAME_ARRAY),
    }

// 2.2.1.2.3 NL_SITE_NAME_EX_ARRAY
 type RPC_UNICODE_STRING_ARRAY struct { // NDRUniConformantArray:
    item = RPC_UNICODE_STRING

 type NL_SITE_NAME_EX_ARRAY struct { // NDRSTRUCT: (
        ('EntryCount', ULONG),
        ('SiteNames', PRPC_UNICODE_STRING_ARRAY),
        ('SubnetNames', PRPC_UNICODE_STRING_ARRAY),
    }

 type PNL_SITE_NAME_EX_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', NL_SITE_NAME_EX_ARRAY),
    }

// 2.2.1.2.4 NL_SOCKET_ADDRESS
// 2.2.1.2.4.1 IPv4 Address Structure
 type IPv4Address struct { // Structure: (
         AddressFamily uint16 // =0
         Port uint16 // =0
         Address uint32 // =0
         Padding uint32 // =0
    }

 type UCHAR_ARRAY struct { // NDRUniConformantArray:
    item = "c"

 type PUCHAR_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', UCHAR_ARRAY),
    }

 type NL_SOCKET_ADDRESS struct { // NDRSTRUCT: (
        ('lpSockaddr', PUCHAR_ARRAY),
        ('iSockaddrLength', ULONG),
    }

 type NL_SOCKET_ADDRESS_ARRAY struct { // NDRUniConformantArray:
    item = NL_SOCKET_ADDRESS

// 2.2.1.2.5 NL_DNS_NAME_INFO
 type NL_DNS_NAME_INFO struct { // NDRSTRUCT: (
        ('Type', ULONG),
        ('DnsDomainInfoType', WSTR),
        ('Priority', ULONG),
        ('Weight', ULONG),
        ('Port', ULONG),
        ('Register', UCHAR),
        ('Status', ULONG),
    }

// 2.2.1.2.6 NL_DNS_NAME_INFO_ARRAY
 type NL_DNS_NAME_INFO_ARRAY struct { // NDRUniConformantArray:
    item = NL_DNS_NAME_INFO

 type PNL_DNS_NAME_INFO_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', NL_DNS_NAME_INFO_ARRAY),
    }

 type NL_DNS_NAME_INFO_ARRAY struct { // NDRSTRUCT: (
        ('EntryCount', ULONG),
        ('DnsNamesInfo', PNL_DNS_NAME_INFO_ARRAY),
    }

// 2.2.1.3 Secure Channel Establishment and Maintenance Structures
// ToDo

// 2.2.1.3.5 NETLOGON_LSA_POLICY_INFO
 type NETLOGON_LSA_POLICY_INFO struct { // NDRSTRUCT: (
        ('LsaPolicySize', ULONG),
        ('LsaPolicy', PUCHAR_ARRAY),
    }

 type PNETLOGON_LSA_POLICY_INFO struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_LSA_POLICY_INFO),
    }

// 2.2.1.3.6 NETLOGON_WORKSTATION_INFO
 type NETLOGON_WORKSTATION_INFO struct { // NDRSTRUCT: (
        ('LsaPolicy', NETLOGON_LSA_POLICY_INFO),
        ('DnsHostName', LPWSTR),
        ('SiteName', LPWSTR),
        ('Dummy1', LPWSTR),
        ('Dummy2', LPWSTR),
        ('Dummy3', LPWSTR),
        ('Dummy4', LPWSTR),
        ('OsVersion', RPC_UNICODE_STRING),
        ('OsName', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('WorkstationFlags', ULONG),
        ('KerberosSupportedEncryptionTypes', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    }

 type PNETLOGON_WORKSTATION_INFO struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_WORKSTATION_INFO),
    }

// 2.2.1.3.7 NL_TRUST_PASSWORD
 type WCHAR_ARRAY struct { // NDRUniFixedArray:
     func (self TYPE) getDataLen(data interface{}){
        return 512

 type NL_TRUST_PASSWORD struct { // NDRSTRUCT: (
        ('Buffer', WCHAR_ARRAY),
        ('Length', LPWSTR),
    }

// 2.2.1.3.8 NL_PASSWORD_VERSION
 type NL_PASSWORD_VERSION struct { // NDRSTRUCT: (
        ('ReservedField', ULONG),
        ('PasswordVersionNumber', ULONG),
        ('PasswordVersionPresent', ULONG),
    }

// 2.2.1.3.9 NETLOGON_WORKSTATION_INFORMATION
 type NETLOGON_WORKSTATION_INFORMATION struct { // NDRUNION:
    commonHdr = (
        ('tag', DWORD),
    }

    union = {
        1 : ('WorkstationInfo', PNETLOGON_WORKSTATION_INFO),
        2 : ('LsaPolicyInfo', PNETLOGON_LSA_POLICY_INFO),
    }

// 2.2.1.3.10 NETLOGON_ONE_DOMAIN_INFO
 type NETLOGON_ONE_DOMAIN_INFO struct { // NDRSTRUCT: (
        ('DomainName', RPC_UNICODE_STRING),
        ('DnsDomainName', RPC_UNICODE_STRING),
        ('DnsForestName', RPC_UNICODE_STRING),
        ('DomainGuid', GUID),
        ('DomainSid', PRPC_SID),
        ('TrustExtension', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    }

 type NETLOGON_ONE_DOMAIN_INFO_ARRAY struct { // NDRUniConformantArray:
    item = NETLOGON_ONE_DOMAIN_INFO

 type PNETLOGON_ONE_DOMAIN_INFO_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_ONE_DOMAIN_INFO_ARRAY),
    }

// 2.2.1.3.11 NETLOGON_DOMAIN_INFO
 type NETLOGON_DOMAIN_INFO struct { // NDRSTRUCT: (
        ('PrimaryDomain', NETLOGON_ONE_DOMAIN_INFO),
        ('TrustedDomainCount', ULONG),
        ('TrustedDomains', PNETLOGON_ONE_DOMAIN_INFO_ARRAY),
        ('LsaPolicy', NETLOGON_LSA_POLICY_INFO),
        ('DnsHostNameInDs', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('WorkstationFlags', ULONG),
        ('SupportedEncTypes', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    }

 type PNETLOGON_DOMAIN_INFO struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_DOMAIN_INFO),
    }

// 2.2.1.3.12 NETLOGON_DOMAIN_INFORMATION
 type NETLOGON_DOMAIN_INFORMATION struct { // NDRUNION:
    commonHdr = (
        ('tag', DWORD),
    }

    union = {
        1 : ('DomainInfo', PNETLOGON_DOMAIN_INFO),
        2 : ('LsaPolicyInfo', PNETLOGON_LSA_POLICY_INFO),
    }

// 2.2.1.3.13 NETLOGON_SECURE_CHANNEL_TYPE
 type NETLOGON_SECURE_CHANNEL_TYPE struct { // NDRENUM:
     type enumItems struct { // Enum:
        NullSecureChannel             = 0
        MsvApSecureChannel            = 1
        WorkstationSecureChannel      = 2
        TrustedDnsDomainSecureChannel = 3
        TrustedDomainSecureChannel    = 4
        UasServerSecureChannel        = 5
        ServerSecureChannel           = 6
        CdcServerSecureChannel        = 7

// 2.2.1.3.14 NETLOGON_CAPABILITIES
 type NETLOGON_CAPABILITIES struct { // NDRUNION:
    commonHdr = (
        ('tag', DWORD),
    }

    union = {
        1 : ('ServerCapabilities', ULONG),
    }

// 2.2.1.3.15 NL_OSVERSIONINFO_V1
 type UCHAR_FIXED_ARRAY struct { // NDRUniFixedArray:
     func (self TYPE) getDataLen(data interface{}){
        return 128

 type NL_OSVERSIONINFO_V1 struct { // NDRSTRUCT: (
        ('dwOSVersionInfoSize', DWORD),
        ('dwMajorVersion', DWORD),
        ('dwMinorVersion', DWORD),
        ('dwBuildNumber', DWORD),
        ('dwPlatformId', DWORD),
        ('szCSDVersion', UCHAR_FIXED_ARRAY),
        ('wServicePackMajor', USHORT),
        ('wServicePackMinor', USHORT),
        ('wSuiteMask', USHORT),
        ('wProductType', UCHAR),
        ('wReserved', UCHAR),
    }

 type PNL_OSVERSIONINFO_V1 struct { // NDRPOINTER:
    referent = (
        ('Data', NL_OSVERSIONINFO_V1),
    }

// 2.2.1.3.16 NL_IN_CHAIN_SET_CLIENT_ATTRIBUTES_V1
 type PLPWSTR struct { // NDRPOINTER:
    referent = (
        ('Data', LPWSTR),
    }

 type NL_IN_CHAIN_SET_CLIENT_ATTRIBUTES_V1 struct { // NDRSTRUCT: (
        ('ClientDnsHostName', PLPWSTR),
        ('OsVersionInfo', PNL_OSVERSIONINFO_V1),
        ('OsName', PLPWSTR),
    }

// 2.2.1.3.17 NL_IN_CHAIN_SET_CLIENT_ATTRIBUTES
 type NL_IN_CHAIN_SET_CLIENT_ATTRIBUTES struct { // NDRUNION:
    commonHdr = (
        ('tag', DWORD),
    }

    union = {
        1 : ('V1', NL_IN_CHAIN_SET_CLIENT_ATTRIBUTES_V1),
    }

// 2.2.1.3.18 NL_OUT_CHAIN_SET_CLIENT_ATTRIBUTES_V1
 type NL_OUT_CHAIN_SET_CLIENT_ATTRIBUTES_V1 struct { // NDRSTRUCT: (
        ('HubName', PLPWSTR),
        ('OldDnsHostName', PLPWSTR),
        ('SupportedEncTypes', LPULONG),
    }

// 2.2.1.3.19 NL_OUT_CHAIN_SET_CLIENT_ATTRIBUTES
 type NL_OUT_CHAIN_SET_CLIENT_ATTRIBUTES struct { // NDRUNION:
    commonHdr = (
        ('tag', DWORD),
    }

    union = {
        1 : ('V1', NL_OUT_CHAIN_SET_CLIENT_ATTRIBUTES_V1),
    }

// 2.2.1.4.1 LM_CHALLENGE
 type CHAR_FIXED_8_ARRAY struct { // NDRUniFixedArray:
     func (self TYPE) getDataLen(data interface{}){
        return 8

 type LM_CHALLENGE struct { // NDRSTRUCT: (
        ('Data', CHAR_FIXED_8_ARRAY),
    }

// 2.2.1.4.15 NETLOGON_LOGON_IDENTITY_INFO
 type NETLOGON_LOGON_IDENTITY_INFO struct { // NDRSTRUCT: (
        ('LogonDomainName', RPC_UNICODE_STRING),
        ('ParameterControl', ULONG),
        ('Reserved', OLD_LARGE_INTEGER),
        ('UserName', RPC_UNICODE_STRING),
        ('Workstation', RPC_UNICODE_STRING),
    }

 type PNETLOGON_LOGON_IDENTITY_INFO struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_LOGON_IDENTITY_INFO),
    }

// 2.2.1.4.2 NETLOGON_GENERIC_INFO
 type NETLOGON_GENERIC_INFO struct { // NDRSTRUCT: (
        ('Identity', NETLOGON_LOGON_IDENTITY_INFO),
        ('PackageName', RPC_UNICODE_STRING),
        ('DataLength', ULONG),
        ('LogonData', PUCHAR_ARRAY),
    }

 type PNETLOGON_GENERIC_INFO struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_GENERIC_INFO),
    }

// 2.2.1.4.3 NETLOGON_INTERACTIVE_INFO
 type NETLOGON_INTERACTIVE_INFO struct { // NDRSTRUCT: (
        ('Identity', NETLOGON_LOGON_IDENTITY_INFO),
        ('LmOwfPassword', LM_OWF_PASSWORD),
        ('NtOwfPassword', NT_OWF_PASSWORD),
    }

 type PNETLOGON_INTERACTIVE_INFO struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_INTERACTIVE_INFO),
    }

// 2.2.1.4.4 NETLOGON_SERVICE_INFO
 type NETLOGON_SERVICE_INFO struct { // NDRSTRUCT: (
        ('Identity', NETLOGON_LOGON_IDENTITY_INFO),
        ('LmOwfPassword', LM_OWF_PASSWORD),
        ('NtOwfPassword', NT_OWF_PASSWORD),
    }

 type PNETLOGON_SERVICE_INFO struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_SERVICE_INFO),
    }

// 2.2.1.4.5 NETLOGON_NETWORK_INFO
 type NETLOGON_NETWORK_INFO struct { // NDRSTRUCT: (
        ('Identity', NETLOGON_LOGON_IDENTITY_INFO),
        ('LmChallenge', LM_CHALLENGE),
        ('NtChallengeResponse', STRING),
        ('LmChallengeResponse', STRING),
    }

 type PNETLOGON_NETWORK_INFO struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_NETWORK_INFO),
    }

// 2.2.1.4.16 NETLOGON_LOGON_INFO_CLASS
 type NETLOGON_LOGON_INFO_CLASS struct { // NDRENUM:
     type enumItems struct { // Enum:
        NetlogonInteractiveInformation           = 1
        NetlogonNetworkInformation               = 2
        NetlogonServiceInformation               = 3
        NetlogonGenericInformation               = 4
        NetlogonInteractiveTransitiveInformation = 5
        NetlogonNetworkTransitiveInformation     = 6
        NetlogonServiceTransitiveInformation     = 7

// 2.2.1.4.6 NETLOGON_LEVEL
 type NETLOGON_LEVEL struct { // NDRUNION:
    union = {
        NETLOGON_LOGON_INFO_CLASS.NetlogonInteractiveInformation           : ('LogonInteractive', PNETLOGON_INTERACTIVE_INFO),
        NETLOGON_LOGON_INFO_CLASS.NetlogonInteractiveTransitiveInformation : ('LogonInteractiveTransitive', PNETLOGON_INTERACTIVE_INFO),
        NETLOGON_LOGON_INFO_CLASS.NetlogonServiceInformation               : ('LogonService', PNETLOGON_SERVICE_INFO),
        NETLOGON_LOGON_INFO_CLASS.NetlogonServiceTransitiveInformation     : ('LogonServiceTransitive', PNETLOGON_SERVICE_INFO),
        NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkInformation               : ('LogonNetwork', PNETLOGON_NETWORK_INFO),
        NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation     : ('LogonNetworkTransitive', PNETLOGON_NETWORK_INFO),
        NETLOGON_LOGON_INFO_CLASS.NetlogonGenericInformation               : ('LogonGeneric', PNETLOGON_GENERIC_INFO),
    }

// 2.2.1.4.7 NETLOGON_SID_AND_ATTRIBUTES
 type NETLOGON_SID_AND_ATTRIBUTES struct { // NDRSTRUCT: (
        ('Sid', PRPC_SID),
        ('Attributes', ULONG),
    }

// 2.2.1.4.8 NETLOGON_VALIDATION_GENERIC_INFO2
 type NETLOGON_VALIDATION_GENERIC_INFO2 struct { // NDRSTRUCT: (
        ('DataLength', ULONG),
        ('ValidationData', PUCHAR_ARRAY),
    }

 type PNETLOGON_VALIDATION_GENERIC_INFO2 struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_VALIDATION_GENERIC_INFO2),
    }

// 2.2.1.4.9 USER_SESSION_KEY
USER_SESSION_KEY = LM_OWF_PASSWORD

// 2.2.1.4.10 GROUP_MEMBERSHIP
 type GROUP_MEMBERSHIP struct { // NDRSTRUCT: (
        ('RelativeId', ULONG),
        ('Attributes', ULONG),
    }

 type GROUP_MEMBERSHIP_ARRAY struct { // NDRUniConformantArray:
    item = GROUP_MEMBERSHIP

 type PGROUP_MEMBERSHIP_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', GROUP_MEMBERSHIP_ARRAY),
    }

// 2.2.1.4.11 NETLOGON_VALIDATION_SAM_INFO
 type LONG_ARRAY struct { // NDRUniFixedArray:
     func (self TYPE) getDataLen(data interface{}){
        return 4*10

 type NETLOGON_VALIDATION_SAM_INFO struct { // NDRSTRUCT: (
        ('LogonTime', OLD_LARGE_INTEGER),
        ('LogoffTime', OLD_LARGE_INTEGER),
        ('KickOffTime', OLD_LARGE_INTEGER),
        ('PasswordLastSet', OLD_LARGE_INTEGER),
        ('PasswordCanChange', OLD_LARGE_INTEGER),
        ('PasswordMustChange', OLD_LARGE_INTEGER),
        ('EffectiveName', RPC_UNICODE_STRING),
        ('FullName', RPC_UNICODE_STRING),
        ('LogonScript', RPC_UNICODE_STRING),
        ('ProfilePath', RPC_UNICODE_STRING),
        ('HomeDirectory', RPC_UNICODE_STRING),
        ('HomeDirectoryDrive', RPC_UNICODE_STRING),
        ('LogonCount', USHORT),
        ('BadPasswordCount', USHORT),
        ('UserId', ULONG),
        ('PrimaryGroupId', ULONG),
        ('GroupCount', ULONG),
        ('GroupIds', PGROUP_MEMBERSHIP_ARRAY),
        ('UserFlags', ULONG),
        ('UserSessionKey', USER_SESSION_KEY),
        ('LogonServer', RPC_UNICODE_STRING),
        ('LogonDomainName', RPC_UNICODE_STRING),
        ('LogonDomainId', PRPC_SID),
        ('ExpansionRoom', LONG_ARRAY),
    }

 type PNETLOGON_VALIDATION_SAM_INFO struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_VALIDATION_SAM_INFO),
    }

// 2.2.1.4.12 NETLOGON_VALIDATION_SAM_INFO2
 type NETLOGON_SID_AND_ATTRIBUTES_ARRAY struct { // NDRUniConformantArray:
    item = NETLOGON_SID_AND_ATTRIBUTES

 type PNETLOGON_SID_AND_ATTRIBUTES_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_SID_AND_ATTRIBUTES_ARRAY),
    }

 type NETLOGON_VALIDATION_SAM_INFO2 struct { // NDRSTRUCT: (
        ('LogonTime', OLD_LARGE_INTEGER),
        ('LogoffTime', OLD_LARGE_INTEGER),
        ('KickOffTime', OLD_LARGE_INTEGER),
        ('PasswordLastSet', OLD_LARGE_INTEGER),
        ('PasswordCanChange', OLD_LARGE_INTEGER),
        ('PasswordMustChange', OLD_LARGE_INTEGER),
        ('EffectiveName', RPC_UNICODE_STRING),
        ('FullName', RPC_UNICODE_STRING),
        ('LogonScript', RPC_UNICODE_STRING),
        ('ProfilePath', RPC_UNICODE_STRING),
        ('HomeDirectory', RPC_UNICODE_STRING),
        ('HomeDirectoryDrive', RPC_UNICODE_STRING),
        ('LogonCount', USHORT),
        ('BadPasswordCount', USHORT),
        ('UserId', ULONG),
        ('PrimaryGroupId', ULONG),
        ('GroupCount', ULONG),
        ('GroupIds', PGROUP_MEMBERSHIP_ARRAY),
        ('UserFlags', ULONG),
        ('UserSessionKey', USER_SESSION_KEY),
        ('LogonServer', RPC_UNICODE_STRING),
        ('LogonDomainName', RPC_UNICODE_STRING),
        ('LogonDomainId', PRPC_SID),
        ('ExpansionRoom', LONG_ARRAY),
        ('SidCount', ULONG),
        ('ExtraSids', PNETLOGON_SID_AND_ATTRIBUTES_ARRAY),
    }

 type PNETLOGON_VALIDATION_SAM_INFO2 struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_VALIDATION_SAM_INFO2),
    }

// 2.2.1.4.13 NETLOGON_VALIDATION_SAM_INFO4
 type NETLOGON_VALIDATION_SAM_INFO4 struct { // NDRSTRUCT: (
        ('LogonTime', OLD_LARGE_INTEGER),
        ('LogoffTime', OLD_LARGE_INTEGER),
        ('KickOffTime', OLD_LARGE_INTEGER),
        ('PasswordLastSet', OLD_LARGE_INTEGER),
        ('PasswordCanChange', OLD_LARGE_INTEGER),
        ('PasswordMustChange', OLD_LARGE_INTEGER),
        ('EffectiveName', RPC_UNICODE_STRING),
        ('FullName', RPC_UNICODE_STRING),
        ('LogonScript', RPC_UNICODE_STRING),
        ('ProfilePath', RPC_UNICODE_STRING),
        ('HomeDirectory', RPC_UNICODE_STRING),
        ('HomeDirectoryDrive', RPC_UNICODE_STRING),
        ('LogonCount', USHORT),
        ('BadPasswordCount', USHORT),
        ('UserId', ULONG),
        ('PrimaryGroupId', ULONG),
        ('GroupCount', ULONG),
        ('GroupIds', PGROUP_MEMBERSHIP_ARRAY),
        ('UserFlags', ULONG),
        ('UserSessionKey', USER_SESSION_KEY),
        ('LogonServer', RPC_UNICODE_STRING),
        ('LogonDomainName', RPC_UNICODE_STRING),
        ('LogonDomainId', PRPC_SID),

        ('LMKey', CHAR_FIXED_8_ARRAY),
        ('UserAccountControl', ULONG),
        ('SubAuthStatus', ULONG),
        ('LastSuccessfulILogon', OLD_LARGE_INTEGER),
        ('LastFailedILogon', OLD_LARGE_INTEGER),
        ('FailedILogonCount', ULONG),
        ('Reserved4', ULONG),

        ('SidCount', ULONG),
        ('ExtraSids', PNETLOGON_SID_AND_ATTRIBUTES_ARRAY),
        ('DnsLogonDomainName', RPC_UNICODE_STRING),
        ('Upn', RPC_UNICODE_STRING),
        ('ExpansionString1', RPC_UNICODE_STRING),
        ('ExpansionString2', RPC_UNICODE_STRING),
        ('ExpansionString3', RPC_UNICODE_STRING),
        ('ExpansionString4', RPC_UNICODE_STRING),
        ('ExpansionString5', RPC_UNICODE_STRING),
        ('ExpansionString6', RPC_UNICODE_STRING),
        ('ExpansionString7', RPC_UNICODE_STRING),
        ('ExpansionString8', RPC_UNICODE_STRING),
        ('ExpansionString9', RPC_UNICODE_STRING),
        ('ExpansionString10', RPC_UNICODE_STRING),
    }

 type PNETLOGON_VALIDATION_SAM_INFO4 struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_VALIDATION_SAM_INFO4),
    }

// 2.2.1.4.17 NETLOGON_VALIDATION_INFO_CLASS
 type NETLOGON_VALIDATION_INFO_CLASS struct { // NDRENUM:
     type enumItems struct { // Enum:
        NetlogonValidationUasInfo      = 1
        NetlogonValidationSamInfo      = 2
        NetlogonValidationSamInfo2     = 3
        NetlogonValidationGenericInfo  = 4
        NetlogonValidationGenericInfo2 = 5
        NetlogonValidationSamInfo4     = 6

// 2.2.1.4.14 NETLOGON_VALIDATION
 type NETLOGON_VALIDATION struct { // NDRUNION:
    union = {
        NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo     : ('ValidationSam', PNETLOGON_VALIDATION_SAM_INFO),
        NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo2    : ('ValidationSam2', PNETLOGON_VALIDATION_SAM_INFO2),
        NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationGenericInfo2: ('ValidationGeneric2', PNETLOGON_VALIDATION_GENERIC_INFO2),
        NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo4    : ('ValidationSam4', PNETLOGON_VALIDATION_SAM_INFO4),
    }

// 2.2.1.5.2 NLPR_QUOTA_LIMITS
 type NLPR_QUOTA_LIMITS struct { // NDRSTRUCT: (
        ('PagedPoolLimit', ULONG),
        ('NonPagedPoolLimit', ULONG),
        ('MinimumWorkingSetSize', ULONG),
        ('MaximumWorkingSetSize', ULONG),
        ('PagefileLimit', ULONG),
        ('Reserved', OLD_LARGE_INTEGER),
    }

// 2.2.1.5.3 NETLOGON_DELTA_ACCOUNTS
 type ULONG_ARRAY struct { // NDRUniConformantArray:
    item = ULONG

 type PULONG_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', ULONG_ARRAY),
    }

 type NETLOGON_DELTA_ACCOUNTS struct { // NDRSTRUCT: (
        ('PrivilegeEntries', ULONG),
        ('PrivilegeControl', ULONG),
        ('PrivilegeAttributes', PULONG_ARRAY),
        ('PrivilegeNames', PRPC_UNICODE_STRING_ARRAY),
        ('QuotaLimits', NLPR_QUOTA_LIMITS),
        ('SystemAccessFlags', ULONG),
        ('SecurityInformation', SECURITY_INFORMATION),
        ('SecuritySize', ULONG),
        ('SecurityDescriptor', PUCHAR_ARRAY),
        ('DummyString1', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    }

 type PNETLOGON_DELTA_ACCOUNTS struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_DELTA_ACCOUNTS),
    }

// 2.2.1.5.5 NLPR_SID_INFORMATION
 type NLPR_SID_INFORMATION struct { // NDRSTRUCT: (
        ('SidPointer', PRPC_SID),
    }

// 2.2.1.5.6 NLPR_SID_ARRAY
 type NLPR_SID_INFORMATION_ARRAY struct { // NDRUniConformantArray:
    item = NLPR_SID_INFORMATION

 type PNLPR_SID_INFORMATION_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', NLPR_SID_INFORMATION_ARRAY),
    }

 type NLPR_SID_ARRAY struct { // NDRSTRUCT:
    referent = (
        ('Count', ULONG),
        ('Sids', PNLPR_SID_INFORMATION_ARRAY),
    }

// 2.2.1.5.7 NETLOGON_DELTA_ALIAS_MEMBER
 type NETLOGON_DELTA_ALIAS_MEMBER struct { // NDRSTRUCT: (
        ('Members', NLPR_SID_ARRAY),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    }

 type PNETLOGON_DELTA_ALIAS_MEMBER struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_DELTA_ALIAS_MEMBER),
    }

// 2.2.1.5.8 NETLOGON_DELTA_DELETE_GROUP
 type NETLOGON_DELTA_DELETE_GROUP struct { // NDRSTRUCT: (
        ('AccountName', LPWSTR),
        ('DummyString1', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    }

 type PNETLOGON_DELTA_DELETE_GROUP struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_DELTA_DELETE_GROUP),
    }

// 2.2.1.5.9 NETLOGON_DELTA_DELETE_USER
 type NETLOGON_DELTA_DELETE_USER struct { // NDRSTRUCT: (
        ('AccountName', LPWSTR),
        ('DummyString1', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    }

 type PNETLOGON_DELTA_DELETE_USER struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_DELTA_DELETE_USER),
    }

// 2.2.1.5.10 NETLOGON_DELTA_DOMAIN
 type NETLOGON_DELTA_DOMAIN struct { // NDRSTRUCT: (
        ('DomainName', RPC_UNICODE_STRING),
        ('OemInformation', RPC_UNICODE_STRING),
        ('ForceLogoff', OLD_LARGE_INTEGER),
        ('MinPasswordLength', USHORT),
        ('PasswordHistoryLength', USHORT),
        ('MaxPasswordAge', OLD_LARGE_INTEGER),
        ('MinPasswordAge', OLD_LARGE_INTEGER),
        ('DomainModifiedCount', OLD_LARGE_INTEGER),
        ('DomainCreationTime', OLD_LARGE_INTEGER),
        ('SecurityInformation', SECURITY_INFORMATION),
        ('SecuritySize', ULONG),
        ('SecurityDescriptor', PUCHAR_ARRAY),
        ('DomainLockoutInformation', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('PasswordProperties', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    }
        
 type PNETLOGON_DELTA_DOMAIN struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_DELTA_DOMAIN),
    }

// 2.2.1.5.13 NETLOGON_DELTA_GROUP
 type NETLOGON_DELTA_GROUP struct { // NDRSTRUCT: (
        ('Name', RPC_UNICODE_STRING),
        ('RelativeId', ULONG),
        ('Attributes', ULONG),
        ('AdminComment', RPC_UNICODE_STRING),
        ('SecurityInformation', USHORT),
        ('SecuritySize', ULONG),
        ('SecurityDescriptor', SECURITY_INFORMATION),
        ('DummyString1', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    }

 type PNETLOGON_DELTA_GROUP struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_DELTA_GROUP),
    }

// 2.2.1.5.24 NETLOGON_RENAME_GROUP
 type NETLOGON_RENAME_GROUP struct { // NDRSTRUCT: (
        ('OldName', RPC_UNICODE_STRING),
        ('NewName', RPC_UNICODE_STRING),
        ('DummyString1', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    }

 type PNETLOGON_DELTA_RENAME_GROUP struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_RENAME_GROUP),
    }

// 2.2.1.5.14 NLPR_LOGON_HOURS
from impacket.dcerpc.v5.samr import SAMPR_LOGON_HOURS
NLPR_LOGON_HOURS = SAMPR_LOGON_HOURS

// 2.2.1.5.15 NLPR_USER_PRIVATE_INFO
 type NLPR_USER_PRIVATE_INFO struct { // NDRSTRUCT: (
        ('SensitiveData', UCHAR),
        ('DataLength', ULONG),
        ('Data', PUCHAR_ARRAY),
    }

// 2.2.1.5.16 NETLOGON_DELTA_USER
 type NETLOGON_DELTA_USER struct { // NDRSTRUCT: (
        ('UserName', RPC_UNICODE_STRING),
        ('FullName', RPC_UNICODE_STRING),
        ('UserId', ULONG),
        ('PrimaryGroupId', ULONG),
        ('HomeDirectory', RPC_UNICODE_STRING),
        ('HomeDirectoryDrive', RPC_UNICODE_STRING),
        ('ScriptPath', RPC_UNICODE_STRING),
        ('AdminComment', RPC_UNICODE_STRING),
        ('WorkStations', RPC_UNICODE_STRING),
        ('LastLogon', OLD_LARGE_INTEGER),
        ('LastLogoff', OLD_LARGE_INTEGER),
        ('LogonHours', NLPR_LOGON_HOURS),
        ('BadPasswordCount', USHORT),
        ('LogonCount', USHORT),
        ('PasswordLastSet', OLD_LARGE_INTEGER),
        ('AccountExpires', OLD_LARGE_INTEGER),
        ('UserAccountControl', ULONG),
        ('EncryptedNtOwfPassword', PUCHAR_ARRAY),
        ('EncryptedLmOwfPassword', PUCHAR_ARRAY),
        ('NtPasswordPresent', UCHAR),
        ('LmPasswordPresent', UCHAR),
        ('PasswordExpired', UCHAR),
        ('UserComment', RPC_UNICODE_STRING),
        ('Parameters', RPC_UNICODE_STRING),
        ('CountryCode', USHORT),
        ('CodePage', USHORT),
        ('PrivateData', NLPR_USER_PRIVATE_INFO),
        ('SecurityInformation', SECURITY_INFORMATION),
        ('SecuritySize', ULONG),
        ('SecurityDescriptor', PUCHAR_ARRAY),
        ('ProfilePath', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    }

 type PNETLOGON_DELTA_USER struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_DELTA_USER),
    }

// 2.2.1.5.25 NETLOGON_RENAME_USER
 type NETLOGON_RENAME_USER struct { // NDRSTRUCT: (
        ('OldName', RPC_UNICODE_STRING),
        ('NewName', RPC_UNICODE_STRING),
        ('DummyString1', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    }

 type PNETLOGON_DELTA_RENAME_USER struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_RENAME_USER),
    }

// 2.2.1.5.17 NETLOGON_DELTA_GROUP_MEMBER
 type NETLOGON_DELTA_GROUP_MEMBER struct { // NDRSTRUCT: (
        ('Members', PULONG_ARRAY),
        ('Attributes', PULONG_ARRAY),
        ('MemberCount', ULONG),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    }

 type PNETLOGON_DELTA_GROUP_MEMBER struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_DELTA_GROUP_MEMBER),
    }

// 2.2.1.5.4 NETLOGON_DELTA_ALIAS
 type NETLOGON_DELTA_ALIAS struct { // NDRSTRUCT: (
        ('Name', RPC_UNICODE_STRING),
        ('RelativeId', ULONG),
        ('SecurityInformation', SECURITY_INFORMATION),
        ('SecuritySize', ULONG),
        ('SecurityDescriptor', PUCHAR_ARRAY),
        ('Comment', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    }

 type PNETLOGON_DELTA_ALIAS struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_DELTA_ALIAS),
    }

// 2.2.1.5.23 NETLOGON_RENAME_ALIAS
 type NETLOGON_RENAME_ALIAS struct { // NDRSTRUCT: (
        ('OldName', RPC_UNICODE_STRING),
        ('NewName', RPC_UNICODE_STRING),
        ('DummyString1', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    }

 type PNETLOGON_DELTA_RENAME_ALIAS struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_RENAME_ALIAS),
    }

// 2.2.1.5.19 NETLOGON_DELTA_POLICY
 type NETLOGON_DELTA_POLICY struct { // NDRSTRUCT: (
        ('MaximumLogSize', ULONG),
        ('AuditRetentionPeriod', OLD_LARGE_INTEGER),
        ('AuditingMode', UCHAR),
        ('MaximumAuditEventCount', ULONG),
        ('EventAuditingOptions', PULONG_ARRAY),
        ('PrimaryDomainName', RPC_UNICODE_STRING),
        ('PrimaryDomainSid', PRPC_SID),
        ('QuotaLimits', NLPR_QUOTA_LIMITS),
        ('ModifiedId', OLD_LARGE_INTEGER),
        ('DatabaseCreationTime', OLD_LARGE_INTEGER),
        ('SecurityInformation', SECURITY_INFORMATION),
        ('SecuritySize', ULONG),
        ('SecurityDescriptor', PUCHAR_ARRAY),
        ('DummyString1', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    }

 type PNETLOGON_DELTA_POLICY struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_DELTA_POLICY),
    }

// 2.2.1.5.22 NETLOGON_DELTA_TRUSTED_DOMAINS
 type NETLOGON_DELTA_TRUSTED_DOMAINS struct { // NDRSTRUCT: (
        ('DomainName', RPC_UNICODE_STRING),
        ('NumControllerEntries', ULONG),
        ('ControllerNames', PRPC_UNICODE_STRING_ARRAY),
        ('SecurityInformation', SECURITY_INFORMATION),
        ('SecuritySize', ULONG),
        ('SecurityDescriptor', PUCHAR_ARRAY),
        ('DummyString1', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    }

 type PNETLOGON_DELTA_TRUSTED_DOMAINS struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_DELTA_TRUSTED_DOMAINS),
    }

// 2.2.1.5.20 NLPR_CR_CIPHER_VALUE
 type UCHAR_ARRAY2 struct { // NDRUniConformantVaryingArray:
    item = UCHAR

 type PUCHAR_ARRAY2 struct { // NDRPOINTER:
    referent = (
        ('Data', UCHAR_ARRAY2),
    }

 type NLPR_CR_CIPHER_VALUE struct { // NDRSTRUCT: (
        ('Length', ULONG),
        ('MaximumLength', ULONG),
        ('Buffer', PUCHAR_ARRAY2),
    }

// 2.2.1.5.21 NETLOGON_DELTA_SECRET
 type NETLOGON_DELTA_SECRET struct { // NDRSTRUCT: (
        ('CurrentValue', NLPR_CR_CIPHER_VALUE),
        ('CurrentValueSetTime', OLD_LARGE_INTEGER),
        ('OldValue', NLPR_CR_CIPHER_VALUE),
        ('OldValueSetTime', OLD_LARGE_INTEGER),
        ('SecurityInformation', SECURITY_INFORMATION),
        ('SecuritySize', ULONG),
        ('SecurityDescriptor', PUCHAR_ARRAY),
        ('DummyString1', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    }

 type PNETLOGON_DELTA_SECRET struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_DELTA_SECRET),
    }

// 2.2.1.5.26 NLPR_MODIFIED_COUNT
 type NLPR_MODIFIED_COUNT struct { // NDRSTRUCT: (
        ('ModifiedCount', OLD_LARGE_INTEGER),
    }

 type PNLPR_MODIFIED_COUNT struct { // NDRPOINTER:
    referent = (
        ('Data', NLPR_MODIFIED_COUNT),
    }

// 2.2.1.5.28 NETLOGON_DELTA_TYPE
 type NETLOGON_DELTA_TYPE struct { // NDRENUM:
     type enumItems struct { // Enum:
        AddOrChangeDomain     = 1
        AddOrChangeGroup      = 2
        DeleteGroup           = 3
        RenameGroup           = 4
        AddOrChangeUser       = 5
        DeleteUser            = 6
        RenameUser            = 7
        ChangeGroupMembership = 8
        AddOrChangeAlias      = 9
        DeleteAlias           = 10
        RenameAlias           = 11
        ChangeAliasMembership = 12
        AddOrChangeLsaPolicy  = 13
        AddOrChangeLsaTDomain = 14
        DeleteLsaTDomain      = 15
        AddOrChangeLsaAccount = 16
        DeleteLsaAccount      = 17
        AddOrChangeLsaSecret  = 18
        DeleteLsaSecret       = 19
        DeleteGroupByName     = 20
        DeleteUserByName      = 21
        SerialNumberSkip      = 22

// 2.2.1.5.27 NETLOGON_DELTA_UNION
 type NETLOGON_DELTA_UNION struct { // NDRUNION:
    union = {
        NETLOGON_DELTA_TYPE.AddOrChangeDomain     : ('DeltaDomain', PNETLOGON_DELTA_DOMAIN),
        NETLOGON_DELTA_TYPE.AddOrChangeGroup      : ('DeltaGroup', PNETLOGON_DELTA_GROUP),
        NETLOGON_DELTA_TYPE.RenameGroup           : ('DeltaRenameGroup', PNETLOGON_DELTA_RENAME_GROUP),
        NETLOGON_DELTA_TYPE.AddOrChangeUser       : ('DeltaUser', PNETLOGON_DELTA_USER),
        NETLOGON_DELTA_TYPE.RenameUser            : ('DeltaRenameUser', PNETLOGON_DELTA_RENAME_USER),
        NETLOGON_DELTA_TYPE.ChangeGroupMembership : ('DeltaGroupMember', PNETLOGON_DELTA_GROUP_MEMBER),
        NETLOGON_DELTA_TYPE.AddOrChangeAlias      : ('DeltaAlias', PNETLOGON_DELTA_ALIAS),
        NETLOGON_DELTA_TYPE.RenameAlias           : ('DeltaRenameAlias', PNETLOGON_DELTA_RENAME_ALIAS),
        NETLOGON_DELTA_TYPE.ChangeAliasMembership : ('DeltaAliasMember', PNETLOGON_DELTA_ALIAS_MEMBER),
        NETLOGON_DELTA_TYPE.AddOrChangeLsaPolicy  : ('DeltaPolicy', PNETLOGON_DELTA_POLICY),
        NETLOGON_DELTA_TYPE.AddOrChangeLsaTDomain : ('DeltaTDomains', PNETLOGON_DELTA_TRUSTED_DOMAINS),
        NETLOGON_DELTA_TYPE.AddOrChangeLsaAccount : ('DeltaAccounts', PNETLOGON_DELTA_ACCOUNTS),
        NETLOGON_DELTA_TYPE.AddOrChangeLsaSecret  : ('DeltaSecret', PNETLOGON_DELTA_SECRET),
        NETLOGON_DELTA_TYPE.DeleteGroupByName     : ('DeltaDeleteGroup', PNETLOGON_DELTA_DELETE_GROUP),
        NETLOGON_DELTA_TYPE.DeleteUserByName      : ('DeltaDeleteUser', PNETLOGON_DELTA_DELETE_USER),
        NETLOGON_DELTA_TYPE.SerialNumberSkip      : ('DeltaSerialNumberSkip', PNLPR_MODIFIED_COUNT),
    }

// 2.2.1.5.18 NETLOGON_DELTA_ID_UNION
 type NETLOGON_DELTA_ID_UNION struct { // NDRUNION:
    union = {
        NETLOGON_DELTA_TYPE.AddOrChangeDomain     : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.AddOrChangeGroup      : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.DeleteGroup           : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.RenameGroup           : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.AddOrChangeUser       : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.DeleteUser            : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.RenameUser            : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.ChangeGroupMembership : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.AddOrChangeAlias      : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.DeleteAlias           : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.RenameAlias           : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.ChangeAliasMembership : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.DeleteGroupByName     : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.DeleteUserByName      : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.AddOrChangeLsaPolicy  : ('Sid', PRPC_SID),
        NETLOGON_DELTA_TYPE.AddOrChangeLsaTDomain : ('Sid', PRPC_SID),
        NETLOGON_DELTA_TYPE.DeleteLsaTDomain      : ('Sid', PRPC_SID),
        NETLOGON_DELTA_TYPE.AddOrChangeLsaAccount : ('Sid', PRPC_SID),
        NETLOGON_DELTA_TYPE.DeleteLsaAccount      : ('Sid', PRPC_SID),
        NETLOGON_DELTA_TYPE.AddOrChangeLsaSecret  : ('Name', LPWSTR),
        NETLOGON_DELTA_TYPE.DeleteLsaSecret       : ('Name', LPWSTR),
    }

// 2.2.1.5.11 NETLOGON_DELTA_ENUM
 type NETLOGON_DELTA_ENUM struct { // NDRSTRUCT: (
        ('DeltaType', NETLOGON_DELTA_TYPE),
        ('DeltaID', NETLOGON_DELTA_ID_UNION),
        ('DeltaUnion', NETLOGON_DELTA_UNION),
    }

// 2.2.1.5.12 NETLOGON_DELTA_ENUM_ARRAY
 type NETLOGON_DELTA_ENUM_ARRAY_ARRAY struct { // NDRUniConformantArray:
    item = NETLOGON_DELTA_ENUM

 type PNETLOGON_DELTA_ENUM_ARRAY_ARRAY struct { // NDRSTRUCT:
    referent = (
        ('Data', NETLOGON_DELTA_ENUM_ARRAY_ARRAY),
    }

 type PNETLOGON_DELTA_ENUM_ARRAY struct { // NDRPOINTER: (
        ('CountReturned', DWORD),
        ('Deltas', PNETLOGON_DELTA_ENUM_ARRAY_ARRAY),
    }

// 2.2.1.5.29 SYNC_STATE
 type SYNC_STATE struct { // NDRENUM:
     type enumItems struct { // Enum:
        NormalState          = 0
        DomainState          = 1
        GroupState           = 2
        UasBuiltInGroupState = 3
        UserState            = 4
        GroupMemberState     = 5
        AliasState           = 6
        AliasMemberState     = 7
        SamDoneState         = 8

// 2.2.1.6.1 DOMAIN_NAME_BUFFER
 type DOMAIN_NAME_BUFFER struct { // NDRSTRUCT: (
        ('DomainNameByteCount', ULONG),
        ('DomainNames', PUCHAR_ARRAY),
    }

// 2.2.1.6.2 DS_DOMAIN_TRUSTSW
 type DS_DOMAIN_TRUSTSW struct { // NDRSTRUCT: (
        ('NetbiosDomainName', LPWSTR),
        ('DnsDomainName', LPWSTR),
        ('Flags', ULONG),
        ('ParentIndex', ULONG),
        ('TrustType', ULONG),
        ('TrustAttributes', ULONG),
        ('DomainSid', PRPC_SID),
        ('DomainGuid', GUID),
    }

// 2.2.1.6.3 NETLOGON_TRUSTED_DOMAIN_ARRAY
 type DS_DOMAIN_TRUSTSW_ARRAY struct { // NDRUniConformantArray:
    item = DS_DOMAIN_TRUSTSW

 type PDS_DOMAIN_TRUSTSW_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', DS_DOMAIN_TRUSTSW_ARRAY),
    }

 type NETLOGON_TRUSTED_DOMAIN_ARRAY struct { // NDRSTRUCT: (
        ('DomainCount', DWORD),
        ('Domains', PDS_DOMAIN_TRUSTSW_ARRAY),
    }

// 2.2.1.6.4 NL_GENERIC_RPC_DATA
 type NL_GENERIC_RPC_DATA struct { // NDRSTRUCT: (
        ('UlongEntryCount', ULONG),
        ('UlongData', PULONG_ARRAY),
        ('UnicodeStringEntryCount', ULONG),
        ('UnicodeStringData', PRPC_UNICODE_STRING_ARRAY),
    }

 type PNL_GENERIC_RPC_DATA struct { // NDRPOINTER:
    referent = (
        ('Data', NL_GENERIC_RPC_DATA),
    }

// 2.2.1.7.1 NETLOGON_CONTROL_DATA_INFORMATION
 type NETLOGON_CONTROL_DATA_INFORMATION struct { // NDRUNION:
    commonHdr = (
        ('tag', DWORD),
    }

    union = {
        5 : ('TrustedDomainName', LPWSTR),
        6 : ('TrustedDomainName', LPWSTR),
        9 : ('TrustedDomainName', LPWSTR),
        10 : ('TrustedDomainName', LPWSTR),
        65534 : ('DebugFlag', DWORD),
        8: ('UserName', LPWSTR),
    }

// 2.2.1.7.2 NETLOGON_INFO_1
 type NETLOGON_INFO_1 struct { // NDRSTRUCT: (
        ('netlog1_flags', DWORD),
        ('netlog1_pdc_connection_status', NET_API_STATUS),
    }

 type PNETLOGON_INFO_1 struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_INFO_1),
    }

// 2.2.1.7.3 NETLOGON_INFO_2
 type NETLOGON_INFO_2 struct { // NDRSTRUCT: (
        ('netlog2_flags', DWORD),
        ('netlog2_pdc_connection_status', NET_API_STATUS),
        ('netlog2_trusted_dc_name', LPWSTR),
        ('netlog2_tc_connection_status', NET_API_STATUS),
    }

 type PNETLOGON_INFO_2 struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_INFO_2),
    }

// 2.2.1.7.4 NETLOGON_INFO_3
 type NETLOGON_INFO_3 struct { // NDRSTRUCT: (
        ('netlog3_flags', DWORD),
        ('netlog3_logon_attempts', DWORD),
        ('netlog3_reserved1', DWORD),
        ('netlog3_reserved2', DWORD),
        ('netlog3_reserved3', DWORD),
        ('netlog3_reserved4', DWORD),
        ('netlog3_reserved5', DWORD),
    }

 type PNETLOGON_INFO_3 struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_INFO_3),
    }

// 2.2.1.7.5 NETLOGON_INFO_4
 type NETLOGON_INFO_4 struct { // NDRSTRUCT: (
        ('netlog4_trusted_dc_name', LPWSTR),
        ('netlog4_trusted_domain_name', LPWSTR),
    }

 type PNETLOGON_INFO_4 struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_INFO_4),
    }

// 2.2.1.7.6 NETLOGON_CONTROL_QUERY_INFORMATION
 type NETLOGON_CONTROL_QUERY_INFORMATION struct { // NDRUNION:
    commonHdr = (
        ('tag', DWORD),
    }

    union = {
        1 : ('NetlogonInfo1', PNETLOGON_INFO_1),
        2 : ('NetlogonInfo2', PNETLOGON_INFO_2),
        3 : ('NetlogonInfo3', PNETLOGON_INFO_3),
        4 : ('NetlogonInfo4', PNETLOGON_INFO_4),
    }

// 2.2.1.8.1 NETLOGON_VALIDATION_UAS_INFO
 type NETLOGON_VALIDATION_UAS_INFO struct { // NDRSTRUCT: (
        ('usrlog1_eff_name', DWORD),
        ('usrlog1_priv', DWORD),
        ('usrlog1_auth_flags', DWORD),
        ('usrlog1_num_logons', DWORD),
        ('usrlog1_bad_pw_count', DWORD),
        ('usrlog1_last_logon', DWORD),
        ('usrlog1_last_logoff', DWORD),
        ('usrlog1_logoff_time', DWORD),
        ('usrlog1_kickoff_time', DWORD),
        ('usrlog1_password_age', DWORD),
        ('usrlog1_pw_can_change', DWORD),
        ('usrlog1_pw_must_change', DWORD),
        ('usrlog1_computer', LPWSTR),
        ('usrlog1_domain', LPWSTR),
        ('usrlog1_script_path', LPWSTR),
        ('usrlog1_reserved1', DWORD),
    }

 type PNETLOGON_VALIDATION_UAS_INFO struct { // NDRPOINTER:
    referent = (
        ('Data', NETLOGON_VALIDATION_UAS_INFO),
    }

// 2.2.1.8.2 NETLOGON_LOGOFF_UAS_INFO
 type NETLOGON_LOGOFF_UAS_INFO struct { // NDRSTRUCT: (
        ('Duration', DWORD),
        ('LogonCount', USHORT),
    }

// 2.2.1.8.3 UAS_INFO_0
 type UAS_INFO_0 struct { // NDRSTRUCT: (
         ComputerName [6]byte // =""
        ('TimeCreated', ULONG),
        ('SerialNumber', ULONG),
    }
     func (self TYPE) getAlignment(){
        return 4

// 2.2.1.8.4 NETLOGON_DUMMY1
 type NETLOGON_DUMMY1 struct { // NDRUNION:
    commonHdr = (
        ('tag', DWORD),
    }

    union = {
        1 : ('Dummy', ULONG),
    }

// 3.5.4.8.2 NetrLogonComputeServerDigest (Opnum 24)
 type CHAR_FIXED_16_ARRAY struct { // NDRUniFixedArray:
     func (self TYPE) getDataLen(data interface{}){
        return 16


//###############################################################################
// SSPI
//###############################################################################
// Constants
NL_AUTH_MESSAGE_NETBIOS_DOMAIN        = 0x1
NL_AUTH_MESSAGE_NETBIOS_HOST          = 0x2
NL_AUTH_MESSAGE_DNS_DOMAIN            = 0x4
NL_AUTH_MESSAGE_DNS_HOST              = 0x8
NL_AUTH_MESSAGE_NETBIOS_HOST_UTF8     = 0x10

NL_AUTH_MESSAGE_REQUEST               = 0x0
NL_AUTH_MESSAGE_RESPONSE              = 0x1

NL_SIGNATURE_HMAC_MD5    = 0x77
NL_SIGNATURE_HMAC_SHA256 = 0x13
NL_SEAL_NOT_ENCRYPTED    = 0xffff
NL_SEAL_RC4              = 0x7A
NL_SEAL_AES128           = 0x1A

// Structures
 type NL_AUTH_MESSAGE struct { // Structure: (
         MessageType uint32 // =0
         Flags uint32 // =0
        ('Buffer',':'),
    }
     func (self TYPE) __init__(data = nil, alignment = 0 interface{}){
        Structure.__init__(self, data, alignment)
        if data == nil {
            self.Buffer = "\x00"*4

 type NL_AUTH_SIGNATURE struct { // Structure: (
         SignatureAlgorithm uint16 // =0
         SealAlgorithm uint16 // =0
         Pad uint16 // =0xffff
         Flags uint16 // =0
         SequenceNumber [8]byte // =""
         Checksum [8]byte // =""
        ('_Confounder','_-Confounder','8'),
        ('Confounder',':'),
    }
     func (self TYPE) __init__(data = nil, alignment = 0 interface{}){
        Structure.__init__(self, data, alignment)
        if data == nil {
            self.Confounder = ""

 type NL_AUTH_SHA2_SIGNATURE struct { // Structure: (
         SignatureAlgorithm uint16 // =0
         SealAlgorithm uint16 // =0
         Pad uint16 // =0xffff
         Flags uint16 // =0
         SequenceNumber [8]byte // =""
         Checksum [2]byte // =""
        ('_Confounder','_-Confounder','8'),
        ('Confounder',':'),
    }
     func (self TYPE) __init__(data = nil, alignment = 0 interface{}){
        Structure.__init__(self, data, alignment)
        if data == nil {
            self.Confounder = ""

// Section 3.1.4.4.2
 func ComputeNetlogonCredential(inputData, Sk interface{}){
    k1 = Sk[:7]
    k3 = crypto.transformKey(k1)
    k2 = Sk[7:14]
    k4 = crypto.transformKey(k2)
    Crypt1 = DES.new(k3, DES.MODE_ECB)
    Crypt2 = DES.new(k4, DES.MODE_ECB)
    cipherText = Crypt1.encrypt(inputData)
    return Crypt2.encrypt(cipherText)

// Section 3.1.4.4.1
 func ComputeNetlogonCredentialAES(inputData, Sk interface{}){
    IV='\x00'*16
    Crypt1 = AES.new(Sk, AES.MODE_CFB, IV)
    return Crypt1.encrypt(inputData)

// Section 3.1.4.3.1
 func ComputeSessionKeyAES(sharedSecret, clientChallenge, serverChallenge, sharedSecretHash = nil interface{}){
    // added the ability to receive hashes already
    if sharedSecretHash == nil {
        M4SS = ntlm.NTOWFv1(sharedSecret)
    } else  {
        M4SS = sharedSecretHash

    hm = hmac.new(key=M4SS, digestmod=hashlib.sha256)
    hm.update(clientChallenge)
    hm.update(serverChallenge)
    sessionKey = hm.digest()

    return sessionKey[:16]

// 3.1.4.3.2 Strong-key Session-Key
 func ComputeSessionKeyStrongKey(sharedSecret, clientChallenge, serverChallenge, sharedSecretHash = nil interface{}){
    // added the ability to receive hashes already

    if sharedSecretHash == nil {
        M4SS = ntlm.NTOWFv1(sharedSecret)
    } else  {
        M4SS = sharedSecretHash

    md5 = hashlib.new("md5")
    md5.update(b'\x00'*4)
    md5.update(clientChallenge)
    md5.update(serverChallenge)
    finalMD5 = md5.digest()
    hm = hmac.new(M4SS) 
    hm.update(finalMD5)
    return hm.digest()

 func deriveSequenceNumber(sequenceNum interface{}){
    sequenceLow = sequenceNum & 0xffffffff
    sequenceHigh = (sequenceNum >> 32) & 0xffffffff
    sequenceHigh |= 0x80000000

    res = pack('>L', sequenceLow)
    res += pack('>L', sequenceHigh)
    return res

 func ComputeNetlogonSignatureAES(authSignature, message, confounder, sessionKey interface{}){
    // [MS-NRPC] Section 3.3.4.2.1, point 7
    hm = hmac.new(key=sessionKey, digestmod=hashlib.sha256)
    hm.update(str(authSignature)[:8])
    // If no confidentiality requested, it should be ''
    hm.update(confounder)
    hm.update(str(message))
    return hm.digest()[:8]+'\x00'*24

 func ComputeNetlogonSignatureMD5(authSignature, message, confounder, sessionKey interface{}){
    // [MS-NRPC] Section 3.3.4.2.1, point 7
    md5 = hashlib.new("md5")
    md5.update('\x00'*4)
    md5.update(str(authSignature)[:8])
    // If no confidentiality requested, it should be ''
    md5.update(confounder)
    md5.update(str(message))
    finalMD5 = md5.digest()
    hm = hmac.new(sessionKey)
    hm.update(finalMD5)
    return hm.digest()[:8]

 func encryptSequenceNumberRC4(sequenceNum, checkSum, sessionKey interface{}){
    // [MS-NRPC] Section 3.3.4.2.1, point 9

    hm = hmac.new(sessionKey)
    hm.update('\x00'*4)
    hm2 = hmac.new(hm.digest())
    hm2.update(checkSum)
    encryptionKey = hm2.digest()

    cipher = ARC4.new(encryptionKey)
    return cipher.encrypt(sequenceNum)

 func decryptSequenceNumberRC4(sequenceNum, checkSum, sessionKey interface{}){
    // [MS-NRPC] Section 3.3.4.2.2, point 5

    return encryptSequenceNumberRC4(sequenceNum, checkSum, sessionKey)

 func encryptSequenceNumberAES(sequenceNum, checkSum, sessionKey interface{}){
    // [MS-NRPC] Section 3.3.4.2.1, point 9
    IV = checkSum[:8] + checkSum[:8]
    Cipher = AES.new(sessionKey, AES.MODE_CFB, IV)
    return Cipher.encrypt(sequenceNum)

 func decryptSequenceNumberAES(sequenceNum, checkSum, sessionKey interface{}){
    // [MS-NRPC] Section 3.3.4.2.1, point 9
    IV = checkSum[:8] + checkSum[:8]
    Cipher = AES.new(sessionKey, AES.MODE_CFB, IV)
    return Cipher.decrypt(sequenceNum)

 func SIGN(data, confounder, sequenceNum, key, aes = false interface{}){
    if aes is false {
        signature = NL_AUTH_SIGNATURE()
        signature["SignatureAlgorithm"] = NL_SIGNATURE_HMAC_MD5
        if confounder == '' {
            signature["SealAlgorithm"] = NL_SEAL_NOT_ENCRYPTED
        } else  {
            signature["SealAlgorithm"] = NL_SEAL_RC4
        signature["Checksum"] = ComputeNetlogonSignatureMD5(signature, data, confounder, key)
        signature["SequenceNumber"] = encryptSequenceNumberRC4(deriveSequenceNumber(sequenceNum), signature["Checksum"], key)
        return signature
    } else  {
        signature = NL_AUTH_SIGNATURE()
        signature["SignatureAlgorithm"] = NL_SIGNATURE_HMAC_SHA256
        if confounder == '' {
            signature["SealAlgorithm"] = NL_SEAL_NOT_ENCRYPTED
        } else  {
            signature["SealAlgorithm"] = NL_SEAL_AES128
        signature["Checksum"] = ComputeNetlogonSignatureAES(signature, data, confounder, key)
        signature["SequenceNumber"] = encryptSequenceNumberAES(deriveSequenceNumber(sequenceNum), signature["Checksum"], key)
        return signature

 func SEAL(data, confounder, sequenceNum, key, aes = false interface{}){
    signature = SIGN(data, confounder, sequenceNum, key, aes)
    sequenceNum = deriveSequenceNumber(sequenceNum)
    XorKey = []
    for i in key:
       XorKey.append(chr(ord(i) ^ 0xf0))

    XorKey = "".join(XorKey)
    if aes is false {
        hm = hmac.new(XorKey)
        hm.update('\x00'*4)
        hm2 = hmac.new(hm.digest())
        hm2.update(sequenceNum)
        encryptionKey = hm2.digest()

        cipher = ARC4.new(encryptionKey)
        cfounder = cipher.encrypt(confounder)
        cipher = ARC4.new(encryptionKey)
        encrypted = cipher.encrypt(data)

        signature["Confounder"] = cfounder

        return encrypted, signature
    } else  {
        IV = sequenceNum + sequenceNum
        cipher = AES.new(XorKey, AES.MODE_CFB, IV)
        cfounder = cipher.encrypt(confounder)
        encrypted = cipher.encrypt(data)

        signature["Confounder"] = cfounder

        return encrypted, signature
        
 func UNSEAL(data, auth_data, key, aes = false interface{}){
    auth_data = NL_AUTH_SIGNATURE(auth_data)
    XorKey = []
    for i in key:
       XorKey.append(chr(ord(i) ^ 0xf0))

    XorKey = "".join(XorKey)
    if aes is false {
        sequenceNum = decryptSequenceNumberRC4(auth_data["SequenceNumber"], auth_data["Checksum"],  key)
        hm = hmac.new(XorKey)
        hm.update('\x00'*4)
        hm2 = hmac.new(hm.digest())
        hm2.update(sequenceNum)
        encryptionKey = hm2.digest()

        cipher = ARC4.new(encryptionKey)
        cfounder = cipher.encrypt(auth_data["Confounder"])
        cipher = ARC4.new(encryptionKey)
        plain = cipher.encrypt(data)

        return plain, cfounder
    } else  {
        sequenceNum = decryptSequenceNumberAES(auth_data["SequenceNumber"], auth_data["Checksum"],  key)
        IV = sequenceNum + sequenceNum
        cipher = AES.new(XorKey, AES.MODE_CFB, IV)
        cfounder = cipher.decrypt(auth_data["Confounder"])
        plain = cipher.decrypt(data)
        return plain, cfounder
        
    
 func getSSPType1(workstation='', domain='', signingRequired=false interface{}){
    auth = NL_AUTH_MESSAGE()
    auth["Flags"] = 0
    auth["Buffer"] = ""
    auth["Flags"] |= NL_AUTH_MESSAGE_NETBIOS_DOMAIN 
    if domain != '' {
        auth["Buffer"] = auth["Buffer"] + domain + '\x00'
    } else  {
        auth["Buffer"] += 'WORKGROUP\x00'

    auth["Flags"] |= NL_AUTH_MESSAGE_NETBIOS_HOST 
    if workstation != '' {
        auth["Buffer"] = auth["Buffer"] + workstation + '\x00'
    } else  {
        auth["Buffer"] += 'MYHOST\x00'

    auth["Flags"] |= NL_AUTH_MESSAGE_NETBIOS_HOST_UTF8 
    if workstation != '' {
        auth["Buffer"] += pack('<B',len(workstation)) + workstation + '\x00'
    } else  {
        auth["Buffer"] += '\x06MYHOST\x00'

    return auth

//###############################################################################
// RPC CALLS
//###############################################################################
// 3.5.4.3.1 DsrGetDcNameEx2 (Opnum 34)
 type DsrGetDcNameEx2 struct { // NDRCALL:
    opnum = 34 (
       ('ComputerName',PLOGONSRV_HANDLE),
       ('AccountName', LPWSTR),
       ('AllowableAccountControlBits', ULONG),
       ('DomainName',LPWSTR),
       ('DomainGuid',PGUID),
       ('SiteName',LPWSTR),
       ('Flags',ULONG),
    }

 type DsrGetDcNameEx2Response struct { // NDRCALL: (
       ('DomainControllerInfo',PDOMAIN_CONTROLLER_INFOW),
       ('ErrorCode',NET_API_STATUS),
    }

// 3.5.4.3.2 DsrGetDcNameEx (Opnum 27)
 type DsrGetDcNameEx struct { // NDRCALL:
    opnum = 27 (
       ('ComputerName',PLOGONSRV_HANDLE),
       ('DomainName',LPWSTR),
       ('DomainGuid',PGUID),
       ('SiteName',LPWSTR),
       ('Flags',ULONG),
    }

 type DsrGetDcNameExResponse struct { // NDRCALL: (
       ('DomainControllerInfo',PDOMAIN_CONTROLLER_INFOW),
       ('ErrorCode',NET_API_STATUS),
    }

// 3.5.4.3.3 DsrGetDcName (Opnum 20)
 type DsrGetDcName struct { // NDRCALL:
    opnum = 20 (
       ('ComputerName',PLOGONSRV_HANDLE),
       ('DomainName',LPWSTR),
       ('DomainGuid',PGUID),
       ('SiteGuid',PGUID),
       ('Flags',ULONG),
    }

 type DsrGetDcNameResponse struct { // NDRCALL: (
       ('DomainControllerInfo',PDOMAIN_CONTROLLER_INFOW),
       ('ErrorCode',NET_API_STATUS),
    }

// 3.5.4.3.4 NetrGetDCName (Opnum 11)
 type NetrGetDCName struct { // NDRCALL:
    opnum = 11 (
       ('ServerName',LOGONSRV_HANDLE),
       ('DomainName',LPWSTR),
    }

 type NetrGetDCNameResponse struct { // NDRCALL: (
       ('Buffer',LPWSTR),
       ('ErrorCode',NET_API_STATUS),
    }

// 3.5.4.3.5 NetrGetAnyDCName (Opnum 13)
 type NetrGetAnyDCName struct { // NDRCALL:
    opnum = 13 (
       ('ServerName',PLOGONSRV_HANDLE),
       ('DomainName',LPWSTR),
    }

 type NetrGetAnyDCNameResponse struct { // NDRCALL: (
       ('Buffer',LPWSTR),
       ('ErrorCode',NET_API_STATUS),
    }

// 3.5.4.3.6 DsrGetSiteName (Opnum 28)
 type DsrGetSiteName struct { // NDRCALL:
    opnum = 28 (
       ('ComputerName',PLOGONSRV_HANDLE),
    }

 type DsrGetSiteNameResponse struct { // NDRCALL: (
       ('SiteName',LPWSTR),
       ('ErrorCode',NET_API_STATUS),
    }

// 3.5.4.3.7 DsrGetDcSiteCoverageW (Opnum 38)
 type DsrGetDcSiteCoverageW struct { // NDRCALL:
    opnum = 38 (
       ('ServerName',PLOGONSRV_HANDLE),
    }

 type DsrGetDcSiteCoverageWResponse struct { // NDRCALL: (
       ('SiteNames',PNL_SITE_NAME_ARRAY),
       ('ErrorCode',NET_API_STATUS),
    }

// 3.5.4.3.8 DsrAddressToSiteNamesW (Opnum 33)
 type DsrAddressToSiteNamesW struct { // NDRCALL:
    opnum = 33 (
       ('ComputerName',PLOGONSRV_HANDLE),
       ('EntryCount',ULONG),
       ('SocketAddresses',NL_SOCKET_ADDRESS_ARRAY),
    }

 type DsrAddressToSiteNamesWResponse struct { // NDRCALL: (
       ('SiteNames',PNL_SITE_NAME_ARRAY),
       ('ErrorCode',NET_API_STATUS),
    }

// 3.5.4.3.9 DsrAddressToSiteNamesExW (Opnum 37)
 type DsrAddressToSiteNamesExW struct { // NDRCALL:
    opnum = 37 (
       ('ComputerName',PLOGONSRV_HANDLE),
       ('EntryCount',ULONG),
       ('SocketAddresses',NL_SOCKET_ADDRESS_ARRAY),
    }

 type DsrAddressToSiteNamesExWResponse struct { // NDRCALL: (
       ('SiteNames',PNL_SITE_NAME_EX_ARRAY),
       ('ErrorCode',NET_API_STATUS),
    }

// 3.5.4.3.10 DsrDeregisterDnsHostRecords (Opnum 41)
 type DsrDeregisterDnsHostRecords struct { // NDRCALL:
    opnum = 41 (
       ('ServerName',PLOGONSRV_HANDLE),
       ('DnsDomainName',LPWSTR),
       ('DomainGuid',PGUID),
       ('DsaGuid',PGUID),
       ('DnsHostName',WSTR),
    }

 type DsrDeregisterDnsHostRecordsResponse struct { // NDRCALL: (
       ('ErrorCode',NET_API_STATUS),
    }

// 3.5.4.3.11 DSRUpdateReadOnlyServerDnsRecords (Opnum 48)
 type DSRUpdateReadOnlyServerDnsRecords struct { // NDRCALL:
    opnum = 48 (
       ('ServerName',PLOGONSRV_HANDLE),
       ('ComputerName',WSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
       ('SiteName',LPWSTR),
       ('DnsTtl',ULONG),
       ('DnsNames',NL_DNS_NAME_INFO_ARRAY),
    }

 type DSRUpdateReadOnlyServerDnsRecordsResponse struct { // NDRCALL: (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('DnsNames',NL_DNS_NAME_INFO_ARRAY),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.4.1 NetrServerReqChallenge (Opnum 4)
 type NetrServerReqChallenge struct { // NDRCALL:
    opnum = 4 (
       ('PrimaryName',PLOGONSRV_HANDLE),
       ('ComputerName',WSTR),
       ('ClientChallenge',NETLOGON_CREDENTIAL),
    }

 type NetrServerReqChallengeResponse struct { // NDRCALL: (
       ('ServerChallenge',NETLOGON_CREDENTIAL),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.4.2 NetrServerAuthenticate3 (Opnum 26)
 type NetrServerAuthenticate3 struct { // NDRCALL:
    opnum = 26 (
       ('PrimaryName',PLOGONSRV_HANDLE),
       ('AccountName',WSTR),
       ('SecureChannelType',NETLOGON_SECURE_CHANNEL_TYPE),
       ('ComputerName',WSTR),
       ('ClientCredential',NETLOGON_CREDENTIAL),
       ('NegotiateFlags',ULONG),
    }

 type NetrServerAuthenticate3Response struct { // NDRCALL: (
       ('ServerCredential',NETLOGON_CREDENTIAL),
       ('NegotiateFlags',ULONG),
       ('AccountRid',ULONG),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.4.3 NetrServerAuthenticate2 (Opnum 15)
 type NetrServerAuthenticate2 struct { // NDRCALL:
    opnum = 15 (
       ('PrimaryName',PLOGONSRV_HANDLE),
       ('AccountName',WSTR),
       ('SecureChannelType',NETLOGON_SECURE_CHANNEL_TYPE),
       ('ComputerName',WSTR),
       ('ClientCredential',NETLOGON_CREDENTIAL),
       ('NegotiateFlags',ULONG),
    }

 type NetrServerAuthenticate2Response struct { // NDRCALL: (
       ('ServerCredential',NETLOGON_CREDENTIAL),
       ('NegotiateFlags',ULONG),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.4.4 NetrServerAuthenticate (Opnum 5)
 type NetrServerAuthenticate struct { // NDRCALL:
    opnum = 5 (
       ('PrimaryName',PLOGONSRV_HANDLE),
       ('AccountName',WSTR),
       ('SecureChannelType',NETLOGON_SECURE_CHANNEL_TYPE),
       ('ComputerName',WSTR),
       ('ClientCredential',NETLOGON_CREDENTIAL),
    }

 type NetrServerAuthenticateResponse struct { // NDRCALL: (
       ('ServerCredential',NETLOGON_CREDENTIAL),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.4.5 NetrServerPasswordSet2 (Opnum 30)

// 3.5.4.4.6 NetrServerPasswordSet (Opnum 6)

// 3.5.4.4.7 NetrServerPasswordGet (Opnum 31)
 type NetrServerPasswordGet struct { // NDRCALL:
    opnum = 31 (
       ('PrimaryName',PLOGONSRV_HANDLE),
       ('AccountName',WSTR),
       ('AccountType',NETLOGON_SECURE_CHANNEL_TYPE),
       ('ComputerName',WSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
    }

 type NetrServerPasswordGetResponse struct { // NDRCALL: (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('EncryptedNtOwfPassword',ENCRYPTED_NT_OWF_PASSWORD),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.4.8 NetrServerTrustPasswordsGet (Opnum 42)
 type NetrServerTrustPasswordsGet struct { // NDRCALL:
    opnum = 42 (
       ('TrustedDcName',PLOGONSRV_HANDLE),
       ('AccountName',WSTR),
       ('SecureChannelType',NETLOGON_SECURE_CHANNEL_TYPE),
       ('ComputerName',WSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
    }

 type NetrServerTrustPasswordsGetResponse struct { // NDRCALL: (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('EncryptedNewOwfPassword',ENCRYPTED_NT_OWF_PASSWORD),
       ('EncryptedOldOwfPassword',ENCRYPTED_NT_OWF_PASSWORD),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.4.9 NetrLogonGetDomainInfo (Opnum 29)
 type NetrLogonGetDomainInfo struct { // NDRCALL:
    opnum = 29 (
       ('ServerName',LOGONSRV_HANDLE),
       ('ComputerName',LPWSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('Level',DWORD),
       ('WkstaBuffer',NETLOGON_WORKSTATION_INFORMATION),
    }

 type NetrLogonGetDomainInfoResponse struct { // NDRCALL: (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('DomBuffer',NETLOGON_DOMAIN_INFORMATION),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.4.10 NetrLogonGetCapabilities (Opnum 21)
 type NetrLogonGetCapabilities struct { // NDRCALL:
    opnum = 21 (
       ('ServerName',LOGONSRV_HANDLE),
       ('ComputerName',LPWSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('QueryLevel',DWORD),
    }

 type NetrLogonGetCapabilitiesResponse struct { // NDRCALL: (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('ServerCapabilities',NETLOGON_CAPABILITIES),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.4.11 NetrChainSetClientAttributes (Opnum 49)

// 3.5.4.5.1 NetrLogonSamLogonEx (Opnum 39)
 type NetrLogonSamLogonEx struct { // NDRCALL:
    opnum = 39 (
       ('LogonServer',LPWSTR),
       ('ComputerName',LPWSTR),
       ('LogonLevel',NETLOGON_LOGON_INFO_CLASS),
       ('LogonInformation',NETLOGON_LEVEL),
       ('ValidationLevel',NETLOGON_VALIDATION_INFO_CLASS),
       ('ExtraFlags',ULONG),
    }

 type NetrLogonSamLogonExResponse struct { // NDRCALL: (
       ('ValidationInformation',NETLOGON_VALIDATION),
       ('Authoritative',UCHAR),
       ('ExtraFlags',ULONG),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.5.2 NetrLogonSamLogonWithFlags (Opnum 45)
 type NetrLogonSamLogonWithFlags struct { // NDRCALL:
    opnum = 45 (
       ('LogonServer',LPWSTR),
       ('ComputerName',LPWSTR),
       ('Authenticator',PNETLOGON_AUTHENTICATOR),
       ('ReturnAuthenticator',PNETLOGON_AUTHENTICATOR),
       ('LogonLevel',NETLOGON_LOGON_INFO_CLASS),
       ('LogonInformation',NETLOGON_LEVEL),
       ('ValidationLevel',NETLOGON_VALIDATION_INFO_CLASS),
       ('ExtraFlags',ULONG),
    }

 type NetrLogonSamLogonWithFlagsResponse struct { // NDRCALL: (
       ('ReturnAuthenticator',PNETLOGON_AUTHENTICATOR),
       ('ValidationInformation',NETLOGON_VALIDATION),
       ('Authoritative',UCHAR),
       ('ExtraFlags',ULONG),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.5.3 NetrLogonSamLogon (Opnum 2)
 type NetrLogonSamLogon struct { // NDRCALL:
    opnum = 2 (
       ('LogonServer',LPWSTR),
       ('ComputerName',LPWSTR),
       ('Authenticator',PNETLOGON_AUTHENTICATOR),
       ('ReturnAuthenticator',PNETLOGON_AUTHENTICATOR),
       ('LogonLevel',NETLOGON_LOGON_INFO_CLASS),
       ('LogonInformation',NETLOGON_LEVEL),
       ('ValidationLevel',NETLOGON_VALIDATION_INFO_CLASS),
    }

 type NetrLogonSamLogonResponse struct { // NDRCALL: (
       ('ReturnAuthenticator',PNETLOGON_AUTHENTICATOR),
       ('ValidationInformation',NETLOGON_VALIDATION),
       ('Authoritative',UCHAR),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.5.4 NetrLogonSamLogoff (Opnum 3)
 type NetrLogonSamLogoff struct { // NDRCALL:
    opnum = 3 (
       ('LogonServer',LPWSTR),
       ('ComputerName',LPWSTR),
       ('Authenticator',PNETLOGON_AUTHENTICATOR),
       ('ReturnAuthenticator',PNETLOGON_AUTHENTICATOR),
       ('LogonLevel',NETLOGON_LOGON_INFO_CLASS),
       ('LogonInformation',NETLOGON_LEVEL),
    }

 type NetrLogonSamLogoffResponse struct { // NDRCALL: (
       ('ReturnAuthenticator',PNETLOGON_AUTHENTICATOR),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.6.1 NetrDatabaseDeltas (Opnum 7)
 type NetrDatabaseDeltas struct { // NDRCALL:
    opnum = 7 (
       ('PrimaryName',LOGONSRV_HANDLE),
       ('ComputerName',WSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('DatabaseID',DWORD),
       ('DomainModifiedCount',NLPR_MODIFIED_COUNT),
       ('PreferredMaximumLength',DWORD),
    }

 type NetrDatabaseDeltasResponse struct { // NDRCALL: (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('DomainModifiedCount',NLPR_MODIFIED_COUNT),
       ('DeltaArray',PNETLOGON_DELTA_ENUM_ARRAY),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.6.2 NetrDatabaseSync2 (Opnum 16)
 type NetrDatabaseSync2 struct { // NDRCALL:
    opnum = 16 (
       ('PrimaryName',LOGONSRV_HANDLE),
       ('ComputerName',WSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('DatabaseID',DWORD),
       ('RestartState',SYNC_STATE),
       ('SyncContext',ULONG),
       ('PreferredMaximumLength',DWORD),
    }

 type NetrDatabaseSync2Response struct { // NDRCALL: (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('SyncContext',ULONG),
       ('DeltaArray',PNETLOGON_DELTA_ENUM_ARRAY),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.6.3 NetrDatabaseSync (Opnum 8)
 type NetrDatabaseSync struct { // NDRCALL:
    opnum = 8 (
       ('PrimaryName',LOGONSRV_HANDLE),
       ('ComputerName',WSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('DatabaseID',DWORD),
       ('SyncContext',ULONG),
       ('PreferredMaximumLength',DWORD),
    }

 type NetrDatabaseSyncResponse struct { // NDRCALL: (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('SyncContext',ULONG),
       ('DeltaArray',PNETLOGON_DELTA_ENUM_ARRAY),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.6.4 NetrDatabaseRedo (Opnum 17)
 type NetrDatabaseRedo struct { // NDRCALL:
    opnum = 17 (
       ('PrimaryName',LOGONSRV_HANDLE),
       ('ComputerName',WSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('ChangeLogEntry',PUCHAR_ARRAY),
       ('ChangeLogEntrySize',DWORD),
    }

 type NetrDatabaseRedoResponse struct { // NDRCALL: (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('DeltaArray',PNETLOGON_DELTA_ENUM_ARRAY),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.7.1 DsrEnumerateDomainTrusts (Opnum 40)
 type DsrEnumerateDomainTrusts struct { // NDRCALL:
    opnum = 40 (
       ('ServerName',PLOGONSRV_HANDLE),
       ('Flags',ULONG),
    }

 type DsrEnumerateDomainTrustsResponse struct { // NDRCALL: (
       ('Domains',NETLOGON_TRUSTED_DOMAIN_ARRAY),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.7.2 NetrEnumerateTrustedDomainsEx (Opnum 36)
 type NetrEnumerateTrustedDomainsEx struct { // NDRCALL:
    opnum = 36 (
       ('ServerName',PLOGONSRV_HANDLE),
    }

 type NetrEnumerateTrustedDomainsExResponse struct { // NDRCALL: (
       ('Domains',NETLOGON_TRUSTED_DOMAIN_ARRAY),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.7.3 NetrEnumerateTrustedDomains (Opnum 19)
 type NetrEnumerateTrustedDomains struct { // NDRCALL:
    opnum = 19 (
       ('ServerName',PLOGONSRV_HANDLE),
    }

 type NetrEnumerateTrustedDomainsResponse struct { // NDRCALL: (
       ('DomainNameBuffer',DOMAIN_NAME_BUFFER),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.7.4 NetrGetForestTrustInformation (Opnum 44)
 type NetrGetForestTrustInformation struct { // NDRCALL:
    opnum = 44 (
       ('ServerName',PLOGONSRV_HANDLE),
       ('ComputerName',WSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('Flags',DWORD),
    }

 type NetrGetForestTrustInformationResponse struct { // NDRCALL: (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('ForestTrustInfo',PLSA_FOREST_TRUST_INFORMATION),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.7.5 DsrGetForestTrustInformation (Opnum 43)
 type DsrGetForestTrustInformation struct { // NDRCALL:
    opnum = 43 (
       ('ServerName',PLOGONSRV_HANDLE),
       ('TrustedDomainName',LPWSTR),
       ('Flags',DWORD),
    }

 type DsrGetForestTrustInformationResponse struct { // NDRCALL: (
       ('ForestTrustInfo',PLSA_FOREST_TRUST_INFORMATION),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.7.6 NetrServerGetTrustInfo (Opnum 46)
 type NetrServerGetTrustInfo struct { // NDRCALL:
    opnum = 46 (
       ('TrustedDcName',PLOGONSRV_HANDLE),
       ('AccountName',WSTR),
       ('SecureChannelType',NETLOGON_SECURE_CHANNEL_TYPE),
       ('ComputerName',WSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
    }

 type NetrServerGetTrustInfoResponse struct { // NDRCALL: (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('EncryptedNewOwfPassword',ENCRYPTED_NT_OWF_PASSWORD),
       ('EncryptedOldOwfPassword',ENCRYPTED_NT_OWF_PASSWORD),
       ('TrustInfo',PNL_GENERIC_RPC_DATA),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.8.1 NetrLogonGetTrustRid (Opnum 23)
 type NetrLogonGetTrustRid struct { // NDRCALL:
    opnum = 23 (
       ('ServerName',PLOGONSRV_HANDLE),
       ('DomainName',LPWSTR),
    }

 type NetrLogonGetTrustRidResponse struct { // NDRCALL: (
       ('Rid',ULONG),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.8.2 NetrLogonComputeServerDigest (Opnum 24)
 type NetrLogonComputeServerDigest struct { // NDRCALL:
    opnum = 24 (
       ('ServerName',PLOGONSRV_HANDLE),
       ('Rid',ULONG),
       ('Message',UCHAR_ARRAY),
       ('MessageSize',ULONG),
    }

 type NetrLogonComputeServerDigestResponse struct { // NDRCALL: (
       ('NewMessageDigest',CHAR_FIXED_16_ARRAY),
       ('OldMessageDigest',CHAR_FIXED_16_ARRAY),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.8.3 NetrLogonComputeClientDigest (Opnum 25)
 type NetrLogonComputeClientDigest struct { // NDRCALL:
    opnum = 25 (
       ('ServerName',PLOGONSRV_HANDLE),
       ('DomainName',LPWSTR),
       ('Message',UCHAR_ARRAY),
       ('MessageSize',ULONG),
    }

 type NetrLogonComputeClientDigestResponse struct { // NDRCALL: (
       ('NewMessageDigest',CHAR_FIXED_16_ARRAY),
       ('OldMessageDigest',CHAR_FIXED_16_ARRAY),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.8.4 NetrLogonSendToSam (Opnum 32)
 type NetrLogonSendToSam struct { // NDRCALL:
    opnum = 32 (
       ('PrimaryName',PLOGONSRV_HANDLE),
       ('ComputerName',WSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
       ('OpaqueBuffer',UCHAR_ARRAY),
       ('OpaqueBufferSize',ULONG),
    }

 type NetrLogonSendToSamResponse struct { // NDRCALL: (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.8.5 NetrLogonSetServiceBits (Opnum 22)
 type NetrLogonSetServiceBits struct { // NDRCALL:
    opnum = 22 (
       ('ServerName',PLOGONSRV_HANDLE),
       ('ServiceBitsOfInterest',DWORD),
       ('ServiceBits',DWORD),
    }

 type NetrLogonSetServiceBitsResponse struct { // NDRCALL: (
       ('ErrorCode',NTSTATUS),
    }

// 3.5.4.8.6 NetrLogonGetTimeServiceParentDomain (Opnum 35)
 type NetrLogonGetTimeServiceParentDomain struct { // NDRCALL:
    opnum = 35 (
       ('ServerName',PLOGONSRV_HANDLE),
    }

 type NetrLogonGetTimeServiceParentDomainResponse struct { // NDRCALL: (
       ('DomainName',LPWSTR),
       ('PdcSameSite',LONG),
       ('ErrorCode',NET_API_STATUS),
    }

// 3.5.4.9.1 NetrLogonControl2Ex (Opnum 18)
 type NetrLogonControl2Ex struct { // NDRCALL:
    opnum = 18 (
       ('ServerName',PLOGONSRV_HANDLE),
       ('FunctionCode',DWORD),
       ('QueryLevel',DWORD),
       ('Data',NETLOGON_CONTROL_DATA_INFORMATION),
    }

 type NetrLogonControl2ExResponse struct { // NDRCALL: (
       ('Buffer',NETLOGON_CONTROL_DATA_INFORMATION),
       ('ErrorCode',NET_API_STATUS),
    }

// 3.5.4.9.2 NetrLogonControl2 (Opnum 14)
 type NetrLogonControl2 struct { // NDRCALL:
    opnum = 14 (
       ('ServerName',PLOGONSRV_HANDLE),
       ('FunctionCode',DWORD),
       ('QueryLevel',DWORD),
       ('Data',NETLOGON_CONTROL_DATA_INFORMATION),
    }

 type NetrLogonControl2Response struct { // NDRCALL: (
       ('Buffer',NETLOGON_CONTROL_DATA_INFORMATION),
       ('ErrorCode',NET_API_STATUS),
    }

// 3.5.4.9.3 NetrLogonControl (Opnum 12)
 type NetrLogonControl struct { // NDRCALL:
    opnum = 12 (
       ('ServerName',PLOGONSRV_HANDLE),
       ('FunctionCode',DWORD),
       ('QueryLevel',DWORD),
       ('Data',NETLOGON_CONTROL_DATA_INFORMATION),
    }

 type NetrLogonControlResponse struct { // NDRCALL: (
       ('Buffer',NETLOGON_CONTROL_DATA_INFORMATION),
       ('ErrorCode',NET_API_STATUS),
    }

// 3.5.4.10.1 NetrLogonUasLogon (Opnum 0)
 type NetrLogonUasLogon struct { // NDRCALL:
    opnum = 0 (
       ('ServerName',PLOGONSRV_HANDLE),
       ('UserName',WSTR),
       ('Workstation',WSTR),
    }

 type NetrLogonUasLogonResponse struct { // NDRCALL: (
       ('ValidationInformation',PNETLOGON_VALIDATION_UAS_INFO),
       ('ErrorCode',NET_API_STATUS),
    }

// 3.5.4.10.2 NetrLogonUasLogoff (Opnum 1)
 type NetrLogonUasLogoff struct { // NDRCALL:
    opnum = 1 (
       ('ServerName',PLOGONSRV_HANDLE),
       ('UserName',WSTR),
       ('Workstation',WSTR),
    }

 type NetrLogonUasLogoffResponse struct { // NDRCALL: (
       ('LogoffInformation',NETLOGON_LOGOFF_UAS_INFO),
       ('ErrorCode',NET_API_STATUS),
    }

//###############################################################################
// OPNUMs and their corresponding structures
//###############################################################################
OPNUMS = {
 0 : (NetrLogonUasLogon, NetrLogonUasLogonResponse),
 1 : (NetrLogonUasLogoff, NetrLogonUasLogoffResponse),
 2 : (NetrLogonSamLogon, NetrLogonSamLogonResponse),
 3 : (NetrLogonSamLogoff, NetrLogonSamLogoffResponse),
 4 : (NetrServerReqChallenge, NetrServerReqChallengeResponse),
 5 : (NetrServerAuthenticate, NetrServerAuthenticateResponse),
// 6 : (NetrServerPasswordSet, NetrServerPasswordSetResponse),
 7 : (NetrDatabaseDeltas, NetrDatabaseDeltasResponse),
 8 : (NetrDatabaseSync, NetrDatabaseSyncResponse),
// 9 : (NetrAccountDeltas, NetrAccountDeltasResponse),
// 10 : (NetrAccountSync, NetrAccountSyncResponse),
 11 : (NetrGetDCName, NetrGetDCNameResponse),
 12 : (NetrLogonControl, NetrLogonControlResponse),
 13 : (NetrGetAnyDCName, NetrGetAnyDCNameResponse),
 14 : (NetrLogonControl2, NetrLogonControl2Response),
 15 : (NetrServerAuthenticate2, NetrServerAuthenticate2Response),
 16 : (NetrDatabaseSync2, NetrDatabaseSync2Response),
 17 : (NetrDatabaseRedo, NetrDatabaseRedoResponse),
 18 : (NetrLogonControl2Ex, NetrLogonControl2ExResponse),
 19 : (NetrEnumerateTrustedDomains, NetrEnumerateTrustedDomainsResponse),
 20 : (DsrGetDcName, DsrGetDcNameResponse),
 21 : (NetrLogonGetCapabilities, NetrLogonGetCapabilitiesResponse),
 22 : (NetrLogonSetServiceBits, NetrLogonSetServiceBitsResponse),
 23 : (NetrLogonGetTrustRid, NetrLogonGetTrustRidResponse),
 24 : (NetrLogonComputeServerDigest, NetrLogonComputeServerDigestResponse),
 25 : (NetrLogonComputeClientDigest, NetrLogonComputeClientDigestResponse),
 26 : (NetrServerAuthenticate3, NetrServerAuthenticate3Response),
 27 : (DsrGetDcNameEx, DsrGetDcNameExResponse),
 28 : (DsrGetSiteName, DsrGetSiteNameResponse),
 29 : (NetrLogonGetDomainInfo, NetrLogonGetDomainInfoResponse),
// 30 : (NetrServerPasswordSet2, NetrServerPasswordSet2Response),
 31 : (NetrServerPasswordGet, NetrServerPasswordGetResponse),
 32 : (NetrLogonSendToSam, NetrLogonSendToSamResponse),
 33 : (DsrAddressToSiteNamesW, DsrAddressToSiteNamesWResponse),
 34 : (DsrGetDcNameEx2, DsrGetDcNameEx2Response),
 35 : (NetrLogonGetTimeServiceParentDomain, NetrLogonGetTimeServiceParentDomainResponse),
 36 : (NetrEnumerateTrustedDomainsEx, NetrEnumerateTrustedDomainsExResponse),
 37 : (DsrAddressToSiteNamesExW, DsrAddressToSiteNamesExWResponse),
 38 : (DsrGetDcSiteCoverageW, DsrGetDcSiteCoverageWResponse),
 39 : (NetrLogonSamLogonEx, NetrLogonSamLogonExResponse),
 40 : (DsrEnumerateDomainTrusts, DsrEnumerateDomainTrustsResponse),
 41 : (DsrDeregisterDnsHostRecords, DsrDeregisterDnsHostRecordsResponse),
 42 : (NetrServerTrustPasswordsGet, NetrServerTrustPasswordsGetResponse),
 43 : (DsrGetForestTrustInformation, DsrGetForestTrustInformationResponse),
 44 : (NetrGetForestTrustInformation, NetrGetForestTrustInformationResponse),
 45 : (NetrLogonSamLogonWithFlags, NetrLogonSamLogonWithFlagsResponse),
 46 : (NetrServerGetTrustInfo, NetrServerGetTrustInfoResponse),
// 48 : (DsrUpdateReadOnlyServerDnsRecords, DsrUpdateReadOnlyServerDnsRecordsResponse),
// 49 : (NetrChainSetClientAttributes, NetrChainSetClientAttributesResponse),
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

 func hNetrServerReqChallenge(dce, primaryName, computerName, clientChallenge interface{}){
    request = NetrServerReqChallenge()
    request["PrimaryName"] = checkNullString(primaryName)
    request["ComputerName"] = checkNullString(computerName)
    request["ClientChallenge"] = clientChallenge
    return dce.request(request)

 func hNetrServerAuthenticate3(dce, primaryName, accountName, secureChannelType, computerName, clientCredential, negotiateFlags interface{}){
    request = NetrServerAuthenticate3()
    request["PrimaryName"] = checkNullString(primaryName)
    request["AccountName"] = checkNullString(accountName)
    request["SecureChannelType"] = secureChannelType
    request["ClientCredential"] = clientCredential
    request["ComputerName"] = checkNullString(computerName)
    request["NegotiateFlags"] = negotiateFlags
    return dce.request(request)

 func hDsrGetDcNameEx2(dce, computerName, accountName, allowableAccountControlBits, domainName, domainGuid, siteName, flags interface{}){
    request = DsrGetDcNameEx2()
    request["ComputerName"] = checkNullString(computerName)
    request["AccountName"] = checkNullString(accountName)
    request["AllowableAccountControlBits"] = allowableAccountControlBits
    request["DomainName"] = checkNullString(domainName)
    request["DomainGuid"] = domainGuid
    request["SiteName"] = checkNullString(siteName)
    request["Flags"] = flags
    return dce.request(request)

 func hDsrGetDcNameEx(dce, computerName, domainName, domainGuid, siteName, flags interface{}){
    request = DsrGetDcNameEx()
    request["ComputerName"] = checkNullString(computerName)
    request["DomainName"] = checkNullString(domainName)
    request["DomainGuid"] = domainGuid
    request["SiteName"] = siteName
    request["Flags"] = flags
    return dce.request(request)

 func hDsrGetDcName(dce, computerName, domainName, domainGuid, siteGuid, flags interface{}){
    request = DsrGetDcName()
    request["ComputerName"] = checkNullString(computerName)
    request["DomainName"] = checkNullString(domainName)
    request["DomainGuid"] = domainGuid
    request["SiteGuid"] = siteGuid
    request["Flags"] = flags
    return dce.request(request)

 func hNetrGetAnyDCName(dce, serverName, domainName interface{}){
    request = NetrGetAnyDCName()
    request["ServerName"] = checkNullString(serverName)
    request["DomainName"] = checkNullString(domainName)
    return dce.request(request)

 func hNetrGetDCName(dce, serverName, domainName interface{}){
    request = NetrGetDCName()
    request["ServerName"] = checkNullString(serverName)
    request["DomainName"] = checkNullString(domainName)
    return dce.request(request)

 func hDsrGetSiteName(dce, computerName interface{}){
    request = DsrGetSiteName()
    request["ComputerName"] = checkNullString(computerName)
    return dce.request(request)

 func hDsrGetDcSiteCoverageW(dce, serverName interface{}){
    request = DsrGetDcSiteCoverageW()
    request["ServerName"] = checkNullString(serverName)
    return dce.request(request)

 func hNetrServerAuthenticate2(dce, primaryName, accountName, secureChannelType, computerName, clientCredential, negotiateFlags interface{}){
    request = NetrServerAuthenticate2()
    request["PrimaryName"] = checkNullString(primaryName)
    request["AccountName"] = checkNullString(accountName)
    request["SecureChannelType"] = secureChannelType
    request["ClientCredential"] = clientCredential
    request["ComputerName"] = checkNullString(computerName)
    request["NegotiateFlags"] = negotiateFlags
    return dce.request(request)

 func hNetrServerAuthenticate(dce, primaryName, accountName, secureChannelType, computerName, clientCredential interface{}){
    request = NetrServerAuthenticate()
    request["PrimaryName"] = checkNullString(primaryName)
    request["AccountName"] = checkNullString(accountName)
    request["SecureChannelType"] = secureChannelType
    request["ClientCredential"] = clientCredential
    request["ComputerName"] = checkNullString(computerName)
    return dce.request(request)

 func hNetrServerPasswordGet(dce, primaryName, accountName, accountType, computerName, authenticator interface{}){
    request = NetrServerPasswordGet()
    request["PrimaryName"] = checkNullString(primaryName)
    request["AccountName"] = checkNullString(accountName)
    request["AccountType"] = accountType
    request["ComputerName"] = checkNullString(computerName)
    request["Authenticator"] = authenticator
    return dce.request(request)

 func hNetrServerTrustPasswordsGet(dce, trustedDcName, accountName, secureChannelType, computerName, authenticator interface{}){
    request = NetrServerTrustPasswordsGet()
    request["TrustedDcName"] = checkNullString(trustedDcName)
    request["AccountName"] = checkNullString(accountName)
    request["SecureChannelType"] = secureChannelType
    request["ComputerName"] = checkNullString(computerName)
    request["Authenticator"] = authenticator
    return dce.request(request)

 func hNetrLogonGetDomainInfo(dce, serverName, computerName, authenticator, returnAuthenticator=0, level=1 interface{}){
    request = NetrLogonGetDomainInfo()
    request["ServerName"] = checkNullString(serverName)
    request["ComputerName"] = checkNullString(computerName)
    request["Authenticator"] = authenticator
    if returnAuthenticator == 0 {
        request["ReturnAuthenticator"]["Credential"] = b'\x00'*8
        request["ReturnAuthenticator"]["Timestamp"] = 0
    } else  {
        request["ReturnAuthenticator"] = returnAuthenticator

    request["Level"] = 1
    if level == 1 {
        request["WkstaBuffer"]["tag"] = 1
        request["WkstaBuffer"]["WorkstationInfo"]["DnsHostName"] = NULL
        request["WkstaBuffer"]["WorkstationInfo"]["SiteName"] = NULL
        request["WkstaBuffer"]["WorkstationInfo"]["OsName"] = ""
        request["WkstaBuffer"]["WorkstationInfo"]["Dummy1"] = NULL 
        request["WkstaBuffer"]["WorkstationInfo"]["Dummy2"] = NULL  
        request["WkstaBuffer"]["WorkstationInfo"]["Dummy3"] = NULL 
        request["WkstaBuffer"]["WorkstationInfo"]["Dummy4"] = NULL  
    } else  {
        request["WkstaBuffer"]["tag"] = 2
        request["WkstaBuffer"]["LsaPolicyInfo"]["LsaPolicy"] = NULL
    return dce.request(request)

 func hNetrLogonGetCapabilities(dce, serverName, computerName, authenticator, returnAuthenticator=0, queryLevel=1 interface{}){
    request = NetrLogonGetCapabilities()
    request["ServerName"] = checkNullString(serverName)
    request["ComputerName"] = checkNullString(computerName)
    request["Authenticator"] = authenticator
    if returnAuthenticator == 0 {
        request["ReturnAuthenticator"]["Credential"] = b'\x00'*8
        request["ReturnAuthenticator"]["Timestamp"] = 0
    } else  {
        request["ReturnAuthenticator"] = returnAuthenticator
    request["QueryLevel"] = queryLevel
    return dce.request(request)

 func hNetrServerGetTrustInfo(dce, trustedDcName, accountName, secureChannelType, computerName, authenticator interface{}){
    request = NetrServerGetTrustInfo()
    request["TrustedDcName"] = checkNullString(trustedDcName)
    request["AccountName"] = checkNullString(accountName)
    request["SecureChannelType"] = secureChannelType
    request["ComputerName"] = checkNullString(computerName)
    request["Authenticator"] = authenticator
    return dce.request(request)
