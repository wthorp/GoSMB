// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Author: Alberto Solino (@agsolino)
//
// Description:
//   [MS-LSAD] Interface implementation
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
from impacket.dcerpc.v5.ndr import NDRCALL, NDRENUM, NDRUNION, NDRUniConformantVaryingArray, NDRPOINTER, NDR, NDRSTRUCT, \
    NDRUniConformantArray
from impacket.dcerpc.v5.dtypes import DWORD, LPWSTR, STR, LUID, LONG, ULONG, RPC_UNICODE_STRING, PRPC_SID, LPBYTE, \
    LARGE_INTEGER, NTSTATUS, RPC_SID, ACCESS_MASK, UCHAR, PRPC_UNICODE_STRING, PLARGE_INTEGER, USHORT, \
    SECURITY_INFORMATION, NULL, MAXIMUM_ALLOWED, GUID, SECURITY_DESCRIPTOR, OWNER_SECURITY_INFORMATION
from impacket import nt_errors
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.enum import Enum
from impacket.dcerpc.v5.rpcrt import DCERPCException

MSRPC_UUID_LSAD  = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AB','0.0'))

 type DCERPCSessionError struct { // DCERPCException:
     func (self TYPE) __init__(error_string=nil, error_code=nil, packet=nil interface{}){
        DCERPCException.__init__(self, error_string, error_code, packet)

     func __str__( self  interface{}){
        key = self.error_code
        if key in nt_errors.ERROR_MESSAGES {
            error_msg_short = nt_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = nt_errors.ERROR_MESSAGES[key][1] 
            return 'LSAD SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        } else  {
            return 'LSAD SessionError: unknown error code: 0x%x' % self.error_code

//###############################################################################
// CONSTANTS
//###############################################################################
// 2.2.1.1.2 ACCESS_MASK for Policy Objects
POLICY_VIEW_LOCAL_INFORMATION   = 0x00000001
POLICY_VIEW_AUDIT_INFORMATION   = 0x00000002
POLICY_GET_PRIVATE_INFORMATION  = 0x00000004
POLICY_TRUST_ADMIN              = 0x00000008
POLICY_CREATE_ACCOUNT           = 0x00000010
POLICY_CREATE_SECRET            = 0x00000020
POLICY_CREATE_PRIVILEGE         = 0x00000040
POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080
POLICY_SET_AUDIT_REQUIREMENTS   = 0x00000100
POLICY_AUDIT_LOG_ADMIN          = 0x00000200
POLICY_SERVER_ADMIN             = 0x00000400
POLICY_LOOKUP_NAMES             = 0x00000800
POLICY_NOTIFICATION             = 0x00001000

// 2.2.1.1.3 ACCESS_MASK for Account Objects
ACCOUNT_VIEW                 = 0x00000001
ACCOUNT_ADJUST_PRIVILEGES    = 0x00000002
ACCOUNT_ADJUST_QUOTAS        = 0x00000004
ACCOUNT_ADJUST_SYSTEM_ACCESS = 0x00000008

// 2.2.1.1.4 ACCESS_MASK for Secret Objects
SECRET_SET_VALUE   = 0x00000001
SECRET_QUERY_VALUE = 0x00000002

// 2.2.1.1.5 ACCESS_MASK for Trusted Domain Objects
TRUSTED_QUERY_DOMAIN_NAME = 0x00000001
TRUSTED_QUERY_CONTROLLERS = 0x00000002
TRUSTED_SET_CONTROLLERS   = 0x00000004
TRUSTED_QUERY_POSIX       = 0x00000008
TRUSTED_SET_POSIX         = 0x00000010
TRUSTED_SET_AUTH          = 0x00000020
TRUSTED_QUERY_AUTH        = 0x00000040

// 2.2.1.2 POLICY_SYSTEM_ACCESS_MODE
POLICY_MODE_INTERACTIVE             = 0x00000001
POLICY_MODE_NETWORK                 = 0x00000002
POLICY_MODE_BATCH                   = 0x00000004
POLICY_MODE_SERVICE                 = 0x00000010
POLICY_MODE_DENY_INTERACTIVE        = 0x00000040
POLICY_MODE_DENY_NETWORK            = 0x00000080
POLICY_MODE_DENY_BATCH              = 0x00000100
POLICY_MODE_DENY_SERVICE            = 0x00000200
POLICY_MODE_REMOTE_INTERACTIVE      = 0x00000400
POLICY_MODE_DENY_REMOTE_INTERACTIVE = 0x00000800
POLICY_MODE_ALL                     = 0x00000FF7
POLICY_MODE_ALL_NT4                 = 0x00000037

// 2.2.4.4 LSAPR_POLICY_AUDIT_EVENTS_INFO
// EventAuditingOptions
POLICY_AUDIT_EVENT_UNCHANGED = 0x00000000
POLICY_AUDIT_EVENT_NONE      = 0x00000004
POLICY_AUDIT_EVENT_SUCCESS   = 0x00000001
POLICY_AUDIT_EVENT_FAILURE   = 0x00000002

// 2.2.4.19 POLICY_DOMAIN_KERBEROS_TICKET_INFO
// AuthenticationOptions
POLICY_KERBEROS_VALIDATE_CLIENT = 0x00000080

// 2.2.7.21 LSA_FOREST_TRUST_RECORD
// Flags
LSA_TLN_DISABLED_NEW          = 0x00000001
LSA_TLN_DISABLED_ADMIN        = 0x00000002
LSA_TLN_DISABLED_CONFLICT     = 0x00000004
LSA_SID_DISABLED_ADMIN        = 0x00000001
LSA_SID_DISABLED_CONFLICT     = 0x00000002
LSA_NB_DISABLED_ADMIN         = 0x00000004
LSA_NB_DISABLED_CONFLICT      = 0x00000008
LSA_FTRECORD_DISABLED_REASONS = 0x0000FFFF

//###############################################################################
// STRUCTURES
//###############################################################################
// 2.2.2.1 LSAPR_HANDLE
 type LSAPR_HANDLE struct { // NDRSTRUCT:
    align = 1  (
         Data [0]byte // =""
    }

// 2.2.2.3 LSA_UNICODE_STRING
LSA_UNICODE_STRING = RPC_UNICODE_STRING

// 2.2.3.1 STRING
 type STRING struct { // NDRSTRUCT:
    commonHdr = (
         MaximumLength uint16 // =len(Data)-12
         Length uint16 // =len(Data)-12
         ReferentID uint32 // =0xff
    }
    commonHdr64 = (
         MaximumLength uint16 // =len(Data)-24
         Length uint16 // =len(Data)-24
         ReferentID uint64 // =0xff
    }

    referent = (
        ('Data',STR),
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
            self.fields["MaximumLength"] = nil
            self.fields["Length"] = nil
            self.data = nil        // force recompute
        return NDR.__setitem__(self, key, value)

// 2.2.3.2 LSAPR_ACL
 type LSAPR_ACL struct { // NDRSTRUCT:  (
        ('AclRevision', UCHAR),
        ('Sbz1', UCHAR),
        ('AclSize', USHORT),
        ('Dummy1',NDRUniConformantArray),
    }

// 2.2.3.4 LSAPR_SECURITY_DESCRIPTOR
LSAPR_SECURITY_DESCRIPTOR = SECURITY_DESCRIPTOR

 type PLSAPR_SECURITY_DESCRIPTOR struct { // NDRPOINTER:
    referent = (
        ('Data', LSAPR_SECURITY_DESCRIPTOR),
    }

// 2.2.3.5 SECURITY_IMPERSONATION_LEVEL
 type SECURITY_IMPERSONATION_LEVEL struct { // NDRENUM:
     type enumItems struct { // Enum:
        SecurityAnonymous      = 0
        SecurityIdentification = 1
        SecurityImpersonation  = 2
        SecurityDelegation     = 3

// 2.2.3.6 SECURITY_CONTEXT_TRACKING_MODE
SECURITY_CONTEXT_TRACKING_MODE = UCHAR

// 2.2.3.7 SECURITY_QUALITY_OF_SERVICE
 type SECURITY_QUALITY_OF_SERVICE struct { // NDRSTRUCT: (
        ('Length', DWORD), 
        ('ImpersonationLevel', SECURITY_IMPERSONATION_LEVEL), 
        ('ContextTrackingMode', SECURITY_CONTEXT_TRACKING_MODE), 
        ('EffectiveOnly', UCHAR), 
    }

 type PSECURITY_QUALITY_OF_SERVICE struct { // NDRPOINTER:
    referent = (
        ('Data', SECURITY_QUALITY_OF_SERVICE),
    }

// 2.2.2.4 LSAPR_OBJECT_ATTRIBUTES
 type LSAPR_OBJECT_ATTRIBUTES struct { // NDRSTRUCT: (
        ('Length', DWORD), 
        ('RootDirectory', LPWSTR), 
        ('ObjectName', LPWSTR), 
        ('Attributes', DWORD), 
        ('SecurityDescriptor', PLSAPR_SECURITY_DESCRIPTOR), 
        ('SecurityQualityOfService', PSECURITY_QUALITY_OF_SERVICE), 
    }

// 2.2.2.5 LSAPR_SR_SECURITY_DESCRIPTOR
 type LSAPR_SR_SECURITY_DESCRIPTOR struct { // NDRSTRUCT: (
        ('Length', DWORD), 
        ('SecurityDescriptor', LPBYTE), 
    }

 type PLSAPR_SR_SECURITY_DESCRIPTOR struct { // NDRPOINTER:
    referent = (
        ('Data', LSAPR_SR_SECURITY_DESCRIPTOR),
    }

// 2.2.3.3 SECURITY_DESCRIPTOR_CONTROL
SECURITY_DESCRIPTOR_CONTROL = ULONG

// 2.2.4.1 POLICY_INFORMATION_CLASS
 type POLICY_INFORMATION_CLASS struct { // NDRENUM:
     type enumItems struct { // Enum:
        PolicyAuditLogInformation           = 1
        PolicyAuditEventsInformation        = 2
        PolicyPrimaryDomainInformation      = 3
        PolicyPdAccountInformation          = 4
        PolicyAccountDomainInformation      = 5
        PolicyLsaServerRoleInformation      = 6
        PolicyReplicaSourceInformation      = 7
        PolicyInformationNotUsedOnWire      = 8
        PolicyModificationInformation       = 9
        PolicyAuditFullSetInformation       = 10
        PolicyAuditFullQueryInformation     = 11
        PolicyDnsDomainInformation          = 12
        PolicyDnsDomainInformationInt       = 13
        PolicyLocalAccountDomainInformation = 14
        PolicyLastEntry                     = 15

// 2.2.4.3 POLICY_AUDIT_LOG_INFO
 type POLICY_AUDIT_LOG_INFO struct { // NDRSTRUCT: (
        ('AuditLogPercentFull', DWORD), 
        ('MaximumLogSize', DWORD), 
        ('AuditRetentionPeriod', LARGE_INTEGER), 
        ('AuditLogFullShutdownInProgress', UCHAR), 
        ('TimeToShutdown', LARGE_INTEGER), 
        ('NextAuditRecordId', DWORD), 
    }

// 2.2.4.4 LSAPR_POLICY_AUDIT_EVENTS_INFO
 type DWORD_ARRAY struct { // NDRUniConformantArray:
    item = DWORD

 type PDWORD_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', DWORD_ARRAY),
    }

 type LSAPR_POLICY_AUDIT_EVENTS_INFO struct { // NDRSTRUCT: (
        ('AuditingMode', UCHAR), 
        ('EventAuditingOptions', PDWORD_ARRAY), 
        ('MaximumAuditEventCount', DWORD), 
    }

// 2.2.4.5 LSAPR_POLICY_PRIMARY_DOM_INFO
 type LSAPR_POLICY_PRIMARY_DOM_INFO struct { // NDRSTRUCT: (
        ('Name', RPC_UNICODE_STRING), 
        ('Sid', PRPC_SID), 
    }

// 2.2.4.6 LSAPR_POLICY_ACCOUNT_DOM_INFO
 type LSAPR_POLICY_ACCOUNT_DOM_INFO struct { // NDRSTRUCT: (
        ('DomainName', RPC_UNICODE_STRING), 
        ('DomainSid', PRPC_SID), 
    }

// 2.2.4.7 LSAPR_POLICY_PD_ACCOUNT_INFO
 type LSAPR_POLICY_PD_ACCOUNT_INFO struct { // NDRSTRUCT: (
        ('Name', RPC_UNICODE_STRING), 
    }

// 2.2.4.8 POLICY_LSA_SERVER_ROLE
 type POLICY_LSA_SERVER_ROLE struct { // NDRENUM:
     type enumItems struct { // Enum:
        PolicyServerRoleBackup   = 2
        PolicyServerRolePrimary  = 3

// 2.2.4.9 POLICY_LSA_SERVER_ROLE_INFO
 type POLICY_LSA_SERVER_ROLE_INFO struct { // NDRSTRUCT: (
        ('LsaServerRole', POLICY_LSA_SERVER_ROLE), 
    }

// 2.2.4.10 LSAPR_POLICY_REPLICA_SRCE_INFO
 type LSAPR_POLICY_REPLICA_SRCE_INFO struct { // NDRSTRUCT: (
        ('ReplicaSource', RPC_UNICODE_STRING), 
        ('ReplicaAccountName', RPC_UNICODE_STRING), 
    }

// 2.2.4.11 POLICY_MODIFICATION_INFO
 type POLICY_MODIFICATION_INFO struct { // NDRSTRUCT: (
        ('ModifiedId', LARGE_INTEGER), 
        ('DatabaseCreationTime', LARGE_INTEGER), 
    }

// 2.2.4.12 POLICY_AUDIT_FULL_SET_INFO
 type POLICY_AUDIT_FULL_SET_INFO struct { // NDRSTRUCT: (
        ('ShutDownOnFull', UCHAR), 
    }

// 2.2.4.13 POLICY_AUDIT_FULL_QUERY_INFO
 type POLICY_AUDIT_FULL_QUERY_INFO struct { // NDRSTRUCT: (
        ('ShutDownOnFull', UCHAR), 
        ('LogIsFull', UCHAR), 
    }

// 2.2.4.14 LSAPR_POLICY_DNS_DOMAIN_INFO
 type LSAPR_POLICY_DNS_DOMAIN_INFO struct { // NDRSTRUCT: (
        ('Name', RPC_UNICODE_STRING), 
        ('DnsDomainName', RPC_UNICODE_STRING), 
        ('DnsForestName', RPC_UNICODE_STRING), 
        ('DomainGuid', GUID), 
        ('Sid', PRPC_SID), 
    }

// 2.2.4.2 LSAPR_POLICY_INFORMATION
 type LSAPR_POLICY_INFORMATION struct { // NDRUNION:
    union = {
        POLICY_INFORMATION_CLASS.PolicyAuditLogInformation          : ('PolicyAuditLogInfo', POLICY_AUDIT_LOG_INFO),
        POLICY_INFORMATION_CLASS.PolicyAuditEventsInformation       : ('PolicyAuditEventsInfo', LSAPR_POLICY_AUDIT_EVENTS_INFO),
        POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation     : ('PolicyPrimaryDomainInfo', LSAPR_POLICY_PRIMARY_DOM_INFO),
        POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation     : ('PolicyAccountDomainInfo', LSAPR_POLICY_ACCOUNT_DOM_INFO),
        POLICY_INFORMATION_CLASS.PolicyPdAccountInformation         : ('PolicyPdAccountInfo', LSAPR_POLICY_PD_ACCOUNT_INFO),
        POLICY_INFORMATION_CLASS.PolicyLsaServerRoleInformation     : ('PolicyServerRoleInfo', POLICY_LSA_SERVER_ROLE_INFO),
        POLICY_INFORMATION_CLASS.PolicyReplicaSourceInformation     : ('PolicyReplicaSourceInfo', LSAPR_POLICY_REPLICA_SRCE_INFO),
        POLICY_INFORMATION_CLASS.PolicyModificationInformation      : ('PolicyModificationInfo', POLICY_MODIFICATION_INFO),
        POLICY_INFORMATION_CLASS.PolicyAuditFullSetInformation      : ('PolicyAuditFullSetInfo', POLICY_AUDIT_FULL_SET_INFO),
        POLICY_INFORMATION_CLASS.PolicyAuditFullQueryInformation    : ('PolicyAuditFullQueryInfo', POLICY_AUDIT_FULL_QUERY_INFO),
        POLICY_INFORMATION_CLASS.PolicyDnsDomainInformation         : ('PolicyDnsDomainInfo', LSAPR_POLICY_DNS_DOMAIN_INFO),
        POLICY_INFORMATION_CLASS.PolicyDnsDomainInformationInt      : ('PolicyDnsDomainInfoInt', LSAPR_POLICY_DNS_DOMAIN_INFO),
        POLICY_INFORMATION_CLASS.PolicyLocalAccountDomainInformation: ('PolicyLocalAccountDomainInfo', LSAPR_POLICY_ACCOUNT_DOM_INFO),
    }

 type PLSAPR_POLICY_INFORMATION struct { // NDRPOINTER:
    referent = (
       ('Data', LSAPR_POLICY_INFORMATION),
    }

// 2.2.4.15 POLICY_DOMAIN_INFORMATION_CLASS
 type POLICY_DOMAIN_INFORMATION_CLASS struct { // NDRENUM:
     type enumItems struct { // Enum:
        PolicyDomainQualityOfServiceInformation = 1
        PolicyDomainEfsInformation              = 2
        PolicyDomainKerberosTicketInformation   = 3

// 2.2.4.17 POLICY_DOMAIN_QUALITY_OF_SERVICE_INFO
 type POLICY_DOMAIN_QUALITY_OF_SERVICE_INFO struct { // NDRSTRUCT: (
        ('QualityOfService', DWORD), 
    }

// 2.2.4.18 LSAPR_POLICY_DOMAIN_EFS_INFO
 type LSAPR_POLICY_DOMAIN_EFS_INFO struct { // NDRSTRUCT: (
        ('InfoLength', DWORD), 
        ('EfsBlob', LPBYTE), 
    }

// 2.2.4.19 POLICY_DOMAIN_KERBEROS_TICKET_INFO
 type POLICY_DOMAIN_KERBEROS_TICKET_INFO struct { // NDRSTRUCT: (
        ('AuthenticationOptions', DWORD), 
        ('MaxServiceTicketAge', LARGE_INTEGER), 
        ('MaxTicketAge', LARGE_INTEGER), 
        ('MaxRenewAge', LARGE_INTEGER), 
        ('MaxClockSkew', LARGE_INTEGER), 
        ('Reserved', LARGE_INTEGER), 
    }

// 2.2.4.16 LSAPR_POLICY_DOMAIN_INFORMATION
 type LSAPR_POLICY_DOMAIN_INFORMATION struct { // NDRUNION:
    union = {
        POLICY_DOMAIN_INFORMATION_CLASS.PolicyDomainQualityOfServiceInformation : ('PolicyDomainQualityOfServiceInfo', POLICY_DOMAIN_QUALITY_OF_SERVICE_INFO ),
        POLICY_DOMAIN_INFORMATION_CLASS.PolicyDomainEfsInformation              : ('PolicyDomainEfsInfo', LSAPR_POLICY_DOMAIN_EFS_INFO),
        POLICY_DOMAIN_INFORMATION_CLASS.PolicyDomainKerberosTicketInformation   : ('PolicyDomainKerbTicketInfo', POLICY_DOMAIN_KERBEROS_TICKET_INFO),
    }

 type PLSAPR_POLICY_DOMAIN_INFORMATION struct { // NDRPOINTER:
    referent = (
        ('Data', LSAPR_POLICY_DOMAIN_INFORMATION),
    }

// 2.2.4.20 POLICY_AUDIT_EVENT_TYPE
 type POLICY_AUDIT_EVENT_TYPE struct { // NDRENUM:
     type enumItems struct { // Enum:
        AuditCategorySystem                 = 0
        AuditCategoryLogon                  = 1
        AuditCategoryObjectAccess           = 2
        AuditCategoryPrivilegeUse           = 3
        AuditCategoryDetailedTracking       = 4
        AuditCategoryPolicyChange           = 5
        AuditCategoryAccountManagement      = 6
        AuditCategoryDirectoryServiceAccess = 7
        AuditCategoryAccountLogon           = 8

// 2.2.5.1 LSAPR_ACCOUNT_INFORMATION
 type LSAPR_ACCOUNT_INFORMATION struct { // NDRSTRUCT: (
        ('Sid', PRPC_SID), 
    }

// 2.2.5.2 LSAPR_ACCOUNT_ENUM_BUFFER
 type LSAPR_ACCOUNT_INFORMATION_ARRAY struct { // NDRUniConformantArray:
    item = LSAPR_ACCOUNT_INFORMATION

 type PLSAPR_ACCOUNT_INFORMATION_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', LSAPR_ACCOUNT_INFORMATION_ARRAY),
    }

 type LSAPR_ACCOUNT_ENUM_BUFFER struct { // NDRSTRUCT: (
        ('EntriesRead', ULONG), 
        ('Information', PLSAPR_ACCOUNT_INFORMATION_ARRAY), 
    }

// 2.2.5.3 LSAPR_USER_RIGHT_SET
 type RPC_UNICODE_STRING_ARRAY struct { // NDRUniConformantArray:
    item = RPC_UNICODE_STRING

 type PRPC_UNICODE_STRING_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', RPC_UNICODE_STRING_ARRAY),
    }

 type LSAPR_USER_RIGHT_SET struct { // NDRSTRUCT: (
        ('EntriesRead', ULONG), 
        ('UserRights', PRPC_UNICODE_STRING_ARRAY), 
    }

// 2.2.5.4 LSAPR_LUID_AND_ATTRIBUTES
 type LSAPR_LUID_AND_ATTRIBUTES struct { // NDRSTRUCT: (
        ('Luid', LUID), 
        ('Attributes', ULONG), 
    }

// 2.2.5.5 LSAPR_PRIVILEGE_SET
 type LSAPR_LUID_AND_ATTRIBUTES_ARRAY struct { // NDRUniConformantArray:
    item = LSAPR_LUID_AND_ATTRIBUTES

 type LSAPR_PRIVILEGE_SET struct { // NDRSTRUCT: (
        ('PrivilegeCount', ULONG), 
        ('Control', ULONG), 
        ('Privilege', LSAPR_LUID_AND_ATTRIBUTES_ARRAY), 
    }

 type PLSAPR_PRIVILEGE_SET struct { // NDRPOINTER:
    referent = (
        ('Data', LSAPR_PRIVILEGE_SET),
    }

// 2.2.6.1 LSAPR_CR_CIPHER_VALUE
 type PCHAR_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', NDRUniConformantVaryingArray),
    }

 type LSAPR_CR_CIPHER_VALUE struct { // NDRSTRUCT: (
        ('Length', LONG), 
        ('MaximumLength', LONG), 
        ('Buffer', PCHAR_ARRAY), 
    }

 type PLSAPR_CR_CIPHER_VALUE struct { // NDRPOINTER:
    referent = (
        ('Data', LSAPR_CR_CIPHER_VALUE), 
    }

 type PPLSAPR_CR_CIPHER_VALUE struct { // NDRPOINTER:
    referent = (
        ('Data', PLSAPR_CR_CIPHER_VALUE),
    }

// 2.2.7.1 LSAPR_TRUST_INFORMATION
 type LSAPR_TRUST_INFORMATION struct { // NDRSTRUCT: (
        ('Name', RPC_UNICODE_STRING), 
        ('Sid', PRPC_SID), 
    }

// 2.2.7.2 TRUSTED_INFORMATION_CLASS
 type TRUSTED_INFORMATION_CLASS struct { // NDRENUM:
     type enumItems struct { // Enum:
        TrustedDomainNameInformation          = 1
        TrustedControllersInformation         = 2
        TrustedPosixOffsetInformation         = 3
        TrustedPasswordInformation            = 4
        TrustedDomainInformationBasic         = 5
        TrustedDomainInformationEx            = 6
        TrustedDomainAuthInformation          = 7
        TrustedDomainFullInformation          = 8
        TrustedDomainAuthInformationInternal  = 9
        TrustedDomainFullInformationInternal  = 10
        TrustedDomainInformationEx2Internal   = 11
        TrustedDomainFullInformation2Internal = 12
        TrustedDomainSupportedEncryptionTypes = 13

// 2.2.7.4 LSAPR_TRUSTED_DOMAIN_NAME_INFO
 type LSAPR_TRUSTED_DOMAIN_NAME_INFO struct { // NDRSTRUCT: (
        ('Name', RPC_UNICODE_STRING), 
    }

// 2.2.7.5 LSAPR_TRUSTED_CONTROLLERS_INFO
 type LSAPR_TRUSTED_CONTROLLERS_INFO struct { // NDRSTRUCT: (
        ('Entries', ULONG), 
        ('Names', PRPC_UNICODE_STRING_ARRAY), 
    }

// 2.2.7.6 TRUSTED_POSIX_OFFSET_INFO
 type TRUSTED_POSIX_OFFSET_INFO struct { // NDRSTRUCT: (
        ('Offset', ULONG), 
    }

// 2.2.7.7 LSAPR_TRUSTED_PASSWORD_INFO
 type LSAPR_TRUSTED_PASSWORD_INFO struct { // NDRSTRUCT: (
        ('Password', PLSAPR_CR_CIPHER_VALUE), 
        ('OldPassword', PLSAPR_CR_CIPHER_VALUE), 
    }

// 2.2.7.8 LSAPR_TRUSTED_DOMAIN_INFORMATION_BASIC
LSAPR_TRUSTED_DOMAIN_INFORMATION_BASIC = LSAPR_TRUST_INFORMATION

// 2.2.7.9 LSAPR_TRUSTED_DOMAIN_INFORMATION_EX
 type LSAPR_TRUSTED_DOMAIN_INFORMATION_EX struct { // NDRSTRUCT: (
        ('Name', RPC_UNICODE_STRING), 
        ('FlatName', RPC_UNICODE_STRING), 
        ('Sid', PRPC_SID), 
        ('TrustDirection', ULONG), 
        ('TrustType', ULONG), 
        ('TrustAttributes', ULONG), 
    }

// 2.2.7.10 LSAPR_TRUSTED_DOMAIN_INFORMATION_EX2
 type LSAPR_TRUSTED_DOMAIN_INFORMATION_EX2 struct { // NDRSTRUCT: (
        ('Name', RPC_UNICODE_STRING), 
        ('FlatName', RPC_UNICODE_STRING), 
        ('Sid', PRPC_SID), 
        ('TrustDirection', ULONG), 
        ('TrustType', ULONG), 
        ('TrustAttributes', ULONG), 
        ('ForestTrustLength', ULONG), 
        ('ForestTrustInfo', LPBYTE), 
    }

// 2.2.7.17 LSAPR_AUTH_INFORMATION
 type LSAPR_AUTH_INFORMATION struct { // NDRSTRUCT: (
        ('LastUpdateTime', LARGE_INTEGER), 
        ('AuthType', ULONG), 
        ('AuthInfoLength', ULONG), 
        ('AuthInfo', LPBYTE), 
    }

 type PLSAPR_AUTH_INFORMATION struct { // NDRPOINTER:
    referent = (
        ('Data', LSAPR_AUTH_INFORMATION),
    }

// 2.2.7.11 LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION
 type LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION struct { // NDRSTRUCT: (
        ('IncomingAuthInfos', ULONG), 
        ('IncomingAuthenticationInformation', PLSAPR_AUTH_INFORMATION), 
        ('IncomingPreviousAuthenticationInformation', PLSAPR_AUTH_INFORMATION), 
        ('OutgoingAuthInfos', ULONG), 
        ('OutgoingAuthenticationInformation', PLSAPR_AUTH_INFORMATION), 
        ('OutgoingPreviousAuthenticationInformation', PLSAPR_AUTH_INFORMATION), 
    }

// 2.2.7.16 LSAPR_TRUSTED_DOMAIN_AUTH_BLOB
 type LSAPR_TRUSTED_DOMAIN_AUTH_BLOB struct { // NDRSTRUCT: (
        ('AuthSize', ULONG), 
        ('AuthBlob', LPBYTE), 
    }

// 2.2.7.12 LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION_INTERNAL
 type LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION_INTERNAL struct { // NDRSTRUCT: (
        ('AuthBlob', LSAPR_TRUSTED_DOMAIN_AUTH_BLOB), 
    }

// 2.2.7.13 LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION
 type LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION struct { // NDRSTRUCT: (
        ('Information', LSAPR_TRUSTED_DOMAIN_INFORMATION_EX), 
        ('PosixOffset', TRUSTED_POSIX_OFFSET_INFO), 
        ('AuthInformation', LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION), 
    }

// 2.2.7.14 LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION_INTERNAL
 type LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION_INTERNAL struct { // NDRSTRUCT: (
        ('Information', LSAPR_TRUSTED_DOMAIN_INFORMATION_EX), 
        ('PosixOffset', TRUSTED_POSIX_OFFSET_INFO), 
        ('AuthInformation', LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION_INTERNAL), 
    }

// 2.2.7.15 LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION2
 type LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION2 struct { // NDRSTRUCT: (
        ('Information', LSAPR_TRUSTED_DOMAIN_INFORMATION_EX), 
        ('PosixOffset', TRUSTED_POSIX_OFFSET_INFO), 
        ('AuthInformation', LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION), 
    }

// 2.2.7.18 TRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES
 type TRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES struct { // NDRSTRUCT: (
        ('SupportedEncryptionTypes', ULONG), 
    }

// 2.2.7.3 LSAPR_TRUSTED_DOMAIN_INFO
 type LSAPR_TRUSTED_DOMAIN_INFO struct { // NDRUNION:
    union = {
        TRUSTED_INFORMATION_CLASS.TrustedDomainNameInformation          : ('TrustedDomainNameInfo', LSAPR_TRUSTED_DOMAIN_NAME_INFO ),
        TRUSTED_INFORMATION_CLASS.TrustedControllersInformation         : ('TrustedControllersInfo', LSAPR_TRUSTED_CONTROLLERS_INFO),
        TRUSTED_INFORMATION_CLASS.TrustedPosixOffsetInformation         : ('TrustedPosixOffsetInfo', TRUSTED_POSIX_OFFSET_INFO),
        TRUSTED_INFORMATION_CLASS.TrustedPasswordInformation            : ('TrustedPasswordInfo', LSAPR_TRUSTED_PASSWORD_INFO ),
        TRUSTED_INFORMATION_CLASS.TrustedDomainInformationBasic         : ('TrustedDomainInfoBasic', LSAPR_TRUSTED_DOMAIN_INFORMATION_BASIC),
        TRUSTED_INFORMATION_CLASS.TrustedDomainInformationEx            : ('TrustedDomainInfoEx', LSAPR_TRUSTED_DOMAIN_INFORMATION_EX),
        TRUSTED_INFORMATION_CLASS.TrustedDomainAuthInformation          : ('TrustedAuthInfo', LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION),
        TRUSTED_INFORMATION_CLASS.TrustedDomainFullInformation          : ('TrustedFullInfo', LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION),
        TRUSTED_INFORMATION_CLASS.TrustedDomainAuthInformationInternal  : ('TrustedAuthInfoInternal', LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION_INTERNAL),
        TRUSTED_INFORMATION_CLASS.TrustedDomainFullInformationInternal  : ('TrustedFullInfoInternal', LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION_INTERNAL),
        TRUSTED_INFORMATION_CLASS.TrustedDomainInformationEx2Internal   : ('TrustedDomainInfoEx2', LSAPR_TRUSTED_DOMAIN_INFORMATION_EX2),
        TRUSTED_INFORMATION_CLASS.TrustedDomainFullInformation2Internal : ('TrustedFullInfo2', LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION2),
        TRUSTED_INFORMATION_CLASS.TrustedDomainSupportedEncryptionTypes : ('TrustedDomainSETs', TRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES),
    }

// 2.2.7.19 LSAPR_TRUSTED_ENUM_BUFFER
 type LSAPR_TRUST_INFORMATION_ARRAY struct { // NDRUniConformantArray:
    item = LSAPR_TRUST_INFORMATION

 type PLSAPR_TRUST_INFORMATION_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', LSAPR_TRUST_INFORMATION_ARRAY),
    }

 type LSAPR_TRUSTED_ENUM_BUFFER struct { // NDRSTRUCT: (
        ('Entries', ULONG), 
        ('Information', PLSAPR_TRUST_INFORMATION_ARRAY), 
    }

// 2.2.7.20 LSAPR_TRUSTED_ENUM_BUFFER_EX
 type LSAPR_TRUSTED_DOMAIN_INFORMATION_EX_ARRAY struct { // NDRUniConformantArray:
    item = LSAPR_TRUSTED_DOMAIN_INFORMATION_EX

 type PLSAPR_TRUSTED_DOMAIN_INFORMATION_EX_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', LSAPR_TRUSTED_DOMAIN_INFORMATION_EX_ARRAY),
    }

 type LSAPR_TRUSTED_ENUM_BUFFER_EX struct { // NDRSTRUCT: (
        ('Entries', ULONG), 
        ('EnumerationBuffer', PLSAPR_TRUSTED_DOMAIN_INFORMATION_EX_ARRAY), 
    }

// 2.2.7.22 LSA_FOREST_TRUST_RECORD_TYPE
 type LSA_FOREST_TRUST_RECORD_TYPE struct { // NDRENUM:
     type enumItems struct { // Enum:
        ForestTrustTopLevelName   = 0
        ForestTrustTopLevelNameEx = 1
        ForestTrustDomainInfo     = 2

// 2.2.7.24 LSA_FOREST_TRUST_DOMAIN_INFO
 type LSA_FOREST_TRUST_DOMAIN_INFO struct { // NDRSTRUCT: (
        ('Sid', PRPC_SID), 
        ('DnsName', LSA_UNICODE_STRING), 
        ('NetbiosName', LSA_UNICODE_STRING), 
    }

// 2.2.7.21 LSA_FOREST_TRUST_RECORD
 type LSA_FOREST_TRUST_DATA_UNION struct { // NDRUNION:
    union = {
        LSA_FOREST_TRUST_RECORD_TYPE.ForestTrustTopLevelName   : ('TopLevelName', LSA_UNICODE_STRING ),
        LSA_FOREST_TRUST_RECORD_TYPE.ForestTrustTopLevelNameEx : ('TopLevelName', LSA_UNICODE_STRING),
        LSA_FOREST_TRUST_RECORD_TYPE.ForestTrustDomainInfo     : ('DomainInfo', LSA_FOREST_TRUST_DOMAIN_INFO),
    }

 type LSA_FOREST_TRUST_RECORD struct { // NDRSTRUCT: (
        ('Flags', ULONG), 
        ('ForestTrustType', LSA_FOREST_TRUST_RECORD_TYPE), 
        ('Time', LARGE_INTEGER), 
        ('ForestTrustData', LSA_FOREST_TRUST_DATA_UNION), 
    }

 type PLSA_FOREST_TRUST_RECORD struct { // NDRPOINTER:
    referent = (
        ('Data', LSA_FOREST_TRUST_RECORD),
    }

// 2.2.7.23 LSA_FOREST_TRUST_BINARY_DATA
 type LSA_FOREST_TRUST_BINARY_DATA struct { // NDRSTRUCT: (
        ('Length', ULONG), 
        ('Buffer', LPBYTE), 
    }

// 2.2.7.25 LSA_FOREST_TRUST_INFORMATION
 type LSA_FOREST_TRUST_RECORD_ARRAY struct { // NDRUniConformantArray:
    item = PLSA_FOREST_TRUST_RECORD

 type PLSA_FOREST_TRUST_RECORD_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', LSA_FOREST_TRUST_RECORD_ARRAY),
    }

 type LSA_FOREST_TRUST_INFORMATION struct { // NDRSTRUCT: (
        ('RecordCount', ULONG), 
        ('Entries', PLSA_FOREST_TRUST_RECORD_ARRAY), 
    }

 type PLSA_FOREST_TRUST_INFORMATION struct { // NDRPOINTER:
    referent = (
        ('Data', LSA_FOREST_TRUST_INFORMATION),
    }

// 2.2.7.26 LSA_FOREST_TRUST_COLLISION_RECORD_TYPE
 type LSA_FOREST_TRUST_COLLISION_RECORD_TYPE struct { // NDRENUM:
     type enumItems struct { // Enum:
        CollisionTdo   = 0
        CollisionXref  = 1
        CollisionOther = 2

// 2.2.7.27 LSA_FOREST_TRUST_COLLISION_RECORD
 type LSA_FOREST_TRUST_COLLISION_RECORD struct { // NDRSTRUCT: (
        ('Index', ULONG), 
        ('Type', LSA_FOREST_TRUST_COLLISION_RECORD_TYPE), 
        ('Flags', ULONG), 
        ('Name', LSA_UNICODE_STRING), 
    }

// 2.2.8.1 LSAPR_POLICY_PRIVILEGE_DEF
 type LSAPR_POLICY_PRIVILEGE_DEF struct { // NDRSTRUCT: (
        ('Name', RPC_UNICODE_STRING), 
        ('LocalValue', LUID), 
    }

// 2.2.8.2 LSAPR_PRIVILEGE_ENUM_BUFFER
 type LSAPR_POLICY_PRIVILEGE_DEF_ARRAY struct { // NDRUniConformantArray:
    item = LSAPR_POLICY_PRIVILEGE_DEF

 type PLSAPR_POLICY_PRIVILEGE_DEF_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', LSAPR_POLICY_PRIVILEGE_DEF_ARRAY),
    }

 type LSAPR_PRIVILEGE_ENUM_BUFFER struct { // NDRSTRUCT: (
        ('Entries', ULONG), 
        ('Privileges', PLSAPR_POLICY_PRIVILEGE_DEF_ARRAY), 
    }


//###############################################################################
// RPC CALLS
//###############################################################################
// 3.1.4.4.1 LsarOpenPolicy2 (Opnum 44)
 type LsarOpenPolicy2 struct { // NDRCALL:
    opnum = 44 (
       ('SystemName', LPWSTR),
       ('ObjectAttributes',LSAPR_OBJECT_ATTRIBUTES),
       ('DesiredAccess',ACCESS_MASK),
    }

 type LsarOpenPolicy2Response struct { // NDRCALL: (
       ('PolicyHandle',LSAPR_HANDLE),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.4.2 LsarOpenPolicy (Opnum 6)
 type LsarOpenPolicy struct { // NDRCALL:
    opnum = 6 (
       ('SystemName', LPWSTR),
       ('ObjectAttributes',LSAPR_OBJECT_ATTRIBUTES),
       ('DesiredAccess',ACCESS_MASK),
    }

 type LsarOpenPolicyResponse struct { // NDRCALL: (
       ('PolicyHandle',LSAPR_HANDLE),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.4.3 LsarQueryInformationPolicy2 (Opnum 46)
 type LsarQueryInformationPolicy2 struct { // NDRCALL:
    opnum = 46 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('InformationClass',POLICY_INFORMATION_CLASS),
    }

 type LsarQueryInformationPolicy2Response struct { // NDRCALL: (
       ('PolicyInformation',PLSAPR_POLICY_INFORMATION),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.4.4 LsarQueryInformationPolicy (Opnum 7)
 type LsarQueryInformationPolicy struct { // NDRCALL:
    opnum = 7 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('InformationClass',POLICY_INFORMATION_CLASS),
    }

 type LsarQueryInformationPolicyResponse struct { // NDRCALL: (
       ('PolicyInformation',PLSAPR_POLICY_INFORMATION),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.4.5 LsarSetInformationPolicy2 (Opnum 47)
 type LsarSetInformationPolicy2 struct { // NDRCALL:
    opnum = 47 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('InformationClass',POLICY_INFORMATION_CLASS),
       ('PolicyInformation',LSAPR_POLICY_INFORMATION),
    }

 type LsarSetInformationPolicy2Response struct { // NDRCALL: (
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.4.6 LsarSetInformationPolicy (Opnum 8)
 type LsarSetInformationPolicy struct { // NDRCALL:
    opnum = 8 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('InformationClass',POLICY_INFORMATION_CLASS),
       ('PolicyInformation',LSAPR_POLICY_INFORMATION),
    }

 type LsarSetInformationPolicyResponse struct { // NDRCALL: (
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.4.7 LsarQueryDomainInformationPolicy (Opnum 53)
 type LsarQueryDomainInformationPolicy struct { // NDRCALL:
    opnum = 53 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('InformationClass',POLICY_DOMAIN_INFORMATION_CLASS),
    }

 type LsarQueryDomainInformationPolicyResponse struct { // NDRCALL: (
       ('PolicyDomainInformation',PLSAPR_POLICY_DOMAIN_INFORMATION),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.4.8 LsarSetDomainInformationPolicy (Opnum 54)
// 3.1.4.5.1 LsarCreateAccount (Opnum 10)
 type LsarCreateAccount struct { // NDRCALL:
    opnum = 10 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('AccountSid',RPC_SID),
       ('DesiredAccess',ACCESS_MASK),
    }

 type LsarCreateAccountResponse struct { // NDRCALL: (
       ('AccountHandle',LSAPR_HANDLE),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.5.2 LsarEnumerateAccounts (Opnum 11)
 type LsarEnumerateAccounts struct { // NDRCALL:
    opnum = 11 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('EnumerationContext',ULONG),
       ('PreferedMaximumLength',ULONG),
    }

 type LsarEnumerateAccountsResponse struct { // NDRCALL: (
       ('EnumerationContext',ULONG),
       ('EnumerationBuffer',LSAPR_ACCOUNT_ENUM_BUFFER),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.5.3 LsarOpenAccount (Opnum 17)
 type LsarOpenAccount struct { // NDRCALL:
    opnum = 17 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('AccountSid',RPC_SID),
       ('DesiredAccess',ACCESS_MASK),
    }

 type LsarOpenAccountResponse struct { // NDRCALL: (
       ('AccountHandle',LSAPR_HANDLE),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.5.4 LsarEnumeratePrivilegesAccount (Opnum 18)
 type LsarEnumeratePrivilegesAccount struct { // NDRCALL:
    opnum = 18 (
       ('AccountHandle', LSAPR_HANDLE),
    }

 type LsarEnumeratePrivilegesAccountResponse struct { // NDRCALL: (
       ('Privileges',PLSAPR_PRIVILEGE_SET),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.5.5 LsarAddPrivilegesToAccount (Opnum 19)
 type LsarAddPrivilegesToAccount struct { // NDRCALL:
    opnum = 19 (
       ('AccountHandle', LSAPR_HANDLE),
       ('Privileges', LSAPR_PRIVILEGE_SET),
    }

 type LsarAddPrivilegesToAccountResponse struct { // NDRCALL: (
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.5.6 LsarRemovePrivilegesFromAccount (Opnum 20)
 type LsarRemovePrivilegesFromAccount struct { // NDRCALL:
    opnum = 20 (
       ('AccountHandle', LSAPR_HANDLE),
       ('AllPrivileges', UCHAR),
       ('Privileges', PLSAPR_PRIVILEGE_SET),
    }

 type LsarRemovePrivilegesFromAccountResponse struct { // NDRCALL: (
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.5.7 LsarGetSystemAccessAccount (Opnum 23)
 type LsarGetSystemAccessAccount struct { // NDRCALL:
    opnum = 23 (
       ('AccountHandle', LSAPR_HANDLE),
    }

 type LsarGetSystemAccessAccountResponse struct { // NDRCALL: (
       ('SystemAccess', ULONG),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.5.8 LsarSetSystemAccessAccount (Opnum 24)
 type LsarSetSystemAccessAccount struct { // NDRCALL:
    opnum = 24 (
       ('AccountHandle', LSAPR_HANDLE),
       ('SystemAccess', ULONG),
    }

 type LsarSetSystemAccessAccountResponse struct { // NDRCALL: (
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.5.9 LsarEnumerateAccountsWithUserRight (Opnum 35)
 type LsarEnumerateAccountsWithUserRight struct { // NDRCALL:
    opnum = 35 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('UserRight', PRPC_UNICODE_STRING),
    }

 type LsarEnumerateAccountsWithUserRightResponse struct { // NDRCALL: (
       ('EnumerationBuffer',LSAPR_ACCOUNT_ENUM_BUFFER),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.5.10 LsarEnumerateAccountRights (Opnum 36)
 type LsarEnumerateAccountRights struct { // NDRCALL:
    opnum = 36 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('AccountSid', RPC_SID),
    }

 type LsarEnumerateAccountRightsResponse struct { // NDRCALL: (
       ('UserRights',LSAPR_USER_RIGHT_SET),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.5.11 LsarAddAccountRights (Opnum 37)
 type LsarAddAccountRights struct { // NDRCALL:
    opnum = 37 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('AccountSid', RPC_SID),
       ('UserRights',LSAPR_USER_RIGHT_SET),
    }

 type LsarAddAccountRightsResponse struct { // NDRCALL: (
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.5.12 LsarRemoveAccountRights (Opnum 38)
 type LsarRemoveAccountRights struct { // NDRCALL:
    opnum = 38 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('AccountSid', RPC_SID),
       ('AllRights', UCHAR),
       ('UserRights',LSAPR_USER_RIGHT_SET),
    }

 type LsarRemoveAccountRightsResponse struct { // NDRCALL: (
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.6.1 LsarCreateSecret (Opnum 16)
 type LsarCreateSecret struct { // NDRCALL:
    opnum = 16 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('SecretName', RPC_UNICODE_STRING),
       ('DesiredAccess', ACCESS_MASK),
    }

 type LsarCreateSecretResponse struct { // NDRCALL: (
       ('SecretHandle', LSAPR_HANDLE),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.6.2 LsarOpenSecret (Opnum 28)
 type LsarOpenSecret struct { // NDRCALL:
    opnum = 28 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('SecretName', RPC_UNICODE_STRING),
       ('DesiredAccess', ACCESS_MASK),
    }

 type LsarOpenSecretResponse struct { // NDRCALL: (
       ('SecretHandle', LSAPR_HANDLE),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.6.3 LsarSetSecret (Opnum 29)
 type LsarSetSecret struct { // NDRCALL:
    opnum = 29 (
       ('SecretHandle', LSAPR_HANDLE),
       ('EncryptedCurrentValue', PLSAPR_CR_CIPHER_VALUE),
       ('EncryptedOldValue', PLSAPR_CR_CIPHER_VALUE),
    }

 type LsarSetSecretResponse struct { // NDRCALL: (
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.6.4 LsarQuerySecret (Opnum 30)
 type LsarQuerySecret struct { // NDRCALL:
    opnum = 30 (
       ('SecretHandle', LSAPR_HANDLE),
       ('EncryptedCurrentValue', PPLSAPR_CR_CIPHER_VALUE),
       ('CurrentValueSetTime', PLARGE_INTEGER),
       ('EncryptedOldValue', PPLSAPR_CR_CIPHER_VALUE),
       ('OldValueSetTime', PLARGE_INTEGER),
    }

 type LsarQuerySecretResponse struct { // NDRCALL: (
       ('EncryptedCurrentValue', PPLSAPR_CR_CIPHER_VALUE),
       ('CurrentValueSetTime', PLARGE_INTEGER),
       ('EncryptedOldValue', PPLSAPR_CR_CIPHER_VALUE),
       ('OldValueSetTime', PLARGE_INTEGER),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.6.5 LsarStorePrivateData (Opnum 42)
 type LsarStorePrivateData struct { // NDRCALL:
    opnum = 42 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('KeyName', RPC_UNICODE_STRING),
       ('EncryptedData', PLSAPR_CR_CIPHER_VALUE),
    }

 type LsarStorePrivateDataResponse struct { // NDRCALL: (
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.6.6 LsarRetrievePrivateData (Opnum 43)
 type LsarRetrievePrivateData struct { // NDRCALL:
    opnum = 43 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('KeyName', RPC_UNICODE_STRING),
       ('EncryptedData', PLSAPR_CR_CIPHER_VALUE),
    }

 type LsarRetrievePrivateDataResponse struct { // NDRCALL: (
       ('EncryptedData', PLSAPR_CR_CIPHER_VALUE),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.7.1 LsarOpenTrustedDomain (Opnum 25)
// 3.1.4.7.1 LsarQueryInfoTrustedDomain (Opnum 26)
// 3.1.4.7.2 LsarQueryTrustedDomainInfo (Opnum 39)
// 3.1.4.7.3 LsarSetTrustedDomainInfo (Opnum 40)
// 3.1.4.7.4 LsarDeleteTrustedDomain (Opnum 41)
// 3.1.4.7.5 LsarQueryTrustedDomainInfoByName (Opnum 48)
// 3.1.4.7.6 LsarSetTrustedDomainInfoByName (Opnum 49)
// 3.1.4.7.7 LsarEnumerateTrustedDomainsEx (Opnum 50)
 type LsarEnumerateTrustedDomainsEx struct { // NDRCALL:
    opnum = 50 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('EnumerationContext', ULONG),
       ('PreferedMaximumLength', ULONG),
    }

 type LsarEnumerateTrustedDomainsExResponse struct { // NDRCALL: (
       ('EnumerationContext', ULONG),
       ('EnumerationBuffer',LSAPR_TRUSTED_ENUM_BUFFER_EX),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.7.8 LsarEnumerateTrustedDomains (Opnum 13)
 type LsarEnumerateTrustedDomains struct { // NDRCALL:
    opnum = 13 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('EnumerationContext', ULONG),
       ('PreferedMaximumLength', ULONG),
    }

 type LsarEnumerateTrustedDomainsResponse struct { // NDRCALL: (
       ('EnumerationContext', ULONG),
       ('EnumerationBuffer',LSAPR_TRUSTED_ENUM_BUFFER),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.7.9 LsarOpenTrustedDomainByName (Opnum 55)
// 3.1.4.7.10 LsarCreateTrustedDomainEx2 (Opnum 59)
// 3.1.4.7.11 LsarCreateTrustedDomainEx (Opnum 51)
// 3.1.4.7.12 LsarCreateTrustedDomain (Opnum 12)
// 3.1.4.7.14 LsarSetInformationTrustedDomain (Opnum 27)
// 3.1.4.7.15 LsarQueryForestTrustInformation (Opnum 73)
 type LsarQueryForestTrustInformation struct { // NDRCALL:
    opnum = 73 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('TrustedDomainName', LSA_UNICODE_STRING),
       ('HighestRecordType', LSA_FOREST_TRUST_RECORD_TYPE),
    }

 type LsarQueryForestTrustInformationResponse struct { // NDRCALL: (
       ('ForestTrustInfo', PLSA_FOREST_TRUST_INFORMATION),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.7.16 LsarSetForestTrustInformation (Opnum 74)

// 3.1.4.8.1 LsarEnumeratePrivileges (Opnum 2)
 type LsarEnumeratePrivileges struct { // NDRCALL:
    opnum = 2 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('EnumerationContext', ULONG),
       ('PreferedMaximumLength', ULONG),
    }

 type LsarEnumeratePrivilegesResponse struct { // NDRCALL: (
       ('EnumerationContext', ULONG),
       ('EnumerationBuffer', LSAPR_PRIVILEGE_ENUM_BUFFER),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.8.2 LsarLookupPrivilegeValue (Opnum 31)
 type LsarLookupPrivilegeValue struct { // NDRCALL:
    opnum = 31 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('Name', RPC_UNICODE_STRING),
    }

 type LsarLookupPrivilegeValueResponse struct { // NDRCALL: (
       ('Value', LUID),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.8.3 LsarLookupPrivilegeName (Opnum 32)
 type LsarLookupPrivilegeName struct { // NDRCALL:
    opnum = 32 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('Value', LUID),
    }

 type LsarLookupPrivilegeNameResponse struct { // NDRCALL: (
       ('Name', PRPC_UNICODE_STRING),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.8.4 LsarLookupPrivilegeDisplayName (Opnum 33)
 type LsarLookupPrivilegeDisplayName struct { // NDRCALL:
    opnum = 33 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('Name', RPC_UNICODE_STRING),
       ('ClientLanguage', USHORT),
       ('ClientSystemDefaultLanguage', USHORT),
    }

 type LsarLookupPrivilegeDisplayNameResponse struct { // NDRCALL: (
       ('Name', PRPC_UNICODE_STRING),
       ('LanguageReturned', UCHAR),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.9.1 LsarQuerySecurityObject (Opnum 3)
 type LsarQuerySecurityObject struct { // NDRCALL:
    opnum = 3 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('SecurityInformation', SECURITY_INFORMATION),
    }

 type LsarQuerySecurityObjectResponse struct { // NDRCALL: (
       ('SecurityDescriptor', PLSAPR_SR_SECURITY_DESCRIPTOR),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.9.2 LsarSetSecurityObject (Opnum 4)
 type LsarSetSecurityObject struct { // NDRCALL:
    opnum = 4 (
       ('PolicyHandle', LSAPR_HANDLE),
       ('SecurityInformation', SECURITY_INFORMATION),
       ('SecurityDescriptor', LSAPR_SR_SECURITY_DESCRIPTOR),
    }

 type LsarSetSecurityObjectResponse struct { // NDRCALL: (
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.9.3 LsarDeleteObject (Opnum 34)
 type LsarDeleteObject struct { // NDRCALL:
    opnum = 34 (
       ('ObjectHandle', LSAPR_HANDLE),
    }

 type LsarDeleteObjectResponse struct { // NDRCALL: (
       ('ObjectHandle', LSAPR_HANDLE),
       ('ErrorCode', NTSTATUS),
    }

// 3.1.4.9.4 LsarClose (Opnum 0)
 type LsarClose struct { // NDRCALL:
    opnum = 0 (
       ('ObjectHandle', LSAPR_HANDLE),
    }

 type LsarCloseResponse struct { // NDRCALL: (
       ('ObjectHandle', LSAPR_HANDLE),
       ('ErrorCode', NTSTATUS),
    }

//###############################################################################
// OPNUMs and their corresponding structures
//###############################################################################
OPNUMS = {
 0 : (LsarClose, LsarCloseResponse),
 2 : (LsarEnumeratePrivileges, LsarEnumeratePrivilegesResponse),
 3 : (LsarQuerySecurityObject, LsarQuerySecurityObjectResponse),
 4 : (LsarSetSecurityObject, LsarSetSecurityObjectResponse),
 6 : (LsarOpenPolicy, LsarOpenPolicyResponse),
 7 : (LsarQueryInformationPolicy, LsarQueryInformationPolicyResponse),
 8 : (LsarSetInformationPolicy, LsarSetInformationPolicyResponse),
10 : (LsarCreateAccount, LsarCreateAccountResponse),
11 : (LsarEnumerateAccounts, LsarEnumerateAccountsResponse),
//12 : (LsarCreateTrustedDomain, LsarCreateTrustedDomainResponse),
13 : (LsarEnumerateTrustedDomains, LsarEnumerateTrustedDomainsResponse),
16 : (LsarCreateSecret, LsarCreateSecretResponse),
17 : (LsarOpenAccount, LsarOpenAccountResponse),
18 : (LsarEnumeratePrivilegesAccount, LsarEnumeratePrivilegesAccountResponse),
19 : (LsarAddPrivilegesToAccount, LsarAddPrivilegesToAccountResponse),
20 : (LsarRemovePrivilegesFromAccount, LsarRemovePrivilegesFromAccountResponse),
23 : (LsarGetSystemAccessAccount, LsarGetSystemAccessAccountResponse),
24 : (LsarSetSystemAccessAccount, LsarSetSystemAccessAccountResponse),
//25 : (LsarOpenTrustedDomain, LsarOpenTrustedDomainResponse),
//26 : (LsarQueryInfoTrustedDomain, LsarQueryInfoTrustedDomainResponse),
//27 : (LsarSetInformationTrustedDomain, LsarSetInformationTrustedDomainResponse),
28 : (LsarOpenSecret, LsarOpenSecretResponse),
29 : (LsarSetSecret, LsarSetSecretResponse),
30 : (LsarQuerySecret, LsarQuerySecretResponse),
31 : (LsarLookupPrivilegeValue, LsarLookupPrivilegeValueResponse),
32 : (LsarLookupPrivilegeName, LsarLookupPrivilegeNameResponse),
33 : (LsarLookupPrivilegeDisplayName, LsarLookupPrivilegeDisplayNameResponse),
34 : (LsarDeleteObject, LsarDeleteObjectResponse),
35 : (LsarEnumerateAccountsWithUserRight, LsarEnumerateAccountsWithUserRightResponse),
36 : (LsarEnumerateAccountRights, LsarEnumerateAccountRightsResponse),
37 : (LsarAddAccountRights, LsarAddAccountRightsResponse),
38 : (LsarRemoveAccountRights, LsarRemoveAccountRightsResponse),
//39 : (LsarQueryTrustedDomainInfo, LsarQueryTrustedDomainInfoResponse),
//40 : (LsarSetTrustedDomainInfo, LsarSetTrustedDomainInfoResponse),
//41 : (LsarDeleteTrustedDomain, LsarDeleteTrustedDomainResponse),
42 : (LsarStorePrivateData, LsarStorePrivateDataResponse),
43 : (LsarRetrievePrivateData, LsarRetrievePrivateDataResponse),
44 : (LsarOpenPolicy2, LsarOpenPolicy2Response),
46 : (LsarQueryInformationPolicy2, LsarQueryInformationPolicy2Response),
47 : (LsarSetInformationPolicy2, LsarSetInformationPolicy2Response),
//48 : (LsarQueryTrustedDomainInfoByName, LsarQueryTrustedDomainInfoByNameResponse),
//49 : (LsarSetTrustedDomainInfoByName, LsarSetTrustedDomainInfoByNameResponse),
50 : (LsarEnumerateTrustedDomainsEx, LsarEnumerateTrustedDomainsExResponse),
//51 : (LsarCreateTrustedDomainEx, LsarCreateTrustedDomainExResponse),
53 : (LsarQueryDomainInformationPolicy, LsarQueryDomainInformationPolicyResponse),
//54 : (LsarSetDomainInformationPolicy, LsarSetDomainInformationPolicyResponse),
//55 : (LsarOpenTrustedDomainByName, LsarOpenTrustedDomainByNameResponse),
//59 : (LsarCreateTrustedDomainEx2, LsarCreateTrustedDomainEx2Response),
//73 : (LsarQueryForestTrustInformation, LsarQueryForestTrustInformationResponse),
//74 : (LsarSetForestTrustInformation, LsarSetForestTrustInformationResponse),
}

//###############################################################################
// HELPER FUNCTIONS
//###############################################################################
 func hLsarOpenPolicy2(dce, desiredAccess = MAXIMUM_ALLOWED interface{}){
    request = LsarOpenPolicy2()
    request["SystemName"] = NULL
    request["ObjectAttributes"]["RootDirectory"] = NULL
    request["ObjectAttributes"]["ObjectName"] = NULL
    request["ObjectAttributes"]["SecurityDescriptor"] = NULL
    request["ObjectAttributes"]["SecurityQualityOfService"] = NULL
    request["DesiredAccess"] = desiredAccess
    return dce.request(request)

 func hLsarOpenPolicy(dce, desiredAccess = MAXIMUM_ALLOWED interface{}){
    request = LsarOpenPolicy()
    request["SystemName"] = NULL
    request["ObjectAttributes"]["RootDirectory"] = NULL
    request["ObjectAttributes"]["ObjectName"] = NULL
    request["ObjectAttributes"]["SecurityDescriptor"] = NULL
    request["ObjectAttributes"]["SecurityQualityOfService"] = NULL
    request["DesiredAccess"] = desiredAccess
    return dce.request(request)

 func hLsarQueryInformationPolicy2(dce, policyHandle, informationClass interface{}){
    request = LsarQueryInformationPolicy2()
    request["PolicyHandle"] = policyHandle
    request["InformationClass"] = informationClass
    return dce.request(request)

 func hLsarQueryInformationPolicy(dce, policyHandle, informationClass interface{}){
    request = LsarQueryInformationPolicy()
    request["PolicyHandle"] = policyHandle
    request["InformationClass"] = informationClass
    return dce.request(request)

 func hLsarQueryDomainInformationPolicy(dce, policyHandle, informationClass interface{}){
    request = LsarQueryInformationPolicy()
    request["PolicyHandle"] = policyHandle
    request["InformationClass"] = informationClass
    return dce.request(request)

 func hLsarEnumerateAccounts(dce, policyHandle, preferedMaximumLength=0xffffffff interface{}){
    request = LsarEnumerateAccounts()
    request["PolicyHandle"] = policyHandle
    request["PreferedMaximumLength"] = preferedMaximumLength
    return dce.request(request)

 func hLsarEnumerateAccountsWithUserRight(dce, policyHandle, UserRight interface{}){
    request = LsarEnumerateAccountsWithUserRight()
    request["PolicyHandle"] = policyHandle
    request["UserRight"] = UserRight
    return dce.request(request)

 func hLsarEnumerateTrustedDomainsEx(dce, policyHandle, enumerationContext=0, preferedMaximumLength=0xffffffff interface{}){
    request = LsarEnumerateTrustedDomainsEx()
    request["PolicyHandle"] = policyHandle
    request["EnumerationContext"] = enumerationContext
    request["PreferedMaximumLength"] = preferedMaximumLength
    return dce.request(request)

 func hLsarEnumerateTrustedDomains(dce, policyHandle, enumerationContext=0, preferedMaximumLength=0xffffffff interface{}){
    request = LsarEnumerateTrustedDomains()
    request["PolicyHandle"] = policyHandle
    request["EnumerationContext"] = enumerationContext
    request["PreferedMaximumLength"] = preferedMaximumLength
    return dce.request(request)

 func hLsarOpenAccount(dce, policyHandle, accountSid, desiredAccess=MAXIMUM_ALLOWED interface{}){
    request = LsarOpenAccount()
    request["PolicyHandle"] = policyHandle
    request["AccountSid"].fromCanonical(accountSid)
    request["DesiredAccess"] = desiredAccess
    return dce.request(request)

 func hLsarClose(dce, objectHandle interface{}){
    request = LsarClose()
    request["ObjectHandle"] = objectHandle
    return dce.request(request)

 func hLsarCreateAccount(dce, policyHandle, accountSid, desiredAccess=MAXIMUM_ALLOWED interface{}){
    request = LsarCreateAccount()
    request["PolicyHandle"] = policyHandle
    request["AccountSid"].fromCanonical(accountSid)
    request["DesiredAccess"] = desiredAccess
    return dce.request(request)

 func hLsarDeleteObject(dce, objectHandle interface{}){
    request = LsarDeleteObject()
    request["ObjectHandle"] = objectHandle
    return dce.request(request)

 func hLsarEnumeratePrivilegesAccount(dce, accountHandle interface{}){
    request = LsarEnumeratePrivilegesAccount()
    request["AccountHandle"] = accountHandle
    return dce.request(request)

 func hLsarGetSystemAccessAccount(dce, accountHandle interface{}){
    request = LsarGetSystemAccessAccount()
    request["AccountHandle"] = accountHandle
    return dce.request(request)

 func hLsarSetSystemAccessAccount(dce, accountHandle, systemAccess interface{}){
    request = LsarSetSystemAccessAccount()
    request["AccountHandle"] = accountHandle
    request["SystemAccess"] = systemAccess
    return dce.request(request)

 func hLsarAddPrivilegesToAccount(dce, accountHandle, privileges interface{}){
    request = LsarAddPrivilegesToAccount()
    request["AccountHandle"] = accountHandle
    request["Privileges"]["PrivilegeCount"] = len(privileges)
    request["Privileges"]["Control"] = 0
    for priv in privileges:
        request["Privileges"]["Privilege"].append(priv)

    return dce.request(request)

 func hLsarRemovePrivilegesFromAccount(dce, accountHandle, privileges, allPrivileges = false interface{}){
    request = LsarRemovePrivilegesFromAccount()
    request["AccountHandle"] = accountHandle
    request["Privileges"]["Control"] = 0
    if privileges != NULL {
        request["Privileges"]["PrivilegeCount"] = len(privileges)
        for priv in privileges:
            request["Privileges"]["Privilege"].append(priv)
    } else  {
        request["Privileges"]["PrivilegeCount"] = NULL
    request["AllPrivileges"] = allPrivileges

    return dce.request(request)

 func hLsarEnumerateAccountRights(dce, policyHandle, accountSid interface{}){
    request = LsarEnumerateAccountRights()
    request["PolicyHandle"] = policyHandle
    request["AccountSid"].fromCanonical(accountSid)
    return dce.request(request)

 func hLsarAddAccountRights(dce, policyHandle, accountSid, userRights interface{}){
    request = LsarAddAccountRights()
    request["PolicyHandle"] = policyHandle
    request["AccountSid"].fromCanonical(accountSid)
    request["UserRights"]["EntriesRead"] = len(userRights)
    for userRight in userRights:
        right = RPC_UNICODE_STRING()
        right["Data"] = userRight
        request["UserRights"]["UserRights"].append(right)

    return dce.request(request)

 func hLsarRemoveAccountRights(dce, policyHandle, accountSid, userRights interface{}){
    request = LsarRemoveAccountRights()
    request["PolicyHandle"] = policyHandle
    request["AccountSid"].fromCanonical(accountSid)
    request["UserRights"]["EntriesRead"] = len(userRights)
    for userRight in userRights:
        right = RPC_UNICODE_STRING()
        right["Data"] = userRight
        request["UserRights"]["UserRights"].append(right)

    return dce.request(request)

 func hLsarCreateSecret(dce, policyHandle, secretName, desiredAccess=MAXIMUM_ALLOWED interface{}){
    request = LsarCreateSecret()
    request["PolicyHandle"] = policyHandle
    request["SecretName"] = secretName
    request["DesiredAccess"] = desiredAccess
    return dce.request(request)

 func hLsarOpenSecret(dce, policyHandle, secretName, desiredAccess=MAXIMUM_ALLOWED interface{}){
    request = LsarOpenSecret()
    request["PolicyHandle"] = policyHandle
    request["SecretName"] = secretName
    request["DesiredAccess"] = desiredAccess
    return dce.request(request)

 func hLsarSetSecret(dce, secretHandle, encryptedCurrentValue, encryptedOldValue interface{}){
    request = LsarOpenSecret()
    request["SecretHandle"] = secretHandle
    if encryptedCurrentValue != NULL {
        request["EncryptedCurrentValue"]["Length"] = len(encryptedCurrentValue)
        request["EncryptedCurrentValue"]["MaximumLength"] = len(encryptedCurrentValue)
        request["EncryptedCurrentValue"]["Buffer"] = list(encryptedCurrentValue)
    if encryptedOldValue != NULL {
        request["EncryptedOldValue"]["Length"] = len(encryptedOldValue)
        request["EncryptedOldValue"]["MaximumLength"] = len(encryptedOldValue)
        request["EncryptedOldValue"]["Buffer"] = list(encryptedOldValue)
    return dce.request(request)

 func hLsarQuerySecret(dce, secretHandle interface{}){
    request = LsarQuerySecret()
    request["SecretHandle"] = secretHandle
    request["EncryptedCurrentValue"]["Buffer"] = NULL
    request["EncryptedOldValue"]["Buffer"] = NULL
    request["OldValueSetTime"] = NULL
    return dce.request(request)

 func hLsarRetrievePrivateData(dce, policyHandle, keyName interface{}){
    request = LsarRetrievePrivateData()
    request["PolicyHandle"] = policyHandle
    request["KeyName"] = keyName
    retVal = dce.request(request)
    return b''.join(retVal["EncryptedData"]["Buffer"])

 func hLsarStorePrivateData(dce, policyHandle, keyName, encryptedData interface{}){
    request = LsarStorePrivateData()
    request["PolicyHandle"] = policyHandle
    request["KeyName"] = keyName
    if encryptedData != NULL {
        request["EncryptedData"]["Length"] = len(encryptedData)
        request["EncryptedData"]["MaximumLength"] = len(encryptedData)
        request["EncryptedData"]["Buffer"] = list(encryptedData)
    } else  {
        request["EncryptedData"] = NULL
    return dce.request(request)

 func hLsarEnumeratePrivileges(dce, policyHandle, enumerationContext = 0, preferedMaximumLength = 0xffffffff interface{}){
    request = LsarEnumeratePrivileges()
    request["PolicyHandle"] = policyHandle
    request["EnumerationContext"] = enumerationContext
    request["PreferedMaximumLength"] = preferedMaximumLength
    return dce.request(request)

 func hLsarLookupPrivilegeValue(dce, policyHandle, name interface{}){
    request = LsarLookupPrivilegeValue()
    request["PolicyHandle"] = policyHandle
    request["Name"] = name
    return dce.request(request)

 func hLsarLookupPrivilegeName(dce, policyHandle, luid interface{}){
    request = LsarLookupPrivilegeName()
    request["PolicyHandle"] = policyHandle
    request["Value"] = luid
    return dce.request(request)

 func hLsarQuerySecurityObject(dce, policyHandle, securityInformation = OWNER_SECURITY_INFORMATION interface{}){
    request = LsarQuerySecurityObject()
    request["PolicyHandle"] = policyHandle
    request["SecurityInformation"] = securityInformation
    retVal =  dce.request(request)
    return b''.join(retVal["SecurityDescriptor"]["SecurityDescriptor"])

 func hLsarSetSecurityObject(dce, policyHandle, securityInformation, securityDescriptor interface{}){
    request = LsarSetSecurityObject()
    request["PolicyHandle"] = policyHandle
    request["SecurityInformation"] = securityInformation
    request["SecurityDescriptor"]["Length"] = len(securityDescriptor)
    request["SecurityDescriptor"]["SecurityDescriptor"] = list(securityDescriptor)
    return dce.request(request)

 func hLsarSetInformationPolicy2(dce, policyHandle, informationClass, policyInformation interface{}){
    request = LsarSetInformationPolicy2()
    request["PolicyHandle"] = policyHandle
    request["InformationClass"] = informationClass
    request["PolicyInformation"] = policyInformation
    return dce.request(request)

 func hLsarSetInformationPolicy(dce, policyHandle, informationClass, policyInformation interface{}){
    request = LsarSetInformationPolicy()
    request["PolicyHandle"] = policyHandle
    request["InformationClass"] = informationClass
    request["PolicyInformation"] = policyInformation
    return dce.request(request)
