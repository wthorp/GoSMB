// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Author: Alberto Solino (@agsolino)
//
// Description:
//   [MS-SAMR] Interface implementation
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
from binascii import unhexlify

from impacket.dcerpc.v5.ndr import NDRCALL, NDR, NDRSTRUCT, NDRUNION, NDRPOINTER, NDRUniConformantArray, \
    NDRUniConformantVaryingArray, NDRENUM
from impacket.dcerpc.v5.dtypes import NULL, RPC_UNICODE_STRING, ULONG, USHORT, UCHAR, LARGE_INTEGER, RPC_SID, LONG, STR, \
    LPBYTE, SECURITY_INFORMATION, PRPC_SID, PRPC_UNICODE_STRING, LPWSTR
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket import nt_errors, LOG
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.enum import Enum
from impacket.structure import Structure

MSRPC_UUID_SAMR   = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AC', '1.0'))

 type DCERPCSessionError struct { // DCERPCException:
     func (self TYPE) __init__(error_string=nil, error_code=nil, packet=nil interface{}){
        DCERPCException.__init__(self, error_string, error_code, packet)

     func __str__( self  interface{}){
        key = self.error_code
        if key in nt_errors.ERROR_MESSAGES {
            error_msg_short = nt_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = nt_errors.ERROR_MESSAGES[key][1] 
            return 'SAMR SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        } else  {
            return 'SAMR SessionError: unknown error code: 0x%x' % self.error_code

//###############################################################################
// CONSTANTS
//###############################################################################
PSAMPR_SERVER_NAME = LPWSTR
// 2.2.1.1 Common ACCESS_MASK Values
DELETE                  = 0x00010000
READ_CONTROL            = 0x00020000
WRITE_DAC               = 0x00040000
WRITE_OWNER             = 0x00080000
ACCESS_SYSTEM_SECURITY  = 0x01000000
MAXIMUM_ALLOWED         = 0x02000000

// 2.2.1.2 Generic ACCESS_MASK Values
GENERIC_READ     = 0x80000000
GENERIC_WRITE    = 0x40000000
GENERIC_EXECUTE  = 0x20000000
GENERIC_ALL      = 0x10000000

// 2.2.1.3 Server ACCESS_MASK Values
SAM_SERVER_CONNECT            = 0x00000001
SAM_SERVER_SHUTDOWN           = 0x00000002
SAM_SERVER_INITIALIZE         = 0x00000004
SAM_SERVER_CREATE_DOMAIN      = 0x00000008
SAM_SERVER_ENUMERATE_DOMAINS  = 0x00000010
SAM_SERVER_LOOKUP_DOMAIN      = 0x00000020
SAM_SERVER_ALL_ACCESS         = 0x000F003F
SAM_SERVER_READ               = 0x00020010
SAM_SERVER_WRITE              = 0x0002000E
SAM_SERVER_EXECUTE            = 0x00020021

// 2.2.1.4 Domain ACCESS_MASK Values
DOMAIN_READ_PASSWORD_PARAMETERS = 0x00000001
DOMAIN_WRITE_PASSWORD_PARAMS    = 0x00000002
DOMAIN_READ_OTHER_PARAMETERS    = 0x00000004
DOMAIN_WRITE_OTHER_PARAMETERS   = 0x00000008
DOMAIN_CREATE_USER              = 0x00000010
DOMAIN_CREATE_GROUP             = 0x00000020
DOMAIN_CREATE_ALIAS             = 0x00000040
DOMAIN_GET_ALIAS_MEMBERSHIP     = 0x00000080
DOMAIN_LIST_ACCOUNTS            = 0x00000100
DOMAIN_LOOKUP                   = 0x00000200
DOMAIN_ADMINISTER_SERVER        = 0x00000400
DOMAIN_ALL_ACCESS               = 0x000F07FF
DOMAIN_READ                     = 0x00020084
DOMAIN_WRITE                    = 0x0002047A
DOMAIN_EXECUTE                  = 0x00020301

// 2.2.1.5 Group ACCESS_MASK Values
GROUP_READ_INFORMATION  = 0x00000001
GROUP_WRITE_ACCOUNT     = 0x00000002
GROUP_ADD_MEMBER        = 0x00000004
GROUP_REMOVE_MEMBER     = 0x00000008
GROUP_LIST_MEMBERS      = 0x00000010
GROUP_ALL_ACCESS        = 0x000F001F
GROUP_READ              = 0x00020010
GROUP_WRITE             = 0x0002000E
GROUP_EXECUTE           = 0x00020001

// 2.2.1.6 Alias ACCESS_MASK Values
ALIAS_ADD_MEMBER        = 0x00000001
ALIAS_REMOVE_MEMBER     = 0x00000002
ALIAS_LIST_MEMBERS      = 0x00000004
ALIAS_READ_INFORMATION  = 0x00000008
ALIAS_WRITE_ACCOUNT     = 0x00000010
ALIAS_ALL_ACCESS        = 0x000F001F
ALIAS_READ              = 0x00020004
ALIAS_WRITE             = 0x00020013
ALIAS_EXECUTE           = 0x00020008

// 2.2.1.7 User ACCESS_MASK Values
USER_READ_GENERAL            = 0x00000001
USER_READ_PREFERENCES        = 0x00000002
USER_WRITE_PREFERENCES       = 0x00000004
USER_READ_LOGON              = 0x00000008
USER_READ_ACCOUNT            = 0x00000010
USER_WRITE_ACCOUNT           = 0x00000020
USER_CHANGE_PASSWORD         = 0x00000040
USER_FORCE_PASSWORD_CHANGE   = 0x00000080
USER_LIST_GROUPS             = 0x00000100
USER_READ_GROUP_INFORMATION  = 0x00000200
USER_WRITE_GROUP_INFORMATION = 0x00000400
USER_ALL_ACCESS              = 0x000F07FF
USER_READ                    = 0x0002031A
USER_WRITE                   = 0x00020044
USER_EXECUTE                 = 0x00020041

// 2.2.1.8 USER_ALL Values
USER_ALL_USERNAME            = 0x00000001
USER_ALL_FULLNAME            = 0x00000002
USER_ALL_USERID              = 0x00000004
USER_ALL_PRIMARYGROUPID      = 0x00000008
USER_ALL_ADMINCOMMENT        = 0x00000010
USER_ALL_USERCOMMENT         = 0x00000020
USER_ALL_HOMEDIRECTORY       = 0x00000040
USER_ALL_HOMEDIRECTORYDRIVE  = 0x00000080
USER_ALL_SCRIPTPATH          = 0x00000100
USER_ALL_PROFILEPATH         = 0x00000200
USER_ALL_WORKSTATIONS        = 0x00000400
USER_ALL_LASTLOGON           = 0x00000800
USER_ALL_LASTLOGOFF          = 0x00001000
USER_ALL_LOGONHOURS          = 0x00002000
USER_ALL_BADPASSWORDCOUNT    = 0x00004000
USER_ALL_LOGONCOUNT          = 0x00008000
USER_ALL_PASSWORDCANCHANGE   = 0x00010000
USER_ALL_PASSWORDMUSTCHANGE  = 0x00020000
USER_ALL_PASSWORDLASTSET     = 0x00040000
USER_ALL_ACCOUNTEXPIRES      = 0x00080000
USER_ALL_USERACCOUNTCONTROL  = 0x00100000
USER_ALL_PARAMETERS          = 0x00200000
USER_ALL_COUNTRYCODE         = 0x00400000
USER_ALL_CODEPAGE            = 0x00800000
USER_ALL_NTPASSWORDPRESENT   = 0x01000000
USER_ALL_LMPASSWORDPRESENT   = 0x02000000
USER_ALL_PRIVATEDATA         = 0x04000000
USER_ALL_PASSWORDEXPIRED     = 0x08000000
USER_ALL_SECURITYDESCRIPTOR  = 0x10000000
USER_ALL_UNDEFINED_MASK      = 0xC0000000

// 2.2.1.9 ACCOUNT_TYPE Values
SAM_DOMAIN_OBJECT             = 0x00000000
SAM_GROUP_OBJECT              = 0x10000000
SAM_NON_SECURITY_GROUP_OBJECT = 0x10000001
SAM_ALIAS_OBJECT              = 0x20000000
SAM_NON_SECURITY_ALIAS_OBJECT = 0x20000001
SAM_USER_OBJECT               = 0x30000000
SAM_MACHINE_ACCOUNT           = 0x30000001
SAM_TRUST_ACCOUNT             = 0x30000002
SAM_APP_BASIC_GROUP           = 0x40000000
SAM_APP_QUERY_GROUP           = 0x40000001

// 2.2.1.10 SE_GROUP Attributes
SE_GROUP_MANDATORY            = 0x00000001
SE_GROUP_ENABLED_BY_DEFAULT   = 0x00000002
SE_GROUP_ENABLED              = 0x00000004

// 2.2.1.11 GROUP_TYPE Codes
GROUP_TYPE_ACCOUNT_GROUP      = 0x00000002
GROUP_TYPE_RESOURCE_GROUP     = 0x00000004
GROUP_TYPE_UNIVERSAL_GROUP    = 0x00000008
GROUP_TYPE_SECURITY_ENABLED   = 0x80000000
GROUP_TYPE_SECURITY_ACCOUNT   = 0x80000002
GROUP_TYPE_SECURITY_RESOURCE  = 0x80000004
GROUP_TYPE_SECURITY_UNIVERSAL = 0x80000008

// 2.2.1.12 USER_ACCOUNT Codes
USER_ACCOUNT_DISABLED                       = 0x00000001
USER_HOME_DIRECTORY_REQUIRED                = 0x00000002
USER_PASSWORD_NOT_REQUIRED                  = 0x00000004
USER_TEMP_DUPLICATE_ACCOUNT                 = 0x00000008
USER_NORMAL_ACCOUNT                         = 0x00000010
USER_MNS_LOGON_ACCOUNT                      = 0x00000020
USER_INTERDOMAIN_TRUST_ACCOUNT              = 0x00000040
USER_WORKSTATION_TRUST_ACCOUNT              = 0x00000080
USER_SERVER_TRUST_ACCOUNT                   = 0x00000100
USER_DONT_EXPIRE_PASSWORD                   = 0x00000200
USER_ACCOUNT_AUTO_LOCKED                    = 0x00000400
USER_ENCRYPTED_TEXT_PASSWORD_ALLOWED        = 0x00000800
USER_SMARTCARD_REQUIRED                     = 0x00001000
USER_TRUSTED_FOR_DELEGATION                 = 0x00002000
USER_NOT_DELEGATED                          = 0x00004000
USER_USE_DES_KEY_ONLY                       = 0x00008000
USER_DONT_REQUIRE_PREAUTH                   = 0x00010000
USER_PASSWORD_EXPIRED                       = 0x00020000
USER_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x00040000
USER_NO_AUTH_DATA_REQUIRED                  = 0x00080000
USER_PARTIAL_SECRETS_ACCOUNT                = 0x00100000
USER_USE_AES_KEYS                           = 0x00200000

// 2.2.1.13 UF_FLAG Codes
UF_SCRIPT                                 = 0x00000001
UF_ACCOUNTDISABLE                         = 0x00000002
UF_HOMEDIR_REQUIRED                       = 0x00000008
UF_LOCKOUT                                = 0x00000010
UF_PASSWD_NOTREQD                         = 0x00000020
UF_PASSWD_CANT_CHANGE                     = 0x00000040
UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED        = 0x00000080
UF_TEMP_DUPLICATE_ACCOUNT                 = 0x00000100
UF_NORMAL_ACCOUNT                         = 0x00000200
UF_INTERDOMAIN_TRUST_ACCOUNT              = 0x00000800
UF_WORKSTATION_TRUST_ACCOUNT              = 0x00001000
UF_SERVER_TRUST_ACCOUNT                   = 0x00002000
UF_DONT_EXPIRE_PASSWD                     = 0x00010000
UF_MNS_LOGON_ACCOUNT                      = 0x00020000
UF_SMARTCARD_REQUIRED                     = 0x00040000
UF_TRUSTED_FOR_DELEGATION                 = 0x00080000
UF_NOT_DELEGATED                          = 0x00100000
UF_USE_DES_KEY_ONLY                       = 0x00200000
UF_DONT_REQUIRE_PREAUTH                   = 0x00400000
UF_PASSWORD_EXPIRED                       = 0x00800000
UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000
UF_NO_AUTH_DATA_REQUIRED                  = 0x02000000
UF_PARTIAL_SECRETS_ACCOUNT                = 0x04000000
UF_USE_AES_KEYS                           = 0x08000000

// 2.2.1.14 Predefined RIDs
DOMAIN_USER_RID_ADMIN                 = 0x000001F4
DOMAIN_USER_RID_GUEST                 = 0x000001F5
DOMAIN_USER_RID_KRBTGT                = 0x000001F6
DOMAIN_GROUP_RID_ADMINS               = 0x00000200
DOMAIN_GROUP_RID_USERS                = 0x00000201
DOMAIN_GROUP_RID_COMPUTERS            = 0x00000203
DOMAIN_GROUP_RID_CONTROLLERS          = 0x00000204
DOMAIN_ALIAS_RID_ADMINS               = 0x00000220
DOMAIN_GROUP_RID_READONLY_CONTROLLERS = 0x00000209

// 2.2.4.1 Domain Fields
DOMAIN_PASSWORD_COMPLEX         = 0x00000001
DOMAIN_PASSWORD_NO_ANON_CHANGE  = 0x00000002
DOMAIN_PASSWORD_NO_CLEAR_CHANGE = 0x00000004
DOMAIN_LOCKOUT_ADMINS           = 0x00000008
DOMAIN_PASSWORD_STORE_CLEARTEXT = 0x00000010
DOMAIN_REFUSE_PASSWORD_CHANGE   = 0x00000020

// 2.2.9.2 SAM_VALIDATE_PERSISTED_FIELDS PresentFields
SAM_VALIDATE_PASSWORD_LAST_SET       = 0x00000001
SAM_VALIDATE_BAD_PASSWORD_TIME       = 0x00000002
SAM_VALIDATE_LOCKOUT_TIME            = 0x00000004
SAM_VALIDATE_BAD_PASSWORD_COUNT      = 0x00000008
SAM_VALIDATE_PASSWORD_HISTORY_LENGTH = 0x00000010
SAM_VALIDATE_PASSWORD_HISTORY        = 0x00000020

//###############################################################################
// STRUCTURES
//###############################################################################
 type RPC_UNICODE_STRING_ARRAY struct { // NDRUniConformantVaryingArray:
    item = RPC_UNICODE_STRING

 type RPC_UNICODE_STRING_ARRAY_C struct { // NDRUniConformantArray:
    item = RPC_UNICODE_STRING

 type PRPC_UNICODE_STRING_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data',RPC_UNICODE_STRING_ARRAY_C),
    }

// 2.2.2.1 RPC_STRING, PRPC_STRING
 type RPC_STRING struct { // NDRSTRUCT:
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

 type PRPC_STRING struct { // NDRPOINTER:
    referent = (
        ('Data', RPC_STRING),
    }
 
// 2.2.2.2 OLD_LARGE_INTEGER
 type OLD_LARGE_INTEGER struct { // NDRSTRUCT: (
        ('LowPart',ULONG),
        ('HighPart',LONG),
    }

// 2.2.2.3 SID_NAME_USE
 type SID_NAME_USE struct { // NDRENUM:
     type enumItems struct { // Enum:
        SidTypeUser            = 1
        SidTypeGroup           = 2
        SidTypeDomain          = 3
        SidTypeAlias           = 4
        SidTypeWellKnownGroup  = 5
        SidTypeDeletedAccount  = 6
        SidTypeInvalid         = 7
        SidTypeUnknown         = 8
        SidTypeComputer        = 9
        SidTypeLabel           = 10

// 2.2.2.4 RPC_SHORT_BLOB
 type USHORT_ARRAY struct { // NDRUniConformantVaryingArray:
    item = "<H"
    pass

 type PUSHORT_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', USHORT_ARRAY),
    }

 type RPC_SHORT_BLOB struct { // NDRSTRUCT: (
        ('Length', USHORT),
        ('MaximumLength', USHORT),
        ('Buffer',PUSHORT_ARRAY),
    }

// 2.2.3.2 SAMPR_HANDLE
 type SAMPR_HANDLE struct { // NDRSTRUCT:  (
         Data [0]byte // =b""
    }
     func (self TYPE) getAlignment(){
        if self._isNDR64 is true {
            return 8
        } else  {
            return 4

// 2.2.3.3 ENCRYPTED_LM_OWF_PASSWORD, ENCRYPTED_NT_OWF_PASSWORD
 type ENCRYPTED_LM_OWF_PASSWORD struct { // NDRSTRUCT: (
         Data [6]byte // =b""
    }
     func (self TYPE) getAlignment(){
        return 1

ENCRYPTED_NT_OWF_PASSWORD = ENCRYPTED_LM_OWF_PASSWORD

 type PENCRYPTED_LM_OWF_PASSWORD struct { // NDRPOINTER:
    referent = (
        ('Data', ENCRYPTED_LM_OWF_PASSWORD),
    }

PENCRYPTED_NT_OWF_PASSWORD = PENCRYPTED_LM_OWF_PASSWORD

// 2.2.3.4 SAMPR_ULONG_ARRAY
// type SAMPR_ULONG_ARRAY struct { // NDRUniConformantVaryingArray:
//    item = "<L"
 type ULONG_ARRAY struct { // NDRUniConformantArray:
    item = ULONG

 type PULONG_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', ULONG_ARRAY),
    }

 type ULONG_ARRAY_CV struct { // NDRUniConformantVaryingArray:
    item = ULONG

 type SAMPR_ULONG_ARRAY struct { // NDRSTRUCT: (
        ('Count', ULONG),
        ('Element', PULONG_ARRAY),
    }

// 2.2.3.5 SAMPR_SID_INFORMATION
 type SAMPR_SID_INFORMATION struct { // NDRSTRUCT: (
        ('SidPointer', RPC_SID),
    }

 type PSAMPR_SID_INFORMATION struct { // NDRPOINTER:
    referent = (
        ('Data', SAMPR_SID_INFORMATION),
    }

 type SAMPR_SID_INFORMATION_ARRAY struct { // NDRUniConformantArray:
    item = PSAMPR_SID_INFORMATION

 type PSAMPR_SID_INFORMATION_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SAMPR_SID_INFORMATION_ARRAY),
    }

// 2.2.3.6 SAMPR_PSID_ARRAY
 type SAMPR_PSID_ARRAY struct { // NDRSTRUCT: (
        ('Count', ULONG),
        ('Sids', PSAMPR_SID_INFORMATION_ARRAY),
    }

// 2.2.3.7 SAMPR_PSID_ARRAY_OUT
 type SAMPR_PSID_ARRAY_OUT struct { // NDRSTRUCT: (
        ('Count', ULONG),
        ('Sids', PSAMPR_SID_INFORMATION_ARRAY),
    }

// 2.2.3.8 SAMPR_RETURNED_USTRING_ARRAY
 type SAMPR_RETURNED_USTRING_ARRAY struct { // NDRSTRUCT: (
        ('Count', ULONG),
        ('Element', PRPC_UNICODE_STRING_ARRAY),
    }

// 2.2.3.9 SAMPR_RID_ENUMERATION
 type SAMPR_RID_ENUMERATION struct { // NDRSTRUCT: (
        ('RelativeId',ULONG),
        ('Name',RPC_UNICODE_STRING),
    }

 type SAMPR_RID_ENUMERATION_ARRAY struct { // NDRUniConformantArray:
    item = SAMPR_RID_ENUMERATION

 type PSAMPR_RID_ENUMERATION_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', SAMPR_RID_ENUMERATION_ARRAY),
    }

// 2.2.3.10 SAMPR_ENUMERATION_BUFFER
 type SAMPR_ENUMERATION_BUFFER struct { // NDRSTRUCT: (
        ('EntriesRead',ULONG ),
        ('Buffer',PSAMPR_RID_ENUMERATION_ARRAY ),
    }

 type PSAMPR_ENUMERATION_BUFFER struct { // NDRPOINTER:
    referent = (
        ('Data',SAMPR_ENUMERATION_BUFFER),
    }

// 2.2.3.11 SAMPR_SR_SECURITY_DESCRIPTOR
 type CHAR_ARRAY struct { // NDRUniConformantArray:
    pass

 type PCHAR_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', CHAR_ARRAY),
    }

 type SAMPR_SR_SECURITY_DESCRIPTOR struct { // NDRSTRUCT: (
        ('Length', ULONG),
        ('SecurityDescriptor', PCHAR_ARRAY),
    }

 type PSAMPR_SR_SECURITY_DESCRIPTOR struct { // NDRPOINTER:
    referent = (
        ('Data', SAMPR_SR_SECURITY_DESCRIPTOR),
    }

// 2.2.3.12 GROUP_MEMBERSHIP
 type GROUP_MEMBERSHIP struct { // NDRSTRUCT: (
        ('RelativeId',ULONG),
        ('Attributes',ULONG),
    }

 type GROUP_MEMBERSHIP_ARRAY struct { // NDRUniConformantArray:
    item = GROUP_MEMBERSHIP

 type PGROUP_MEMBERSHIP_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data',GROUP_MEMBERSHIP_ARRAY),
    } 

// 2.2.3.13 SAMPR_GET_GROUPS_BUFFER
 type SAMPR_GET_GROUPS_BUFFER struct { // NDRSTRUCT: (
        ('MembershipCount',ULONG),
        ('Groups',PGROUP_MEMBERSHIP_ARRAY),
    }

 type PSAMPR_GET_GROUPS_BUFFER struct { // NDRPOINTER:
    referent = (
        ('Data',SAMPR_GET_GROUPS_BUFFER),
    }

// 2.2.3.14 SAMPR_GET_MEMBERS_BUFFER
 type SAMPR_GET_MEMBERS_BUFFER struct { // NDRSTRUCT: (
        ('MemberCount', ULONG),
        ('Members', PULONG_ARRAY),
        ('Attributes', PULONG_ARRAY),
    }

 type PSAMPR_GET_MEMBERS_BUFFER struct { // NDRPOINTER:
    referent = (
        ('Data', SAMPR_GET_MEMBERS_BUFFER),
    }

// 2.2.3.15 SAMPR_REVISION_INFO_V1
 type SAMPR_REVISION_INFO_V1 struct { // NDRSTRUCT: (
       ('Revision',ULONG),
       ('SupportedFeatures',ULONG),
    }

// 2.2.3.16 SAMPR_REVISION_INFO
 type SAMPR_REVISION_INFO struct { // NDRUNION:
    commonHdr = (
        ('tag', ULONG),
    }

    union = {
        1: ('V1', SAMPR_REVISION_INFO_V1),
    }

// 2.2.3.17 USER_DOMAIN_PASSWORD_INFORMATION
 type USER_DOMAIN_PASSWORD_INFORMATION struct { // NDRSTRUCT: (
        ('MinPasswordLength', USHORT),
        ('PasswordProperties', ULONG),
    }

// 2.2.4.2 DOMAIN_SERVER_ENABLE_STATE
 type DOMAIN_SERVER_ENABLE_STATE struct { // NDRENUM:
     type enumItems struct { // Enum:
        DomainServerEnabled  = 1
        DomainServerDisabled = 2

// 2.2.4.3 DOMAIN_STATE_INFORMATION
 type DOMAIN_STATE_INFORMATION struct { // NDRSTRUCT: (
        ('DomainServerState', DOMAIN_SERVER_ENABLE_STATE),
    }

// 2.2.4.4 DOMAIN_SERVER_ROLE
 type DOMAIN_SERVER_ROLE struct { // NDRENUM:
     type enumItems struct { // Enum:
        DomainServerRoleBackup  = 2
        DomainServerRolePrimary = 3

// 2.2.4.5 DOMAIN_PASSWORD_INFORMATION
 type DOMAIN_PASSWORD_INFORMATION struct { // NDRSTRUCT: (
        ('MinPasswordLength', USHORT),
        ('PasswordHistoryLength', USHORT),
        ('PasswordProperties', ULONG),
        ('MaxPasswordAge', OLD_LARGE_INTEGER),
        ('MinPasswordAge', OLD_LARGE_INTEGER),
    }

// 2.2.4.6 DOMAIN_LOGOFF_INFORMATION
 type DOMAIN_LOGOFF_INFORMATION struct { // NDRSTRUCT: (
        ('ForceLogoff', OLD_LARGE_INTEGER),
    }

// 2.2.4.7 DOMAIN_SERVER_ROLE_INFORMATION
 type DOMAIN_SERVER_ROLE_INFORMATION struct { // NDRSTRUCT: (
        ('DomainServerRole', DOMAIN_SERVER_ROLE),
    }

// 2.2.4.8 DOMAIN_MODIFIED_INFORMATION
 type DOMAIN_MODIFIED_INFORMATION struct { // NDRSTRUCT: (
        ('DomainModifiedCount', OLD_LARGE_INTEGER),
        ('CreationTime', OLD_LARGE_INTEGER),
    }

// 2.2.4.9 DOMAIN_MODIFIED_INFORMATION2
 type DOMAIN_MODIFIED_INFORMATION2 struct { // NDRSTRUCT: (
        ('DomainModifiedCount', OLD_LARGE_INTEGER),
        ('CreationTime', OLD_LARGE_INTEGER),
        ('ModifiedCountAtLastPromotion', OLD_LARGE_INTEGER),
    }

// 2.2.4.10 SAMPR_DOMAIN_GENERAL_INFORMATION
 type SAMPR_DOMAIN_GENERAL_INFORMATION struct { // NDRSTRUCT: (
        ('ForceLogoff', OLD_LARGE_INTEGER),
        ('OemInformation', RPC_UNICODE_STRING),
        ('DomainName', RPC_UNICODE_STRING),
        ('ReplicaSourceNodeName', RPC_UNICODE_STRING),
        ('DomainModifiedCount', OLD_LARGE_INTEGER),
        ('DomainServerState', ULONG),
        ('DomainServerRole', ULONG),
        ('UasCompatibilityRequired', UCHAR),
        ('UserCount', ULONG),
        ('GroupCount', ULONG),
        ('AliasCount', ULONG),
    }

// 2.2.4.11 SAMPR_DOMAIN_GENERAL_INFORMATION2
 type SAMPR_DOMAIN_GENERAL_INFORMATION2 struct { // NDRSTRUCT: (
        ('I1', SAMPR_DOMAIN_GENERAL_INFORMATION),
        ('LockoutDuration', LARGE_INTEGER),
        ('LockoutObservationWindow', LARGE_INTEGER),
        ('LockoutThreshold', USHORT),
    }

// 2.2.4.12 SAMPR_DOMAIN_OEM_INFORMATION
 type SAMPR_DOMAIN_OEM_INFORMATION struct { // NDRSTRUCT: (
        ('OemInformation', RPC_UNICODE_STRING),
    }

// 2.2.4.13 SAMPR_DOMAIN_NAME_INFORMATION
 type SAMPR_DOMAIN_NAME_INFORMATION struct { // NDRSTRUCT: (
        ('DomainName', RPC_UNICODE_STRING),
    }

// 2.2.4.14 SAMPR_DOMAIN_REPLICATION_INFORMATION
 type SAMPR_DOMAIN_REPLICATION_INFORMATION struct { // NDRSTRUCT: (
        ('ReplicaSourceNodeName', RPC_UNICODE_STRING),
    }

// 2.2.4.15 SAMPR_DOMAIN_LOCKOUT_INFORMATION
 type SAMPR_DOMAIN_LOCKOUT_INFORMATION struct { // NDRSTRUCT: (
        ('LockoutDuration', LARGE_INTEGER),
        ('LockoutObservationWindow', LARGE_INTEGER),
        ('LockoutThreshold', USHORT),
    }

// 2.2.4.16 DOMAIN_INFORMATION_CLASS
 type DOMAIN_INFORMATION_CLASS struct { // NDRENUM:
     type enumItems struct { // Enum:
        DomainPasswordInformation    = 1
        DomainGeneralInformation     = 2
        DomainLogoffInformation      = 3
        DomainOemInformation         = 4
        DomainNameInformation        = 5
        DomainReplicationInformation = 6
        DomainServerRoleInformation  = 7
        DomainModifiedInformation    = 8
        DomainStateInformation       = 9
        DomainGeneralInformation2    = 11
        DomainLockoutInformation     = 12
        DomainModifiedInformation2   = 13

// 2.2.4.17 SAMPR_DOMAIN_INFO_BUFFER
 type SAMPR_DOMAIN_INFO_BUFFER struct { // NDRUNION:
    union = {
        DOMAIN_INFORMATION_CLASS.DomainPasswordInformation    : ('Password', DOMAIN_PASSWORD_INFORMATION),
        DOMAIN_INFORMATION_CLASS.DomainGeneralInformation     : ('General', SAMPR_DOMAIN_GENERAL_INFORMATION),
        DOMAIN_INFORMATION_CLASS.DomainLogoffInformation      : ('Logoff', DOMAIN_LOGOFF_INFORMATION),
        DOMAIN_INFORMATION_CLASS.DomainOemInformation         : ('Oem', SAMPR_DOMAIN_OEM_INFORMATION),
        DOMAIN_INFORMATION_CLASS.DomainNameInformation        : ('Name', SAMPR_DOMAIN_NAME_INFORMATION),
        DOMAIN_INFORMATION_CLASS.DomainServerRoleInformation  : ('Role', DOMAIN_SERVER_ROLE_INFORMATION),
        DOMAIN_INFORMATION_CLASS.DomainReplicationInformation : ('Replication', SAMPR_DOMAIN_REPLICATION_INFORMATION),
        DOMAIN_INFORMATION_CLASS.DomainModifiedInformation    : ('Modified', DOMAIN_MODIFIED_INFORMATION),
        DOMAIN_INFORMATION_CLASS.DomainStateInformation       : ('State', DOMAIN_STATE_INFORMATION),
        DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2    : ('General2', SAMPR_DOMAIN_GENERAL_INFORMATION2),
        DOMAIN_INFORMATION_CLASS.DomainLockoutInformation     : ('Lockout', SAMPR_DOMAIN_LOCKOUT_INFORMATION),
        DOMAIN_INFORMATION_CLASS.DomainModifiedInformation2   : ('Modified2', DOMAIN_MODIFIED_INFORMATION2),
    }

 type PSAMPR_DOMAIN_INFO_BUFFER struct { // NDRPOINTER:
    referent = (
        ('Data', SAMPR_DOMAIN_INFO_BUFFER),
    }

// 2.2.5.2 GROUP_ATTRIBUTE_INFORMATION
 type GROUP_ATTRIBUTE_INFORMATION struct { // NDRSTRUCT: (
        ('Attributes', ULONG),
    }

// 2.2.5.3 SAMPR_GROUP_GENERAL_INFORMATION
 type SAMPR_GROUP_GENERAL_INFORMATION struct { // NDRSTRUCT: (
        ('Name', RPC_UNICODE_STRING),
        ('Attributes', ULONG),
        ('MemberCount', ULONG),
        ('AdminComment', RPC_UNICODE_STRING),
    }

// 2.2.5.4 SAMPR_GROUP_NAME_INFORMATION
 type SAMPR_GROUP_NAME_INFORMATION struct { // NDRSTRUCT: (
        ('Name', RPC_UNICODE_STRING),
    }

// 2.2.5.5 SAMPR_GROUP_ADM_COMMENT_INFORMATION
 type SAMPR_GROUP_ADM_COMMENT_INFORMATION struct { // NDRSTRUCT: (
        ('AdminComment', RPC_UNICODE_STRING),
    }

// 2.2.5.6 GROUP_INFORMATION_CLASS
 type GROUP_INFORMATION_CLASS struct { // NDRENUM:
     type enumItems struct { // Enum:
        GroupGeneralInformation      = 1 
        GroupNameInformation         = 2
        GroupAttributeInformation    = 3
        GroupAdminCommentInformation = 4
        GroupReplicationInformation  = 5

// 2.2.5.7 SAMPR_GROUP_INFO_BUFFER
 type SAMPR_GROUP_INFO_BUFFER struct { // NDRUNION:
    union = {
        GROUP_INFORMATION_CLASS.GroupGeneralInformation      : ('General', SAMPR_GROUP_GENERAL_INFORMATION),
        GROUP_INFORMATION_CLASS.GroupNameInformation         : ('Name', SAMPR_GROUP_NAME_INFORMATION),
        GROUP_INFORMATION_CLASS.GroupAttributeInformation    : ('Attribute', GROUP_ATTRIBUTE_INFORMATION),
        GROUP_INFORMATION_CLASS.GroupAdminCommentInformation : ('AdminComment', SAMPR_GROUP_ADM_COMMENT_INFORMATION),
        GROUP_INFORMATION_CLASS.GroupReplicationInformation  : ('DoNotUse', SAMPR_GROUP_GENERAL_INFORMATION),
    }

 type PSAMPR_GROUP_INFO_BUFFER struct { // NDRPOINTER:
    referent = (
        ('Data', SAMPR_GROUP_INFO_BUFFER),
    }

// 2.2.6.2 SAMPR_ALIAS_GENERAL_INFORMATION
 type SAMPR_ALIAS_GENERAL_INFORMATION struct { // NDRSTRUCT: (
        ('Name', RPC_UNICODE_STRING),
        ('MemberCount', ULONG),
        ('AdminComment', RPC_UNICODE_STRING),
    }

// 2.2.6.3 SAMPR_ALIAS_NAME_INFORMATION
 type SAMPR_ALIAS_NAME_INFORMATION struct { // NDRSTRUCT: (
        ('Name', RPC_UNICODE_STRING),
    }

// 2.2.6.4 SAMPR_ALIAS_ADM_COMMENT_INFORMATION
 type SAMPR_ALIAS_ADM_COMMENT_INFORMATION struct { // NDRSTRUCT: (
        ('AdminComment', RPC_UNICODE_STRING),
    }

// 2.2.6.5 ALIAS_INFORMATION_CLASS
 type ALIAS_INFORMATION_CLASS struct { // NDRENUM:
     type enumItems struct { // Enum:
        AliasGeneralInformation      = 1
        AliasNameInformation         = 2
        AliasAdminCommentInformation = 3

// 2.2.6.6 SAMPR_ALIAS_INFO_BUFFER
 type SAMPR_ALIAS_INFO_BUFFER struct { // NDRUNION:
    union = {
        ALIAS_INFORMATION_CLASS.AliasGeneralInformation      : ('General', SAMPR_ALIAS_GENERAL_INFORMATION),
        ALIAS_INFORMATION_CLASS.AliasNameInformation         : ('Name', SAMPR_ALIAS_NAME_INFORMATION),
        ALIAS_INFORMATION_CLASS.AliasAdminCommentInformation : ('AdminComment', SAMPR_ALIAS_ADM_COMMENT_INFORMATION),
    }
 
 type PSAMPR_ALIAS_INFO_BUFFER struct { // NDRPOINTER:
    referent = (
        ('Data', SAMPR_ALIAS_INFO_BUFFER),
    }

// 2.2.7.2 USER_PRIMARY_GROUP_INFORMATION
 type USER_PRIMARY_GROUP_INFORMATION struct { // NDRSTRUCT: (
        ('PrimaryGroupId', ULONG),
    }

// 2.2.7.3 USER_CONTROL_INFORMATION
 type USER_CONTROL_INFORMATION struct { // NDRSTRUCT: (
        ('UserAccountControl', ULONG),
    }

// 2.2.7.4 USER_EXPIRES_INFORMATION
 type USER_EXPIRES_INFORMATION struct { // NDRSTRUCT: (
        ('AccountExpires', OLD_LARGE_INTEGER),
    }

// 2.2.7.5 SAMPR_LOGON_HOURS
 type LOGON_HOURS_ARRAY struct { // NDRUniConformantVaryingArray:
    pass

 type PLOGON_HOURS_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', LOGON_HOURS_ARRAY),
    }

 type SAMPR_LOGON_HOURS struct { // NDRSTRUCT: (
        //('UnitsPerWeek', NDRSHORT),
        ('UnitsPerWeek', ULONG),
        ('LogonHours', PLOGON_HOURS_ARRAY),
    }

     func (self TYPE) getData(soFar = 0 interface{}){
        self.UnitsPerWeek"] = len(self["LogonHours) * 8 
        return NDR.getData(self, soFar)

// 2.2.7.6 SAMPR_USER_ALL_INFORMATION
 type SAMPR_USER_ALL_INFORMATION struct { // NDRSTRUCT: (
        ('LastLogon', OLD_LARGE_INTEGER),
        ('LastLogoff', OLD_LARGE_INTEGER),
        ('PasswordLastSet', OLD_LARGE_INTEGER),
        ('AccountExpires', OLD_LARGE_INTEGER),
        ('PasswordCanChange', OLD_LARGE_INTEGER),
        ('PasswordMustChange', OLD_LARGE_INTEGER),
        ('UserName', RPC_UNICODE_STRING),
        ('FullName', RPC_UNICODE_STRING),
        ('HomeDirectory', RPC_UNICODE_STRING),
        ('HomeDirectoryDrive', RPC_UNICODE_STRING),
        ('ScriptPath', RPC_UNICODE_STRING),
        ('ProfilePath', RPC_UNICODE_STRING),
        ('AdminComment', RPC_UNICODE_STRING),
        ('WorkStations', RPC_UNICODE_STRING),
        ('UserComment', RPC_UNICODE_STRING),
        ('Parameters', RPC_UNICODE_STRING),

        ('LmOwfPassword', RPC_SHORT_BLOB),
        ('NtOwfPassword', RPC_SHORT_BLOB),
        ('PrivateData', RPC_UNICODE_STRING),

        ('SecurityDescriptor', SAMPR_SR_SECURITY_DESCRIPTOR),

        ('UserId', ULONG),
        ('PrimaryGroupId', ULONG),
        ('UserAccountControl', ULONG),
        ('WhichFields', ULONG),
        ('LogonHours', SAMPR_LOGON_HOURS),
        ('BadPasswordCount', USHORT),
        ('LogonCount', USHORT),
        ('CountryCode', USHORT),
        ('CodePage', USHORT),
        ('LmPasswordPresent', UCHAR),
        ('NtPasswordPresent', UCHAR),
        ('PasswordExpired', UCHAR),
        ('PrivateDataSensitive', UCHAR),
    }

// 2.2.7.7 SAMPR_USER_GENERAL_INFORMATION
 type SAMPR_USER_GENERAL_INFORMATION struct { // NDRSTRUCT: (
        ('UserName', RPC_UNICODE_STRING),
        ('FullName', RPC_UNICODE_STRING),
        ('PrimaryGroupId', ULONG),
        ('AdminComment', RPC_UNICODE_STRING),
        ('UserComment', RPC_UNICODE_STRING),
    }

// 2.2.7.8 SAMPR_USER_PREFERENCES_INFORMATION
 type SAMPR_USER_PREFERENCES_INFORMATION struct { // NDRSTRUCT: (
        ('UserComment', RPC_UNICODE_STRING),
        ('Reserved1', RPC_UNICODE_STRING),
        ('CountryCode', USHORT),
        ('CodePage', USHORT),
    }

// 2.2.7.9 SAMPR_USER_PARAMETERS_INFORMATION
 type SAMPR_USER_PARAMETERS_INFORMATION struct { // NDRSTRUCT: (
        ('Parameters', RPC_UNICODE_STRING),
    }

// 2.2.7.10 SAMPR_USER_LOGON_INFORMATION
 type SAMPR_USER_LOGON_INFORMATION struct { // NDRSTRUCT: (
        ('UserName', RPC_UNICODE_STRING),
        ('FullName', RPC_UNICODE_STRING),
        ('UserId', ULONG),
        ('PrimaryGroupId', ULONG),
        ('HomeDirectory', RPC_UNICODE_STRING),
        ('HomeDirectoryDrive', RPC_UNICODE_STRING),
        ('ScriptPath', RPC_UNICODE_STRING),
        ('ProfilePath', RPC_UNICODE_STRING),
        ('WorkStations', RPC_UNICODE_STRING),
        ('LastLogon', OLD_LARGE_INTEGER),
        ('LastLogoff', OLD_LARGE_INTEGER),
        ('PasswordLastSet', OLD_LARGE_INTEGER),
        ('PasswordCanChange', OLD_LARGE_INTEGER),
        ('PasswordMustChange', OLD_LARGE_INTEGER),
        ('LogonHours', SAMPR_LOGON_HOURS),
        ('BadPasswordCount', USHORT),
        ('LogonCount', USHORT),
        ('UserAccountControl', ULONG),
    }

// 2.2.7.11 SAMPR_USER_ACCOUNT_INFORMATION
 type SAMPR_USER_ACCOUNT_INFORMATION struct { // NDRSTRUCT: (
        ('UserName', RPC_UNICODE_STRING),
        ('FullName', RPC_UNICODE_STRING),
        ('UserId', ULONG),
        ('PrimaryGroupId', ULONG),
        ('HomeDirectory', RPC_UNICODE_STRING),
        ('HomeDirectoryDrive', RPC_UNICODE_STRING),
        ('ScriptPath', RPC_UNICODE_STRING),
        ('ProfilePath', RPC_UNICODE_STRING),
        ('AdminComment', RPC_UNICODE_STRING),
        ('WorkStations', RPC_UNICODE_STRING),
        ('LastLogon', OLD_LARGE_INTEGER),
        ('LastLogoff', OLD_LARGE_INTEGER),
        ('LogonHours', SAMPR_LOGON_HOURS),
        ('BadPasswordCount', USHORT),
        ('LogonCount', USHORT),
        ('PasswordLastSet', OLD_LARGE_INTEGER),
        ('AccountExpires', OLD_LARGE_INTEGER),
        ('UserAccountControl', ULONG)
    }

// 2.2.7.12 SAMPR_USER_A_NAME_INFORMATION
 type SAMPR_USER_A_NAME_INFORMATION struct { // NDRSTRUCT: (
        ('UserName', RPC_UNICODE_STRING),
    }

// 2.2.7.13 SAMPR_USER_F_NAME_INFORMATION
 type SAMPR_USER_F_NAME_INFORMATION struct { // NDRSTRUCT: (
        ('FullName', RPC_UNICODE_STRING),
    }

// 2.2.7.14 SAMPR_USER_NAME_INFORMATION
 type SAMPR_USER_NAME_INFORMATION struct { // NDRSTRUCT: (
        ('UserName', RPC_UNICODE_STRING),
        ('FullName', RPC_UNICODE_STRING),
    }

// 2.2.7.15 SAMPR_USER_HOME_INFORMATION
 type SAMPR_USER_HOME_INFORMATION struct { // NDRSTRUCT: (
        ('HomeDirectory', RPC_UNICODE_STRING),
        ('HomeDirectoryDrive', RPC_UNICODE_STRING),
    }

// 2.2.7.16 SAMPR_USER_SCRIPT_INFORMATION
 type SAMPR_USER_SCRIPT_INFORMATION struct { // NDRSTRUCT: (
        ('ScriptPath', RPC_UNICODE_STRING),
    }

// 2.2.7.17 SAMPR_USER_PROFILE_INFORMATION
 type SAMPR_USER_PROFILE_INFORMATION struct { // NDRSTRUCT: (
        ('ProfilePath', RPC_UNICODE_STRING),
    }

// 2.2.7.18 SAMPR_USER_ADMIN_COMMENT_INFORMATION
 type SAMPR_USER_ADMIN_COMMENT_INFORMATION struct { // NDRSTRUCT: (
        ('AdminComment', RPC_UNICODE_STRING),
    }

// 2.2.7.19 SAMPR_USER_WORKSTATIONS_INFORMATION
 type SAMPR_USER_WORKSTATIONS_INFORMATION struct { // NDRSTRUCT: (
        ('WorkStations', RPC_UNICODE_STRING),
    }

// 2.2.7.20 SAMPR_USER_LOGON_HOURS_INFORMATION
 type SAMPR_USER_LOGON_HOURS_INFORMATION struct { // NDRSTRUCT: (
        ('LogonHours', SAMPR_LOGON_HOURS),
    }

// 2.2.7.21 SAMPR_ENCRYPTED_USER_PASSWORD
 type SAMPR_USER_PASSWORD struct { // NDRSTRUCT: (
         Buffer [2]byte // =b""
        ('Length', ULONG),
    }
     func (self TYPE) getAlignment(){
        return 4


 type SAMPR_ENCRYPTED_USER_PASSWORD struct { // NDRSTRUCT: (
         Buffer [6]byte // =b""
    }
     func (self TYPE) getAlignment(){
        return 1

 type PSAMPR_ENCRYPTED_USER_PASSWORD struct { // NDRPOINTER:
    referent = (
        ('Data', SAMPR_ENCRYPTED_USER_PASSWORD),
    }

// 2.2.7.22 SAMPR_ENCRYPTED_USER_PASSWORD_NEW
 type SAMPR_ENCRYPTED_USER_PASSWORD_NEW struct { // NDRSTRUCT: (
         Buffer [2]byte // =b""
    }
     func (self TYPE) getAlignment(){
        return 1

// 2.2.7.23 SAMPR_USER_INTERNAL1_INFORMATION
 type SAMPR_USER_INTERNAL1_INFORMATION struct { // NDRSTRUCT: (
        ('EncryptedNtOwfPassword', ENCRYPTED_NT_OWF_PASSWORD),
        ('EncryptedLmOwfPassword', ENCRYPTED_LM_OWF_PASSWORD),
        ('NtPasswordPresent', UCHAR),
        ('LmPasswordPresent', UCHAR),
        ('PasswordExpired', UCHAR),
    }

// 2.2.7.24 SAMPR_USER_INTERNAL4_INFORMATION
 type SAMPR_USER_INTERNAL4_INFORMATION struct { // NDRSTRUCT: (
        ('I1', SAMPR_USER_ALL_INFORMATION),
        ('UserPassword', SAMPR_ENCRYPTED_USER_PASSWORD),
    }

// 2.2.7.25 SAMPR_USER_INTERNAL4_INFORMATION_NEW
 type SAMPR_USER_INTERNAL4_INFORMATION_NEW struct { // NDRSTRUCT: (
        ('I1', SAMPR_USER_ALL_INFORMATION),
        ('UserPassword', SAMPR_ENCRYPTED_USER_PASSWORD_NEW),
    }

// 2.2.7.26 SAMPR_USER_INTERNAL5_INFORMATION
 type SAMPR_USER_INTERNAL5_INFORMATION struct { // NDRSTRUCT: (
        ('UserPassword', SAMPR_ENCRYPTED_USER_PASSWORD),
        ('PasswordExpired', UCHAR),
    }

// 2.2.7.27 SAMPR_USER_INTERNAL5_INFORMATION_NEW
 type SAMPR_USER_INTERNAL5_INFORMATION_NEW struct { // NDRSTRUCT: (
        ('UserPassword', SAMPR_ENCRYPTED_USER_PASSWORD_NEW),
        ('PasswordExpired', UCHAR),
    }

// 2.2.7.28 USER_INFORMATION_CLASS
 type USER_INFORMATION_CLASS struct { // NDRENUM:
     type enumItems struct { // Enum:
        UserGeneralInformation      = 1
        UserPreferencesInformation  = 2
        UserLogonInformation        = 3
        UserLogonHoursInformation   = 4
        UserAccountInformation      = 5
        UserNameInformation         = 6
        UserAccountNameInformation  = 7
        UserFullNameInformation     = 8
        UserPrimaryGroupInformation = 9
        UserHomeInformation         = 10
        UserScriptInformation       = 11
        UserProfileInformation      = 12
        UserAdminCommentInformation = 13
        UserWorkStationsInformation = 14
        UserControlInformation      = 16
        UserExpiresInformation      = 17
        UserInternal1Information    = 18
        UserParametersInformation   = 20
        UserAllInformation          = 21
        UserInternal4Information    = 23
        UserInternal5Information    = 24
        UserInternal4InformationNew = 25
        UserInternal5InformationNew = 26

// 2.2.7.29 SAMPR_USER_INFO_BUFFER
 type SAMPR_USER_INFO_BUFFER struct { // NDRUNION:
    union = {
        USER_INFORMATION_CLASS.UserGeneralInformation     : ('General', SAMPR_USER_GENERAL_INFORMATION),
        USER_INFORMATION_CLASS.UserPreferencesInformation : ('Preferences', SAMPR_USER_PREFERENCES_INFORMATION),
        USER_INFORMATION_CLASS.UserLogonInformation       : ('Logon', SAMPR_USER_LOGON_INFORMATION),
        USER_INFORMATION_CLASS.UserLogonHoursInformation  : ('LogonHours', SAMPR_USER_LOGON_HOURS_INFORMATION),
        USER_INFORMATION_CLASS.UserAccountInformation     : ('Account', SAMPR_USER_ACCOUNT_INFORMATION),
        USER_INFORMATION_CLASS.UserNameInformation        : ('Name', SAMPR_USER_NAME_INFORMATION),
        USER_INFORMATION_CLASS.UserAccountNameInformation : ('AccountName', SAMPR_USER_A_NAME_INFORMATION),
        USER_INFORMATION_CLASS.UserFullNameInformation    : ('FullName', SAMPR_USER_F_NAME_INFORMATION),
        USER_INFORMATION_CLASS.UserPrimaryGroupInformation: ('PrimaryGroup', USER_PRIMARY_GROUP_INFORMATION),
        USER_INFORMATION_CLASS.UserHomeInformation        : ('Home', SAMPR_USER_HOME_INFORMATION),
        USER_INFORMATION_CLASS.UserScriptInformation      : ('Script', SAMPR_USER_SCRIPT_INFORMATION),
        USER_INFORMATION_CLASS.UserProfileInformation     : ('Profile', SAMPR_USER_PROFILE_INFORMATION),
        USER_INFORMATION_CLASS.UserAdminCommentInformation: ('AdminComment', SAMPR_USER_ADMIN_COMMENT_INFORMATION),
        USER_INFORMATION_CLASS.UserWorkStationsInformation: ('WorkStations', SAMPR_USER_WORKSTATIONS_INFORMATION),
        USER_INFORMATION_CLASS.UserControlInformation     : ('Control', USER_CONTROL_INFORMATION),
        USER_INFORMATION_CLASS.UserExpiresInformation     : ('Expires', USER_EXPIRES_INFORMATION),
        USER_INFORMATION_CLASS.UserInternal1Information   : ('Internal1', SAMPR_USER_INTERNAL1_INFORMATION),
        USER_INFORMATION_CLASS.UserParametersInformation  : ('Parameters', SAMPR_USER_PARAMETERS_INFORMATION ),
        USER_INFORMATION_CLASS.UserAllInformation         : ('All', SAMPR_USER_ALL_INFORMATION),
        USER_INFORMATION_CLASS.UserInternal4Information   : ('Internal4', SAMPR_USER_INTERNAL4_INFORMATION),
        USER_INFORMATION_CLASS.UserInternal5Information   : ('Internal5', SAMPR_USER_INTERNAL5_INFORMATION),
        USER_INFORMATION_CLASS.UserInternal4InformationNew: ('Internal4New', SAMPR_USER_INTERNAL4_INFORMATION_NEW),
        USER_INFORMATION_CLASS.UserInternal5InformationNew: ('Internal5New', SAMPR_USER_INTERNAL5_INFORMATION_NEW),
    }
 
 type PSAMPR_USER_INFO_BUFFER struct { // NDRPOINTER:
    referent = (
        ('Data', SAMPR_USER_INFO_BUFFER),
    }

 type PSAMPR_SERVER_NAME2 struct { // NDRPOINTER:
    referent = (
         Data [4]byte // =b""
    } 

// 2.2.8.2 SAMPR_DOMAIN_DISPLAY_USER
 type SAMPR_DOMAIN_DISPLAY_USER struct { // NDRSTRUCT: (
        ('Index',ULONG),
        ('Rid',ULONG),
        ('AccountControl',ULONG),
        ('AccountName',RPC_UNICODE_STRING),
        ('AdminComment',RPC_UNICODE_STRING),
        ('FullName',RPC_UNICODE_STRING),
    }

 type SAMPR_DOMAIN_DISPLAY_USER_ARRAY struct { // NDRUniConformantArray:
    item = SAMPR_DOMAIN_DISPLAY_USER

 type PSAMPR_DOMAIN_DISPLAY_USER_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data',SAMPR_DOMAIN_DISPLAY_USER_ARRAY),
    }

// 2.2.8.3 SAMPR_DOMAIN_DISPLAY_MACHINE
 type SAMPR_DOMAIN_DISPLAY_MACHINE struct { // NDRSTRUCT: (
        ('Index',ULONG),
        ('Rid',ULONG),
        ('AccountControl',ULONG),
        ('AccountName',RPC_UNICODE_STRING),
        ('AdminComment',RPC_UNICODE_STRING),
    }

 type SAMPR_DOMAIN_DISPLAY_MACHINE_ARRAY struct { // NDRUniConformantArray:
    item = SAMPR_DOMAIN_DISPLAY_MACHINE

 type PSAMPR_DOMAIN_DISPLAY_MACHINE_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data',SAMPR_DOMAIN_DISPLAY_MACHINE_ARRAY),
    }

// 2.2.8.4 SAMPR_DOMAIN_DISPLAY_GROUP
 type SAMPR_DOMAIN_DISPLAY_GROUP struct { // NDRSTRUCT: (
        ('Index',ULONG),
        ('Rid',ULONG),
        ('AccountControl',ULONG),
        ('AccountName',RPC_UNICODE_STRING),
        ('AdminComment',RPC_UNICODE_STRING),
    }

 type SAMPR_DOMAIN_DISPLAY_GROUP_ARRAY struct { // NDRUniConformantArray:
    item = SAMPR_DOMAIN_DISPLAY_GROUP

 type PSAMPR_DOMAIN_DISPLAY_GROUP_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data',SAMPR_DOMAIN_DISPLAY_GROUP_ARRAY),
    }

// 2.2.8.5 SAMPR_DOMAIN_DISPLAY_OEM_USER
 type SAMPR_DOMAIN_DISPLAY_OEM_USER struct { // NDRSTRUCT: (
        ('Index',ULONG),
        ('OemAccountName',RPC_STRING),
    }

 type SAMPR_DOMAIN_DISPLAY_OEM_USER_ARRAY struct { // NDRUniConformantArray:
    item = SAMPR_DOMAIN_DISPLAY_OEM_USER

 type PSAMPR_DOMAIN_DISPLAY_OEM_USER_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data',SAMPR_DOMAIN_DISPLAY_OEM_USER_ARRAY),
    }

// 2.2.8.6 SAMPR_DOMAIN_DISPLAY_OEM_GROUP
 type SAMPR_DOMAIN_DISPLAY_OEM_GROUP struct { // NDRSTRUCT: (
        ('Index',ULONG),
        ('OemAccountName',RPC_STRING),
    }

 type SAMPR_DOMAIN_DISPLAY_OEM_GROUP_ARRAY struct { // NDRUniConformantArray:
    item = SAMPR_DOMAIN_DISPLAY_OEM_GROUP

 type PSAMPR_DOMAIN_DISPLAY_OEM_GROUP_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data',SAMPR_DOMAIN_DISPLAY_OEM_GROUP_ARRAY),
    }

//2.2.8.7 SAMPR_DOMAIN_DISPLAY_USER_BUFFER
 type SAMPR_DOMAIN_DISPLAY_USER_BUFFER struct { // NDRSTRUCT: (
        ('EntriesRead', ULONG),
        ('Buffer', PSAMPR_DOMAIN_DISPLAY_USER_ARRAY),
    }

// 2.2.8.8 SAMPR_DOMAIN_DISPLAY_MACHINE_BUFFER
 type SAMPR_DOMAIN_DISPLAY_MACHINE_BUFFER struct { // NDRSTRUCT: (
        ('EntriesRead', ULONG),
        ('Buffer', PSAMPR_DOMAIN_DISPLAY_MACHINE_ARRAY),
    }
 
// 2.2.8.9 SAMPR_DOMAIN_DISPLAY_GROUP_BUFFER
 type SAMPR_DOMAIN_DISPLAY_GROUP_BUFFER struct { // NDRSTRUCT: (
        ('EntriesRead', ULONG),
        ('Buffer', PSAMPR_DOMAIN_DISPLAY_GROUP_ARRAY),
    }
 
// 2.2.8.10 SAMPR_DOMAIN_DISPLAY_OEM_USER_BUFFER
 type SAMPR_DOMAIN_DISPLAY_OEM_USER_BUFFER struct { // NDRSTRUCT: (
        ('EntriesRead', ULONG),
        ('Buffer', PSAMPR_DOMAIN_DISPLAY_OEM_USER_ARRAY),
    }
 
// 2.2.8.11 SAMPR_DOMAIN_DISPLAY_OEM_GROUP_BUFFER
 type SAMPR_DOMAIN_DISPLAY_OEM_GROUP_BUFFER struct { // NDRSTRUCT: (
        ('EntriesRead', ULONG),
        ('Buffer', PSAMPR_DOMAIN_DISPLAY_OEM_GROUP_ARRAY),
    }

// 2.2.8.12 DOMAIN_DISPLAY_INFORMATION
 type DOMAIN_DISPLAY_INFORMATION struct { // NDRENUM:
     type enumItems struct { // Enum:
        DomainDisplayUser     = 1
        DomainDisplayMachine  = 2
        DomainDisplayGroup    = 3
        DomainDisplayOemUser  = 4
        DomainDisplayOemGroup = 5

// 2.2.8.13 SAMPR_DISPLAY_INFO_BUFFER
 type SAMPR_DISPLAY_INFO_BUFFER struct { // NDRUNION:
    union = {
        DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser     : ('UserInformation', SAMPR_DOMAIN_DISPLAY_USER_BUFFER),
        DOMAIN_DISPLAY_INFORMATION.DomainDisplayMachine  : ('MachineInformation', SAMPR_DOMAIN_DISPLAY_MACHINE_BUFFER),
        DOMAIN_DISPLAY_INFORMATION.DomainDisplayGroup    : ('GroupInformation', SAMPR_DOMAIN_DISPLAY_GROUP_BUFFER),
        DOMAIN_DISPLAY_INFORMATION.DomainDisplayOemUser  : ('OemUserInformation', SAMPR_DOMAIN_DISPLAY_OEM_USER_BUFFER),
        DOMAIN_DISPLAY_INFORMATION.DomainDisplayOemGroup : ('OemGroupInformation', SAMPR_DOMAIN_DISPLAY_OEM_GROUP_BUFFER),
    }

// 2.2.9.1 SAM_VALIDATE_PASSWORD_HASH
 type SAM_VALIDATE_PASSWORD_HASH struct { // NDRSTRUCT: (
        ('Length', ULONG),
        ('Hash', LPBYTE),
    }

 type PSAM_VALIDATE_PASSWORD_HASH struct { // NDRPOINTER:
    referent = (
        ('Data', SAM_VALIDATE_PASSWORD_HASH),
    }

// 2.2.9.2 SAM_VALIDATE_PERSISTED_FIELDS
 type SAM_VALIDATE_PERSISTED_FIELDS struct { // NDRSTRUCT: (
        ('PresentFields', ULONG),
        ('PasswordLastSet', LARGE_INTEGER),
        ('BadPasswordTime', LARGE_INTEGER),
        ('LockoutTime', LARGE_INTEGER),
        ('BadPasswordCount', ULONG),
        ('PasswordHistoryLength', ULONG),
        ('PasswordHistory', PSAM_VALIDATE_PASSWORD_HASH),
    }

// 2.2.9.3 SAM_VALIDATE_VALIDATION_STATUS
 type SAM_VALIDATE_VALIDATION_STATUS struct { // NDRENUM:
     type enumItems struct { // Enum:
        SamValidateSuccess                  = 0
        SamValidatePasswordMustChange       = 1
        SamValidateAccountLockedOut         = 2
        SamValidatePasswordExpired          = 3
        SamValidatePasswordIncorrect        = 4
        SamValidatePasswordIsInHistory      = 5
        SamValidatePasswordTooShort         = 6
        SamValidatePasswordTooLong          = 7
        SamValidatePasswordNotComplexEnough = 8
        SamValidatePasswordTooRecent        = 9
        SamValidatePasswordFilterError      = 10

// 2.2.9.4 SAM_VALIDATE_STANDARD_OUTPUT_ARG
 type SAM_VALIDATE_STANDARD_OUTPUT_ARG struct { // NDRSTRUCT: (
        ('ChangedPersistedFields', SAM_VALIDATE_PERSISTED_FIELDS),
        ('ValidationStatus', SAM_VALIDATE_VALIDATION_STATUS),
    }

 type PSAM_VALIDATE_STANDARD_OUTPUT_ARG struct { // NDRPOINTER:
    referent = (
        ('Data', SAM_VALIDATE_STANDARD_OUTPUT_ARG),
    }

// 2.2.9.5 SAM_VALIDATE_AUTHENTICATION_INPUT_ARG
 type SAM_VALIDATE_AUTHENTICATION_INPUT_ARG struct { // NDRSTRUCT: (
        ('InputPersistedFields', SAM_VALIDATE_PERSISTED_FIELDS),
        ('PasswordMatched', UCHAR),
    }

// 2.2.9.6 SAM_VALIDATE_PASSWORD_CHANGE_INPUT_ARG
 type SAM_VALIDATE_PASSWORD_CHANGE_INPUT_ARG struct { // NDRSTRUCT: (
        ('InputPersistedFields', SAM_VALIDATE_PERSISTED_FIELDS),
        ('ClearPassword', RPC_UNICODE_STRING),
        ('UserAccountName', RPC_UNICODE_STRING),
        ('HashedPassword', SAM_VALIDATE_PASSWORD_HASH),
        ('PasswordMatch', UCHAR),
    }

// 2.2.9.7 SAM_VALIDATE_PASSWORD_RESET_INPUT_ARG
 type SAM_VALIDATE_PASSWORD_RESET_INPUT_ARG struct { // NDRSTRUCT: (
        ('InputPersistedFields', SAM_VALIDATE_PERSISTED_FIELDS),
        ('ClearPassword', RPC_UNICODE_STRING),
        ('UserAccountName', RPC_UNICODE_STRING),
        ('HashedPassword', SAM_VALIDATE_PASSWORD_HASH),
        ('PasswordMustChangeAtNextLogon', UCHAR),
        ('ClearLockout', UCHAR),
    }

// 2.2.9.8 PASSWORD_POLICY_VALIDATION_TYPE
 type PASSWORD_POLICY_VALIDATION_TYPE struct { // NDRENUM:
     type enumItems struct { // Enum:
        SamValidateAuthentication   = 1
        SamValidatePasswordChange   = 2
        SamValidatePasswordReset    = 3

// 2.2.9.9 SAM_VALIDATE_INPUT_ARG
 type SAM_VALIDATE_INPUT_ARG struct { // NDRUNION:
    union = {
        PASSWORD_POLICY_VALIDATION_TYPE.SamValidateAuthentication : ('ValidateAuthenticationInput', SAM_VALIDATE_AUTHENTICATION_INPUT_ARG),
        PASSWORD_POLICY_VALIDATION_TYPE.SamValidatePasswordChange : ('ValidatePasswordChangeInput', SAM_VALIDATE_PASSWORD_CHANGE_INPUT_ARG),
        PASSWORD_POLICY_VALIDATION_TYPE.SamValidatePasswordReset  : ('ValidatePasswordResetInput', SAM_VALIDATE_PASSWORD_RESET_INPUT_ARG),
    }

// 2.2.9.10 SAM_VALIDATE_OUTPUT_ARG
 type SAM_VALIDATE_OUTPUT_ARG struct { // NDRUNION:
    union = {
        PASSWORD_POLICY_VALIDATION_TYPE.SamValidateAuthentication : ('ValidateAuthenticationOutput', SAM_VALIDATE_STANDARD_OUTPUT_ARG),
        PASSWORD_POLICY_VALIDATION_TYPE.SamValidatePasswordChange : ('ValidatePasswordChangeOutput', SAM_VALIDATE_STANDARD_OUTPUT_ARG),
        PASSWORD_POLICY_VALIDATION_TYPE.SamValidatePasswordReset  : ('ValidatePasswordResetOutput', SAM_VALIDATE_STANDARD_OUTPUT_ARG),
    }

 type PSAM_VALIDATE_OUTPUT_ARG struct { // NDRPOINTER:
    referent = (
        ('Data', SAM_VALIDATE_OUTPUT_ARG),
    }

// 2.2.10 Supplemental Credentials Structures

// 2.2.10.1 USER_PROPERTIES
 type USER_PROPERTIES struct { // Structure: (
         Reserved1 uint32 // =0
         Length uint32 // =0
         Reserved2 uint16 // =0
         Reserved3 uint16 // =0
         Reserved4 [6]byte // =""
         PropertySignature uint16 // =0x50
         PropertyCount uint16 // =0
        ('UserProperties',':'),
    }

// 2.2.10.2 USER_PROPERTY
 type USER_PROPERTY struct { // Structure: (
         NameLength uint16 // =0
         ValueLength uint16 // =0
         Reserved uint16 // =0
        ('_PropertyName','_-PropertyName', "self.NameLength"),
        ('PropertyName',':'),
        ('_PropertyValue','_-PropertyValue', "self.ValueLength"),
        ('PropertyValue',':'),
    }

// 2.2.10.3 Primary:WDigest - WDIGEST_CREDENTIALS
 type WDIGEST_CREDENTIALS struct { // Structure: (
        ('Reserved1','B=0'),
        ('Reserved2','B=0'),
        ('Version','B=1'),
        ('NumberOfHashes','B=29'),
         Reserved3 [2]byte // =""
         Hash1 [6]byte // =""
         Hash2 [6]byte // =""
         Hash3 [6]byte // =""
         Hash4 [6]byte // =""
         Hash5 [6]byte // =""
         Hash6 [6]byte // =""
         Hash7 [6]byte // =""
         Hash8 [6]byte // =""
         Hash9 [6]byte // =""
         Hash10 [6]byte // =""
         Hash11 [6]byte // =""
         Hash12 [6]byte // =""
         Hash13 [6]byte // =""
         Hash14 [6]byte // =""
         Hash15 [6]byte // =""
         Hash16 [6]byte // =""
         Hash17 [6]byte // =""
         Hash18 [6]byte // =""
         Hash19 [6]byte // =""
         Hash20 [6]byte // =""
         Hash21 [6]byte // =""
         Hash22 [6]byte // =""
         Hash23 [6]byte // =""
         Hash24 [6]byte // =""
         Hash25 [6]byte // =""
         Hash26 [6]byte // =""
         Hash27 [6]byte // =""
         Hash28 [6]byte // =""
         Hash29 [6]byte // =""
    }

// 2.2.10.5 KERB_KEY_DATA
 type KERB_KEY_DATA struct { // Structure: (
         Reserved1 uint16 // =0
         Reserved2 uint16 // =0
         Reserved3 uint16 // =0
         KeyType uint32 // =0
         KeyLength uint32 // =0
         KeyOffset uint32 // =0
    }

// 2.2.10.4 Primary:Kerberos - KERB_STORED_CREDENTIAL
 type KERB_STORED_CREDENTIAL struct { // Structure: (
         Revision uint16 // =3
         Flags uint16 // =0
         CredentialCount uint16 // =0
         OldCredentialCount uint16 // =0
         DefaultSaltLength uint16 // =0
         DefaultSaltMaximumLength uint16 // =0
         DefaultSaltOffset uint32 // =0
        //('Credentials',':'),
        //('OldCredentials',':'),
        //('DefaultSalt',':'),
        //('KeyValues',':'),
        // All the preceding stuff inside this Buffer
        ('Buffer',':'),
    }

// 2.2.10.7 KERB_KEY_DATA_NEW
 type KERB_KEY_DATA_NEW struct { // Structure: (
         Reserved1 uint16 // =0
         Reserved2 uint16 // =0
         Reserved3 uint32 // =0
         IterationCount uint32 // =0
         KeyType uint32 // =0
         KeyLength uint32 // =0
         KeyOffset uint32 // =0
    }

// 2.2.10.6 Primary:Kerberos-Newer-Keys - KERB_STORED_CREDENTIAL_NEW
 type KERB_STORED_CREDENTIAL_NEW struct { // Structure: (
         Revision uint16 // =4
         Flags uint16 // =0
         CredentialCount uint16 // =0
         ServiceCredentialCount uint16 // =0
         OldCredentialCount uint16 // =0
         OlderCredentialCount uint16 // =0
         DefaultSaltLength uint16 // =0
         DefaultSaltMaximumLength uint16 // =0
         DefaultSaltOffset uint32 // =0
         DefaultIterationCount uint32 // =0
        //('Credentials',':'),
        //('ServiceCredentials',':'),
        //('OldCredentials',':'),
        //('OlderCredentials',':'),
        //('DefaultSalt',':'),
        //('KeyValues',':'),
        // All the preceding stuff inside this Buffer
        ('Buffer',':'),
    }

//###############################################################################
// RPC CALLS
//###############################################################################

 type SamrConnect struct { // NDRCALL:
    opnum = 0 (
       ('ServerName',PSAMPR_SERVER_NAME2),
       ('DesiredAccess', ULONG),
    }

 type SamrConnectResponse struct { // NDRCALL: (
       ('ServerHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    }

 type SamrCloseHandle struct { // NDRCALL:
    opnum = 1 (
       ('SamHandle',SAMPR_HANDLE),
       ('DesiredAccess', LONG),
    }

 type SamrCloseHandleResponse struct { // NDRCALL: (
       ('SamHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    }

 type SamrSetSecurityObject struct { // NDRCALL:
    opnum = 2 (
       ('ObjectHandle',SAMPR_HANDLE),
       ('SecurityInformation', SECURITY_INFORMATION),
       ('SecurityDescriptor', SAMPR_SR_SECURITY_DESCRIPTOR),
    }

 type SamrSetSecurityObjectResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

 type SamrQuerySecurityObject struct { // NDRCALL:
    opnum = 3 (
       ('ObjectHandle',SAMPR_HANDLE),
       ('SecurityInformation', SECURITY_INFORMATION),
    }

 type SamrQuerySecurityObjectResponse struct { // NDRCALL: (
       ('SecurityDescriptor',PSAMPR_SR_SECURITY_DESCRIPTOR),
       ('ErrorCode',ULONG),
    }

 type SamrLookupDomainInSamServer struct { // NDRCALL:
    opnum = 5 (
       ('ServerHandle',SAMPR_HANDLE),
       ('Name', RPC_UNICODE_STRING),
    }

 type SamrLookupDomainInSamServerResponse struct { // NDRCALL: (
       ('DomainId',PRPC_SID),
       ('ErrorCode',ULONG),
    }

 type SamrEnumerateDomainsInSamServer struct { // NDRCALL:
    opnum = 6 (
       ('ServerHandle',SAMPR_HANDLE),
       ('EnumerationContext', ULONG),
       ('PreferedMaximumLength', ULONG),
    }

 type SamrEnumerateDomainsInSamServerResponse struct { // NDRCALL: (
       ('EnumerationContext',ULONG),
       ('Buffer',PSAMPR_ENUMERATION_BUFFER),
       ('CountReturned',ULONG),
       ('ErrorCode',ULONG),
    }

 type SamrOpenDomain struct { // NDRCALL:
    opnum = 7 (
       ('ServerHandle',SAMPR_HANDLE),
       ('DesiredAccess', ULONG),
       ('DomainId', RPC_SID),
    }

 type SamrOpenDomainResponse struct { // NDRCALL: (
       ('DomainHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    }

 type SamrQueryInformationDomain struct { // NDRCALL:
    opnum = 8 (
       ('DomainHandle',SAMPR_HANDLE),
       ('DomainInformationClass', DOMAIN_INFORMATION_CLASS),
    }

 type SamrQueryInformationDomainResponse struct { // NDRCALL: (
       ('Buffer',PSAMPR_DOMAIN_INFO_BUFFER),
       ('ErrorCode',ULONG),
    }

 type SamrSetInformationDomain struct { // NDRCALL:
    opnum = 9 (
       ('DomainHandle',SAMPR_HANDLE),
       ('DomainInformationClass', DOMAIN_INFORMATION_CLASS),
       ('DomainInformation', SAMPR_DOMAIN_INFO_BUFFER),
    }

 type SamrSetInformationDomainResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

 type SamrCreateGroupInDomain struct { // NDRCALL:
    opnum = 10 (
       ('DomainHandle',SAMPR_HANDLE),
       ('Name', RPC_UNICODE_STRING),
       ('DesiredAccess', ULONG),
    }

 type SamrCreateGroupInDomainResponse struct { // NDRCALL: (
       ('GroupHandle',SAMPR_HANDLE),
       ('RelativeId',ULONG),
       ('ErrorCode',ULONG),
    }

 type SamrEnumerateGroupsInDomain struct { // NDRCALL:
    opnum = 11 (
       ('DomainHandle',SAMPR_HANDLE),
       ('EnumerationContext', ULONG),
       ('PreferedMaximumLength', ULONG),
    }

 type SamrCreateUserInDomain struct { // NDRCALL:
    opnum = 12 (
       ('DomainHandle',SAMPR_HANDLE),
       ('Name', RPC_UNICODE_STRING),
       ('DesiredAccess', ULONG),
    }

 type SamrCreateUserInDomainResponse struct { // NDRCALL: (
       ('UserHandle',SAMPR_HANDLE),
       ('RelativeId',ULONG),
       ('ErrorCode',ULONG),
    }

 type SamrEnumerateGroupsInDomainResponse struct { // NDRCALL: (
       ('EnumerationContext',ULONG),
       ('Buffer',PSAMPR_ENUMERATION_BUFFER),
       ('CountReturned',ULONG),
       ('ErrorCode',ULONG),
    }

 type SamrEnumerateUsersInDomain struct { // NDRCALL:
    opnum = 13 (
       ('DomainHandle',SAMPR_HANDLE),
       ('EnumerationContext', ULONG),
       ('UserAccountControl', ULONG),
       ('PreferedMaximumLength', ULONG),
    }

 type SamrEnumerateUsersInDomainResponse struct { // NDRCALL: (
       ('EnumerationContext',ULONG),
       ('Buffer',PSAMPR_ENUMERATION_BUFFER),
       ('CountReturned',ULONG),
       ('ErrorCode',ULONG),
    }

 type SamrCreateAliasInDomain struct { // NDRCALL:
    opnum = 14 (
       ('DomainHandle',SAMPR_HANDLE),
       ('AccountName', RPC_UNICODE_STRING),
       ('DesiredAccess', ULONG),
    }

 type SamrCreateAliasInDomainResponse struct { // NDRCALL: (
       ('AliasHandle',SAMPR_HANDLE),
       ('RelativeId',ULONG),
       ('ErrorCode',ULONG),
    }


 type SamrEnumerateAliasesInDomain struct { // NDRCALL:
    opnum = 15 (
       ('DomainHandle',SAMPR_HANDLE),
       ('EnumerationContext', ULONG),
       ('PreferedMaximumLength', ULONG),
    }

 type SamrEnumerateAliasesInDomainResponse struct { // NDRCALL: (
       ('EnumerationContext',ULONG),
       ('Buffer',PSAMPR_ENUMERATION_BUFFER),
       ('CountReturned',ULONG),
       ('ErrorCode',ULONG),
    }

 type SamrGetAliasMembership struct { // NDRCALL:
    opnum = 16 (
       ('DomainHandle',SAMPR_HANDLE),
       ('SidArray',SAMPR_PSID_ARRAY),
    }

 type SamrGetAliasMembershipResponse struct { // NDRCALL: (
       ('Membership',SAMPR_ULONG_ARRAY),
       ('ErrorCode',ULONG),
    }

 type SamrLookupNamesInDomain struct { // NDRCALL:
    opnum = 17 (
       ('DomainHandle',SAMPR_HANDLE),
       ('Count',ULONG),
       ('Names',RPC_UNICODE_STRING_ARRAY),
    }

 type SamrLookupNamesInDomainResponse struct { // NDRCALL: (
       ('RelativeIds',SAMPR_ULONG_ARRAY),
       ('Use',SAMPR_ULONG_ARRAY),
       ('ErrorCode',ULONG),
    }

 type SamrLookupIdsInDomain struct { // NDRCALL:
    opnum = 18 (
       ('DomainHandle',SAMPR_HANDLE),
       ('Count',ULONG),
       ('RelativeIds',ULONG_ARRAY_CV),
    }

 type SamrLookupIdsInDomainResponse struct { // NDRCALL: (
       ('Names',SAMPR_RETURNED_USTRING_ARRAY),
       ('Use',SAMPR_ULONG_ARRAY),
       ('ErrorCode',ULONG),
    }

 type SamrOpenGroup struct { // NDRCALL:
    opnum = 19 (
       ('DomainHandle',SAMPR_HANDLE),
       ('DesiredAccess', ULONG),
       ('GroupId', ULONG),
    }

 type SamrOpenGroupResponse struct { // NDRCALL: (
       ('GroupHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    }

 type SamrQueryInformationGroup struct { // NDRCALL:
    opnum = 20 (
       ('GroupHandle',SAMPR_HANDLE),
       ('GroupInformationClass', GROUP_INFORMATION_CLASS),
    }

 type SamrQueryInformationGroupResponse struct { // NDRCALL: (
       ('Buffer',PSAMPR_GROUP_INFO_BUFFER),
       ('ErrorCode',ULONG),
    }

 type SamrSetInformationGroup struct { // NDRCALL:
    opnum = 21 (
       ('GroupHandle',SAMPR_HANDLE),
       ('GroupInformationClass', GROUP_INFORMATION_CLASS),
       ('Buffer', SAMPR_GROUP_INFO_BUFFER),
    }

 type SamrSetInformationGroupResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

 type SamrAddMemberToGroup struct { // NDRCALL:
    opnum = 22 (
       ('GroupHandle',SAMPR_HANDLE),
       ('MemberId', ULONG),
       ('Attributes', ULONG),
    }

 type SamrAddMemberToGroupResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

 type SamrDeleteGroup struct { // NDRCALL:
    opnum = 23 (
       ('GroupHandle',SAMPR_HANDLE),
    }

 type SamrDeleteGroupResponse struct { // NDRCALL: (
       ('GroupHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    }

 type SamrRemoveMemberFromGroup struct { // NDRCALL:
    opnum = 24 (
       ('GroupHandle',SAMPR_HANDLE),
       ('MemberId', ULONG),
    }

 type SamrRemoveMemberFromGroupResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

 type SamrGetMembersInGroup struct { // NDRCALL:
    opnum = 25 (
       ('GroupHandle',SAMPR_HANDLE),
    }

 type SamrGetMembersInGroupResponse struct { // NDRCALL: (
       ('Members',PSAMPR_GET_MEMBERS_BUFFER),
       ('ErrorCode',ULONG),
    }

 type SamrSetMemberAttributesOfGroup struct { // NDRCALL:
    opnum = 26 (
       ('GroupHandle',SAMPR_HANDLE),
       ('MemberId',ULONG),
       ('Attributes',ULONG),
    }

 type SamrSetMemberAttributesOfGroupResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

 type SamrOpenAlias struct { // NDRCALL:
    opnum = 27 (
       ('DomainHandle',SAMPR_HANDLE),
       ('DesiredAccess', ULONG),
       ('AliasId', ULONG),
    }

 type SamrOpenAliasResponse struct { // NDRCALL: (
       ('AliasHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    }

 type SamrQueryInformationAlias struct { // NDRCALL:
    opnum = 28 (
       ('AliasHandle',SAMPR_HANDLE),
       ('AliasInformationClass', ALIAS_INFORMATION_CLASS),
    }

 type SamrQueryInformationAliasResponse struct { // NDRCALL: (
       ('Buffer',PSAMPR_ALIAS_INFO_BUFFER),
       ('ErrorCode',ULONG),
    }

 type SamrSetInformationAlias struct { // NDRCALL:
    opnum = 29 (
       ('AliasHandle',SAMPR_HANDLE),
       ('AliasInformationClass', ALIAS_INFORMATION_CLASS),
       ('Buffer',SAMPR_ALIAS_INFO_BUFFER),
    }

 type SamrSetInformationAliasResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

 type SamrDeleteAlias struct { // NDRCALL:
    opnum = 30 (
       ('AliasHandle',SAMPR_HANDLE),
    }

 type SamrDeleteAliasResponse struct { // NDRCALL: (
       ('AliasHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    }

 type SamrAddMemberToAlias struct { // NDRCALL:
    opnum = 31 (
       ('AliasHandle',SAMPR_HANDLE),
       ('MemberId', RPC_SID),
    }

 type SamrAddMemberToAliasResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

 type SamrRemoveMemberFromAlias struct { // NDRCALL:
    opnum = 32 (
       ('AliasHandle',SAMPR_HANDLE),
       ('MemberId', RPC_SID),
    }

 type SamrRemoveMemberFromAliasResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

 type SamrGetMembersInAlias struct { // NDRCALL:
    opnum = 33 (
       ('AliasHandle',SAMPR_HANDLE),
    }

 type SamrGetMembersInAliasResponse struct { // NDRCALL: (
       ('Members',SAMPR_PSID_ARRAY_OUT),
       ('ErrorCode',ULONG),
    }

 type SamrOpenUser struct { // NDRCALL:
    opnum = 34 (
       ('DomainHandle',SAMPR_HANDLE),
       ('DesiredAccess', ULONG),
       ('UserId', ULONG),
    }

 type SamrOpenUserResponse struct { // NDRCALL: (
       ('UserHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    }

 type SamrDeleteUser struct { // NDRCALL:
    opnum = 35 (
       ('UserHandle',SAMPR_HANDLE),
    }

 type SamrDeleteUserResponse struct { // NDRCALL: (
       ('UserHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    }

 type SamrQueryInformationUser struct { // NDRCALL:
    opnum = 36 (
       ('UserHandle',SAMPR_HANDLE),
       ('UserInformationClass', USER_INFORMATION_CLASS ),
    }

 type SamrQueryInformationUserResponse struct { // NDRCALL: (
       ('Buffer',PSAMPR_USER_INFO_BUFFER),
       ('ErrorCode',ULONG),
    }

 type SamrSetInformationUser struct { // NDRCALL:
    opnum = 37 (
       ('UserHandle',SAMPR_HANDLE),
       ('UserInformationClass', USER_INFORMATION_CLASS ),
       ('Buffer',SAMPR_USER_INFO_BUFFER),
    }

 type SamrSetInformationUserResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

 type SamrChangePasswordUser struct { // NDRCALL:
    opnum = 38 (
       ('UserHandle',SAMPR_HANDLE),
       ('LmPresent', UCHAR ),
       ('OldLmEncryptedWithNewLm',PENCRYPTED_LM_OWF_PASSWORD),
       ('NewLmEncryptedWithOldLm',PENCRYPTED_LM_OWF_PASSWORD),
       ('NtPresent', UCHAR),
       ('OldNtEncryptedWithNewNt',PENCRYPTED_NT_OWF_PASSWORD),
       ('NewNtEncryptedWithOldNt',PENCRYPTED_NT_OWF_PASSWORD),
       ('NtCrossEncryptionPresent',UCHAR),
       ('NewNtEncryptedWithNewLm',PENCRYPTED_NT_OWF_PASSWORD),
       ('LmCrossEncryptionPresent',UCHAR),
       ('NewLmEncryptedWithNewNt',PENCRYPTED_NT_OWF_PASSWORD),
    }

 type SamrChangePasswordUserResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

 type SamrGetGroupsForUser struct { // NDRCALL:
    opnum = 39 (
       ('UserHandle',SAMPR_HANDLE),
    }

 type SamrGetGroupsForUserResponse struct { // NDRCALL: (
       ('Groups',PSAMPR_GET_GROUPS_BUFFER),
       ('ErrorCode',ULONG),
    }

 type SamrQueryDisplayInformation struct { // NDRCALL:
    opnum = 40 (
       ('DomainHandle',SAMPR_HANDLE),
       ('DisplayInformationClass', DOMAIN_DISPLAY_INFORMATION),
       ('Index', ULONG),
       ('EntryCount',ULONG),
       ('PreferredMaximumLength',ULONG),
    }

 type SamrQueryDisplayInformationResponse struct { // NDRCALL: (
       ('TotalAvailable',ULONG),
       ('TotalReturned',ULONG),
       ('Buffer',SAMPR_DISPLAY_INFO_BUFFER),
       ('ErrorCode',ULONG),
    }

 type SamrGetDisplayEnumerationIndex struct { // NDRCALL:
    opnum = 41 (
       ('DomainHandle',SAMPR_HANDLE),
       ('DisplayInformationClass', DOMAIN_DISPLAY_INFORMATION),
       ('Prefix', RPC_UNICODE_STRING),
    }

 type SamrGetDisplayEnumerationIndexResponse struct { // NDRCALL: (
       ('Index',ULONG),
       ('ErrorCode',ULONG),
    }

 type SamrGetUserDomainPasswordInformation struct { // NDRCALL:
    opnum = 44 (
       ('UserHandle',SAMPR_HANDLE),
    }

 type SamrGetUserDomainPasswordInformationResponse struct { // NDRCALL: (
       ('PasswordInformation',USER_DOMAIN_PASSWORD_INFORMATION),
       ('ErrorCode',ULONG),
    }

 type SamrRemoveMemberFromForeignDomain struct { // NDRCALL:
    opnum = 45 (
       ('DomainHandle',SAMPR_HANDLE),
       ('MemberSid', RPC_SID),
    }

 type SamrRemoveMemberFromForeignDomainResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

 type SamrQueryInformationDomain2 struct { // NDRCALL:
    opnum = 46 (
       ('DomainHandle',SAMPR_HANDLE),
       ('DomainInformationClass', DOMAIN_INFORMATION_CLASS),
    }

 type SamrQueryInformationDomain2Response struct { // NDRCALL: (
       ('Buffer',PSAMPR_DOMAIN_INFO_BUFFER),
       ('ErrorCode',ULONG),
    }

 type SamrQueryInformationUser2 struct { // NDRCALL:
    opnum = 47 (
       ('UserHandle',SAMPR_HANDLE),
       ('UserInformationClass', USER_INFORMATION_CLASS ),
    }

 type SamrQueryInformationUser2Response struct { // NDRCALL: (
       ('Buffer',PSAMPR_USER_INFO_BUFFER),
       ('ErrorCode',ULONG),
    }

 type SamrQueryDisplayInformation2 struct { // NDRCALL:
    opnum = 48 (
       ('DomainHandle',SAMPR_HANDLE),
       ('DisplayInformationClass', DOMAIN_DISPLAY_INFORMATION),
       ('Index', ULONG),
       ('EntryCount',ULONG),
       ('PreferredMaximumLength',ULONG),
    }

 type SamrQueryDisplayInformation2Response struct { // NDRCALL: (
       ('TotalAvailable',ULONG),
       ('TotalReturned',ULONG),
       ('Buffer',SAMPR_DISPLAY_INFO_BUFFER),
       ('ErrorCode',ULONG),
    }

 type SamrGetDisplayEnumerationIndex2 struct { // NDRCALL:
    opnum = 49 (
       ('DomainHandle',SAMPR_HANDLE),
       ('DisplayInformationClass', DOMAIN_DISPLAY_INFORMATION),
       ('Prefix', RPC_UNICODE_STRING),
    }

 type SamrGetDisplayEnumerationIndex2Response struct { // NDRCALL: (
       ('Index',ULONG),
       ('ErrorCode',ULONG),
    }

 type SamrCreateUser2InDomain struct { // NDRCALL:
    opnum = 50 (
       ('DomainHandle',SAMPR_HANDLE),
       ('Name', RPC_UNICODE_STRING),
       ('AccountType', ULONG),
       ('DesiredAccess', ULONG),
    }

 type SamrCreateUser2InDomainResponse struct { // NDRCALL: (
       ('UserHandle',SAMPR_HANDLE),
       ('GrantedAccess',ULONG),
       ('RelativeId',ULONG),
       ('ErrorCode',ULONG),
    }

 type SamrQueryDisplayInformation3 struct { // NDRCALL:
    opnum = 51 (
       ('DomainHandle',SAMPR_HANDLE),
       ('DisplayInformationClass', DOMAIN_DISPLAY_INFORMATION),
       ('Index', ULONG),
       ('EntryCount',ULONG),
       ('PreferredMaximumLength',ULONG),
    }

 type SamrQueryDisplayInformation3Response struct { // NDRCALL: (
       ('TotalAvailable',ULONG),
       ('TotalReturned',ULONG),
       ('Buffer',SAMPR_DISPLAY_INFO_BUFFER),
       ('ErrorCode',ULONG),
    }

 type SamrAddMultipleMembersToAlias struct { // NDRCALL:
    opnum = 52 (
       ('AliasHandle',SAMPR_HANDLE),
       ('MembersBuffer', SAMPR_PSID_ARRAY),
    }

 type SamrAddMultipleMembersToAliasResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

 type SamrRemoveMultipleMembersFromAlias struct { // NDRCALL:
    opnum = 53 (
       ('AliasHandle',SAMPR_HANDLE),
       ('MembersBuffer', SAMPR_PSID_ARRAY),
    }

 type SamrRemoveMultipleMembersFromAliasResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

 type SamrOemChangePasswordUser2 struct { // NDRCALL:
    opnum = 54 (
       ('ServerName', PRPC_STRING),
       ('UserName', RPC_STRING),
       ('NewPasswordEncryptedWithOldLm', PSAMPR_ENCRYPTED_USER_PASSWORD),
       ('OldLmOwfPasswordEncryptedWithNewLm', PENCRYPTED_LM_OWF_PASSWORD),
    }

 type SamrOemChangePasswordUser2Response struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

 type SamrUnicodeChangePasswordUser2 struct { // NDRCALL:
    opnum = 55 (
       ('ServerName', PRPC_UNICODE_STRING),
       ('UserName', RPC_UNICODE_STRING),
       ('NewPasswordEncryptedWithOldNt',PSAMPR_ENCRYPTED_USER_PASSWORD),
       ('OldNtOwfPasswordEncryptedWithNewNt',PENCRYPTED_NT_OWF_PASSWORD),
       ('LmPresent',UCHAR),
       ('NewPasswordEncryptedWithOldLm',PSAMPR_ENCRYPTED_USER_PASSWORD),
       ('OldLmOwfPasswordEncryptedWithNewNt',PENCRYPTED_LM_OWF_PASSWORD),
    }

 type SamrUnicodeChangePasswordUser2Response struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

 type SamrGetDomainPasswordInformation struct { // NDRCALL:
    opnum = 56 (
       //('BindingHandle',SAMPR_HANDLE),
       ('Unused', PRPC_UNICODE_STRING),
    }

 type SamrGetDomainPasswordInformationResponse struct { // NDRCALL: (
       ('PasswordInformation',USER_DOMAIN_PASSWORD_INFORMATION),
       ('ErrorCode',ULONG),
    }

 type SamrConnect2 struct { // NDRCALL:
    opnum = 57 (
       ('ServerName',PSAMPR_SERVER_NAME),
       ('DesiredAccess', ULONG),
    }

 type SamrConnect2Response struct { // NDRCALL: (
       ('ServerHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    }

 type SamrSetInformationUser2 struct { // NDRCALL:
    opnum = 58 (
       ('UserHandle',SAMPR_HANDLE),
       ('UserInformationClass', USER_INFORMATION_CLASS),
       ('Buffer', SAMPR_USER_INFO_BUFFER),
    }

 type SamrSetInformationUser2Response struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

 type SamrConnect4 struct { // NDRCALL:
    opnum = 62 (
       ('ServerName',PSAMPR_SERVER_NAME),
       ('ClientRevision', ULONG),
       ('DesiredAccess', ULONG),
    }

 type SamrConnect4Response struct { // NDRCALL: (
       ('ServerHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    }

 type SamrConnect5 struct { // NDRCALL:
    opnum = 64 (
       ('ServerName',PSAMPR_SERVER_NAME),
       ('DesiredAccess', ULONG),
       ('InVersion', ULONG),
       ('InRevisionInfo',SAMPR_REVISION_INFO),
    }

 type SamrConnect5Response struct { // NDRCALL: (
       ('OutVersion',ULONG),
       ('OutRevisionInfo',SAMPR_REVISION_INFO),
       ('ServerHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    }

 type SamrRidToSid struct { // NDRCALL:
    opnum = 65 (
       ('ObjectHandle',SAMPR_HANDLE),
       ('Rid', ULONG),
    }

 type SamrRidToSidResponse struct { // NDRCALL: (
       ('Sid',PRPC_SID),
       ('ErrorCode',ULONG),
    }

 type SamrSetDSRMPassword struct { // NDRCALL:
    opnum = 66 (
       ('Unused', PRPC_UNICODE_STRING),
       ('UserId',ULONG),
       ('EncryptedNtOwfPassword',PENCRYPTED_NT_OWF_PASSWORD),
    }

 type SamrSetDSRMPasswordResponse struct { // NDRCALL: (
       ('ErrorCode',ULONG),
    }

 type SamrValidatePassword struct { // NDRCALL:
    opnum = 67 (
       ('ValidationType', PASSWORD_POLICY_VALIDATION_TYPE),
       ('InputArg',SAM_VALIDATE_INPUT_ARG),
    }

 type SamrValidatePasswordResponse struct { // NDRCALL: (
       ('OutputArg',PSAM_VALIDATE_OUTPUT_ARG),
       ('ErrorCode',ULONG),
    }

//###############################################################################
// OPNUMs and their corresponding structures
//###############################################################################
OPNUMS = {
 0 : (SamrConnect, SamrConnectResponse),
 1 : (SamrCloseHandle, SamrCloseHandleResponse),
 2 : (SamrSetSecurityObject, SamrSetSecurityObjectResponse),
 3 : (SamrQuerySecurityObject, SamrQuerySecurityObjectResponse),
 5 : (SamrLookupDomainInSamServer, SamrLookupDomainInSamServerResponse),
 6 : (SamrEnumerateDomainsInSamServer, SamrEnumerateDomainsInSamServerResponse),
 7 : (SamrOpenDomain, SamrOpenDomainResponse),
 8 : (SamrQueryInformationDomain, SamrQueryInformationDomainResponse),
 9 : (SamrSetInformationDomain, SamrSetInformationDomainResponse),
10 : (SamrCreateGroupInDomain, SamrCreateGroupInDomainResponse),
11 : (SamrEnumerateGroupsInDomain, SamrEnumerateGroupsInDomainResponse),
12 : (SamrCreateUserInDomain, SamrCreateUserInDomainResponse),
13 : (SamrEnumerateUsersInDomain, SamrEnumerateUsersInDomainResponse),
14 : (SamrCreateAliasInDomain, SamrCreateAliasInDomainResponse),
15 : (SamrEnumerateAliasesInDomain, SamrEnumerateAliasesInDomainResponse),
16 : (SamrGetAliasMembership, SamrGetAliasMembershipResponse),
17 : (SamrLookupNamesInDomain, SamrLookupNamesInDomainResponse),
18 : (SamrLookupIdsInDomain, SamrLookupIdsInDomainResponse),
19 : (SamrOpenGroup, SamrOpenGroupResponse),
20 : (SamrQueryInformationGroup, SamrQueryInformationGroupResponse),
21 : (SamrSetInformationGroup, SamrSetInformationGroupResponse),
22 : (SamrAddMemberToGroup, SamrAddMemberToGroupResponse),
23 : (SamrDeleteGroup, SamrDeleteGroupResponse),
24 : (SamrRemoveMemberFromGroup, SamrRemoveMemberFromGroupResponse),
25 : (SamrGetMembersInGroup, SamrGetMembersInGroupResponse),
26 : (SamrSetMemberAttributesOfGroup, SamrSetMemberAttributesOfGroupResponse),
27 : (SamrOpenAlias, SamrOpenAliasResponse),
28 : (SamrQueryInformationAlias, SamrQueryInformationAliasResponse),
29 : (SamrSetInformationAlias, SamrSetInformationAliasResponse),
30 : (SamrDeleteAlias, SamrDeleteAliasResponse),
31 : (SamrAddMemberToAlias, SamrAddMemberToAliasResponse),
32 : (SamrRemoveMemberFromAlias, SamrRemoveMemberFromAliasResponse),
33 : (SamrGetMembersInAlias, SamrGetMembersInAliasResponse),
34 : (SamrOpenUser, SamrOpenUserResponse),
35 : (SamrDeleteUser, SamrDeleteUserResponse),
36 : (SamrQueryInformationUser, SamrQueryInformationUserResponse),
37 : (SamrSetInformationUser, SamrSetInformationUserResponse),
38 : (SamrChangePasswordUser, SamrChangePasswordUserResponse),
39 : (SamrGetGroupsForUser, SamrGetGroupsForUserResponse),
40 : (SamrQueryDisplayInformation, SamrQueryDisplayInformationResponse),
41 : (SamrGetDisplayEnumerationIndex, SamrGetDisplayEnumerationIndexResponse),
44 : (SamrGetUserDomainPasswordInformation, SamrGetUserDomainPasswordInformationResponse),
45 : (SamrRemoveMemberFromForeignDomain, SamrRemoveMemberFromForeignDomainResponse),
46 : (SamrQueryInformationDomain2, SamrQueryInformationDomain2Response),
47 : (SamrQueryInformationUser2, SamrQueryInformationUser2Response),
48 : (SamrQueryDisplayInformation2, SamrQueryDisplayInformation2Response),
49 : (SamrGetDisplayEnumerationIndex2, SamrGetDisplayEnumerationIndex2Response),
50 : (SamrCreateUser2InDomain, SamrCreateUser2InDomainResponse),
51 : (SamrQueryDisplayInformation3, SamrQueryDisplayInformation3Response),
52 : (SamrAddMultipleMembersToAlias, SamrAddMultipleMembersToAliasResponse),
53 : (SamrRemoveMultipleMembersFromAlias, SamrRemoveMultipleMembersFromAliasResponse),
54 : (SamrOemChangePasswordUser2, SamrOemChangePasswordUser2Response),
55 : (SamrUnicodeChangePasswordUser2, SamrUnicodeChangePasswordUser2Response),
56 : (SamrGetDomainPasswordInformation, SamrGetDomainPasswordInformationResponse),
57 : (SamrConnect2, SamrConnect2Response),
58 : (SamrSetInformationUser2, SamrSetInformationUser2Response),
62 : (SamrConnect4, SamrConnect4Response),
64 : (SamrConnect5, SamrConnect5Response),
65 : (SamrRidToSid, SamrRidToSidResponse),
66 : (SamrSetDSRMPassword, SamrSetDSRMPasswordResponse),
67 : (SamrValidatePassword, SamrValidatePasswordResponse),
}

//###############################################################################
// HELPER FUNCTIONS
//###############################################################################

 func hSamrConnect5(dce, serverName='\x00', desiredAccess=MAXIMUM_ALLOWED, inVersion=1 interface{}){
    request = SamrConnect5()
    request["ServerName"] = serverName
    request["DesiredAccess"] = desiredAccess
    request["InVersion"] = inVersion
    request["InRevisionInfo"]["tag"] = inVersion
    return dce.request(request)

 func hSamrConnect4(dce, serverName='\x00', desiredAccess=MAXIMUM_ALLOWED, clientRevision=2 interface{}){
    request = SamrConnect4()
    request["ServerName"] = serverName
    request["DesiredAccess"] = desiredAccess
    request["ClientRevision"] = clientRevision
    return dce.request(request)

 func hSamrConnect2(dce, serverName='\x00', desiredAccess=MAXIMUM_ALLOWED interface{}){
    request = SamrConnect2()
    request["ServerName"] = serverName
    request["DesiredAccess"] = desiredAccess
    return dce.request(request)

 func hSamrConnect(dce, serverName='\x00', desiredAccess=MAXIMUM_ALLOWED interface{}){
    request = SamrConnect()
    request["ServerName"] = serverName
    request["DesiredAccess"] = desiredAccess
    return dce.request(request)

 func hSamrOpenDomain(dce, serverHandle, desiredAccess=MAXIMUM_ALLOWED, domainId=NULL interface{}){
    request = SamrOpenDomain()
    request["ServerHandle"] = serverHandle
    request["DesiredAccess"] = desiredAccess
    request["DomainId"] = domainId
    return dce.request(request)

 func hSamrOpenGroup(dce, domainHandle, desiredAccess=MAXIMUM_ALLOWED, groupId=0 interface{}){
    request = SamrOpenGroup()
    request["DomainHandle"] = domainHandle
    request["DesiredAccess"] = desiredAccess
    request["GroupId"] = groupId
    return dce.request(request)

 func hSamrOpenAlias(dce, domainHandle, desiredAccess=MAXIMUM_ALLOWED, aliasId=0 interface{}){
    request = SamrOpenAlias()
    request["DomainHandle"] = domainHandle
    request["DesiredAccess"] = desiredAccess
    request["AliasId"] = aliasId
    return dce.request(request)

 func hSamrOpenUser(dce, domainHandle, desiredAccess=MAXIMUM_ALLOWED, userId=0 interface{}){
    request = SamrOpenUser()
    request["DomainHandle"] = domainHandle
    request["DesiredAccess"] = desiredAccess
    request["UserId"] = userId
    return dce.request(request)

 func hSamrEnumerateDomainsInSamServer(dce, serverHandle, enumerationContext=0, preferedMaximumLength=0xffffffff interface{}){
    request = SamrEnumerateDomainsInSamServer()
    request["ServerHandle"] = serverHandle
    request["EnumerationContext"] = enumerationContext
    request["PreferedMaximumLength"] = preferedMaximumLength
    return dce.request(request)

 func hSamrEnumerateGroupsInDomain(dce, domainHandle, enumerationContext=0, preferedMaximumLength=0xffffffff interface{}){
    request = SamrEnumerateGroupsInDomain()
    request["DomainHandle"] = domainHandle
    request["EnumerationContext"] = enumerationContext
    request["PreferedMaximumLength"] = preferedMaximumLength
    return dce.request(request)

 func hSamrEnumerateAliasesInDomain(dce, domainHandle, enumerationContext=0, preferedMaximumLength=0xffffffff interface{}){
    request = SamrEnumerateAliasesInDomain()
    request["DomainHandle"] = domainHandle
    request["EnumerationContext"] = enumerationContext
    request["PreferedMaximumLength"] = preferedMaximumLength
    return dce.request(request)

 func hSamrEnumerateUsersInDomain(dce, domainHandle, userAccountControl=USER_NORMAL_ACCOUNT, enumerationContext=0, preferedMaximumLength=0xffffffff interface{}){
    request = SamrEnumerateUsersInDomain()
    request["DomainHandle"] = domainHandle
    request["UserAccountControl"] = userAccountControl
    request["EnumerationContext"] = enumerationContext
    request["PreferedMaximumLength"] = preferedMaximumLength
    return dce.request(request)

 func hSamrQueryDisplayInformation3(dce, domainHandle, displayInformationClass=DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser, index=0, entryCount=0xffffffff, preferedMaximumLength=0xffffffff interface{}){
    request = SamrQueryDisplayInformation3()
    request["DomainHandle"] = domainHandle
    request["DisplayInformationClass"] = displayInformationClass
    request["Index"] = index
    request["EntryCount"] = entryCount
    request["PreferredMaximumLength"] = preferedMaximumLength
    return dce.request(request)

 func hSamrQueryDisplayInformation2(dce, domainHandle, displayInformationClass=DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser, index=0, entryCount=0xffffffff, preferedMaximumLength=0xffffffff interface{}){
    request = SamrQueryDisplayInformation2()
    request["DomainHandle"] = domainHandle
    request["DisplayInformationClass"] = displayInformationClass
    request["Index"] = index
    request["EntryCount"] = entryCount
    request["PreferredMaximumLength"] = preferedMaximumLength
    return dce.request(request)

 func hSamrQueryDisplayInformation(dce, domainHandle, displayInformationClass=DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser, index=0, entryCount=0xffffffff, preferedMaximumLength=0xffffffff interface{}){
    request = SamrQueryDisplayInformation()
    request["DomainHandle"] = domainHandle
    request["DisplayInformationClass"] = displayInformationClass
    request["Index"] = index
    request["EntryCount"] = entryCount
    request["PreferredMaximumLength"] = preferedMaximumLength
    return dce.request(request)

 func hSamrGetDisplayEnumerationIndex2(dce, domainHandle, displayInformationClass=DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser, prefix='' interface{}){
    request = SamrGetDisplayEnumerationIndex2()
    request["DomainHandle"] = domainHandle
    request["DisplayInformationClass"] = displayInformationClass
    request["Prefix"] = prefix
    return dce.request(request)

 func hSamrGetDisplayEnumerationIndex(dce, domainHandle, displayInformationClass=DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser, prefix='' interface{}){
    request = SamrGetDisplayEnumerationIndex()
    request["DomainHandle"] = domainHandle
    request["DisplayInformationClass"] = displayInformationClass
    request["Prefix"] = prefix
    return dce.request(request)

 func hSamrCreateGroupInDomain(dce, domainHandle, name, desiredAccess=GROUP_ALL_ACCESS interface{}){
    request = SamrCreateGroupInDomain()
    request["DomainHandle"] = domainHandle
    request["Name"] = name
    request["DesiredAccess"] = desiredAccess
    return dce.request(request)

 func hSamrCreateAliasInDomain(dce, domainHandle, accountName, desiredAccess=GROUP_ALL_ACCESS interface{}){
    request = SamrCreateAliasInDomain()
    request["DomainHandle"] = domainHandle
    request["AccountName"] = accountName
    request["DesiredAccess"] = desiredAccess
    return dce.request(request)

 func hSamrCreateUser2InDomain(dce, domainHandle, name, accountType=USER_NORMAL_ACCOUNT, desiredAccess=GROUP_ALL_ACCESS interface{}){
    request = SamrCreateUser2InDomain()
    request["DomainHandle"] = domainHandle
    request["Name"] = name
    request["AccountType"] = accountType
    request["DesiredAccess"] = desiredAccess
    return dce.request(request)

 func hSamrCreateUserInDomain(dce, domainHandle, name, desiredAccess=GROUP_ALL_ACCESS interface{}){
    request = SamrCreateUserInDomain()
    request["DomainHandle"] = domainHandle
    request["Name"] = name
    request["DesiredAccess"] = desiredAccess
    return dce.request(request)

 func hSamrQueryInformationDomain(dce, domainHandle, domainInformationClass=DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2 interface{}){
    request = SamrQueryInformationDomain()
    request["DomainHandle"] = domainHandle
    request["DomainInformationClass"] = domainInformationClass
    return dce.request(request)

 func hSamrQueryInformationDomain2(dce, domainHandle, domainInformationClass=DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2 interface{}){
    request = SamrQueryInformationDomain2()
    request["DomainHandle"] = domainHandle
    request["DomainInformationClass"] = domainInformationClass
    return dce.request(request)

 func hSamrQueryInformationGroup(dce, groupHandle, groupInformationClass=GROUP_INFORMATION_CLASS.GroupGeneralInformation interface{}){
    request = SamrQueryInformationGroup()
    request["GroupHandle"] = groupHandle
    request["GroupInformationClass"] = groupInformationClass
    return dce.request(request)

 func hSamrQueryInformationAlias(dce, aliasHandle, aliasInformationClass=ALIAS_INFORMATION_CLASS.AliasGeneralInformation interface{}){
    request = SamrQueryInformationAlias()
    request["AliasHandle"] = aliasHandle
    request["AliasInformationClass"] = aliasInformationClass
    return dce.request(request)

 func hSamrQueryInformationUser2(dce, userHandle, userInformationClass=USER_INFORMATION_CLASS.UserGeneralInformation interface{}){
    request = SamrQueryInformationUser2()
    request["UserHandle"] = userHandle
    request["UserInformationClass"] = userInformationClass
    return dce.request(request)

 func hSamrQueryInformationUser(dce, userHandle, userInformationClass=USER_INFORMATION_CLASS.UserGeneralInformation interface{}){
    request = SamrQueryInformationUser()
    request["UserHandle"] = userHandle
    request["UserInformationClass"] = userInformationClass
    return dce.request(request)

 func hSamrSetInformationDomain(dce, domainHandle, domainInformation interface{}){
    request = SamrSetInformationDomain()
    request["DomainHandle"] = domainHandle
    request["DomainInformationClass"] = domainInformation["tag"]
    request["DomainInformation"] = domainInformation
    return dce.request(request)

 func hSamrSetInformationGroup(dce, groupHandle, buffer interface{}){
    request = SamrSetInformationGroup()
    request["GroupHandle"] = groupHandle
    request["GroupInformationClass"] = buffer["tag"]
    request["Buffer"] = buffer
    return dce.request(request)

 func hSamrSetInformationAlias(dce, aliasHandle, buffer interface{}){
    request = SamrSetInformationAlias()
    request["AliasHandle"] = aliasHandle
    request["AliasInformationClass"] = buffer["tag"]
    request["Buffer"] = buffer
    return dce.request(request)

 func hSamrSetInformationUser2(dce, userHandle, buffer interface{}){
    request = SamrSetInformationUser2()
    request["UserHandle"] = userHandle
    request["UserInformationClass"] = buffer["tag"]
    request["Buffer"] = buffer
    return dce.request(request)

 func hSamrSetInformationUser(dce, userHandle, buffer interface{}){
    request = SamrSetInformationUser()
    request["UserHandle"] = userHandle
    request["UserInformationClass"] = buffer["tag"]
    request["Buffer"] = buffer
    return dce.request(request)

 func hSamrDeleteGroup(dce, groupHandle interface{}){
    request = SamrDeleteGroup()
    request["GroupHandle"] = groupHandle
    return dce.request(request)

 func hSamrDeleteAlias(dce, aliasHandle interface{}){
    request = SamrDeleteAlias()
    request["AliasHandle"] = aliasHandle
    return dce.request(request)

 func hSamrDeleteUser(dce, userHandle interface{}){
    request = SamrDeleteUser()
    request["UserHandle"] = userHandle
    return dce.request(request)

 func hSamrAddMemberToGroup(dce, groupHandle, memberId, attributes interface{}){
    request = SamrAddMemberToGroup()
    request["GroupHandle"] = groupHandle
    request["MemberId"] = memberId
    request["Attributes"] = attributes
    return dce.request(request)

 func hSamrRemoveMemberFromGroup(dce, groupHandle, memberId interface{}){
    request = SamrRemoveMemberFromGroup()
    request["GroupHandle"] = groupHandle
    request["MemberId"] = memberId
    return dce.request(request)

 func hSamrGetMembersInGroup(dce, groupHandle interface{}){
    request = SamrGetMembersInGroup()
    request["GroupHandle"] = groupHandle
    return dce.request(request)

 func hSamrAddMemberToAlias(dce, aliasHandle, memberId interface{}){
    request = SamrAddMemberToAlias()
    request["AliasHandle"] = aliasHandle
    request["MemberId"] = memberId
    return dce.request(request)

 func hSamrRemoveMemberFromAlias(dce, aliasHandle, memberId interface{}){
    request = SamrRemoveMemberFromAlias()
    request["AliasHandle"] = aliasHandle
    request["MemberId"] = memberId
    return dce.request(request)

 func hSamrGetMembersInAlias(dce, aliasHandle interface{}){
    request = SamrGetMembersInAlias()
    request["AliasHandle"] = aliasHandle
    return dce.request(request)

 func hSamrRemoveMemberFromForeignDomain(dce, domainHandle, memberSid interface{}){
    request = SamrRemoveMemberFromForeignDomain()
    request["DomainHandle"] = domainHandle
    request["MemberSid"] = memberSid
    return dce.request(request)

 func hSamrAddMultipleMembersToAlias(dce, aliasHandle, membersBuffer interface{}){
    request = SamrAddMultipleMembersToAlias()
    request["AliasHandle"] = aliasHandle
    request["MembersBuffer"] = membersBuffer
    request["MembersBuffer"]["Count"] = len(membersBuffer["Sids"])
    return dce.request(request)

 func hSamrRemoveMultipleMembersFromAlias(dce, aliasHandle, membersBuffer interface{}){
    request = SamrRemoveMultipleMembersFromAlias()
    request["AliasHandle"] = aliasHandle
    request["MembersBuffer"] = membersBuffer
    request["MembersBuffer"]["Count"] = len(membersBuffer["Sids"])
    return dce.request(request)

 func hSamrGetGroupsForUser(dce, userHandle interface{}){
    request = SamrGetGroupsForUser()
    request["UserHandle"] = userHandle
    return dce.request(request)

 func hSamrGetAliasMembership(dce, domainHandle, sidArray interface{}){
    request = SamrGetAliasMembership()
    request["DomainHandle"] = domainHandle
    request["SidArray"] = sidArray
    request["SidArray"]["Count"] = len(sidArray["Sids"])
    return dce.request(request)

 func hSamrChangePasswordUser(dce, userHandle, oldPassword, newPassword interface{}){
    request = SamrChangePasswordUser()
    request["UserHandle"] = userHandle

    from impacket import crypto, ntlm

    oldPwdHashNT = ntlm.NTOWFv1(oldPassword)
    newPwdHashNT = ntlm.NTOWFv1(newPassword)
    newPwdHashLM = ntlm.LMOWFv1(newPassword)

    request["LmPresent"] = 0
    request["OldLmEncryptedWithNewLm"] = NULL
    request["NewLmEncryptedWithOldLm"] = NULL
    request["NtPresent"] = 1
    request["OldNtEncryptedWithNewNt"] = crypto.SamEncryptNTLMHash(oldPwdHashNT, newPwdHashNT)
    request["NewNtEncryptedWithOldNt"] = crypto.SamEncryptNTLMHash(newPwdHashNT, oldPwdHashNT) 
    request["NtCrossEncryptionPresent"] = 0
    request["NewNtEncryptedWithNewLm"] = NULL
    request["LmCrossEncryptionPresent"] = 1
    request["NewLmEncryptedWithNewNt"] = crypto.SamEncryptNTLMHash(newPwdHashLM, newPwdHashNT)

    return dce.request(request)

 func hSamrUnicodeChangePasswordUser2(dce, serverName='\x00', userName='', oldPassword='', newPassword='', oldPwdHashLM = "", oldPwdHashNT = "" interface{}){
    request = SamrUnicodeChangePasswordUser2()
    request["ServerName"] = serverName
    request["UserName"] = userName

    try:
        from Cryptodome.Cipher import ARC4
    except Exception:
        LOG.critical("Warning: You don't have any crypto installed. You need pycryptodomex")
        LOG.critical("See https://pypi.org/project/pycryptodomex/")
    from impacket import crypto, ntlm

    if oldPwdHashLM == '' and oldPwdHashNT == '' {
        oldPwdHashLM = ntlm.LMOWFv1(oldPassword)
        oldPwdHashNT = ntlm.NTOWFv1(oldPassword)
    } else  {
        // Let's convert the hashes to binary form, if not yet
        try:
            oldPwdHashLM = unhexlify(oldPwdHashLM)
        except:
            pass
        try: 
            oldPwdHashNT = unhexlify(oldPwdHashNT)
        except:
            pass

    newPwdHashNT = ntlm.NTOWFv1(newPassword)

    samUser = SAMPR_USER_PASSWORD()
    try:
        samUser["Buffer"] = b'A'*(512-len(newPassword)*2) + newPassword.encode("utf-16le")
    except UnicodeDecodeError:
        import sys
        samUser["Buffer"] = b'A'*(512-len(newPassword)*2) + newPassword.decode(sys.getfilesystemencoding()).encode("utf-16le")

    samUser["Length"] = len(newPassword)*2
    pwdBuff = samUser.getData()

    rc4 = ARC4.new(oldPwdHashNT)
    encBuf = rc4.encrypt(pwdBuff)
    request["NewPasswordEncryptedWithOldNt"]["Buffer"] = encBuf
    request["OldNtOwfPasswordEncryptedWithNewNt"] = crypto.SamEncryptNTLMHash(oldPwdHashNT, newPwdHashNT)
    request["LmPresent"] = 0
    request["NewPasswordEncryptedWithOldLm"] = NULL
    request["OldLmOwfPasswordEncryptedWithNewNt"] = NULL

    return dce.request(request)

 func hSamrLookupDomainInSamServer(dce, serverHandle, name interface{}){
    request = SamrLookupDomainInSamServer()
    request["ServerHandle"] = serverHandle
    request["Name"] = name
    return dce.request(request)

 func hSamrSetSecurityObject(dce, objectHandle, securityInformation, securityDescriptor interface{}){
    request = SamrSetSecurityObject()
    request["ObjectHandle"] =  objectHandle
    request["SecurityInformation"] =  securityInformation
    request["SecurityDescriptor"] = securityDescriptor
    return dce.request(request)

 func hSamrQuerySecurityObject(dce, objectHandle, securityInformation interface{}){
    request = SamrQuerySecurityObject()
    request["ObjectHandle"] =  objectHandle
    request["SecurityInformation"] =  securityInformation
    return dce.request(request)

 func hSamrCloseHandle(dce, samHandle interface{}){
    request = SamrCloseHandle()
    request["SamHandle"] =  samHandle
    return dce.request(request)

 func hSamrSetMemberAttributesOfGroup(dce, groupHandle, memberId, attributes interface{}){
    request = SamrSetMemberAttributesOfGroup()
    request["GroupHandle"] =  groupHandle
    request["MemberId"] =  memberId
    request["Attributes"] =  attributes
    return dce.request(request)

 func hSamrGetUserDomainPasswordInformation(dce, userHandle interface{}){
    request = SamrGetUserDomainPasswordInformation()
    request["UserHandle"] =  userHandle
    return dce.request(request)

 func hSamrGetDomainPasswordInformation(dce interface{}){
    request = SamrGetDomainPasswordInformation()
    request["Unused"] =  NULL
    return dce.request(request)

 func hSamrRidToSid(dce, objectHandle, rid interface{}){
    request = SamrRidToSid()
    request["ObjectHandle"] = objectHandle
    request["Rid"] =  rid
    return dce.request(request)

 func hSamrValidatePassword(dce, inputArg interface{}){
    request = SamrValidatePassword()
    request["ValidationType"] =  inputArg["tag"]
    request["InputArg"] = inputArg
    return dce.request(request)

 func hSamrLookupNamesInDomain(dce, domainHandle, names interface{}){
    request = SamrLookupNamesInDomain()
    request["DomainHandle"] =  domainHandle
    request["Count"] = len(names)
    for name in names:
        entry = RPC_UNICODE_STRING()
        entry["Data"] = name
        request["Names"].append(entry)

    request.fields["Names"].fields["MaximumCount"] = 1000

    return dce.request(request)

 func hSamrLookupIdsInDomain(dce, domainHandle, ids interface{}){
    request = SamrLookupIdsInDomain()
    request["DomainHandle"] =  domainHandle
    request["Count"] = len(ids)
    for dId in ids:
        entry = ULONG()
        entry["Data"] = dId
        request["RelativeIds"].append(entry)

    request.fields["RelativeIds"].fields["MaximumCount"] = 1000

    return dce.request(request)
