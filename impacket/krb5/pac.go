// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Author: Alberto Solino (@agsolino)
//
// Description:
//   [MS-PAC] Implementation
//
from impacket.dcerpc.v5.dtypes import ULONG, RPC_UNICODE_STRING, FILETIME, PRPC_SID, USHORT
from impacket.dcerpc.v5.ndr import NDRSTRUCT, NDRUniConformantArray, NDRPOINTER
from impacket.dcerpc.v5.nrpc import USER_SESSION_KEY, CHAR_FIXED_8_ARRAY, PUCHAR_ARRAY, PRPC_UNICODE_STRING_ARRAY
from impacket.dcerpc.v5.rpcrt import TypeSerialization1
from impacket.structure import Structure

//###############################################################################
// CONSTANTS
//###############################################################################
// From https://msdn.microsoft.com/library/aa302203#msdn_pac_credentials
// and http://diswww.mit.edu/menelaus.mit.edu/cvs-krb5/25862
PAC_LOGON_INFO       = 1
PAC_CREDENTIALS_INFO = 2
PAC_SERVER_CHECKSUM  = 6
PAC_PRIVSVR_CHECKSUM = 7
PAC_CLIENT_INFO_TYPE = 10
PAC_DELEGATION_INFO  = 11
PAC_UPN_DNS_INFO     = 12

//###############################################################################
// STRUCTURES
//###############################################################################

PISID = PRPC_SID

// 2.2.1 KERB_SID_AND_ATTRIBUTES
 type KERB_SID_AND_ATTRIBUTES struct { // NDRSTRUCT: (
        ('Sid', PISID),
        ('Attributes', ULONG),
    }

 type KERB_SID_AND_ATTRIBUTES_ARRAY struct { // NDRUniConformantArray:
    item = KERB_SID_AND_ATTRIBUTES

 type PKERB_SID_AND_ATTRIBUTES_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', KERB_SID_AND_ATTRIBUTES_ARRAY),
    }

// 2.2.2 GROUP_MEMBERSHIP
from impacket.dcerpc.v5.nrpc import PGROUP_MEMBERSHIP_ARRAY

// 2.2.3 DOMAIN_GROUP_MEMBERSHIP
 type DOMAIN_GROUP_MEMBERSHIP struct { // NDRSTRUCT: (
        ('DomainId', PISID),
        ('GroupCount', ULONG),
        ('GroupIds', PGROUP_MEMBERSHIP_ARRAY),
    }

 type DOMAIN_GROUP_MEMBERSHIP_ARRAY struct { // NDRUniConformantArray:
    item = DOMAIN_GROUP_MEMBERSHIP

 type PDOMAIN_GROUP_MEMBERSHIP_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data', KERB_SID_AND_ATTRIBUTES_ARRAY),
    }

// 2.3 PACTYPE
 type PACTYPE struct { // Structure: (
         cBuffers uint32 // =0
         Version uint32 // =0
        ('Buffers', ':'),
    }

// 2.4 PAC_INFO_BUFFER
 type PAC_INFO_BUFFER struct { // Structure: (
         ulType uint32 // =0
         cbBufferSize uint32 // =0
         Offset uint64 // =0
    }

// 2.5 KERB_VALIDATION_INFO
 type KERB_VALIDATION_INFO struct { // NDRSTRUCT: (
        ('LogonTime', FILETIME),
        ('LogoffTime', FILETIME),
        ('KickOffTime', FILETIME),
        ('PasswordLastSet', FILETIME),
        ('PasswordCanChange', FILETIME),
        ('PasswordMustChange', FILETIME),
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

        // Also called Reserved1
        ('LMKey', CHAR_FIXED_8_ARRAY),

        ('UserAccountControl', ULONG),
        ('SubAuthStatus', ULONG),
        ('LastSuccessfulILogon', FILETIME),
        ('LastFailedILogon', FILETIME),
        ('FailedILogonCount', ULONG),
        ('Reserved3', ULONG),

        ('SidCount', ULONG),
        //('ExtraSids', PNETLOGON_SID_AND_ATTRIBUTES_ARRAY),
        ('ExtraSids', PKERB_SID_AND_ATTRIBUTES_ARRAY),
        ('ResourceGroupDomainSid', PISID),
        ('ResourceGroupCount', ULONG),
        ('ResourceGroupIds', PGROUP_MEMBERSHIP_ARRAY),
    }

 type PKERB_VALIDATION_INFO struct { // NDRPOINTER:
    referent = (
        ('Data', KERB_VALIDATION_INFO),
    }

// 2.6.1 PAC_CREDENTIAL_INFO
 type PAC_CREDENTIAL_INFO struct { // Structure: (
         Version uint32 // =0
         EncryptionType uint32 // =0
        ('SerializedData', ':'),
    }

// 2.6.3 SECPKG_SUPPLEMENTAL_CRED
 type SECPKG_SUPPLEMENTAL_CRED struct { // NDRSTRUCT: (
        ('PackageName', RPC_UNICODE_STRING),
        ('CredentialSize', ULONG),
        ('Credentials', PUCHAR_ARRAY),
    }

 type SECPKG_SUPPLEMENTAL_CRED_ARRAY struct { // NDRUniConformantArray:
    item = SECPKG_SUPPLEMENTAL_CRED

// 2.6.2 PAC_CREDENTIAL_DATA
 type PAC_CREDENTIAL_DATA struct { // NDRSTRUCT: (
        ('CredentialCount', ULONG),
        ('Credentials', SECPKG_SUPPLEMENTAL_CRED_ARRAY),
    }

// 2.6.4 NTLM_SUPPLEMENTAL_CREDENTIAL
 type NTLM_SUPPLEMENTAL_CREDENTIAL struct { // NDRSTRUCT: (
        ('Version', ULONG),
        ('Flags', ULONG),
         LmPassword [6]byte // =b""
         NtPassword [6]byte // =b""
    }

// 2.7 PAC_CLIENT_INFO
 type PAC_CLIENT_INFO struct { // Structure: (
         ClientId uint64 // =0
         NameLength uint16 // =0
        ('_Name', '_-Name', 'self.NameLength'),
        ('Name', ':'),
    }

// 2.8 PAC_SIGNATURE_DATA
 type PAC_SIGNATURE_DATA struct { // Structure: (
        ('SignatureType', '<l=0'),
        ('Signature', ':'),
    }

// 2.9 Constrained Delegation Information - S4U_DELEGATION_INFO
 type S4U_DELEGATION_INFO struct { // NDRSTRUCT: (
        ('S4U2proxyTarget', RPC_UNICODE_STRING),
        ('TransitedListSize', ULONG),
        ('S4UTransitedServices', PRPC_UNICODE_STRING_ARRAY ),
    }

// 2.10 UPN_DNS_INFO
 type UPN_DNS_INFO struct { // Structure: (
         UpnLength uint16 // =0
         UpnOffset uint16 // =0
         DnsDomainNameLength uint16 // =0
         DnsDomainNameOffset uint16 // =0
         Flags uint32 // =0
    }

// 2.11 PAC_CLIENT_CLAIMS_INFO
 type PAC_CLIENT_CLAIMS_INFO struct { // Structure: (
        ('Claims', ':'),
    }

// 2.12 PAC_DEVICE_INFO
 type PAC_DEVICE_INFO struct { // NDRSTRUCT: (
        ('UserId', ULONG),
        ('PrimaryGroupId', ULONG),
        ('AccountDomainId', PISID ),
        ('AccountGroupCount', ULONG ),
        ('AccountGroupIds', PGROUP_MEMBERSHIP_ARRAY ),
        ('SidCount', ULONG ),
        ('ExtraSids', PKERB_SID_AND_ATTRIBUTES_ARRAY ),
        ('DomainGroupCount', ULONG ),
        ('DomainGroup', PDOMAIN_GROUP_MEMBERSHIP_ARRAY ),
    }

// 2.13 PAC_DEVICE_CLAIMS_INFO
 type PAC_DEVICE_CLAIMS_INFO struct { // Structure: (
        ('Claims', ':'),
    }

 type VALIDATION_INFO struct { // TypeSerialization1: (
        ('Data', PKERB_VALIDATION_INFO),
    }
