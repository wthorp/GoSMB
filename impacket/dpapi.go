// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Author:
//  Alberto Solino (@agsolino)
//
// Description:
//       DPAPI and Windows Vault parsing structures and manipulation
//
// References: All of the work done by these guys. I just adapted their work to my needs.
//       https://www.passcape.com/index.php?section=docsys&cmd=details&id=28
//       https://github.com/jordanbtucker/dpapick
//       https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials (and everything else Ben did )
//       http://blog.digital-forensics.it/2016/01/windows-revaulting.html
//       https://www.passcape.com/windows_password_recovery_vault_explorer
//       https://www.passcape.com/windows_password_recovery_dpapi_master_key
//
from __future__ import division
from __future__ import print_function
import sys

from struct import unpack
from datetime import datetime
from binascii import unhexlify, hexlify
from struct import pack
from Cryptodome.Hash import HMAC, SHA512, SHA1
from Cryptodome.Cipher import AES, DES3
from Cryptodome.Util.Padding import unpad
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.number import bytes_to_long
from six import PY3

from impacket.ese import getUnixTime
from impacket.structure import Structure, hexdump
from impacket.uuid import bin_to_string
from impacket.dcerpc.v5.enum import Enum
from impacket.dcerpc.v5.dtypes import RPC_SID

// Algorithm classes
ALG_CLASS_ANY                   = (0)
ALG_CLASS_SIGNATURE             = (1 << 13)
ALG_CLASS_MSG_ENCRYPT           = (2 << 13)
ALG_CLASS_DATA_ENCRYPT          = (3 << 13)
ALG_CLASS_HASH                  = (4 << 13)
ALG_CLASS_KEY_EXCHANGE          = (5 << 13)
ALG_CLASS_ALL                   = (7 << 13)

// Algorithm types
ALG_TYPE_ANY                    = (0)
ALG_TYPE_DSS                    = (1 << 9)
ALG_TYPE_RSA                    = (2 << 9)
ALG_TYPE_BLOCK                  = (3 << 9)
ALG_TYPE_STREAM                 = (4 << 9)
ALG_TYPE_DH                     = (5 << 9)
ALG_TYPE_SECURECHANNEL          = (6 << 9)
ALG_SID_ANY                     = (0)
ALG_SID_RSA_ANY                 = 0
ALG_SID_RSA_PKCS                = 1
ALG_SID_RSA_MSATWORK            = 2
ALG_SID_RSA_ENTRUST             = 3
ALG_SID_RSA_PGP                 = 4
ALG_SID_DSS_ANY                 = 0
ALG_SID_DSS_PKCS                = 1
ALG_SID_DSS_DMS                 = 2
ALG_SID_ECDSA                   = 3

// Block cipher sub ids
ALG_SID_DES                     = 1
ALG_SID_3DES                    = 3
ALG_SID_DESX                    = 4
ALG_SID_IDEA                    = 5
ALG_SID_CAST                    = 6
ALG_SID_SAFERSK64               = 7
ALG_SID_SAFERSK128              = 8
ALG_SID_3DES_112                = 9
ALG_SID_CYLINK_MEK              = 12
ALG_SID_RC5                     = 13
ALG_SID_AES_128                 = 14
ALG_SID_AES_192                 = 15
ALG_SID_AES_256                 = 16
ALG_SID_AES                     = 17
ALG_SID_SKIPJACK                = 10
ALG_SID_TEK                     = 11

CRYPT_MODE_CBCI                 = 6       // ANSI CBC Interleaved
CRYPT_MODE_CFBP                 = 7       // ANSI CFB Pipelined
CRYPT_MODE_OFBP                 = 8       // ANSI OFB Pipelined
CRYPT_MODE_CBCOFM               = 9       // ANSI CBC + OF Masking
CRYPT_MODE_CBCOFMI              = 10      // ANSI CBC + OFM Interleaved

ALG_SID_RC2                     = 2
ALG_SID_RC4                     = 1
ALG_SID_SEAL                    = 2

// Diffie - Hellman sub - ids
ALG_SID_DH_SANDF                = 1
ALG_SID_DH_EPHEM                = 2
ALG_SID_AGREED_KEY_ANY          = 3
ALG_SID_KEA                     = 4
ALG_SID_ECDH                    = 5

// Hash sub ids
ALG_SID_MD2                     = 1
ALG_SID_MD4                     = 2
ALG_SID_MD5                     = 3
ALG_SID_SHA                     = 4
ALG_SID_SHA1                    = 4
ALG_SID_MAC                     = 5
ALG_SID_RIPEMD                  = 6
ALG_SID_RIPEMD160               = 7
ALG_SID_SSL3SHAMD5              = 8
ALG_SID_HMAC                    = 9
ALG_SID_TLS1PRF                 = 10
ALG_SID_HASH_REPLACE_OWF        = 11
ALG_SID_SHA_256                 = 12
ALG_SID_SHA_384                 = 13
ALG_SID_SHA_512                 = 14

// secure channel sub ids
ALG_SID_SSL3_MASTER             = 1
ALG_SID_SCHANNEL_MASTER_HASH    = 2
ALG_SID_SCHANNEL_MAC_KEY        = 3
ALG_SID_PCT1_MASTER             = 4
ALG_SID_SSL2_MASTER             = 5
ALG_SID_TLS1_MASTER             = 6
ALG_SID_SCHANNEL_ENC_KEY        = 7
ALG_SID_ECMQV                   = 1

 func getFlags(myenum, flags interface{}){
    return '|'.join([name for name, member in myenum.__members__.items() if member.value & flags])

 type FLAGS struct { // Enum:
    CRYPTPROTECT_UI_FORBIDDEN = 0x1
    CRYPTPROTECT_LOCAL_MACHINE = 0x4
    CRYPTPROTECT_CRED_SYNC = 0x8
    CRYPTPROTECT_AUDIT = 0x10
    CRYPTPROTECT_VERIFY_PROTECTION = 0x40
    CRYPTPROTECT_CRED_REGENERATE = 0x80
    CRYPTPROTECT_SYSTEM = 0x20000000

// algorithm identifier definitions
 type ALGORITHMS struct { // Enum:
    CALG_MD2                = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD2)
    CALG_MD4                = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD4)
    CALG_MD5                = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD5)
    CALG_SHA                = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA)
    CALG_SHA1               = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA1)
    CALG_RSA_SIGN           = (ALG_CLASS_SIGNATURE | ALG_TYPE_RSA | ALG_SID_RSA_ANY)
    CALG_DSS_SIGN           = (ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | ALG_SID_DSS_ANY)
    CALG_NO_SIGN            = (ALG_CLASS_SIGNATURE | ALG_TYPE_ANY | ALG_SID_ANY)
    CALG_RSA_KEYX           = (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_RSA|ALG_SID_RSA_ANY)
    CALG_DES                = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_DES)
    CALG_3DES_112           = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_3DES_112)
    CALG_3DES               = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_3DES)
    CALG_DESX               = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_DESX)
    CALG_RC2                = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_RC2)
    CALG_RC4                = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_STREAM|ALG_SID_RC4)
    CALG_SEAL               = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_STREAM|ALG_SID_SEAL)
    CALG_DH_SF              = (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_DH_SANDF)
    CALG_DH_EPHEM           = (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_DH_EPHEM)
    CALG_AGREEDKEY_ANY      = (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_AGREED_KEY_ANY)
    CALG_KEA_KEYX           = (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_KEA)
    CALG_HUGHES_MD5         = (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_ANY|ALG_SID_MD5)
    CALG_SKIPJACK           = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_SKIPJACK)
    CALG_TEK                = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_TEK)
    CALG_SSL3_SHAMD5        = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SSL3SHAMD5)
    CALG_SSL3_MASTER        = (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_SSL3_MASTER)
    CALG_SCHANNEL_MASTER_HASH   = (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_SCHANNEL_MASTER_HASH)
    CALG_SCHANNEL_MAC_KEY   = (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_SCHANNEL_MAC_KEY)
    CALG_SCHANNEL_ENC_KEY   = (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_SCHANNEL_ENC_KEY)
    CALG_PCT1_MASTER        = (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_PCT1_MASTER)
    CALG_SSL2_MASTER        = (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_SSL2_MASTER)
    CALG_TLS1_MASTER        = (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_TLS1_MASTER)
    CALG_RC5                = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_RC5)
    CALG_HMAC               = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HMAC)
    CALG_TLS1PRF            = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_TLS1PRF)
    CALG_HASH_REPLACE_OWF   = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HASH_REPLACE_OWF)
    CALG_AES_128            = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_AES_128)
    CALG_AES_192            = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_AES_192)
    CALG_AES_256            = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_AES_256)
    CALG_AES                = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_AES)
    CALG_SHA_256            = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256)
    CALG_SHA_384            = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_384)
    CALG_SHA_512            = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_512)
    CALG_ECDH               = (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_ECDH)
    CALG_ECMQV              = (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | ALG_SID_ECMQV)
    CALG_ECDSA              = (ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | ALG_SID_ECDSA)

 type CREDENTIAL_FLAGS struct { // Enum:
    CRED_FLAGS_PASSWORD_FOR_CERT = 0x1
    CRED_FLAGS_PROMPT_NOW = 0x2
    CRED_FLAGS_USERNAME_TARGET = 0x4
    CRED_FLAGS_OWF_CRED_BLOB = 0x8
    CRED_FLAGS_REQUIRE_CONFIRMATION = 0x10
    CRED_FLAGS_WILDCARD_MATCH = 0x20
    CRED_FLAGS_VSM_PROTECTED = 0x40
    CRED_FLAGS_NGC_CERT = 0x80

 type CREDENTIAL_TYPE struct { // Enum:
    CRED_TYPE_GENERIC = 0x1
    CRED_TYPE_DOMAIN_PASSWORD = 0x2
    CRED_TYPE_DOMAIN_CERTIFICATE = 0x3
    CRED_TYPE_DOMAIN_VISIBLE_PASSWORD = 0x4
    CRED_TYPE_GENERIC_CERTIFICATE = 0x5
    CRED_TYPE_DOMAIN_EXTENDED = 0x6
    CRED_TYPE_MAXIMUM = 0x7
    CRED_TYPE_MAXIMUM_EX = 0x8

 type CREDENTIAL_PERSIST struct { // Enum:
    CRED_PERSIST_NONE = 0x0
    CRED_PERSIST_SESSION = 0x1
    CRED_PERSIST_LOCAL_MACHINE = 0x2
    CRED_PERSIST_ENTERPRISE = 0x3

ALGORITHMS_DATA = {
    // Algorithm: key/SaltLen, CryptHashModule, Mode, IVLen, BlockSize
    ALGORITHMS.CALG_SHA.value: (160//8, SHA1, nil, nil, 512//8),
    ALGORITHMS.CALG_HMAC.value: (160//8, SHA512, nil, nil, 512//8),
    ALGORITHMS.CALG_3DES.value: (192//8, DES3, DES3.MODE_CBC, 64//8),
    ALGORITHMS.CALG_SHA_512.value: (128//8, SHA512, nil, nil, 1024//8),
    ALGORITHMS.CALG_AES_256.value: (256//8, AES, AES.MODE_CBC, 128//8),
}

 type MasterKeyFile struct { // Structure: (
         Version uint32 // =0
         unk1 uint32 // =0
         unk2 uint32 // =0
        ('Guid', "72s=b''"),
         Unkown uint32 // =0
         Policy uint32 // =0
         Flags uint32 // =0
         MasterKeyLen uint64 // =0
         BackupKeyLen uint64 // =0
         CredHistLen uint64 // =0
         DomainKeyLen uint64 // =0
    }

     func (self TYPE) dump(){
        print("[MASTERKEYFILE]")
        print("Version     : %8x (%d)" % (self.Version"], self["Version))
        print("Guid        : %s" % self.Guid.decode("utf-16le"))
        print("Flags       : %8x (%d)" % (self.Flags"], self["Flags))
        print("Policy      : %8x (%d)" % (self.Policy"], self["Policy))
        print("MasterKeyLen: %.8x (%d)" % (self.MasterKeyLen"], self["MasterKeyLen))
        print("BackupKeyLen: %.8x (%d)" % (self.BackupKeyLen"], self["BackupKeyLen))
        print("CredHistLen : %.8x (%d)" % (self.CredHistLen"], self["CredHistLen))
        print("DomainKeyLen: %.8x (%d)" % (self.DomainKeyLen"], self["DomainKeyLen))
        print()

 type MasterKey struct { // Structure: (
         Version uint32 // =0
         Salt [6]byte // =b""
         MasterKeyIterationCount uint32 // =0
        ('HashAlgo', "<L=0"),
         CryptAlgo uint32 // =0
        ('data', ':'),
    }

     func (self TYPE) __init__(data = nil, alignment = 0 interface{}){
        Structure.__init__(self, data, alignment)
        self.decryptedKey = nil

     func (self TYPE) dump(){
        print("[MASTERKEY]")
        print("Version     : %8x (%d)" % (self.Version"], self["Version))
        print("Salt        : %s" % hexlify(self.Salt))
        print("Rounds      : %8x (%d)" % (self.MasterKeyIterationCount"], self["MasterKeyIterationCount))
        print("HashAlgo    : %.8x (%d) (%s)" % (self.HashAlgo"], self["HashAlgo"], ALGORITHMS(self["HashAlgo).name))
        print("CryptAlgo   : %.8x (%d) (%s)" % (self.CryptAlgo"], self["CryptAlgo"], ALGORITHMS(self["CryptAlgo).name))
        print("data        : %s" % (hexlify(self.data)))
        print()

     func (self TYPE) deriveKey(passphrase, salt, keylen, count, hashFunction interface{}){
        keyMaterial = b""
        i = 1
        while len(keyMaterial) < keylen:
            U = salt + pack("!L", i)
            i += 1
            derived = bytearray(hashFunction(passphrase, U))
            for r in range(count - 1):
                actual = bytearray(hashFunction(passphrase, derived))
                if PY3 {
                    derived = (int.from_bytes(derived, sys.byteorder) ^ int.from_bytes(actual, sys.byteorder)).to_bytes(len(actual), sys.byteorder)
                } else  {
                    derived = bytearray([ chr((a) ^ (b)) for (a,b) in zip(derived, actual) ])
            keyMaterial += derived

        return keyMaterial[:keylen]

     func (self TYPE) decrypt(key interface{}){
        if self.HashAlgo == ALGORITHMS.CALG_HMAC.value {
            hashModule = SHA1
        } else  {
            hashModule = ALGORITHMS_DATA[self.HashAlgo][1]

        prf = lambda p, s: HMAC.new(p, s, hashModule).digest()
        derivedBlob = self.deriveKey(key, self.Salt,
                                    ALGORITHMS_DATA[self.CryptAlgo"]][0] + ALGORITHMS_DATA[self["CryptAlgo][3],
                                    count=self.MasterKeyIterationCount, hashFunction=prf)

        cryptKey = derivedBlob[:ALGORITHMS_DATA[self.CryptAlgo][0]]
        iv = derivedBlob[ALGORITHMS_DATA[self.CryptAlgo"]][0]:][:ALGORITHMS_DATA[self["CryptAlgo][3]]

        cipher = ALGORITHMS_DATA[self.CryptAlgo"]][1].new(cryptKey, mode = ALGORITHMS_DATA[self["CryptAlgo][2], iv = iv)
        cleartext = cipher.decrypt(self.data)

        decryptedKey = cleartext[-64:]
        hmacSalt = cleartext[:16]
        hmac = cleartext[16:][:ALGORITHMS_DATA[self.HashAlgo][0]]

        hmacKey = HMAC.new(key, hmacSalt, hashModule).digest()

        hmacCalculated = HMAC.new(hmacKey, decryptedKey, hashModule ).digest()

        if hmacCalculated[:ALGORITHMS_DATA[self.HashAlgo][0]] == hmac {
            self.decryptedKey = decryptedKey
            return decryptedKey
        } else  {
            return nil

 type CredHist struct { // Structure: (
         Version uint32 // =0
        ('Guid', "16s=b''"),
    }
     func (self TYPE) dump(){
        print("[CREDHIST]")
        print("Version       : %8x (%d)" % (self.Version"], self["Version))
        print("Guid          : %s" % bin_to_string(self.Guid))
        print()

 type DomainKey struct { // Structure: (
         Version uint32 // =0
         SecretLen uint32 // =0
         AccessCheckLen uint32 // =0
        ('Guid', "16s=b"""),
        ('_SecretData', '_-SecretData', 'self.SecretLen'),
        ('SecretData', ':'),
        ('_AccessCheck', '_-AccessCheck', 'self.AccessCheckLen'),
        ('AccessCheck', ':'),
    }
     func (self TYPE) dump(){
        print("[DOMAINKEY]")
        print("Version       : %8x (%d)" % (self.Version"], self["Version))
        print("Guid          : %s" % bin_to_string(self.Guid))
        print("SecretLen     : %8x (%d)" % (self.SecretLen"], self["SecretLen))
        print("AccessCheckLen: %.8x (%d)" % (self.AccessCheckLen"], self["AccessCheckLen))
        print("SecretData    : %s" % (hexlify(self.SecretData)))
        print("AccessCheck   : %s" % (hexlify(self.AccessCheck)))
        print()

 type DPAPI_SYSTEM struct { // Structure: (
         Version uint32 // =0
         MachineKey [0]byte // =b""
         UserKey [0]byte // =b""
    }

     func (self TYPE) dump(){
        print("[DPAPI_SYSTEM]")
        print("Version    : %8x (%d)" % (self.Version"], self["Version))
        print("MachineKey : 0x%s" % hexlify(self.MachineKey).decode("latin-1"))
        print("UserKey    : 0x%s" % hexlify(self.UserKey).decode("latin-1"))
        print()

 type CredentialFile struct { // Structure: (
         Version uint32 // =0
         Size uint32 // =0
         Unknown uint32 // =0
        ('_Data', '_-Data', 'self.Size'),
        ('Data', ':'),
    }
    // func (self TYPE) dump(){
    //    print("[CREDENTIAL FILE]")
    //    print("Version    : %8x (%d)" % (self.Version"], self["Version))
    //    print("MachineKey : %s" % hexlify(self.MachineKey))
    //    print("UserKey    : %s" % hexlify(self.UserKey))
    //    print("CryptAlgo   : %.8x (%d) (%s)" % (self.CryptAlgo"], self["CryptAlgo"], ALGORITHMS(self["CryptAlgo).name))
    //    print()


 type DPAPI_BLOB struct { // Structure: (
         Version uint32 // =0
        ('GuidCredential', "16s=b"""),
         MasterKeyVersion uint32 // =0
        ('GuidMasterKey', "16s=b"""),
         Flags uint32 // =0

         DescriptionLen uint32 // =0
        ('_Description', '_-Description', 'self.DescriptionLen'),
        ('Description', ':'),

         CryptAlgo uint32 // =0
         CryptAlgoLen uint32 // =0

         SaltLen uint32 // =0
        ('_Salt', '_-Salt', 'self.SaltLen'),
        ('Salt', ':'),

         HMacKeyLen uint32 // =0
        ('_HMacKey', '_-HMacKey', 'self.HMacKeyLen'),
        ('HMacKey', ':'),

         HashAlgo uint32 // =0
         HashAlgoLen uint32 // =0

         HMac uint32 // =0
        ('_HMac', '_-HMac', 'self.HMac'),
        ('HMac', ':'),

         DataLen uint32 // =0
        ('_Data', '_-Data', 'self.DataLen'),
        ('Data', ':'),

         SignLen uint32 // =0
        ('_Sign', '_-Sign', 'self.SignLen'),
        ('Sign', ':'),

    }

     func (self TYPE) dump(){
        print("[BLOB]")
        print("Version          : %8x (%d)" % (self.Version"], self["Version))
        print("Guid Credential  : %s" % bin_to_string(self.GuidCredential))
        print("MasterKeyVersion : %8x (%d)" % (self.MasterKeyVersion"], self["MasterKeyVersion))
        print("Guid MasterKey   : %s" % bin_to_string(self.GuidMasterKey))
        print("Flags            : %8x (%s)" % (self.Flags"], getFlags(FLAGS, self["Flags)))
        print("Description      : %s" % (self.Description.decode("utf-16le")))
        print("CryptAlgo        : %.8x (%d) (%s)" % (self.CryptAlgo"], self["CryptAlgo"], ALGORITHMS(self["CryptAlgo).name))
        print("Salt             : %s" % (hexlify(self.Salt)))
        print("HMacKey          : %s" % (hexlify(self.HMacKey)))
        print("HashAlgo         : %.8x (%d) (%s)" % (self.HashAlgo"], self["HashAlgo"], ALGORITHMS(self["HashAlgo).name))
        print("HMac             : %s" % (hexlify(self.HMac)))
        print("Data             : %s" % (hexlify(self.Data)))
        print("Sign             : %s" % (hexlify(self.Sign)))
        print()


     func (self TYPE) deriveKey(sessionKey interface{}){
         func fixparity(deskey interface{}){
            from six import indexbytes, b
            temp = b''
            for i in range(len(deskey)):
                t = (bin(indexbytes(deskey,i))[2:]).rjust(8,'0')
                if t[:7].count("1") %2 == 0 {
                    temp+= b(chr(int(t[:7]+'1',2)))
                } else  {
                    temp+= b(chr(int(t[:7]+'0',2)))
            return temp

        if len(sessionKey) > ALGORITHMS_DATA[self.HashAlgo][4] {
            derivedKey = HMAC.new(sessionKey,  digestmod = ALGORITHMS_DATA[self.HashAlgo][1]).digest()
        } else  {
            derivedKey = sessionKey


        if len(derivedKey) < ALGORITHMS_DATA[self.CryptAlgo][0] {
            // Extend the key
            derivedKey += b'\x00'*ALGORITHMS_DATA[self.HashAlgo][4]
            ipad = bytearray([ i ^ 0x36 for i in bytearray(derivedKey)][:ALGORITHMS_DATA[self.HashAlgo][4]])
            opad = bytearray([ i ^ 0x5c for i in bytearray(derivedKey)][:ALGORITHMS_DATA[self.HashAlgo][4]])
            derivedKey = ALGORITHMS_DATA[self.HashAlgo][1].new(ipad).digest() + \
                ALGORITHMS_DATA[self.HashAlgo][1].new(opad).digest()
            derivedKey = fixparity(derivedKey)

        return derivedKey

     func (self TYPE) decrypt(key, entropy = nil interface{}){
        keyHash = SHA1.new(key).digest()
        sessionKey = HMAC.new(keyHash, self.Salt"], ALGORITHMS_DATA[self["HashAlgo][1])
        if entropy is not nil {
            sessionKey.update(entropy)

        sessionKey = sessionKey.digest()

        // Derive the key
        derivedKey = self.deriveKey(sessionKey)

        cipher = ALGORITHMS_DATA[self.CryptAlgo"]][1].new(derivedKey[:ALGORITHMS_DATA[self["CryptAlgo][0]],
                                mode=ALGORITHMS_DATA[self.CryptAlgo"]][2], iv=b'\x00'*ALGORITHMS_DATA[self["CryptAlgo][3])
        cleartext = unpad(cipher.decrypt(self.Data"]), ALGORITHMS_DATA[self["CryptAlgo][1].block_size)

        // Now check the signature

        // ToDo Fix this, it's just ugly, more testing so we can remove one
        toSign = (self.rawData[20:][:len(self.rawData)-20-len(self.Sign)-4])

        // Calculate the different HMACKeys
        keyHash2 = keyHash + b"\x00"*ALGORITHMS_DATA[self.HashAlgo][1].block_size
        ipad = bytearray([i ^ 0x36 for i in bytearray(keyHash2)][:ALGORITHMS_DATA[self.HashAlgo][1].block_size])
        opad = bytearray([i ^ 0x5c for i in bytearray(keyHash2)][:ALGORITHMS_DATA[self.HashAlgo][1].block_size])
        a = ALGORITHMS_DATA[self.HashAlgo][1].new(ipad)
        a.update(self.HMac)

        hmacCalculated1 = ALGORITHMS_DATA[self.HashAlgo][1].new(opad)
        hmacCalculated1.update(a.digest())

        if entropy is not nil {
            hmacCalculated1.update(entropy)

        hmacCalculated1.update(toSign)

        hmacCalculated3 = HMAC.new(keyHash, self.HMac"], ALGORITHMS_DATA[self["HashAlgo][1])
        if entropy is not nil {
            hmacCalculated3.update(entropy)

        hmacCalculated3.update(toSign)

        if hmacCalculated1.digest() == self.Sign"] or hmacCalculated3.digest() == self["Sign {
            return cleartext
        } else  {
            return nil

 type VAULT_ATTRIBUTE struct { // Structure: (
         Id uint32 // =0
         Unknown1 uint32 // =0
         Unknown2 uint32 // =0
         Unknown3 uint32 // =0
    }

    padding = (
         Pad [6]byte // =b""
    }

    id100 = (
         Unknown5 uint32 // =0
    }

    extended = (
         Size uint32 // =0
         IVPresent byte // =?&IVSize
         IVSize uint32 // =0
        ('_IV', '_-IV', 'self.IVSize"] if self["IVSize is not nil else 0'),
        ('IV', ':'),
        ('_Data','_-Data', 'self.Size"]-self["IVSize"]-5 if self["IVPresent"] else self["Size-1'),
        ('Data',':'),
    }
     func (self TYPE) __init__(data = nil, alignment = 0 interface{}){
        if len(data) > 20 {
            if data[16:][:6] == b'\x00'*6 {
                self.structure += self.padding
            if unpack('<L',data[:4])[0] >= 100 {
                self.structure += self.id100
            if len(data[16:]) >= 9 {
                self.structure += self.extended
        Structure.__init__(self, data, alignment)


     func (self TYPE) dump(){
        print("[ATTRIBUTE %d]" % self.Id)
        if len(self.rawData) > 28 {
            print("Size   : 0x%x" % self.Size)
            if self.IVPresent > 0 {
                print("IVSize : 0x%x" % self.IVSize)
                print("IV     : %s" % hexlify(self.IV))
            print("Data   : %s" % hexlify(self.Data))

 type VAULT_ATTRIBUTE_MAP_ENTRY struct { // Structure: (
         Id uint32 // =0
         Offset uint32 // =0
         Unknown1 uint32 // =0
    }
     func (self TYPE) dump(){
        print("[MAP ENTRY %d @ 0x%.8x]" % (self.Id"], self["Offset))

 type VAULT_VCRD struct { // Structure: (
        ('SchemaGuid', "16s=b"""),
         Unknown0 uint32 // =0
         LastWritten uint64 // =0
         Unknown1 uint32 // =0
         Unknown2 uint32 // =0
         FriendlyNameLen uint32 // =0
        ('FriendlyNameL', '_-FriendlyName', 'self.FriendlyNameLen'),
        ('FriendlyName', ':'),
         AttributesMapsSize uint32 // =0
        ('AttributeL', '_-AttributeMaps', 'self.AttributesMapsSize'),
        ('AttributeMaps', ':'),
        ('Data', ':'),
    }

     func (self TYPE) __init__(data = nil, alignment = 0 interface{}){
        Structure.__init__(self, data, alignment)
        if data is not nil {
            // Process the MAP entries
            self.mapEntries = list()
            data = self.AttributeMaps
            for i in range(self.AttributesMapsSize//len(VAULT_ATTRIBUTE_MAP_ENTRY())):
                entry = VAULT_ATTRIBUTE_MAP_ENTRY(data)
                self.mapEntries.append(entry)
                data = data[len(VAULT_ATTRIBUTE_MAP_ENTRY()):]

            self.attributesLen = list()

            for i in range(len(self.mapEntries)):
                if i > 0 {
                    self.attributesLen.append(self.mapEntries[i]["Offset"]-self.mapEntries[i-1]["Offset"])

            self.attributesLen.append(len(self.rawData) - self.mapEntries[i]["Offset"] )

            self.attributes = list()
            for i, entry in enumerate(self.mapEntries):
                attribute = VAULT_ATTRIBUTE(self.rawData[entry["Offset"]:][:self.attributesLen[i]])
                self.attributes.append(attribute)

            // Do we have remaining data?
            self.Data"] = self.rawData[self.mapEntries[-1]["Offset+len(self.attributes[-1].getData()):]

     func (self TYPE) dump(){
        print("[VCRD]")
        print("SchemaGuid  : %s" % bin_to_string(self.SchemaGuid))
        print("LastWritten : %s" % (datetime.utcfromtimestamp(getUnixTime(self.LastWritten))))
        print("FriendlyName: %s" % (self.FriendlyName.decode("utf-16le")))
        print()
        for i,entry in enumerate(self.mapEntries):
            entry.dump()
            self.attributes[i].dump()
        print()
        print("Remaining   : %s" % (hexlify(self.Data)))
        print()

 type VAULT_VPOL struct { // Structure: (
         Version uint32 // =0
        ('Guid', "16s=b"""),
         DescriptionLen uint32 // =0
        ('_Description', '_-Description', 'self.DescriptionLen'),
        ('Description', ':'),
         Unknown [2]byte // =b""
         Size uint32 // =0
        ('Guid2', "16s=b"""),
        ('Guid3', "16s=b"""),
         KeySize uint32 // =0
        ('_Blob', '_-Blob', 'self.KeySize'),
        ('Blob', ':', DPAPI_BLOB),
    }

     func (self TYPE) dump(){
        print("[VAULT_VPOL]")
        print("Version      : %8x (%d)" % (self.Version"], self["Version))
        print("Guid         : %s" % bin_to_string(self.Guid))
        print("Description  : %s" % (self.Description.decode("utf-16le")))
        print("Size         : 0x%.8x (%d)" % (self.Size"], self["Size))
        print("Guid2        : %s" % bin_to_string(self.Guid2))
        print("Guid3        : %s" % bin_to_string(self.Guid3))
        print("KeySize      : 0x%.8x (%d)" % (self.KeySize"], self["KeySize))
        self.Blob.dump()
        print()

// from bcrypt.h
 type BCRYPT_KEY_DATA_BLOB_HEADER struct { // Structure: (
         dwMagic uint32 // =0
         dwVersion uint32 // =0
         cbKeyData uint32 // =0
        ('_bKey','_-bKey', 'self.cbKeyData'),
        ('bKey',':'),
    }

// from https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEFCON-24-Jkambic-Cunning-With-Cng-Soliciting-Secrets-From-Schannel-WP.pdf
 type BCRYPT_KSSM_DATA_BLOB_HEADER struct { // Structure: (
         cbLength uint32 // =0
         dwKeyMagic uint32 // =0
         dwUnknown2 uint32 // =0
         dwUnknown3 uint32 // =0
         dwKeyBitLen uint32 // =0
         cbKeyLength uint32 // =0
        //('_bKey','_-bKey', 'self.cbKeyData'),
        // AesKey [2]byte // =""
        // dwUnknown4 uint32 // =0
        // KeySchedule [8]byte // =""
        // dwUnknown5 uint32 // =0
        // cbScheduleLen uint32 // =0
        // Unknown6 [6]byte // =""
    }

 type BCRYPT_KEY_WRAP struct { // Structure:
    structureKDBM = (
         Size uint32 // =0
         Version uint32 // =0
         Unknown2 uint32 // =0
        ('_bKeyBlob','_-bKeyBlob', 'self.Size'),
        ('bKeyBlob',':', BCRYPT_KEY_DATA_BLOB_HEADER),
    }
    structureKSSM = (
         Size uint32 // =0
         Version uint32 // =0
         Unknown2 uint32 // =0
        ('_bKeyBlob','_-bKeyBlob', 'self.Size-8'),
        ('bKeyBlob',':'),
    }
     func (self TYPE) __init__(data = nil, alignment = 0 interface{}){
        if len(data) >=16 {
            if data[0:1] == b'\x24' or data[0:1] == b'\x34' {
                self. self.structureKDBM
            } else  {
                self. self.structureKSSM
        Structure.__init__(self, data, alignment)

 type VAULT_VPOL_KEYS struct { // Structure: (
        ('Key1',':', BCRYPT_KEY_WRAP),
        ('Key2',':', BCRYPT_KEY_WRAP),
    }
     func (self TYPE) dump(){
        print("[VAULT_VPOL_KEYS]")
        if self.Key1"]["Size > 0x24 {
            print("Key1:")
            hexdump(self.Key1"]["bKeyBlob)
            print("Key2:")
            hexdump(self.Key2"]["bKeyBlob)
        } else  {
            print('Key1: 0x%s' % hexlify(self.Key1"]["bKeyBlob"]["bKey).decode("latin-1"))
            print('Key2: 0x%s' % hexlify(self.Key2"]["bKeyBlob"]["bKey).decode("latin-1"))
            print()

 type VAULT_INTERNET_EXPLORER struct { // Structure: (
         Version uint32 // =0
         Count uint32 // =0
         Unknown uint32 // =0
         Id1 uint32 // =0
         UsernameLen uint32 // =0
        ('_Username', '_-Username','self.UsernameLen'),
        ('Username', ':'),

         Id2 uint32 // =0
         ResourceLen uint32 // =0
        ('_Resource', '_-Resource', 'self.ResourceLen'),
        ('Resource', ':'),

         Id3 uint32 // =0
         PasswordLen uint32 // =0
        ('_Password', '_-Password', 'self.PasswordLen'),
        ('Password', ':'),
    }
     func (self TYPE) fromString(data interface{}){
        Structure.fromString(self, data)

     func (self TYPE) dump(){
        print("[Internet Explorer]")
        print('Username        : %s' % self.Username.decode("utf-16le"))
        print('Resource        : %s' % self.Resource.decode("utf-16le"))
        print('Password        : %s' % (hexlify(self.Password)))
        print()

 type VAULT_WIN_BIO_KEY struct { // Structure: (
         Version uint32 // =0
         Count uint32 // =0
         Unknown uint32 // =0
         Id1 uint32 // =0
         SidLen uint32 // =0
        ('_Sid', '_-Sid','self.SidLen'),
        ('Sid', ':'),

         Id2 uint32 // =0
         NameLen uint32 // =0
        ('_Name', '_-Name', 'self.NameLen'),
        ('Name', ':'),

         Id3 uint32 // =0
         BioKeyLen uint32 // =0
        ('_BioKey', '_-BioKey', 'self.BioKeyLen'),
        ('BioKey', ':'),
    }
     func (self TYPE) fromString(data interface{}){
        Structure.fromString(self, data)
        if data is not nil {
            bioKey = BCRYPT_KEY_DATA_BLOB_HEADER(unhexlify(self.BioKey.decode("utf-16le")[:-1]))
            self.BioKey = bioKey

     func (self TYPE) dump(){
        print("[WINDOWS BIOMETRIC KEY]")
        print('Sid          : %s' % RPC_SID(b'\x05\x00\x00\x00'+self.Sid).formatCanonical())
        print('Friendly Name: %s' % self.Name.decode("utf-16le"))
        print('Biometric Key: 0x%s' % (hexlify(self.BioKey"]["bKey)).decode("latin-1"))
        print()

 type NGC_LOCAL_ACCOOUNT struct { // Structure: (
         Version uint32 // =0
         UnlockKeySize uint32 // =0
         IVSize uint32 // =0
         CipherTextSize uint32 // =0
         MustBeZeroTest uint32 // =0
        ('_UnlockKey', '_-UnlockKey', 'self.UnlockKeySize'),
        ('UnlockKey', ':'),
        ('_IV', '_-IV', 'self.IVSize'),
        ('IV', ':'),
        ('_CipherText', '_-CipherText', 'self.CipherTextSize'),
        ('CipherText', ':'),
    }
//     func (self TYPE) __init__(data=nil, alignment = 0 interface{}){
//        hexdump(data)
     func (self TYPE) dump(){
        print("[NGC LOCAL ACCOOUNT]")
        print('UnlockKey    : %s' % hexlify(self.UnlockKey))
        print('IV           : %s' % hexlify(self.IV))
        print('CipherText   : %s' % hexlify(self.CipherText))

 type VAULT_NGC_ACCOOUNT struct { // Structure: (
         Version uint32 // =0
         Count uint32 // =0
         Unknown uint32 // =0
         Id1 uint32 // =0
         SidLen uint32 // =0
        ('_Sid', '_-Sid','self.SidLen'),
        ('Sid', ':'),

         Id2 uint32 // =0
         NameLen uint32 // =0
        ('_Name', '_-Name', 'self.NameLen'),
        ('Name', ':'),

         Id3 uint32 // =0
         BlobLen uint32 // =0
        ('Blob', '_-Blob', 'self.BlobLen'),
        ('Blob', ':', NGC_LOCAL_ACCOOUNT),
    }
     func (self TYPE) dump(){
        print("[NGC VAULT]")
        print('Sid          : %s' % RPC_SID(b'\x05\x00\x00\x00'+self.Sid).formatCanonical())
        print('Friendly Name: %s' % self.Name.decode("utf-16le"))
        self.Blob.dump()
        print()

VAULT_KNOWN_SCHEMAS = {
    'WinBio Key': VAULT_WIN_BIO_KEY,
    'NGC Local Accoount Logon Vault Credential': VAULT_NGC_ACCOOUNT,
    'Internet Explorer': VAULT_INTERNET_EXPLORER,
}

 type CREDENTIAL_ATTRIBUTE struct { // Structure:
    // some info here https://docs.microsoft.com/en-us/windows/desktop/api/wincred/ns-wincred-_credential_attributea (
         Flags uint32 // =0

         KeyWordSize uint32 // =0
        ('_KeyWord', '_-KeyWord', 'self.KeyWordSize'),
        ('KeyWord', ':'),

         DataSize uint32 // =0
        ('_Data', '_-Data', 'self.DataSize'),
        ('Data', ':'),
    }

     func (self TYPE) dump(){
        print("KeyWord : %s" % (self.KeyWord.decode("utf-16le")))
        //print("Flags   : %8x (%s)" % (self.Flags"], getFlags(CREDENTIAL_FLAGS, self["Flags)))
        print("Data    : ")
        hexdump(self.Data)

 type CREDENTIAL_BLOB struct { // Structure:
    // some info here https://docs.microsoft.com/en-us/windows/desktop/api/wincred/ns-wincred-_credentiala (
         Flags uint32 // =0
         Size uint32 // =0
         Unknown0 uint32 // =0
         Type uint32 // =0
         Flags2 uint32 // =0
         LastWritten uint64 // =0
         Unknown2 uint32 // =0
         Persist uint32 // =0
         AttrCount uint32 // =0
         Unknown3 uint64 // =0

         TargetSize uint32 // =0
        ('_Target','_-Target','self.TargetSize'),
        ('Target',':'),

         TargetAliasSize uint32 // =0
        ('_TargetAliast', '_-TargetAlias', 'self.TargetAliasSize'),
        ('TargetAlias', ':'),

         DescriptionSize uint32 // =0
        ('_Description', '_-Description', 'self.DescriptionSize'),
        ('Description', ':'),

         UnknownSize uint32 // =0
        ('_Unknown', '_-Unknown', 'self.UnknownSize'),
        ('Unknown', ':'),

         UsernameSize uint32 // =0
        ('_Username', '_-Username', 'self.UsernameSize'),
        ('Username', ':'),

         Unknown3Size uint32 // =0
        ('_Unknown3', '_-Unknown3', 'self.Unknown3Size'),
        ('Unknown3', ':'),

        ('Remaining', ':'),
    }
     func (self TYPE) __init__(data = nil, alignment = 0 interface{}){
        Structure.__init__(self, data, alignment)
        self.attributes = 0
        if data is not nil {
            // Unpack the attributes
            remaining = self.Remaining
            self.attributes = list()
            for i in range(self.AttrCount):
                attr = CREDENTIAL_ATTRIBUTE(remaining)
                self.attributes.append(attr)
                remaining = remaining[len(attr):]

     func (self TYPE) dump(){
        print("[CREDENTIAL]")
        print("LastWritten : %s" % (datetime.utcfromtimestamp(getUnixTime(self.LastWritten))))
        print("Flags       : 0x%.8x (%s)" % (self.Flags"], getFlags(CREDENTIAL_FLAGS, self["Flags)))
        print("Persist     : 0x%.8x (%s)" % (self.Persist"], CREDENTIAL_PERSIST(self["Persist).name))
        print("Type        : 0x%.8x (%s)" % (self.Type"], CREDENTIAL_PERSIST(self["Type).name))
        print("Target      : %s" % (self.Target.decode("utf-16le")))
        print("Description : %s" % (self.Description.decode("utf-16le")))
        print("Unknown     : %s" % (self.Unknown.decode("utf-16le")))
        print("Username    : %s" % (self.Username.decode("utf-16le")))
        try:
            print("Unknown     : %s" % (self.Unknown3.decode("utf-16le")))
        except UnicodeDecodeError:
            print("Unknown     : %s" % (self.Unknown3.decode("latin-1")))

        print()
        for entry in self.attributes:
            entry.dump()

ALG_ID = "<L=0"

 type P_BACKUP_KEY struct { // Structure: (
         Version uint32 // =0
        ('Data', ':'),
    }

 type PREFERRED_BACKUP_KEY struct { // Structure: (
         Version uint32 // =0
         KeyLength uint32 // =0
         CertificateLength uint32 // =0
        ('Data', ':'),
    }

 type PVK_FILE_HDR struct { // Structure: (
         dwMagic uint32 // =0
         dwVersion uint32 // =0
         dwKeySpec uint32 // =0
         dwEncryptType uint32 // =0
         cbEncryptData uint32 // =0
         cbPvk uint32 // =0
    }

 type PUBLICKEYSTRUC struct { // Structure: (
         bType byte // =0
         bVersion byte // =0
         reserved uint16 // =0
        ('aiKeyAlg', ALG_ID),
    }

 type RSAPUBKEY struct { // Structure: (
         magic uint32 // =0
         bitlen uint32 // =0
         pubexp uint32 // =0
    }

 type PUBLIC_KEY_BLOB struct { // Structure: (
        ('publickeystruc', ':', PUBLICKEYSTRUC),
        ('rsapubkey', ':', RSAPUBKEY),
        ('_modulus', '_-modulus', 'self.rsapubkey"]["bitlen // 8'),
    }

 type PRIVATE_KEY_BLOB struct { // Structure: (
        ('publickeystruc', ':', PUBLICKEYSTRUC),
        ('rsapubkey', ':', RSAPUBKEY),
        ('_modulus', '_-modulus', 'self.rsapubkey"]["bitlen // 8'),
        ('modulus', ':'),
        ('_prime1', '_-prime1', 'self.rsapubkey"]["bitlen // 16'),
        ('prime1', ':'),
        ('_prime2', '_-prime2', 'self.rsapubkey"]["bitlen // 16'),
        ('prime2', ':'),
        ('_exponent1', '_-exponent1', 'self.rsapubkey"]["bitlen // 16'),
        ('exponent1', ':'),
        ('_exponent2', '_-exponent2', 'self.rsapubkey"]["bitlen // 16'),
        ('exponent2', ':'),
        ('_coefficient', '_-coefficient', 'self.rsapubkey"]["bitlen // 16'),
        ('coefficient', ':'),
        ('_privateExponent', '_-privateExponent', 'self.rsapubkey"]["bitlen // 8'),
        ('privateExponent', ':'),
    }

 type SIMPLE_KEY_BLOB struct { // Structure: (
        ('publickeystruc', ':', PUBLICKEYSTRUC),
        ('algid', ALG_ID),
        ('encryptedkey', ':'),
    }

 type DPAPI_DOMAIN_RSA_MASTER_KEY struct { // Structure: (
         cbMasterKey uint32 // =0
         cbSuppKey uint32 // =0
        ('buffer', ':'),
    }

 func privatekeyblob_to_pkcs1(key interface{}){
    '''
    parse private key into pkcs//1 format
    :param key:
    :return:
    '''
    modulus = bytes_to_long(key["modulus"][::-1]) // n
    prime1 = bytes_to_long(key["prime1"][::-1]) // p
    prime2 = bytes_to_long(key["prime2"][::-1]) // q
    exp1 = bytes_to_long(key["exponent1"][::-1])
    exp2 = bytes_to_long(key["exponent2"][::-1])
    coefficient = bytes_to_long(key["coefficient"][::-1])
    privateExp = bytes_to_long(key["privateExponent"][::-1]) // d
    if PY3 {
        long = int
    pubExp = long(key["rsapubkey"]["pubexp"]) // e
    // RSA.Integer(prime2).inverse(prime1) # u

    r = RSA.construct((modulus, pubExp, privateExp, prime1, prime2))
    return r
