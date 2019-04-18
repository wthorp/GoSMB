// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Author: Alberto Solino (@agsolino)
//
// Description:
//   Mimikatz Interface implementation, based on @gentilkiwi IDL
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
import binascii
import random

from impacket import nt_errors
from impacket.dcerpc.v5.dtypes import DWORD, ULONG
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRPOINTER, NDRUniConformantArray
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.uuid import uuidtup_to_bin
from impacket.structure import Structure

MSRPC_UUID_MIMIKATZ   = uuidtup_to_bin(('17FC11E9-C258-4B8D-8D07-2F4125156244', '1.0'))

 type DCERPCSessionError struct { // DCERPCException:
     func (self TYPE) __init__(error_string=nil, error_code=nil, packet=nil interface{}){
        DCERPCException.__init__(self, error_string, error_code, packet)

     func __str__( self  interface{}){
        key = self.error_code
        if key in nt_errors.ERROR_MESSAGES {
            error_msg_short = nt_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = nt_errors.ERROR_MESSAGES[key][1] 
            return 'Mimikatz SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        } else  {
            return 'Mimikatz SessionError: unknown error code: 0x%x' % self.error_code

//###############################################################################
// CONSTANTS
//###############################################################################
CALG_DH_EPHEM = 0x0000aa02
TPUBLICKEYBLOB = 0x6
CUR_BLOB_VERSION = 0x2
ALG_ID = DWORD
CALG_RC4 = 0x6801

//###############################################################################
// STRUCTURES
//###############################################################################
 type PUBLICKEYSTRUC struct { // Structure: (
        ('bType','B=0'),
        ('bVersion','B=0'),
         reserved uint16 // =0
         aiKeyAlg uint32 // =0
    }
     func (self TYPE) __init__(data = nil, alignment = 0 interface{}){
        Structure.__init__(self,data,alignment)
        self.bType = TPUBLICKEYBLOB
        self.bVersion = CUR_BLOB_VERSION
        self.aiKeyAlg = CALG_DH_EPHEM

 type DHPUBKEY struct { // Structure: (
         magic uint32 // =0
         bitlen uint32 // =0
    }
     func (self TYPE) __init__(data = nil, alignment = 0 interface{}){
        Structure.__init__(self,data,alignment)
        self.magic = 0x31484400
        self.bitlen = 1024

 type PUBLICKEYBLOB struct { // Structure: (
        ('publickeystruc',':', PUBLICKEYSTRUC),
        ('dhpubkey',':', DHPUBKEY),
        ('yLen', '_-y','128'),
        ('y',':'),
    }
     func (self TYPE) __init__(data = nil, alignment = 0 interface{}){
        Structure.__init__(self,data,alignment)
        self.publickeystruc = PUBLICKEYSTRUC().getData()
        self.dhpubkey = DHPUBKEY().getData()

 type MIMI_HANDLE struct { // NDRSTRUCT:  (
         Data [0]byte // =""
    }
     func (self TYPE) getAlignment(){
        if self._isNDR64 is true {
            return 8
        } else  {
            return 4

 type BYTE_ARRAY struct { // NDRUniConformantArray:
    item = "c"

 type PBYTE_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data',BYTE_ARRAY),
    }

 type MIMI_PUBLICKEY struct { // NDRSTRUCT:  (
        ('sessionType',ALG_ID),
        ('cbPublicKey',DWORD),
        ('pbPublicKey',PBYTE_ARRAY),
    }

 type PMIMI_PUBLICKEY struct { // NDRPOINTER:
    referent = (
        ('Data',MIMI_PUBLICKEY),
    }

//###############################################################################
// RPC CALLS
//###############################################################################
 type MimiBind struct { // NDRCALL:
    opnum = 0 (
       ('clientPublicKey',MIMI_PUBLICKEY),
    }

 type MimiBindResponse struct { // NDRCALL: (
       ('serverPublicKey',MIMI_PUBLICKEY),
       ('phMimi',MIMI_HANDLE),
       ('ErrorCode',ULONG),
    }

 type MimiUnbind struct { // NDRCALL:
    opnum = 1 (
       ('phMimi',MIMI_HANDLE),
    }

 type MimiUnbindResponse struct { // NDRCALL: (
       ('phMimi',MIMI_HANDLE),
       ('ErrorCode',ULONG),
    }

 type MimiCommand struct { // NDRCALL:
    opnum = 2 (
        ('phMimi',MIMI_HANDLE),
        ('szEncCommand',DWORD),
        ('encCommand',PBYTE_ARRAY),
    }

 type MimiCommandResponse struct { // NDRCALL: (
       ('szEncResult',DWORD),
       ('encResult',PBYTE_ARRAY),
       ('ErrorCode',ULONG),
    }


//###############################################################################
// OPNUMs and their corresponding structures
//###############################################################################
OPNUMS = {
 0 : (MimiBind, MimiBindResponse),
 1 : (MimiUnbind, MimiUnbindResponse),
 2 : (MimiCommand, MimiCommandResponse),
}

//###############################################################################
// HELPER FUNCTIONS
//###############################################################################

 type MimiDiffeH: struct {
     func (self TYPE) __init__(){
        self.G = 2
        self.P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
        self.privateKey = random.getrandbits(1024)
        //self.privateKey = int('A'*128, base=16)

     func (self TYPE) genPublicKey(){
        self.publicKey = pow(self.G, self.privateKey, self.P)
        tmp = hex(self.publicKey)[2:].rstrip("L")
        if len(tmp) & 1 {
            tmp = "0" + tmp
        return binascii.unhexlify(tmp)

     func (self TYPE) getSharedSecret(serverPublicKey interface{}){
        pubKey = int(binascii.hexlify(serverPublicKey), base=16)
        self.sharedSecret = pow(pubKey, self.privateKey, self.P)
        tmp = hex(self.sharedSecret)[2:].rstrip("L")
        if len(tmp) & 1 {
            tmp = "0" + tmp
        return binascii.unhexlify(tmp)


 func hMimiBind(dce, clientPublicKey interface{}){
    request = MimiBind()
    request["clientPublicKey"] = clientPublicKey
    return dce.request(request)

 func hMimiCommand(dce, phMimi, encCommand interface{}){
    request = MimiCommand()
    request["phMimi"] = phMimi
    request["szEncCommand"] = len(encCommand)
    request["encCommand"] = list(encCommand)
    return dce.request(request)

if __name__ == '__main__' {
    from impacket.winregistry import hexdump
    alice = MimiDiffeH()
    alice.G = 5
    alice.P = 23
    alice.privateKey = 6

    bob = MimiDiffeH()
    bob.G = 5
    bob.P = 23
    bob.privateKey = 15

    print("Alice pubKey")
    hexdump(alice.genPublicKey())
    print("Bob pubKey")
    hexdump(bob.genPublicKey())

    print("Secret")
    hexdump(alice.getSharedSecret(bob.genPublicKey()))
    hexdump(bob.getSharedSecret(alice.genPublicKey()))
