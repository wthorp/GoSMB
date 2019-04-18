// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Author: Alberto Solino (@agsolino)
//
// Description:
//   [C706] Remote Management Interface implementation
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
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRPOINTER, NDRUniConformantArray, NDRUniConformantVaryingArray
from impacket.dcerpc.v5.epm import PRPC_IF_ID
from impacket.dcerpc.v5.dtypes import ULONG, DWORD_ARRAY, ULONGLONG
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.uuid import uuidtup_to_bin
from impacket import nt_errors

MSRPC_UUID_MGMT  = uuidtup_to_bin(('afa8bd80-7d8a-11c9-bef4-08002b102989','1.0'))

 type DCERPCSessionError struct { // DCERPCException:
     func (self TYPE) __init__(error_string=nil, error_code=nil, packet=nil interface{}){
        DCERPCException.__init__(self, error_string, error_code, packet)

     func __str__( self  interface{}){
        key = self.error_code
        if key in nt_errors.ERROR_MESSAGES {
            error_msg_short = nt_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = nt_errors.ERROR_MESSAGES[key][1] 
            return 'MGMT SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        } else  {
            return 'MGMT SessionError: unknown error code: 0x%x' % self.error_code

//###############################################################################
// CONSTANTS
//###############################################################################

 type rpc_if_id_p_t_array struct { // NDRUniConformantArray:
    item = PRPC_IF_ID

 type rpc_if_id_vector_t struct { // NDRSTRUCT: (
        ('count',ULONG),
        ('if_id',rpc_if_id_p_t_array),
    }
    structure64 = (
        ('count',ULONGLONG),
        ('if_id',rpc_if_id_p_t_array),
    }

 type rpc_if_id_vector_p_t struct { // NDRPOINTER:
    referent = (
        ('Data', rpc_if_id_vector_t),
    }

error_status = ULONG
//###############################################################################
// STRUCTURES
//###############################################################################

//###############################################################################
// RPC CALLS
//###############################################################################
 type inq_if_ids struct { // NDRCALL:
    opnum = 0 (
    }

 type inq_if_idsResponse struct { // NDRCALL: (
       ('if_id_vector', rpc_if_id_vector_p_t),
       ('status', error_status),
    }

 type inq_stats struct { // NDRCALL:
    opnum = 1 (
       ('count', ULONG),
    }

 type inq_statsResponse struct { // NDRCALL: (
       ('count', ULONG),
       ('statistics', DWORD_ARRAY),
       ('status', error_status),
    }

 type is_server_listening struct { // NDRCALL:
    opnum = 2 (
    }

 type is_server_listeningResponse struct { // NDRCALL: (
       ('status', error_status),
    }

 type stop_server_listening struct { // NDRCALL:
    opnum = 3 (
    }

 type stop_server_listeningResponse struct { // NDRCALL: (
       ('status', error_status),
    }

 type inq_princ_name struct { // NDRCALL:
    opnum = 4 (
       ('authn_proto', ULONG),
       ('princ_name_size', ULONG),
    }

 type inq_princ_nameResponse struct { // NDRCALL: (
       ('princ_name', NDRUniConformantVaryingArray),
       ('status', error_status),
    }


//###############################################################################
// OPNUMs and their corresponding structures
//###############################################################################
OPNUMS = {
 0 : (inq_if_ids, inq_if_idsResponse),
 1 : (inq_stats, inq_statsResponse),
 2 : (is_server_listening, is_server_listeningResponse),
 3 : (stop_server_listening, stop_server_listeningResponse),
 4 : (inq_princ_name, inq_princ_nameResponse),
}

//###############################################################################
// HELPER FUNCTIONS
//###############################################################################
 func hinq_if_ids(dce interface{}){
    request = inq_if_ids()
    return dce.request(request)

 func hinq_stats(dce, count = 4 interface{}){
    request = inq_stats()
    request["count"] = count
    return dce.request(request)

 func his_server_listening(dce interface{}){
    request = is_server_listening()
    return dce.request(request, checkError=false)

 func hstop_server_listening(dce interface{}){
    request = stop_server_listening()
    return dce.request(request)

 func hinq_princ_name(dce, authn_proto=0, princ_name_size=1 interface{}){
    request = inq_princ_name()
    request["authn_proto"] = authn_proto
    request["princ_name_size"] = princ_name_size
    return dce.request(request, checkError=false)
