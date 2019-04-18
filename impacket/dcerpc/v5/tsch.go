// SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
//
// This software is provided under under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Author: Alberto Solino (@agsolino)
//
// Description:
//   [MS-TSCH] ITaskSchedulerService Interface implementation
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
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRPOINTER, NDRUniConformantArray
from impacket.dcerpc.v5.dtypes import DWORD, LPWSTR, ULONG, WSTR, NULL, GUID, PSYSTEMTIME, SYSTEMTIME
from impacket.structure import Structure
from impacket import hresult_errors, system_errors
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.rpcrt import DCERPCException

MSRPC_UUID_TSCHS  = uuidtup_to_bin(('86D35949-83C9-4044-B424-DB363231FD0C','1.0'))

 type DCERPCSessionError struct { // DCERPCException:
     func (self TYPE) __init__(error_string=nil, error_code=nil, packet=nil interface{}){
        DCERPCException.__init__(self, error_string, error_code, packet)

     func __str__( self  interface{}){
        key = self.error_code
        if key in hresult_errors.ERROR_MESSAGES {
            error_msg_short = hresult_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[key][1]
            return 'TSCH SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        elif key & 0xffff in system_errors.ERROR_MESSAGES {
            error_msg_short = system_errors.ERROR_MESSAGES[key & 0xffff][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key & 0xffff][1]
            return 'TSCH SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        } else  {
            return 'TSCH SessionError: unknown error code: 0x%x' % self.error_code

//###############################################################################
// CONSTANTS
//###############################################################################
// 2.3.1 Constant Values
CNLEN = 15
DNLEN = CNLEN
UNLEN = 256
MAX_BUFFER_SIZE = (DNLEN+UNLEN+1+1)

// 2.3.7 Flags
TASK_FLAG_INTERACTIVE                  = 0x1
TASK_FLAG_DELETE_WHEN_DONE             = 0x2
TASK_FLAG_DISABLED                     = 0x4
TASK_FLAG_START_ONLY_IF_IDLE           = 0x10
TASK_FLAG_KILL_ON_IDLE_END             = 0x20
TASK_FLAG_DONT_START_IF_ON_BATTERIES   = 0x40
TASK_FLAG_KILL_IF_GOING_ON_BATTERIES   = 0x80
TASK_FLAG_RUN_ONLY_IF_DOCKED           = 0x100
TASK_FLAG_HIDDEN                       = 0x200
TASK_FLAG_RUN_IF_CONNECTED_TO_INTERNET = 0x400
TASK_FLAG_RESTART_ON_IDLE_RESUME       = 0x800
TASK_FLAG_SYSTEM_REQUIRED              = 0x1000
TASK_FLAG_RUN_ONLY_IF_LOGGED_ON        = 0x2000

// 2.3.9 TASK_LOGON_TYPE
TASK_LOGON_NONE                          = 0
TASK_LOGON_PASSWORD                      = 1
TASK_LOGON_S4U                           = 2
TASK_LOGON_INTERACTIVE_TOKEN             = 3
TASK_LOGON_GROUP                         = 4
TASK_LOGON_SERVICE_ACCOUNT               = 5
TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD = 6

// 2.3.13 TASK_STATE
TASK_STATE_UNKNOWN  = 0
TASK_STATE_DISABLED = 1
TASK_STATE_QUEUED   = 2
TASK_STATE_READY    = 3
TASK_STATE_RUNNING  = 4

// 2.4.1 FIXDLEN_DATA
SCHED_S_TASK_READY         = 0x00041300
SCHED_S_TASK_RUNNING       = 0x00041301
SCHED_S_TASK_NOT_SCHEDULED = 0x00041301

// 2.4.2.11 Triggers
TASK_TRIGGER_FLAG_HAS_END_DATE         = 0
TASK_TRIGGER_FLAG_KILL_AT_DURATION_END = 0
TASK_TRIGGER_FLAG_DISABLED             = 0

// ToDo: Change this to enums
ONCE                 = 0
DAILY                = 1
WEEKLY               = 2
MONTHLYDATE          = 3
MONTHLYDOW           = 4
EVENT_ON_IDLE        = 5
EVENT_AT_SYSTEMSTART = 6
EVENT_AT_LOGON       = 7

SUNDAY    = 0
MONDAY    = 1
TUESDAY   = 2
WEDNESDAY = 3
THURSDAY  = 4
FRIDAY    = 5
SATURDAY  = 6

JANUARY   = 1
FEBRUARY  = 2
MARCH     = 3
APRIL     = 4
MAY       = 5
JUNE      = 6
JULY      = 7
AUGUST    = 8
SEPTEMBER = 9
OCTOBER   = 10
NOVEMBER  = 11
DECEMBER  = 12

// 2.4.2.11.8 MONTHLYDOW Trigger
FIRST_WEEK  = 1
SECOND_WEEK = 2
THIRD_WEEK  = 3
FOURTH_WEEK = 4
LAST_WEEK   = 5

// 2.3.12 TASK_NAMES
TASK_NAMES = LPWSTR

// 3.2.5.4.2 SchRpcRegisterTask (Opnum 1)
TASK_VALIDATE_ONLY                = 1<<(31-31)
TASK_CREATE                       = 1<<(31-30)
TASK_UPDATE                       = 1<<(31-29)
TASK_DISABLE                      = 1<<(31-28)
TASK_DON_ADD_PRINCIPAL_ACE        = 1<<(31-27)
TASK_IGNORE_REGISTRATION_TRIGGERS = 1<<(31-26)

// 3.2.5.4.7 SchRpcEnumFolders (Opnum 6)
TASK_ENUM_HIDDEN = 1

// 3.2.5.4.13 SchRpcRun (Opnum 12)
TASK_RUN_AS_SELF            = 1<<(31-31)
TASK_RUN_IGNORE_CONSTRAINTS = 1<<(31-30)
TASK_RUN_USE_SESSION_ID     = 1<<(31-29)
TASK_RUN_USER_SID           = 1<<(31-28)

// 3.2.5.4.18 SchRpcGetTaskInfo (Opnum 17)
SCH_FLAG_STATE            = 1<<(31-3)

//###############################################################################
// STRUCTURES
//###############################################################################
// 2.3.12 TASK_NAMES
 type TASK_NAMES_ARRAY struct { // NDRUniConformantArray:
    item = TASK_NAMES

 type PTASK_NAMES_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data',TASK_NAMES_ARRAY),
    }

 type WSTR_ARRAY struct { // NDRUniConformantArray:
    item = WSTR

 type PWSTR_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data',WSTR_ARRAY),
    }

 type GUID_ARRAY struct { // NDRUniConformantArray:
    item = GUID

 type PGUID_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data',TASK_NAMES_ARRAY),
    }

// 3.2.5.4.13 SchRpcRun (Opnum 12)
 type SYSTEMTIME_ARRAY struct { // NDRUniConformantArray:
    item = SYSTEMTIME

 type PSYSTEMTIME_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data',SYSTEMTIME_ARRAY),
    }

// 2.3.8 TASK_USER_CRED
 type TASK_USER_CRED struct { // NDRSTRUCT:  (
        ('userId',LPWSTR),
        ('password',LPWSTR),
        ('flags',DWORD),
    }

 type TASK_USER_CRED_ARRAY struct { // NDRUniConformantArray:
    item = TASK_USER_CRED

 type LPTASK_USER_CRED_ARRAY struct { // NDRPOINTER:
    referent = (
        ('Data',TASK_USER_CRED_ARRAY),
    }

// 2.3.10 TASK_XML_ERROR_INFO
 type TASK_XML_ERROR_INFO struct { // NDRSTRUCT:  (
        ('line',DWORD),
        ('column',DWORD),
        ('node',LPWSTR),
        ('value',LPWSTR),
    }

 type PTASK_XML_ERROR_INFO struct { // NDRPOINTER:
    referent = (
        ('Data',TASK_XML_ERROR_INFO),
    }

// 2.4.1 FIXDLEN_DATA
 type FIXDLEN_DATA struct { // Structure: (
         Product Version uint16 // =0
         File Version uint16 // =0
         Job uuid [6]byte // ="
         App Name Len Offset uint16 // =0
         Trigger Offset uint16 // =0
         Error Retry Count uint16 // =0
         Error Retry Interval uint16 // =0
         Idle Deadline uint16 // =0
         Idle Wait uint16 // =0
         Priority uint32 // =0
         Maximum Run Time uint32 // =0
         Exit Code uint32 // =0
         Status uint32 // =0
         Flags uint32 // =0
    }

// 2.4.2.11 Triggers
 type TRIGGERS struct { // Structure: (
         Trigger Size uint16 // =0
         Reserved1 uint16 // =0
         Begin Year uint16 // =0
         Begin Month uint16 // =0
         Begin Day uint16 // =0
         End Year uint16 // =0
         End Month uint16 // =0
         End Day uint16 // =0
         Start Hour uint16 // =0
         Start Minute uint16 // =0
         Minutes Duration uint32 // =0
         Minutes Interval uint32 // =0
         Flags uint32 // =0
         Trigger Type uint32 // =0
         TriggerSpecific0 uint16 // =0
         TriggerSpecific1 uint16 // =0
         TriggerSpecific2 uint16 // =0
         Padding uint16 // =0
         Reserved2 uint16 // =0
         Reserved3 uint16 // =0
    }

// 2.4.2.11.6 WEEKLY Trigger
 type WEEKLY struct { // Structure: (
         Trigger Type uint32 // =0
         Weeks Interval uint16 // =0
         DaysOfTheWeek uint16 // =0
         Unused uint16 // =0
         Padding uint16 // =0
    }

// 2.4.2.11.7 MONTHLYDATE Trigger
 type MONTHLYDATE struct { // Structure: (
         Trigger Type uint32 // =0
         Days uint32 // =0
         Months uint16 // =0
         Padding uint16 // =0
    }

// 2.4.2.11.8 MONTHLYDOW Trigger
 type MONTHLYDOW struct { // Structure: (
         Trigger Type uint32 // =0
         WhichWeek uint16 // =0
         DaysOfTheWeek uint16 // =0
         Months uint16 // =0
         Padding uint16 // =0
         Reserved2 uint16 // =0
         Reserved3 uint16 // =0
    }

// 2.4.2.12 Job Signature
 type JOB_SIGNATURE struct { // Structure: (
         SignatureVersion uint16 // H0
         MinClientVersion uint16 // =0
         Signature [4]byte // ="
    }

//###############################################################################
// RPC CALLS
//###############################################################################
// 3.2.5.4.1 SchRpcHighestVersion (Opnum 0)
 type SchRpcHighestVersion struct { // NDRCALL:
    opnum = 0 (
    }

 type SchRpcHighestVersionResponse struct { // NDRCALL: (
        ('pVersion', DWORD),
        ('ErrorCode',ULONG),
    }

// 3.2.5.4.2 SchRpcRegisterTask (Opnum 1)
 type SchRpcRegisterTask struct { // NDRCALL:
    opnum = 1 (
        ('path', LPWSTR),
        ('xml', WSTR),
        ('flags', DWORD),
        ('sddl', LPWSTR),
        ('logonType', DWORD),
        ('cCreds', DWORD),
        ('pCreds', LPTASK_USER_CRED_ARRAY),
    }

 type SchRpcRegisterTaskResponse struct { // NDRCALL: (
        ('pActualPath', LPWSTR),
        ('pErrorInfo', PTASK_XML_ERROR_INFO),
        ('ErrorCode',ULONG),
    }

// 3.2.5.4.3 SchRpcRetrieveTask (Opnum 2)
 type SchRpcRetrieveTask struct { // NDRCALL:
    opnum = 2 (
        ('path', WSTR),
        ('lpcwszLanguagesBuffer', WSTR),
        ('pulNumLanguages', DWORD),
    }

 type SchRpcRetrieveTaskResponse struct { // NDRCALL: (
        ('pXml', LPWSTR),
        ('ErrorCode',ULONG),
    }

// 3.2.5.4.4 SchRpcCreateFolder (Opnum 3)
 type SchRpcCreateFolder struct { // NDRCALL:
    opnum = 3 (
        ('path', WSTR),
        ('sddl', LPWSTR),
        ('flags', DWORD),
    }

 type SchRpcCreateFolderResponse struct { // NDRCALL: (
        ('ErrorCode',ULONG),
    }

// 3.2.5.4.7 SchRpcEnumFolders (Opnum 6)
 type SchRpcEnumFolders struct { // NDRCALL:
    opnum = 6 (
        ('path', WSTR),
        ('flags', DWORD),
        ('startIndex', DWORD),
        ('cRequested', DWORD),
    }

 type SchRpcEnumFoldersResponse struct { // NDRCALL: (
        ('startIndex', DWORD),
        ('pcNames', DWORD),
        ('pNames', PTASK_NAMES_ARRAY),
        ('ErrorCode',ULONG),
    }

// 3.2.5.4.8 SchRpcEnumTasks (Opnum 7)
 type SchRpcEnumTasks struct { // NDRCALL:
    opnum = 7 (
        ('path', WSTR),
        ('flags', DWORD),
        ('startIndex', DWORD),
        ('cRequested', DWORD),
    }

 type SchRpcEnumTasksResponse struct { // NDRCALL: (
        ('startIndex', DWORD),
        ('pcNames', DWORD),
        ('pNames', PTASK_NAMES_ARRAY),
        ('ErrorCode',ULONG),
    }

// 3.2.5.4.9 SchRpcEnumInstances (Opnum 8)
 type SchRpcEnumInstances struct { // NDRCALL:
    opnum = 8 (
        ('path', LPWSTR),
        ('flags', DWORD),
    }

 type SchRpcEnumInstancesResponse struct { // NDRCALL: (
        ('pcGuids', DWORD),
        ('pGuids', PGUID_ARRAY),
        ('ErrorCode',ULONG),
    }

// 3.2.5.4.10 SchRpcGetInstanceInfo (Opnum 9)
 type SchRpcGetInstanceInfo struct { // NDRCALL:
    opnum = 9 (
        ('guid', GUID),
    }

 type SchRpcGetInstanceInfoResponse struct { // NDRCALL: (
        ('pPath', LPWSTR),
        ('pState', DWORD),
        ('pCurrentAction', LPWSTR),
        ('pInfo', LPWSTR),
        ('pcGroupInstances', DWORD),
        ('pGroupInstances', PGUID_ARRAY),
        ('pEnginePID', DWORD),
        ('ErrorCode',ULONG),
    }

// 3.2.5.4.11 SchRpcStopInstance (Opnum 10)
 type SchRpcStopInstance struct { // NDRCALL:
    opnum = 10 (
        ('guid', GUID),
        ('flags', DWORD),
    }

 type SchRpcStopInstanceResponse struct { // NDRCALL: (
        ('ErrorCode',ULONG),
    }

// 3.2.5.4.12 SchRpcStop (Opnum 11)
 type SchRpcStop struct { // NDRCALL:
    opnum = 11 (
        ('path', LPWSTR),
        ('flags', DWORD),
    }

 type SchRpcStopResponse struct { // NDRCALL: (
        ('ErrorCode',ULONG),
    }

// 3.2.5.4.13 SchRpcRun (Opnum 12)
 type SchRpcRun struct { // NDRCALL:
    opnum = 12 (
        ('path', WSTR),
        ('cArgs', DWORD),
        ('pArgs', PWSTR_ARRAY),
        ('flags', DWORD),
        ('sessionId', DWORD),
        ('user', LPWSTR),
    }

 type SchRpcRunResponse struct { // NDRCALL: (
        ('pGuid', GUID),
        ('ErrorCode',ULONG),
    }

// 3.2.5.4.14 SchRpcDelete (Opnum 13)
 type SchRpcDelete struct { // NDRCALL:
    opnum = 13 (
        ('path', WSTR),
        ('flags', DWORD),
    }

 type SchRpcDeleteResponse struct { // NDRCALL: (
        ('ErrorCode',ULONG),
    }

// 3.2.5.4.15 SchRpcRename (Opnum 14)
 type SchRpcRename struct { // NDRCALL:
    opnum = 14 (
        ('path', WSTR),
        ('newName', WSTR),
        ('flags', DWORD),
    }

 type SchRpcRenameResponse struct { // NDRCALL: (
        ('ErrorCode',ULONG),
    }

// 3.2.5.4.16 SchRpcScheduledRuntimes (Opnum 15)
 type SchRpcScheduledRuntimes struct { // NDRCALL:
    opnum = 15 (
        ('path', WSTR),
        ('start', PSYSTEMTIME),
        ('end', PSYSTEMTIME),
        ('flags', DWORD),
        ('cRequested', DWORD),
    }

 type SchRpcScheduledRuntimesResponse struct { // NDRCALL: (
        ('pcRuntimes',DWORD),
        ('pRuntimes',PSYSTEMTIME_ARRAY),
        ('ErrorCode',ULONG),
    }

// 3.2.5.4.17 SchRpcGetLastRunInfo (Opnum 16)
 type SchRpcGetLastRunInfo struct { // NDRCALL:
    opnum = 16 (
        ('path', WSTR),
    }

 type SchRpcGetLastRunInfoResponse struct { // NDRCALL: (
        ('pLastRuntime',SYSTEMTIME),
        ('pLastReturnCode',DWORD),
        ('ErrorCode',ULONG),
    }

// 3.2.5.4.18 SchRpcGetTaskInfo (Opnum 17)
 type SchRpcGetTaskInfo struct { // NDRCALL:
    opnum = 17 (
        ('path', WSTR),
        ('flags', DWORD),
    }

 type SchRpcGetTaskInfoResponse struct { // NDRCALL: (
        ('pEnabled',DWORD),
        ('pState',DWORD),
        ('ErrorCode',ULONG),
    }

// 3.2.5.4.19 SchRpcGetNumberOfMissedRuns (Opnum 18)
 type SchRpcGetNumberOfMissedRuns struct { // NDRCALL:
    opnum = 18 (
        ('path', WSTR),
    }

 type SchRpcGetNumberOfMissedRunsResponse struct { // NDRCALL: (
        ('pNumberOfMissedRuns',DWORD),
        ('ErrorCode',ULONG),
    }

// 3.2.5.4.20 SchRpcEnableTask (Opnum 19)
 type SchRpcEnableTask struct { // NDRCALL:
    opnum = 19 (
        ('path', WSTR),
        ('enabled', DWORD),
    }

 type SchRpcEnableTaskResponse struct { // NDRCALL: (
        ('ErrorCode',ULONG),
    }

//###############################################################################
// OPNUMs and their corresponding structures
//###############################################################################
OPNUMS = {
 0 : (SchRpcHighestVersion,SchRpcHighestVersionResponse ),
 1 : (SchRpcRegisterTask,SchRpcRegisterTaskResponse ),
 2 : (SchRpcRetrieveTask,SchRpcRetrieveTaskResponse ),
 3 : (SchRpcCreateFolder,SchRpcCreateFolderResponse ),
 6 : (SchRpcEnumFolders,SchRpcEnumFoldersResponse ),
 7 : (SchRpcEnumTasks,SchRpcEnumTasksResponse ),
 8 : (SchRpcEnumInstances,SchRpcEnumInstancesResponse ),
 9 : (SchRpcGetInstanceInfo,SchRpcGetInstanceInfoResponse ),
 10 : (SchRpcStopInstance,SchRpcStopInstanceResponse ),
 11 : (SchRpcStop,SchRpcStopResponse ),
 12 : (SchRpcRun,SchRpcRunResponse ),
 13 : (SchRpcDelete,SchRpcDeleteResponse ),
 14 : (SchRpcRename,SchRpcRenameResponse ),
 15 : (SchRpcScheduledRuntimes,SchRpcScheduledRuntimesResponse ),
 16 : (SchRpcGetLastRunInfo,SchRpcGetLastRunInfoResponse ),
 17 : (SchRpcGetTaskInfo,SchRpcGetTaskInfoResponse ),
 18 : (SchRpcGetNumberOfMissedRuns,SchRpcGetNumberOfMissedRunsResponse),
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

 func hSchRpcHighestVersion(dce interface{}){
    return dce.request(SchRpcHighestVersion())

 func hSchRpcRegisterTask(dce, path, xml, flags, sddl, logonType, pCreds = () interface{}){
    request = SchRpcRegisterTask()
    request["path"] = checkNullString(path)
    request["xml"] = checkNullString(xml)
    request["flags"] = flags
    request["sddl"] = sddl
    request["logonType"] = logonType
    request["cCreds"] = len(pCreds)
    if len(pCreds) == 0 {
        request["pCreds"] = NULL
    } else  {
        for cred in pCreds:
            request["pCreds"].append(cred)
    return dce.request(request)

 func hSchRpcRetrieveTask(dce, path, lpcwszLanguagesBuffer = "\x00", pulNumLanguages=0  interface{}){
    schRpcRetrieveTask = SchRpcRetrieveTask()
    schRpcRetrieveTask["path"] = checkNullString(path)
    schRpcRetrieveTask["lpcwszLanguagesBuffer"] = lpcwszLanguagesBuffer
    schRpcRetrieveTask["pulNumLanguages"] = pulNumLanguages
    return dce.request(schRpcRetrieveTask)

 func hSchRpcCreateFolder(dce, path, sddl = NULL interface{}){
    schRpcCreateFolder = SchRpcCreateFolder()
    schRpcCreateFolder["path"] = checkNullString(path)
    schRpcCreateFolder["sddl"] = sddl
    schRpcCreateFolder["flags"] = 0
    return dce.request(schRpcCreateFolder)

 func hSchRpcEnumFolders(dce, path, flags=TASK_ENUM_HIDDEN, startIndex=0, cRequested=0xffffffff interface{}){
    schRpcEnumFolders = SchRpcEnumFolders()
    schRpcEnumFolders["path"] = checkNullString(path)
    schRpcEnumFolders["flags"] = flags
    schRpcEnumFolders["startIndex"] = startIndex
    schRpcEnumFolders["cRequested"] = cRequested
    return dce.request(schRpcEnumFolders)

 func hSchRpcEnumTasks(dce, path, flags=TASK_ENUM_HIDDEN, startIndex=0, cRequested=0xffffffff interface{}){
    schRpcEnumTasks = SchRpcEnumTasks()
    schRpcEnumTasks["path"] = checkNullString(path)
    schRpcEnumTasks["flags"] = flags
    schRpcEnumTasks["startIndex"] = startIndex
    schRpcEnumTasks["cRequested"] = cRequested
    return dce.request(schRpcEnumTasks)

 func hSchRpcEnumInstances(dce, path, flags=TASK_ENUM_HIDDEN interface{}){
    schRpcEnumInstances = SchRpcEnumInstances()
    schRpcEnumInstances["path"] = checkNullString(path)
    schRpcEnumInstances["flags"] = flags
    return dce.request(schRpcEnumInstances)

 func hSchRpcGetInstanceInfo(dce, guid interface{}){
    schRpcGetInstanceInfo = SchRpcGetInstanceInfo()
    schRpcGetInstanceInfo["guid"] = guid
    return dce.request(schRpcGetInstanceInfo)

 func hSchRpcStopInstance(dce, guid, flags = 0 interface{}){
    schRpcStopInstance = SchRpcStopInstance()
    schRpcStopInstance["guid"] = guid
    schRpcStopInstance["flags"] = flags
    return dce.request(schRpcStopInstance)

 func hSchRpcStop(dce, path, flags = 0 interface{}){
    schRpcStop= SchRpcStop()
    schRpcStop["path"] = path
    schRpcStop["flags"] = flags
    return dce.request(schRpcStop)

 func hSchRpcRun(dce, path, pArgs=(), flags=0, sessionId=0, user = NULL interface{}){
    schRpcRun = SchRpcRun()
    schRpcRun["path"] = checkNullString(path)
    schRpcRun["cArgs"] = len(pArgs)
    for arg in pArgs:
        argn = LPWSTR()
        argn["Data"] = checkNullString(arg)
        schRpcRun["pArgs"].append(argn)
    schRpcRun["flags"] = flags
    schRpcRun["sessionId"] = sessionId
    schRpcRun["user"] = user
    return dce.request(schRpcRun)

 func hSchRpcDelete(dce, path, flags = 0 interface{}){
    schRpcDelete = SchRpcDelete()
    schRpcDelete["path"] = checkNullString(path)
    schRpcDelete["flags"] = flags
    return dce.request(schRpcDelete)

 func hSchRpcRename(dce, path, newName, flags = 0 interface{}){
    schRpcRename = SchRpcRename()
    schRpcRename["path"] = checkNullString(path)
    schRpcRename["newName"] = checkNullString(newName)
    schRpcRename["flags"] = flags
    return dce.request(schRpcRename)

 func hSchRpcScheduledRuntimes(dce, path, start = NULL, end = NULL, flags = 0, cRequested = 10 interface{}){
    schRpcScheduledRuntimes = SchRpcScheduledRuntimes()
    schRpcScheduledRuntimes["path"] = checkNullString(path)
    schRpcScheduledRuntimes["start"] = start
    schRpcScheduledRuntimes["end"] = end
    schRpcScheduledRuntimes["flags"] = flags
    schRpcScheduledRuntimes["cRequested"] = cRequested
    return dce.request(schRpcScheduledRuntimes)

 func hSchRpcGetLastRunInfo(dce, path interface{}){
    schRpcGetLastRunInfo = SchRpcGetLastRunInfo()
    schRpcGetLastRunInfo["path"] = checkNullString(path)
    return dce.request(schRpcGetLastRunInfo)

 func hSchRpcGetTaskInfo(dce, path, flags = 0 interface{}){
    schRpcGetTaskInfo = SchRpcGetTaskInfo()
    schRpcGetTaskInfo["path"] = checkNullString(path)
    schRpcGetTaskInfo["flags"] = flags
    return dce.request(schRpcGetTaskInfo)

 func hSchRpcGetNumberOfMissedRuns(dce, path interface{}){
    schRpcGetNumberOfMissedRuns = SchRpcGetNumberOfMissedRuns()
    schRpcGetNumberOfMissedRuns["path"] = checkNullString(path)
    return dce.request(schRpcGetNumberOfMissedRuns)

 func hSchRpcEnableTask(dce, path, enabled = true interface{}){
    schRpcEnableTask = SchRpcEnableTask()
    schRpcEnableTask["path"] = checkNullString(path)
    if enabled is true {
        schRpcEnableTask["enabled"] = 1
    } else  {
        schRpcEnableTask["enabled"] = 0
    return dce.request(schRpcEnableTask)
