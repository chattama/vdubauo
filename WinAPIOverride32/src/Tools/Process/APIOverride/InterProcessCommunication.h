/*
Copyright (C) 2004 Jacquelin POTIER <jacquelin.potier@free.fr>
Dynamic aspect ratio code Copyright (C) 2004 Jacquelin POTIER <jacquelin.potier@free.fr>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; version 2 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#pragma once

#include "ExportedStructs.h"

#define REGISTER_BYTE_SIZE sizeof(PBYTE)

#define APIOVERRIDE_MUTEX _T("APIOVERRIDE_MUTEX")

// MailSlots names. These names are followed by Target process Id (allow multiple instance of this soft)
#define APIOVERRIDE_MAILSLOT_TO_INJECTOR _T("\\\\.\\mailslot\\APIOVERRIDE_TO_INJECTOR")
#define APIOVERRIDE_MAILSLOT_FROM_INJECTOR _T("\\\\.\\mailslot\\APIOVERRIDE_FROM_INJECTOR")

// Events names. These names are followed by Target process Id (allow multiple instance of this soft)
//(Injector -> APIOverride)
#define APIOVERRIDE_EVENT_START_MONITORING _T("APIOVERRIDE_EVENT_START_MONITORING")
#define APIOVERRIDE_EVENT_STOP_MONITORING _T("APIOVERRIDE_EVENT_STOP_MONITORING")
#define APIOVERRIDE_EVENT_START_FAKING _T("APIOVERRIDE_EVENT_START_FAKING")
#define APIOVERRIDE_EVENT_STOP_FAKING _T("APIOVERRIDE_EVENT_STOP_FAKING")
#define APIOVERRIDE_EVENT_FREE_PROCESS _T("APIOVERRIDE_EVENT_FREE_PROCESS")

// (APIOverride -> Injector)
#define APIOVERRIDE_EVENT_DLLPROCESS_ATTACH_COMPLETED _T("APIOVERRIDE_EVENT_DLLPROCESS_ATTACH_COMPLETED")
#define APIOVERRIDE_EVENT_DLL_DETACHED_COMPLETED _T("APIOVERRIDE_EVENT_DLLPROCESS_DETACHED_COMPLETED")
#define APIOVERRIDE_EVENT_PROCESS_FREE _T("APIOVERRIDE_EVENT_PROCESS_FREE")
#define APIOVERRIDE_EVENT_MONITORING_FILE_LOADED _T("APIOVERRIDE_EVENT_MONITORING_FILE_LOADED")
#define APIOVERRIDE_EVENT_MONITORING_FILE_UNLOADED _T("APIOVERRIDE_EVENT_MONITORING_FILE_UNLOADED")
#define APIOVERRIDE_EVENT_FAKE_API_DLL_LOADED _T("APIOVERRIDE_EVENT_FAKE_API_DLL_LOADED")
#define APIOVERRIDE_EVENT_FAKE_API_DLL_UNLOADED _T("APIOVERRIDE_EVENT_FAKE_API_DLL_UNLOADED")
#define APIOVERRIDE_EVENT_ERROR _T("APIOVERRIDE_EVENT_ERROR")

// tag to specify internal address of software instead of a libname/funcname
#define EXE_INTERNAL_PREFIX _T("EXE_INTERNAL@0x")
#define EXE_INTERNAL_POINTER_PREFIX _T("EXE_INTERNAL_POINTER@0x")
// tag to specify internal address of a dll instead of an exported funcname
// allow to hook non exported function without knowing loaded bas address
#define DLL_INTERNAL_PREFIX _T("DLL_INTERNAL@0x")
#define DLL_INTERNAL_POINTER_PREFIX _T("DLL_INTERNAL_POINTER@0x")

// tag to specify ordinal exported address of a dll instead of an exported funcname
// allow to hook non exported function without knowing loaded bas address
#define DLL_ORDINAL_PREFIX _T("DLL_ORDINAL@0x")

// struct for commands (Injector -> APIOverride)
enum tagAPIOverrideCommands
{
    CMD_LOAD_MONITORING_FILE,
    CMD_UNLOAD_MONITORING_FILE,
    CMD_LOAD_FAKE_API_DLL,
    CMD_UNLOAD_FAKE_API_DLL,
    CMD_FREE_PROCESS,
    CMD_MONITORING_LOG,
    CMD_PROCESS_INTERNAL_CALL_QUERY,
    CMD_PROCESS_INTERNAL_CALL_REPLY,
    CMD_START_LOG_ONLY_BASE_MODULE,
    CMD_STOP_LOG_ONLY_BASE_MODULE,
    CMD_START_MODULE_LOGGING,
    CMD_STOP_MODULE_LOGGING,
    CMD_SET_LOGGED_MODULE_LIST_FILTERS_WAY,
    CMD_CLEAR_LOGGED_MODULE_LIST_FILTERS,
    CMD_ENABLE_MODULE_FILTERS_FOR_MONITORING,
    CMD_DISABLE_MODULE_FILTERS_FOR_MONITORING,
    CMD_ENABLE_MODULE_FILTERS_FOR_FAKING,
    CMD_DISABLE_MODULE_FILTERS_FOR_FAKING,
    CMD_NOT_LOGGED_MODULE_LIST_QUERY,
    CMD_NOT_LOGGED_MODULE_LIST_REPLY,
    CMD_DUMP,
    CMD_MONITORING_FILE_DEBUG_MODE,
    CMD_CALLSTACK_RETRIEVAL,
    CMD_AUTOANALYSIS,
    CMD_BREAK_DONT_BREAK_APIOVERRIDE_THREADS,
    CMD_REPORT_MESSAGE,
    CMD_COM_HOOKING_START_STOP,
    CMD_COM_HOOKING_OPTIONS,
    CMD_COM_INTERACTION,
    CMD_COM_RELEASE_CREATED_COM_OBJECTS_FOR_STATIC_HOOKS,
    CMD_COM_RELEASE_AUTO_HOOKED_OBJECTS
};

// types of report messages
// DON'T CHANGE EXISTING VALUES TO AVOID TROUBLES RELOADING OLD MONITORING FILES
enum tagReportMessageType
{
    REPORT_MESSAGE_INFORMATION=1,
    REPORT_MESSAGE_WARNING=2,
    REPORT_MESSAGE_ERROR=3
};

enum tagFirstBytesAutoAnalysis
{
    FIRST_BYTES_AUTO_ANALYSIS_NONE,    // no first bytes analysis is done
    FIRST_BYTES_AUTO_ANALYSIS_SECURE,  // first bytes analysis is done and used only 
                                       // - if first instruction length is more than HOOK_SIZE
                                       // - if first bytes match a well known sequence
    FIRST_BYTES_AUTO_ANALYSIS_INSECURE// first bytes analysis is done and used even 
                                       // if first instruction length is less than HOOK_SIZE
};

enum tagFilteringWay
{
    FILTERING_WAY_ONLY_SPECIFIED_MODULES,
    FILTERING_WAY_NOT_SPECIFIED_MODULES,
};

#define MAX_CMD_PARAMS 10
typedef struct _STRUCT_COMMAND
{
    DWORD dwCommand_ID;// must be at first position
    union {
        TCHAR pszStringParam[MAX_PATH];
        DWORD Param[MAX_CMD_PARAMS];
    };
}STRUCT_COMMAND,*PSTRUCT_COMMAND;

// struct for api logging (APIOverride -> Injector)
enum tagParamDirectionType// Param direction type enum
{
    PARAM_DIR_TYPE_IN,
    PARAM_DIR_TYPE_OUT,
    PARAM_DIR_TYPE_IN_NO_RETURN
};



typedef struct tagLogEntryFixedSize
{
    DWORD dwProcessId;
    DWORD dwThreadId;
    PBYTE pOriginAddress;
    PBYTE RelativeAddressFromCallingModuleName;
    REGISTERS RegistersBeforeCall;
    REGISTERS RegistersAfterCall;
    PBYTE ReturnValue;
    double DoubleResult;

    DWORD dwLastError;
    FILETIME CallTime;
    DWORD dwCallDuration;

    BOOLEAN bFailure;// don't use bSuccess because as memory is set to 0 by default, default value is FALSE
                     // Using bFailure allow to have a successful return for undefined Failure returned type
    BYTE bParamDirectionType;
    BYTE bNumberOfParameters;
    WORD CallStackSize;
    WORD CallStackEbpRetrievalSize;

}LOG_ENTRY_FIXED_SIZE,*PLOG_ENTRY_FIXED_SIZE;

#define PARAMETER_LOG_INFOS_PARAM_NAME_MAX_SIZE 40
typedef struct tagParameterLogInfos
{
    // NOTICE keep structure order

    DWORD dwType;
    PBYTE Value;// value of parameter or pointer value
    DWORD dwSizeOfData;// size of Data. If <=REGISTER_BYTE_SIZE param value is stored in Value (no memory allocation) else in pbValue 
    DWORD dwSizeOfPointedValue;// size of pbValue.
    TCHAR pszParameterName[PARAMETER_LOG_INFOS_PARAM_NAME_MAX_SIZE];
    BYTE* pbValue;// content of data if dwSizeOfData > REGISTER_BYTE_SIZE
                  // content of pointer if dwSizeOfPointedData > 0
                  // NULL if (dwSizeOfData <= REGISTER_BYTE_SIZE) && (dwSizeOfPointedData==0)
}PARAMETER_LOG_INFOS,*PPARAMETER_LOG_INFOS;

typedef struct _STRUCT_FUNC_PARAM
{
    BOOL bPassAsRef;    // true if param is pass as ref
    DWORD dwDataSize;   // size in byte
    PBYTE pData;        // pointer to data
}STRUCT_FUNC_PARAM,*PSTRUCT_FUNC_PARAM;
