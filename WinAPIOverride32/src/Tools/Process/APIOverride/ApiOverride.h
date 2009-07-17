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

//-----------------------------------------------------------------------------
// Object: class helper for doing api override or api monitoring
//         it manages the apioverride.dll
//         (It's the hart of project winapioverride)
//-----------------------------------------------------------------------------


#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501 // for xp os
#endif
#include <windows.h>
#include <stdio.h>

#pragma warning (push)
#pragma warning(disable : 4005)// for '_stprintf' : macro redefinition in tchar.h
#include <TCHAR.h>
#pragma warning (pop)
#include "interprocesscommunication.h"
#include "SupportedParameters.h"
#include "../InjLib/injlib.h"
#include "ApiOverrideFuncAndParams.h"
#include "../MailSlot/MailSlotClient.h"
#include "../MailSlot/MailSlotServer.h"
#include "../../GUI/ListView/ListView.h"
#include "../../FIFO/FIFO.h"
#include "../../APIError/ApiError.h"
#include "../../CleanCloseHandle/CleanCloseHandle.h"
#include "../ProcessHelper/ProcessHelper.h"
#include "../memory/processmemory.h"
#include "../../PE/PE.h"
#include "../../String/trimstring.h"
#include "../../File/TextFile.h"
#include "../../File/StdFileOperations.h"
#include "HookCom/HookComExport.h"

#include <shlobj.h>

// dll  name
#define API_OVERRIDE_DLL_NAME _T("ApiOverride.dll")
#define INJECTLIB_DLL_NAME _T("InjLib.dll")

// timeouts in ms
#define TIME_REQUIERED_TO_LOAD 15000 // max time in sec required for dll/monitoring file to be loaded
#define TIME_REQUIERED_TO_UNLOAD 10000 // max time in sec required for dll/monitoring file to be unloaded

#define APIOVERRIDE_NO_MORE_MESSAGE_IF_NO_MESSAGE_DURING_TIME_IN_MS 500 // time with no message before closing mailslot server in case of unexpected unload
#define APIOVERRIDE_CMD_REPLY_MAX_TIME_IN_MS 4000 // max time in ms for a commande to get is associated reply
#define APIOVERRIDE_MAX_ONE_PARAM_STRING_SIZE_FOR_CALL_COLUMN 64

// for FILETIME conversion
#define _SECOND ((ULONGLONG) 10000000)
#define _MINUTE (60 * _SECOND)
#define _HOUR   (60 * _MINUTE)
#define _DAY    (24 * _HOUR) 

typedef struct tagCallStackItemInfo
{
    PBYTE  Address;
    PBYTE  RelativeAddress;
    PBYTE  Parameters;
    TCHAR* pszModuleName;
}CALLSTACK_ITEM_INFO,*PCALLSTACK_ITEM_INFO;

typedef struct tagLogEntry
{
    PLOG_ENTRY_FIXED_SIZE pHookInfos;
    TCHAR* pszModuleName;
    TCHAR* pszApiName;
    TCHAR* pszCallingModuleName;
    PPARAMETER_LOG_INFOS ParametersInfoArray;// number of items is defined by pHookInfos->bNumberOfParameters
    PCALLSTACK_ITEM_INFO CallSackInfoArray;// number of items is defined by pHookInfos->CallStackSize
}LOG_ENTRY,*PLOG_ENTRY;

// First listview column text for report messages
#define LISTVIEW_ITEM_TEXT_INFORMATION  _T("I")
#define LISTVIEW_ITEM_TEXT_ERROR        _T("E")
#define LISTVIEW_ITEM_TEXT_WARNING      _T("W")

#define INCREMENT_STRING _T("-")

// types of report messages
// DON'T CHANGE EXISTING VALUES TO AVOID TROUBLES RELOADING OLD MONITORING FILES
enum tagMsgTypes
{
    MSG_INFORMATION=REPORT_MESSAGE_INFORMATION,
    MSG_WARNING=REPORT_MESSAGE_WARNING,
    MSG_ERROR=REPORT_MESSAGE_ERROR
};

// types of logs
// DON'T CHANGE EXISTING VALUES TO AVOID TROUBLES RELOADING OLD MONITORING FILES
enum tagLogListEntryTypes
{
    ENTRY_LOG=0,
    ENTRY_MSG_INFORMATION=MSG_INFORMATION,
    ENTRY_MSG_WARNING=MSG_WARNING,
    ENTRY_MSG_ERROR=MSG_ERROR
};

typedef struct tagLogListEntry
{
    DWORD dwId;
    tagLogListEntryTypes Type;// log or information
    LOG_ENTRY* pLog;
    TCHAR* pUserMsg;
}LOG_LIST_ENTRY,*PLOG_LIST_ENTRY;

typedef void (*tagCallBackLogFunc)(LOG_ENTRY* pLog,PVOID pUserParam);
typedef void (*tagCallBackUnexpectedUnload)(DWORD dwProcessID,PVOID pUserParam);
typedef void (*tagpCallBackBeforeAppResume)(DWORD dwProcessID,PVOID pUserParam);
typedef void (*tagCallBackReportMessages)(tagReportMessageType ReportMessageType,TCHAR* ReportMessage,LPVOID UserParam);

typedef struct tagRemoteCallInfos
{
    PBYTE ProcessInternalCallReply;
    HANDLE hevtProcessInternalCallReply;
}REMOTE_CALL_INFOS,*PREMOTE_CALL_INFOS;

class CApiOverride
{
private:
    BOOL bAPIOverrideDllLoaded;
    tagCallBackLogFunc pCallBackLogFunc;
    BOOL bManualFreeLogEntry;
    LPVOID pCallBackLogFuncUserParam;
    tagCallBackUnexpectedUnload pCallBackUnexpectedUnloadFunc;
    LPVOID pCallBackUnexpectedUnloadFuncUserParam;
    tagCallBackReportMessages pCallBackReportMessage;
    LPVOID pCallBackReportMessagesUserParam;
    DWORD dwCurrentProcessId;// hooked process id
    TCHAR ProcessName[MAX_PATH];// hooked process name
    TCHAR ProcessPath[MAX_PATH];// hooked process Path
    CMailSlotServer* pMailSlotServer;
    CMailSlotClient* pMailSlotClient;
    CListview* pListview;
    CListview* pInternalListview;
    InjectLib pInjectLib;// InjectLib function pointer
    EjectLib pEjectLib; // EjectLib function pointer 
    HMODULE hmodInjlib; // handle of injlib dll
    HANDLE hThreadWatchingEvents;// handle of watching event thread
    HANDLE hThreadLogging;// handle of logging thread
    TCHAR pszAppPath[MAX_PATH];// winapioverride application path
    PBYTE NotLoggedModulesArray;
    HANDLE hevtGetNotLoggedModulesReply;
    CLinkListSimple* pCurrentRemoteCalls;
    HOOK_COM_OPTIONS ComHookingOptions;
    BOOL bComAutoHookingEnabled;
    HANDLE hStopUnlocked; // lock for Stop function

    // events from api override class to injected dll
    HANDLE hevtStartMonitoring;// query to start monitoring
    HANDLE hevtStopMonitoring;// query to stop monitoring
    HANDLE hevtStartFaking;// query to start overriding
    HANDLE hevtStopFaking;// query to stop overriding
    HANDLE hevtFreeProcess;// query to free process
    
    // events from injected dll to api override class
    HANDLE hevtAPIOverrideDllProcessAttachCompleted; // api override dll is successfully loaded in targeted process
    HANDLE hevtAPIOverrideDllProcessDetachCompleted; // api override dll has been unloaded from targeted process
    HANDLE hevtProcessFree;// api override dll associated memory and process has been free. 
                           // hevtAPIOverrideDllProcessDetachCompleted can follow, but hevtProcessFree
                           // can be raised at dll loading too in case of error
    HANDLE hevtMonitoringFileLoaded; // monitoring file successfully loaded
    HANDLE hevtMonitoringFileUnloaded; // monitoring file successfully unloaded
    HANDLE hevtFakeAPIDLLLoaded;// fake api dll successfully loaded
    HANDLE hevtFakeAPIDLLUnloaded;// fake api dll successfully unloaded
    HANDLE hevtError;// an error has occurred

    PBYTE HookEntryPointRemoteHook;
    PBYTE HookEntryPointRemoteLibName;
    CProcessMemory* HookEntryPointpProcessMemory;
    
    DWORD NotLoggedModulesArraySize;

    tagFirstBytesAutoAnalysis AutoAnalysis;
    BOOL bLogCallStack;
    BOOL bMonitoringFileDebugMode;
    DWORD CallStackEbpRetrievalSize;
    BOOL bOnlyBaseModule;
    BOOL bBreakDialogDontBreakApioverrideThreads;
    HANDLE MonitoringHeap;

    void Initialize();
    void MailSlotServerCallback(PVOID pData,DWORD dwDataSize);
    void MonitoringCallback(PBYTE LogBuffer);
    void MonitoringCallback(LOG_ENTRY* pLog);
    void ShowApiOverrideNotStartedMsg();
    void DllUnloadedCallBack();
    void SetOptions();
    int  UserMessage(TCHAR* pszMessage,TCHAR* pszTitle,UINT uType);
    int  UserMessage(HWND hWnd,TCHAR* pszMessage,TCHAR* pszTitle,UINT uType);
    void ReportError(TCHAR* pszErrorMessage);
    void ReportError(HWND hWnd, TCHAR* pszErrorMessage);

    BOOL InitializeStart(DWORD dwPID);
    BOOL InjectDllByCreateRemoteThread(DWORD dwPID);
    BOOL WaitForInjectedDllToBeLoaded();
    void ResetInjectedDllLoadEvents();
    BOOL HookEntryPoint(TCHAR* pszFileName, DWORD dwProcessId,HANDLE hThreadHandle);
    BOOL HookEntryPointFree();
    HWND hParentWindow;


    static BOOL AddModuleListParseLineStatic(TCHAR* FileName,TCHAR* pszLine,DWORD dwLineNumber,LPVOID UserParam);
    static BOOL RemoveModuleListParseLineStatic(TCHAR* FileName,TCHAR* pszLine,DWORD dwLineNumber,LPVOID UserParam);
    void FilterModuleListParseLine(TCHAR* FileName,TCHAR* pszLine,DWORD dwLineNumber,BOOL ShouldBeLogged);

    static void StaticMailSlotServerCallback(PVOID pData,DWORD dwDataSize,PVOID pUserData);
    static DWORD WINAPI LoggingThreadListener(LPVOID lpParam);
    static DWORD WINAPI DllUnloadedThreadListener(LPVOID lpParam);

    BOOL Stop(BOOL bCalledByhThreadWatchingEvents);
public:

    enum StartWays
    {
        StartWaySleep,
        StartWaySuspended
    };

    enum tagColumnsIndex
    {
        ColumnsIndexId=0,
        ColumnsIndexDirection,
        ColumnsIndexCall,
        ColumnsIndexReturnValue,
        ColumnsIndexCallerAddress,
        ColumnsIndexCallerRelativeIndex,
        ColumnsIndexProcessID,
        ColumnsIndexThreadID,
        ColumnsIndexLastError,
        ColumnsIndexRegistersBeforeCall,
        ColumnsIndexRegistersAfterCall,
        ColumnsIndexFloatingReturnValue,
        ColumnsIndexCallTime,
        ColumnsIndexCallDuration,
        ColumnsIndexModuleName,
        ColumnsIndexAPIName,
        ColumnsIndexCallerFullPath,
        LastColumIndex// delimiter, must be at the end of the enum
    }ColumnsIndex;
    CApiOverride();
    CApiOverride(tagCallBackLogFunc pCallBackLogFunc);
    CApiOverride(HWND hParentWindow,HWND hListView);
    CApiOverride(HWND hParentWindow);
    ~CApiOverride(void);

    BOOL LoadMonitoringFile(TCHAR* pszFileName);
    BOOL UnloadMonitoringFile(TCHAR* pszFileName);
    BOOL LoadFakeAPI(TCHAR* pszFileName);
    BOOL UnloadFakeAPI(TCHAR* pszFileName);

    BOOL StartMonitoring();
    BOOL StopMonitoring();
    BOOL StartFaking();
    BOOL StopFaking();

    BOOL LogOnlyBaseModule(BOOL bOnlyBaseModule);
    BOOL SetModuleFilteringWay(tagFilteringWay FilteringWay);
    BOOL SetModuleLogState(TCHAR* pszModuleFullPath,BOOL bLog);
    BOOL AddToFiltersModuleList(TCHAR* pszFileName);
    BOOL RemoveFromFiltersModuleList(TCHAR* pszFileName);
    BOOL ClearFiltersModuleList();
    BOOL GetNotLoggedModuleList(TCHAR*** pArrayNotLoggedModulesNames,DWORD* pdwArrayNotLoggedModulesNamesSize);
    BOOL SetMonitoringModuleFiltersState(BOOL bEnable);
    BOOL SetFakingModuleFiltersState(BOOL bEnable);
    BOOL SetAutoAnalysis(tagFirstBytesAutoAnalysis AutoAnalysis);
    BOOL EnableCOMAutoHooking(BOOL bEnable);
    BOOL SetCOMOptions(HOOK_COM_OPTIONS* pComOptions);
    BOOL ShowCOMInteractionDialog();
    BOOL SetCallSackRetrieval(BOOL bLogCallStack,DWORD CallStackParametersRetrievalSize);
    BOOL BreakDialogDontBreakApioverrideThreads(BOOL bDontBreak);
    BOOL SetMonitoringFileDebugMode(BOOL bActiveMode);

    BOOL Dump();

    void SetReportMessagesCallBack(tagCallBackReportMessages pCallBackFunc,LPVOID pUserParam);
    void SetUnexpectedUnloadCallBack(tagCallBackUnexpectedUnload pCallBackFunc,LPVOID pUserParam);
    void SetMonitoringCallback(tagCallBackLogFunc pCallBackLogFunc,LPVOID pUserParam,BOOL bManualFreeLogEntry);
    static void FreeLogEntry(LOG_ENTRY* pLog);
    static void FreeLogEntry(LOG_ENTRY* pLog,HANDLE Heap);
    void SetMonitoringListview(HWND hListView);
    void SetMonitoringListview(CListview* pListView);
    void InitializeMonitoringListview();

    void AddLogEntry(LOG_LIST_ENTRY* pLogEntry,BOOL bStorePointerInListViewItemUserData);
    void AddLogEntry(LOG_LIST_ENTRY* pLogEntry,BOOL bStorePointerInListViewItemUserData,int Increment);
    
    BOOL Stop();
    BOOL Start(DWORD dwPID);
    BOOL Start(TCHAR* pszFileName);
    BOOL Start(TCHAR* pszFileName,tagpCallBackBeforeAppResume pCallBackFunc,LPVOID pUserParam);
    BOOL Start(TCHAR* pszFileName,TCHAR* pszCmdLine,tagpCallBackBeforeAppResume pCallBackFunc,LPVOID pUserParam);
    BOOL Start(TCHAR* pszFileName,TCHAR* pszCmdLine,tagpCallBackBeforeAppResume pCallBackFunc,LPVOID pUserParam,StartWays StartMethod,DWORD dwResumeTimeAtStartup);

    BOOL ProcessInternalCall(LPTSTR LibName,LPTSTR FuncName,DWORD NbParams,PSTRUCT_FUNC_PARAM pParams,PBYTE* pReturnValue);
    BOOL ProcessInternalCall(LPTSTR LibName,LPTSTR FuncName,DWORD NbParams,PSTRUCT_FUNC_PARAM pParams,PBYTE* pReturnValue,DWORD dwTimeOutMs);
    BOOL ProcessInternalCall(LPTSTR LibName,LPTSTR FuncName,DWORD NbParams,PSTRUCT_FUNC_PARAM pParams,REGISTERS* pRegisters,PBYTE* pReturnValue,DWORD dwTimeOutMs);
    BOOL ProcessInternalCall(LPTSTR LibName,LPTSTR FuncName,DWORD NbParams,PSTRUCT_FUNC_PARAM pParams,REGISTERS* pRegisters,PBYTE* pReturnValue,double* FloatingReturn,DWORD dwTimeOutMs,DWORD ThreadId);

    DWORD GetProcessID();
    BOOL GetProcessName(TCHAR* ProcessName,int ProcessNameMaxSize);

    void SetMonitoringLogHeap(HANDLE Heap);
};