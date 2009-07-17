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

#include "apioverride.h"

#pragma intrinsic (memcpy,memset,memcmp)
DWORD CApiOverrideColumnsDefaultSize[CApiOverride::LastColumIndex]={40,30,360,80,80,140,80,80,100,200,200,80,120,80,200,80,200};

//-----------------------------------------------------------------------------
// Name: Initialize
// Object: initializing part common to all constructors 
// Parameters :
// Return : 
//-----------------------------------------------------------------------------
void CApiOverride::Initialize()
{
    TCHAR psz[MAX_PATH];
    this->pCallBackUnexpectedUnloadFunc=NULL;
    this->pCallBackUnexpectedUnloadFuncUserParam=NULL;
    this->pCallBackLogFunc=NULL;
    this->pCallBackLogFuncUserParam=NULL;
    this->pCallBackReportMessage=NULL;
    this->pCallBackReportMessagesUserParam=NULL;
    this->pListview=NULL;
    this->pInternalListview=NULL;
    this->dwCurrentProcessId=0;
    this->bAPIOverrideDllLoaded=FALSE;

    this->hThreadWatchingEvents=NULL;
    this->hThreadLogging=NULL;

    this->pMailSlotServer=NULL;
    this->pMailSlotClient=NULL;

    this->hevtStartMonitoring=NULL;
    this->hevtStopMonitoring=NULL;
    this->hevtStartFaking=NULL;
    this->hevtStopFaking=NULL;
    this->hevtFreeProcess=NULL;

    this->hevtAPIOverrideDllProcessAttachCompleted=NULL;
    this->hevtAPIOverrideDllProcessDetachCompleted=NULL;
    this->hevtProcessFree=NULL;
    this->hevtMonitoringFileLoaded=NULL;
    this->hevtMonitoringFileUnloaded=NULL;
    this->hevtFakeAPIDLLLoaded=NULL;
    this->hevtFakeAPIDLLUnloaded=NULL;
    this->hevtError=NULL;

    this->pCurrentRemoteCalls=new CLinkListSimple();
    this->NotLoggedModulesArray=NULL;
    this->hevtGetNotLoggedModulesReply=CreateEvent(NULL,FALSE,FALSE,NULL);

    *this->ProcessName=0;

    this->HookEntryPointRemoteHook=NULL;
    this->HookEntryPointRemoteLibName=NULL;
    this->HookEntryPointpProcessMemory=NULL;

    this->NotLoggedModulesArraySize=0;
    this->hParentWindow=NULL;

    this->AutoAnalysis=FIRST_BYTES_AUTO_ANALYSIS_NONE;
    this->bLogCallStack=FALSE;
    this->bMonitoringFileDebugMode=FALSE;
    this->CallStackEbpRetrievalSize=0;
    this->bOnlyBaseModule=FALSE;

    this->bComAutoHookingEnabled=FALSE;
    memset(&this->ComHookingOptions,0,sizeof(HOOK_COM_OPTIONS));

    this->hStopUnlocked=CreateEvent(NULL,FALSE,TRUE,NULL);

    this->MonitoringHeap=GetProcessHeap();

    // get current application directory
    CStdFileOperations::GetAppPath(this->pszAppPath,MAX_PATH);

    // load injectlib dll
    _tcscpy(psz,this->pszAppPath);
    _tcscat(psz,INJECTLIB_DLL_NAME);
    this->hmodInjlib=LoadLibrary(psz);
    if (!this->hmodInjlib)
    {
        _stprintf(psz,_T("Error loading %s"),INJECTLIB_DLL_NAME);
        MessageBox(this->hParentWindow,psz,_T("Error"),MB_OK|MB_ICONERROR|MB_TOPMOST);
        this->pInjectLib=NULL;
        this->pEjectLib=NULL;
    }
    else
    {
        this->pInjectLib=(InjectLib)GetProcAddress(this->hmodInjlib,INJECTLIB_FUNC_NAME);
        this->pEjectLib=(EjectLib)GetProcAddress(this->hmodInjlib,EJECTLIB_FUNC_NAME);

        if (!this->pInjectLib)
        {
            _stprintf(psz,_T("%s not found in %s"),INJECTLIB_FUNC_NAME,INJECTLIB_DLL_NAME);
            MessageBox(this->hParentWindow,psz,_T("Error"),MB_OK|MB_ICONERROR|MB_TOPMOST);
        }
        if (!this->pEjectLib)
        {
            _stprintf(psz,_T("%s not found in %s"),EJECTLIB_FUNC_NAME,INJECTLIB_DLL_NAME);
            MessageBox(this->hParentWindow,psz,_T("Error"),MB_OK|MB_ICONERROR|MB_TOPMOST);
        }
    }
}

//-----------------------------------------------------------------------------
// Name: CApiOverride
// Object: Constructor 
//         use SetMonitoringCallback or SetMonitoringListview next to monitor hooks
// Parameters :
//     in : 
// Return : 
//-----------------------------------------------------------------------------
CApiOverride::CApiOverride()
{
    this->Initialize();
}

//-----------------------------------------------------------------------------
// Name: CApiOverride
// Object: Constructor to manage yourself logging event
// Parameters :
//     in : tagCallBackLogFunc pCallBackLogFunc : monitoring callback 
//          warning we use mail slot so callback can be called few seconds after real function call
//          for real time function hooking just use a dll (see fake API dll sample)
// Return : 
//-----------------------------------------------------------------------------
CApiOverride::CApiOverride(tagCallBackLogFunc pCallBackLogFunc)
{
    this->Initialize();
    this->SetMonitoringCallback(pCallBackLogFunc,NULL,FALSE);
}

//-----------------------------------------------------------------------------
// Name: CApiOverride
// Object: Constructor. Listview will be configured automatically, and it will be filled by monitoring events
// Parameters :
//     in : HWND hParentWindow : handle of parent window. Allow to make modal messagebox
//          HWND hListView: Handle to a list view
// Return : 
//-----------------------------------------------------------------------------
CApiOverride::CApiOverride(HWND hParentWindow,HWND hListView)
{
    this->Initialize();
    this->hParentWindow=hParentWindow;
    this->SetMonitoringListview(hListView);
}

//-----------------------------------------------------------------------------
// Name: CApiOverride
// Object: Constructor. 
// Parameters :
//     in : HWND hParentWindow : handle of parent window. Allow to make modal messagebox
// Return : 
//-----------------------------------------------------------------------------
CApiOverride::CApiOverride(HWND hParentWindow)
{
    this->Initialize();
    this->hParentWindow=hParentWindow;
}

//-----------------------------------------------------------------------------
// Name: CApiOverride
// Object: destructor. 
// Parameters :
// Return : 
//-----------------------------------------------------------------------------
CApiOverride::~CApiOverride(void)
{
    this->Stop();

    if (this->pInternalListview)
        delete this->pInternalListview;

    // unload injectlib dll
    this->pInjectLib=NULL;
    this->pEjectLib=NULL;
    if (this->hmodInjlib)
        FreeLibrary(this->hmodInjlib);

    CleanCloseHandle(&this->hevtGetNotLoggedModulesReply);
    CleanCloseHandle(&this->hStopUnlocked);

    if (this->HookEntryPointpProcessMemory)
        delete this->HookEntryPointpProcessMemory;

    if (this->pCurrentRemoteCalls)
        delete this->pCurrentRemoteCalls;
}


//-----------------------------------------------------------------------------
// Name: ReportError
// Object: Show an error message merging current process number
// Parameters :
//      in : - TCHAR* pszErrorMessage : error message without process number
// Return : 
//-----------------------------------------------------------------------------
void CApiOverride::ReportError(TCHAR* pszErrorMessage)
{
    this->ReportError(this->hParentWindow,pszErrorMessage);
}
//-----------------------------------------------------------------------------
// Name: ReportError
// Object: Show an error message merging current process number
// Parameters :
//      in : - TCHAR* pszErrorMessage : error message without process number
//           - HWND hWnd : allow to specify a window handle diferent than 
//                         this->hParentWindow like NULL
// Return : 
//-----------------------------------------------------------------------------
void CApiOverride::ReportError(HWND hWnd, TCHAR* pszErrorMessage)
{
    this->UserMessage(hWnd,pszErrorMessage,_T("Error"),MB_OK|MB_ICONERROR|MB_TOPMOST);
}

//-----------------------------------------------------------------------------
// Name: UserMessage
// Object: Show a messagebox merging current process number
// Parameters :
//      in : - TCHAR* pszErrorMessage : message without process number
//           - TCHAR* pszTitle : msgbox title
//           - UINT uType : msgbox title
// Return : msgbox result
//-----------------------------------------------------------------------------
int CApiOverride::UserMessage(TCHAR* pszMessage,TCHAR* pszTitle,UINT uType)
{
    return this->UserMessage(this->hParentWindow,pszMessage,pszTitle,uType);
}
//-----------------------------------------------------------------------------
// Name: UserMessage
// Object: Show a messagebox merging current process number
// Parameters :
//      in : - TCHAR* pszErrorMessage : message without process number
//           - TCHAR* pszTitle : msgbox title
//           - UINT uType : msgbox title
//           - HWND hWnd : allow to specify a window handle different than 
//                         this->hParentWindow like NULL
// Return : msgbox result
//-----------------------------------------------------------------------------
int CApiOverride::UserMessage(HWND hWnd,TCHAR* pszMessage,TCHAR* pszTitle,UINT uType)
{
    TCHAR pszMsg[2*MAX_PATH];
    if (this->dwCurrentProcessId!=0)
    {
        _sntprintf(pszMsg,2*MAX_PATH,_T("%s for process ID 0x%.8X"),pszMessage,this->dwCurrentProcessId);
        if (*this->ProcessName)
        {
            _tcscat(pszMsg,_T(" ("));
            _tcscat(pszMsg,this->ProcessName);
            _tcscat(pszMsg,_T(")"));
        }
        return MessageBox(hWnd,pszMsg,pszTitle,uType);
    }
    else
    {
        return MessageBox(hWnd,pszMessage,pszTitle,uType);
    }
}

//-----------------------------------------------------------------------------
// Name: GetProcessID
// Object: return the process ID with which CApioverride is working or has worked at last
// Parameters :
// Return : PID if CAPIOverride
//-----------------------------------------------------------------------------
DWORD CApiOverride::GetProcessID()
{
    return this->dwCurrentProcessId;
}

//-----------------------------------------------------------------------------
// Name: GetProcessName
// Object: return the process name with which CApioverride is working or has worked at last
// Parameters :
//      in : int ProcessNameMaxSize : max size of ProcessName in tchar
//      out: TCHAR* ProcessName : process name
// Return : TRUE on success
//-----------------------------------------------------------------------------
BOOL CApiOverride::GetProcessName(TCHAR* ProcessName,int ProcessNameMaxSize)
{
    if (IsBadWritePtr(ProcessName,ProcessNameMaxSize*sizeof(TCHAR)))
        return FALSE;

    _tcsncpy(ProcessName,this->ProcessName,ProcessNameMaxSize);

    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: EnableCOMAutoHooking
// Object: enable or disable com hooking
// Parameters :
//      in : BOOL bEnable : TRUE to start COM hooking, FALSE to stop it
//      out: 
// Return : FALSE on error
//-----------------------------------------------------------------------------
BOOL CApiOverride::EnableCOMAutoHooking(BOOL bEnable)
{
    BOOL OldValue;
    // store old option
    OldValue=this->bComAutoHookingEnabled;
    this->bComAutoHookingEnabled=bEnable;

    // if injected dll is loaded
    if (this->bAPIOverrideDllLoaded)
    {
        // fill command
        STRUCT_COMMAND Cmd;
        Cmd.dwCommand_ID=CMD_COM_HOOKING_START_STOP;
        Cmd.Param[0]=this->bComAutoHookingEnabled;
        // send command
        if (!this->pMailSlotClient->Write(&Cmd,sizeof(STRUCT_COMMAND)))
        {
            ReportError(_T("Error modifying COM option.\r\nMailSlot write error"));
            this->bComAutoHookingEnabled=OldValue;
            return FALSE;
        }

        if (!this->bComAutoHookingEnabled)
        {
            TCHAR pszMsg[MAX_PATH];
            if (*this->ProcessName)
                _stprintf(pszMsg,_T("Do you want to unhook already auto hooked COM objects for application %s (0x%.8X)"),this->ProcessName,this->dwCurrentProcessId);
            else
                _stprintf(pszMsg,_T("Do you want to unhook already auto hooked COM objects for process ID 0x%.8X"),this->dwCurrentProcessId);

            if (MessageBox(this->hParentWindow,
                           pszMsg,
                           _T("Question"),
                           MB_TOPMOST|MB_ICONQUESTION|MB_YESNO
                           )
                           ==IDYES
                 )
            {
                Cmd.dwCommand_ID=CMD_COM_RELEASE_AUTO_HOOKED_OBJECTS;
                if (!this->pMailSlotClient->Write(&Cmd,sizeof(STRUCT_COMMAND)))
                {
                    ReportError(_T("Error releasing auto hooked COM objects.\r\nMailSlot write error"));
                    return FALSE;
                }
            }
        }
    }
    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: SetCOMOptions
// Object: set COM options
// Parameters :
//      in : 
//      out: 
// Return : 
//-----------------------------------------------------------------------------
BOOL CApiOverride::SetCOMOptions(HOOK_COM_OPTIONS* pComOptions)
{
    HOOK_COM_OPTIONS OldComOptions={0};
    // store previous option
    if (&this->ComHookingOptions!=pComOptions)
    {
        memcpy(&OldComOptions,&this->ComHookingOptions,sizeof(HOOK_COM_OPTIONS));
        memcpy(&this->ComHookingOptions,pComOptions,sizeof(HOOK_COM_OPTIONS));
    }

    // if injected dll is loaded
    if (this->bAPIOverrideDllLoaded)
    {
        BYTE pCmd[sizeof(DWORD)+sizeof(HOOK_COM_OPTIONS)];
        DWORD CmdId=CMD_COM_HOOKING_OPTIONS;

        // fill command Id
        memcpy(pCmd,&CmdId,sizeof(DWORD));
        // fill Com options
        memcpy(&pCmd[sizeof(DWORD)],pComOptions,sizeof(HOOK_COM_OPTIONS));

        // send command
        if (!this->pMailSlotClient->Write(pCmd,sizeof(DWORD)+sizeof(HOOK_COM_OPTIONS)))
        {
            ReportError(_T("Error modifying COM options.\r\nMailSlot write error"));
            if (&this->ComHookingOptions!=pComOptions)
            {
                // restore previous state 
                memcpy(&this->ComHookingOptions,&OldComOptions,sizeof(HOOK_COM_OPTIONS));
            }
            return FALSE;
        }
    }
    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: ShowCOMInteractionDialog
// Object: display COM Interaction dialog
// Parameters :
//      out: 
// Return : FALSE on error
//-----------------------------------------------------------------------------
BOOL CApiOverride::ShowCOMInteractionDialog()
{
    // store old option
    if(!this->bComAutoHookingEnabled)
        ReportError(_T("Error COM hooking not started"));

    // if injected dll is loaded
    if (this->bAPIOverrideDllLoaded)
    {
        // fill command
        STRUCT_COMMAND Cmd;
        Cmd.dwCommand_ID=CMD_COM_INTERACTION;
        // send command
        if (!this->pMailSlotClient->Write(&Cmd,sizeof(STRUCT_COMMAND)))
        {
            ReportError(_T("Error calling COM Interaction Dialog.\r\nMailSlot write error"));
            return FALSE;
        }
    }
    return TRUE;
}
//-----------------------------------------------------------------------------
// Name: SetAutoAnalysis
// Object: set auto analysis mode
// Parameters :
//      in : tagFirstBytesAutoAnalysis AutoAnalysis : new first bytes auto analysis
//      out: 
// Return : 
//-----------------------------------------------------------------------------
BOOL CApiOverride::SetAutoAnalysis(tagFirstBytesAutoAnalysis AutoAnalysis)
{
    tagFirstBytesAutoAnalysis OldAutoAnalysis;
    OldAutoAnalysis=this->AutoAnalysis;

    this->AutoAnalysis=AutoAnalysis;
    if (this->bAPIOverrideDllLoaded)
    {
        STRUCT_COMMAND Cmd;
        Cmd.dwCommand_ID=CMD_AUTOANALYSIS;
        Cmd.Param[0]=this->AutoAnalysis;
        if (!this->pMailSlotClient->Write(&Cmd,sizeof(STRUCT_COMMAND)))
        {
            ReportError(_T("Error modifying auto analysis mode.\r\nMailSlot write error"));
            // restore previous state 
            this->AutoAnalysis=OldAutoAnalysis;
            return FALSE;
        }
    }
    return TRUE;
}
//-----------------------------------------------------------------------------
// Name: SetCallSackRetrieval
// Object: set if call stack must be log , and the size of stack (in bytes)  
//         that should be logged for each call 
// Parameters :
//      in : BOOL bLogCallStack : TRUE to log call stack
//           DWORD CallStackParametersRetrievalSize : size of stack (in bytes) logged for each call
//                                                    meaningful only if bLogCallStack is TRUE
//      out: 
// Return : 
//-----------------------------------------------------------------------------
BOOL CApiOverride::SetCallSackRetrieval(BOOL bLogCallStack,DWORD CallStackParametersRetrievalSize)
{
    this->bLogCallStack=bLogCallStack;
    this->CallStackEbpRetrievalSize=CallStackParametersRetrievalSize;
    if (this->bAPIOverrideDllLoaded)
    {
        STRUCT_COMMAND Cmd;
        Cmd.dwCommand_ID=CMD_CALLSTACK_RETRIEVAL;
        Cmd.Param[0]=this->bLogCallStack;
        Cmd.Param[1]=this->CallStackEbpRetrievalSize;
        if (!this->pMailSlotClient->Write(&Cmd,sizeof(STRUCT_COMMAND)))
        {
            ReportError(_T("Error modifying stack retrieval way.\r\nMailSlot write error"));
            return FALSE;
        }
    }
    return TRUE;
}
//-----------------------------------------------------------------------------
// Name: SetMonitoringFileDebugMode
// Object: put APIOverride in monitoring file debug mode or not
//         When put in monitoring file debug mode, all logged are configured in InOut direction
//         and sent regardless filters
// Parameters :
//      in : BOOL bActiveMode : TRUE to go in monitoring file debug mode
//                              FALSE to go out of monitoring file debug mode
//      out: 
// Return : 
//-----------------------------------------------------------------------------
BOOL CApiOverride::SetMonitoringFileDebugMode(BOOL bActiveMode)
{
    this->bMonitoringFileDebugMode=bActiveMode;
    if (this->bAPIOverrideDllLoaded)
    {
        STRUCT_COMMAND Cmd;
        Cmd.dwCommand_ID=CMD_MONITORING_FILE_DEBUG_MODE;
        Cmd.Param[0]=this->bMonitoringFileDebugMode;
        if (!this->pMailSlotClient->Write(&Cmd,sizeof(STRUCT_COMMAND)))
        {
            ReportError(_T("Error modifying monitoring file debug mode.\r\nMailSlot write error"));
            return FALSE;
        }
    }
    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: BreakDialogDontBreakApioverrideThreads
// Object: Allow to specify if Break dialog will allow execution of ApiOverride dll threads
// Parameters :
//      in : BOOL bDontBreak : TRUE to avoid breaking ApiOverride threads
//                             FALSE break ApiOverride threads
//      out: 
// Return : 
//-----------------------------------------------------------------------------
BOOL CApiOverride::BreakDialogDontBreakApioverrideThreads(BOOL bDontBreak)
{
    this->bBreakDialogDontBreakApioverrideThreads=bDontBreak;
    if (this->bAPIOverrideDllLoaded)
    {
        STRUCT_COMMAND Cmd;
        Cmd.dwCommand_ID=CMD_BREAK_DONT_BREAK_APIOVERRIDE_THREADS;
        Cmd.Param[0]=this->bBreakDialogDontBreakApioverrideThreads;
        if (!this->pMailSlotClient->Write(&Cmd,sizeof(STRUCT_COMMAND)))
        {
            ReportError(_T("Error modifying ApiOverride breaking threads state on Break dialog.\r\nMailSlot write error"));
            return FALSE;
        }
    }
    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: SetMonitoringCallback
// Object: Let you manage yourself logging event
// Parameters :
//    in : - tagCallBackLogFunc pCallBackLogFunc : monitoring callback 
//          warning we use mail slot so callback can be called few seconds after real function call
//          for real time function hooking just use a dll (see fake API dll sample)
//          if you want to stop callback call, just call SetMonitoringCallback with a NULL parameter
//         - LPVOID pUserParam : parameter for the callback
//         - BOOL bManualFreeLogEntry : TRUE if you want to keep log in memory after callback has been called
//                                      else data of log structure will be free as soon as callback returns
//                                      To manually free memory of a log entry, call FreeLogEntry with the specified log entry
// Return : 
//-----------------------------------------------------------------------------
void CApiOverride::SetMonitoringCallback(tagCallBackLogFunc pCallBackLogFunc,LPVOID pUserParam,BOOL bManualFreeLogEntry)
{
    this->pCallBackLogFunc=pCallBackLogFunc;
    this->pCallBackLogFuncUserParam=pUserParam;
    this->bManualFreeLogEntry=bManualFreeLogEntry;
    if (IsBadCodePtr((FARPROC)pCallBackLogFunc))
        this->bManualFreeLogEntry=FALSE;
}

//-----------------------------------------------------------------------------
// Name: SetMonitoringListview
// Object: Listview will be configured automatically, and it will be field by monitoring events
//         you don't need to manage yourself logging events 
// Parameters :
//     in : HWND hListView: Handle to a list view
// Return : 
//-----------------------------------------------------------------------------
void CApiOverride::SetMonitoringListview(HWND hListView)
{
    if (this->pInternalListview)
    {
        delete this->pInternalListview;
        this->pInternalListview=NULL;
    }

    if (hListView==NULL)
    {
        this->pListview=NULL;
        return;
    }

    this->pInternalListview=new CListview(hListView);
    this->SetMonitoringListview(this->pInternalListview);
    this->InitializeMonitoringListview();
}


//-----------------------------------------------------------------------------
// Name: SetMonitoringListview
// Object: Listview will be field by monitoring events
//         you don't need to manage yourself logging events
// Parameters :
//     in : CListview pListView: CListview object (warning it's not the MFC one)
// Return : 
//-----------------------------------------------------------------------------
void CApiOverride::SetMonitoringListview(CListview* pListView)
{
    this->pListview=pListView;
}

//-----------------------------------------------------------------------------
// Name: InitializeMonitoringListview
// Object: initialize monitoring listview if set
// Return : 
//-----------------------------------------------------------------------------
void CApiOverride::InitializeMonitoringListview()
{
    if (!this->pListview)
        return;

    this->pListview->SetStyle(TRUE,FALSE,FALSE,FALSE);
    this->pListview->SetView(LV_VIEW_DETAILS);
    this->pListview->EnableColumnSorting(TRUE);

    this->pListview->Clear();
    this->pListview->RemoveAllColumns();
    for (int cpt=0;cpt<LastColumIndex;cpt++)
    {
        switch(cpt)
        {
            case ColumnsIndexId:
                this->pListview->SetColumn(cpt,_T("Id"),CApiOverrideColumnsDefaultSize[ColumnsIndexId],LVCFMT_RIGHT);
                break;
            case ColumnsIndexDirection:
                this->pListview->SetColumn(cpt,_T("Dir"),CApiOverrideColumnsDefaultSize[ColumnsIndexDirection],LVCFMT_CENTER);
                break;
            case ColumnsIndexCall:
                this->pListview->SetColumn(cpt,_T("Call"),CApiOverrideColumnsDefaultSize[ColumnsIndexCall],LVCFMT_LEFT);
                break;
            case ColumnsIndexReturnValue:
                this->pListview->SetColumn(cpt,_T("Ret Value"),CApiOverrideColumnsDefaultSize[ColumnsIndexReturnValue],LVCFMT_CENTER);
                break;
            case ColumnsIndexCallerAddress:
                this->pListview->SetColumn(cpt,_T("Caller Addr"),CApiOverrideColumnsDefaultSize[ColumnsIndexCallerAddress],LVCFMT_CENTER);
                break;
            case ColumnsIndexCallerRelativeIndex:
                this->pListview->SetColumn(cpt,_T("Caller Relative Addr"),CApiOverrideColumnsDefaultSize[ColumnsIndexCallerRelativeIndex],LVCFMT_LEFT);
                break;
            case ColumnsIndexProcessID:
                this->pListview->SetColumn(cpt,_T("ProcessID"),CApiOverrideColumnsDefaultSize[ColumnsIndexProcessID],LVCFMT_CENTER);
                break;
            case ColumnsIndexThreadID:
                this->pListview->SetColumn(cpt,_T("ThreadID"),CApiOverrideColumnsDefaultSize[ColumnsIndexThreadID],LVCFMT_CENTER);
                break;
            case ColumnsIndexModuleName:
                this->pListview->SetColumn(cpt,_T("Module Name"),CApiOverrideColumnsDefaultSize[ColumnsIndexModuleName],LVCFMT_LEFT);
                break;
            case ColumnsIndexCallerFullPath:
                this->pListview->SetColumn(cpt,_T("Caller Full Path"),CApiOverrideColumnsDefaultSize[ColumnsIndexCallerFullPath],LVCFMT_LEFT);
                break;
            case ColumnsIndexAPIName:
                this->pListview->SetColumn(cpt,_T("API Name"),CApiOverrideColumnsDefaultSize[ColumnsIndexAPIName],LVCFMT_LEFT);
                break;
            case ColumnsIndexLastError:
                this->pListview->SetColumn(cpt,_T("Last Error"),CApiOverrideColumnsDefaultSize[ColumnsIndexLastError],LVCFMT_CENTER);
                break;
            case ColumnsIndexRegistersBeforeCall:
                this->pListview->SetColumn(cpt,_T("Registers Before Call"),CApiOverrideColumnsDefaultSize[ColumnsIndexRegistersBeforeCall],LVCFMT_LEFT);
                break;
            case ColumnsIndexRegistersAfterCall:
                this->pListview->SetColumn(cpt,_T("Registers After Call"),CApiOverrideColumnsDefaultSize[ColumnsIndexRegistersAfterCall],LVCFMT_LEFT);
                break;
            case ColumnsIndexFloatingReturnValue:
                this->pListview->SetColumn(cpt,_T("Floating Ret"),CApiOverrideColumnsDefaultSize[ColumnsIndexFloatingReturnValue],LVCFMT_CENTER);
                break;
            case ColumnsIndexCallTime:
                this->pListview->SetColumn(cpt,_T("Start Time"),CApiOverrideColumnsDefaultSize[ColumnsIndexCallTime],LVCFMT_CENTER);
                break;
            case ColumnsIndexCallDuration:
                this->pListview->SetColumn(cpt,_T("Duration (us)"),CApiOverrideColumnsDefaultSize[ColumnsIndexCallDuration],LVCFMT_RIGHT);
                break;

        }
    }
}

//-----------------------------------------------------------------------------
// Name: LoadMonitoringFile
// Object: start monitoring API hooked by the file (multiple files can be hooked at the same time)
// Parameters :
//     in : TCHAR* pszFileName: api monitoring file
// Return : TRUE if file is partially loaded (even if some non fatal errors occurs)
//          and so needs a call to UnloadMonitoringFile to restore all hooked func,
//          FALSE if file not loaded at all
//-----------------------------------------------------------------------------
BOOL CApiOverride::LoadMonitoringFile(TCHAR* pszFileName)
{
    if (!this->bAPIOverrideDllLoaded)
    {
        this->ShowApiOverrideNotStartedMsg();
        return FALSE;
    }

    HANDLE pH[4]={this->hevtMonitoringFileLoaded,this->hevtError,this->hevtFreeProcess,this->hevtProcessFree};
    STRUCT_COMMAND Cmd;
    Cmd.dwCommand_ID=CMD_LOAD_MONITORING_FILE;
    _tcsncpy(Cmd.pszStringParam,pszFileName,MAX_PATH);
    // reset event in case of previous timeout
    ResetEvent(pH[0]);
    ResetEvent(pH[1]);
    if (!this->pMailSlotClient->Write(&Cmd,sizeof(STRUCT_COMMAND)))
    {
        ReportError(_T("Load Monitoring File error writing in MailSlot client"));
        return FALSE;
    }

    DWORD dwRet;

WaitEvent:
    dwRet=WaitForMultipleObjects(4,pH,FALSE,TIME_REQUIERED_TO_LOAD);
    if (dwRet==WAIT_TIMEOUT)
    {
        if(this->UserMessage(_T("Timeout for loading. Do you want to wait more ?"),_T("Question"),MB_YESNO|MB_ICONQUESTION|MB_TOPMOST)==IDYES)
            goto WaitEvent;
        else
            return FALSE;
    }

    if (dwRet!=WAIT_OBJECT_0)
        return FALSE;


    return TRUE;
}
//-----------------------------------------------------------------------------
// Name: UnloadMonitoringFile
// Object: stop monitoring API hooked by the file
// Parameters :
//     in : TCHAR* pszFileName: api monitoring file
// Return : FALSE on error, TRUE if success
//-----------------------------------------------------------------------------
BOOL CApiOverride::UnloadMonitoringFile(TCHAR* pszFileName)
{
    if (!this->bAPIOverrideDllLoaded)
    {
        this->ShowApiOverrideNotStartedMsg();
        return FALSE;
    }

    HANDLE pH[4]={this->hevtMonitoringFileUnloaded,this->hevtError,this->hevtFreeProcess,this->hevtProcessFree};
    STRUCT_COMMAND Cmd;
    Cmd.dwCommand_ID=CMD_UNLOAD_MONITORING_FILE;
    _tcsncpy(Cmd.pszStringParam,pszFileName,MAX_PATH);
    // reset event in case of previous timeout
    ResetEvent(pH[0]);
    ResetEvent(pH[1]);
    if (!this->pMailSlotClient->Write(&Cmd,sizeof(STRUCT_COMMAND)))
    {
        ReportError(_T("Unload Monitoring File Error writing in MailSlot client"));
        return FALSE;
    }

    DWORD dwRet;

WaitEvent:
    dwRet=WaitForMultipleObjects(4,pH,FALSE,TIME_REQUIERED_TO_UNLOAD);
    if (dwRet==WAIT_TIMEOUT)
    {
        if(this->UserMessage(_T("Timeout for unloading. Do you want to wait more ?"),_T("Question"),MB_YESNO|MB_ICONQUESTION|MB_TOPMOST)==IDYES)
            goto WaitEvent;
        else
            return FALSE;
    }

    if (dwRet!=WAIT_OBJECT_0)
        return FALSE;
    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: LoadFakeAPI
// Object: load dll and start faking api/func specified in the specified in the dll
//         (see the Fake API sample for more infos on specifying API in dll)
//         multiple fake library can be hooked at the same time
// Parameters :
//     in : TCHAR* pszFileName: fake api dll name
// Return : TRUE if library is loaded (even if some non fatal errors occurs)
//          and so needs a call to UnloadFakeAPI to restore all hooked func,
//          FALSE if library not loaded 
//-----------------------------------------------------------------------------
BOOL CApiOverride::LoadFakeAPI(TCHAR* pszFileName)
{
    if (!this->bAPIOverrideDllLoaded)
    {
        this->ShowApiOverrideNotStartedMsg();
        return FALSE;
    }

    HANDLE pH[4]={this->hevtFakeAPIDLLLoaded,this->hevtError,this->hevtFreeProcess,this->hevtProcessFree};
    STRUCT_COMMAND Cmd;
    Cmd.dwCommand_ID=CMD_LOAD_FAKE_API_DLL;
    _tcsncpy(Cmd.pszStringParam,pszFileName,MAX_PATH);
    // reset event in case of previous timeout
    ResetEvent(pH[0]);
    ResetEvent(pH[1]);
    if (!this->pMailSlotClient->Write(&Cmd,sizeof(STRUCT_COMMAND)))
    {
        ReportError(_T("Load Fake API error writing in MailSlot client"));
        return FALSE;
    }
    DWORD dwRet;

WaitEvent:
    dwRet=WaitForMultipleObjects(4,pH,FALSE,TIME_REQUIERED_TO_LOAD);
    if (dwRet==WAIT_TIMEOUT)
    {
        if(this->UserMessage(_T("Timeout for loading. Do you want to wait more ?"),_T("Question"),MB_YESNO|MB_ICONQUESTION|MB_TOPMOST)==IDYES)
            goto WaitEvent;
        else
            return FALSE;
    }

    if (dwRet!=WAIT_OBJECT_0)
        return FALSE;
    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: UnloadFakeAPI
// Object: stop faking api/func hooked by the dll before unloading this dll
// Parameters :
//     in : TCHAR* pszFileName: fake api dll name
// Return : FALSE on error, TRUE if success
//-----------------------------------------------------------------------------
BOOL CApiOverride::UnloadFakeAPI(TCHAR* pszFileName)
{
    if (!this->bAPIOverrideDllLoaded)
    {
        this->ShowApiOverrideNotStartedMsg();
        return FALSE;
    }

    HANDLE pH[4]={this->hevtFakeAPIDLLUnloaded,this->hevtError,this->hevtFreeProcess,this->hevtProcessFree};
    STRUCT_COMMAND Cmd;
    Cmd.dwCommand_ID=CMD_UNLOAD_FAKE_API_DLL;
    _tcsncpy(Cmd.pszStringParam,pszFileName,MAX_PATH);
    // reset event in case of previous timeout
    ResetEvent(pH[0]);
    ResetEvent(pH[1]);
    if (!this->pMailSlotClient->Write(&Cmd,sizeof(STRUCT_COMMAND)))
    {
        ReportError(_T("Unload Fake API error writing in MailSlot client"));
        return FALSE;
    }

    DWORD dwRet;

WaitEvent:
    dwRet=WaitForMultipleObjects(4,pH,FALSE,TIME_REQUIERED_TO_UNLOAD);
    if (dwRet==WAIT_TIMEOUT)
    {
        if(this->UserMessage(_T("Timeout for unloading. Do you want to wait more ?"),_T("Question"),MB_YESNO|MB_ICONQUESTION|MB_TOPMOST)==IDYES)
            goto WaitEvent;
        else
            return FALSE;
    }

    if (dwRet!=WAIT_OBJECT_0)
        return FALSE;
    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: StartMonitoring
// Object: restore monitoring until the next StopMonitoring
//         API Override dll do monitoring by default (at start up)
//         So you only need to call this function after a StopMonitoring call
// Parameters :
//     in : 
// Return : TRUE on Success
//-----------------------------------------------------------------------------
BOOL CApiOverride::StartMonitoring()
{
    if (!this->bAPIOverrideDllLoaded)
    {
        this->ShowApiOverrideNotStartedMsg();
        return FALSE;
    }
    SetEvent(this->hevtStartMonitoring);
    return TRUE;
}
//-----------------------------------------------------------------------------
// Name: StopMonitoring
// Object: Temporary stop monitoring until the next StartMonitoring call
// Parameters :
//     in : 
// Return : TRUE on Success
//-----------------------------------------------------------------------------
BOOL CApiOverride::StopMonitoring()
{
    if (!this->bAPIOverrideDllLoaded)
    {
        this->ShowApiOverrideNotStartedMsg();
        return FALSE;
    }
    SetEvent(this->hevtStopMonitoring);
    return TRUE;
}
//-----------------------------------------------------------------------------
// Name: StartFaking
// Object: restore faking until the next StopFaking
//         API Override dll do faking by default (at start up)
//         So you only need to call this function after a StopFaking call
// Parameters :
//     in : 
// Return : TRUE on Success
//-----------------------------------------------------------------------------
BOOL CApiOverride::StartFaking()
{
    if (!this->bAPIOverrideDllLoaded)
    {
        this->ShowApiOverrideNotStartedMsg();
        return FALSE;
    }
    SetEvent(this->hevtStartFaking);
    return TRUE;
}
//-----------------------------------------------------------------------------
// Name: StopFaking
// Object: Temporary stop faking until the next StartFaking call
// Parameters :
//     in : 
// Return : TRUE on Success
//-----------------------------------------------------------------------------
BOOL CApiOverride::StopFaking()
{
    if (!this->bAPIOverrideDllLoaded)
    {
        this->ShowApiOverrideNotStartedMsg();
        return FALSE;
    }
    SetEvent(this->hevtStopFaking);
    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: SetMonitoringModuleFiltersState
// Object: enable or disable filters for monitoring
// Parameters :
//     in : BOOL bEnable : TRUE to enable filters, FALSE to disable them
// Return : 
//-----------------------------------------------------------------------------
BOOL CApiOverride::SetMonitoringModuleFiltersState(BOOL bEnable)
{
    if (!this->bAPIOverrideDllLoaded)
    {
        this->ShowApiOverrideNotStartedMsg();
        return FALSE;
    }

    STRUCT_COMMAND Cmd;
    if (bEnable)
        Cmd.dwCommand_ID=CMD_ENABLE_MODULE_FILTERS_FOR_MONITORING;
    else
        Cmd.dwCommand_ID=CMD_DISABLE_MODULE_FILTERS_FOR_MONITORING;
    if (!this->pMailSlotClient->Write(&Cmd,sizeof(STRUCT_COMMAND)))
    {
        ReportError(_T("Error setting monitoring filters state.\r\nMailSlot write error"));
        return FALSE;
    }
    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: SetFakingModuleFiltersState
// Object: enable or disable filters for faking
// Parameters :
//     in : BOOL bEnable : TRUE to enable filters, FALSE to disable them
// Return : 
//-----------------------------------------------------------------------------
BOOL CApiOverride::SetFakingModuleFiltersState(BOOL bEnable)
{
    if (!this->bAPIOverrideDllLoaded)
    {
        this->ShowApiOverrideNotStartedMsg();
        return FALSE;
    }

    STRUCT_COMMAND Cmd;
    if (bEnable)
        Cmd.dwCommand_ID=CMD_ENABLE_MODULE_FILTERS_FOR_FAKING;
    else
        Cmd.dwCommand_ID=CMD_DISABLE_MODULE_FILTERS_FOR_FAKING;
    if (!this->pMailSlotClient->Write(&Cmd,sizeof(STRUCT_COMMAND)))
    {
        ReportError(_T("Error setting Overriding filters state.\r\nMailSlot write error"));
        return FALSE;
    }
    return TRUE;
}


//-----------------------------------------------------------------------------
// Name: LogOnlyBaseModule
// Object: Allow to log only base module or all modules
// Parameters :
//     in : BOOL bOnlyBaseModule : TRUE to log only base module
// Return : 
//-----------------------------------------------------------------------------
BOOL CApiOverride::LogOnlyBaseModule(BOOL bOnlyBaseModule)
{
    this->bOnlyBaseModule=bOnlyBaseModule;

    if (this->bAPIOverrideDllLoaded)
    {
        STRUCT_COMMAND Cmd;
        if (bOnlyBaseModule)
            Cmd.dwCommand_ID=CMD_START_LOG_ONLY_BASE_MODULE;
        else
            Cmd.dwCommand_ID=CMD_STOP_LOG_ONLY_BASE_MODULE;
        if (!this->pMailSlotClient->Write(&Cmd,sizeof(STRUCT_COMMAND)))
        {
            ReportError(_T("Error setting base module logging option.\r\nMailSlot write error"));
            return FALSE;
        }
    }
    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: Dump
// Object: query the dump interface of the hooked process
// Parameters :
//     in : 
// Return : 
//-----------------------------------------------------------------------------
BOOL CApiOverride::Dump()
{
    if (!this->bAPIOverrideDllLoaded)
    {
        this->ShowApiOverrideNotStartedMsg();
        return FALSE;
    }
    STRUCT_COMMAND Cmd;
    Cmd.dwCommand_ID=CMD_DUMP;
    if (!this->pMailSlotClient->Write(&Cmd,sizeof(STRUCT_COMMAND)))
    {
        ReportError(_T("Error querying dump.\r\nMailSlot write error"));
        return FALSE;
    }
    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: AddNotLoggedModuleListParsLineStatic
// Object: static parse line callback of a Module List file
// Parameters :
//     in : TCHAR* FileName : name of file beeing parsed
//          TCHAR* pszLine : line content
//          DWORD dwLineNumber : line number
//          LPVOID UserParam : CApiOverride* object on which to apply changes
// return : TRUE to continue parsing, FALSE to stop it
//-----------------------------------------------------------------------------
BOOL CApiOverride::AddModuleListParseLineStatic(TCHAR* FileName,TCHAR* pszLine,DWORD dwLineNumber,LPVOID UserParam)
{
    if (IsBadReadPtr(UserParam,sizeof(CApiOverride)))
        return TRUE;
    // re enter object model
    ((CApiOverride*)UserParam)->FilterModuleListParseLine(FileName,pszLine,dwLineNumber,TRUE);

    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: RemoveFromFiltersModuleListParseLineStatic
// Object: static parse line callback of a Module List file
// Parameters :
//     in : TCHAR* FileName : name of file beeing parsed
//          TCHAR* pszLine : line content
//          DWORD dwLineNumber : line number
//          LPVOID UserParam : CApiOverride* object on which to apply changes
// return : TRUE to continue parsing, FALSE to stop it
//-----------------------------------------------------------------------------
BOOL CApiOverride::RemoveModuleListParseLineStatic(TCHAR* FileName,TCHAR* pszLine,DWORD dwLineNumber,LPVOID UserParam)
{
    if (IsBadReadPtr(UserParam,sizeof(CApiOverride)))
        return TRUE;
    // re enter object model
    ((CApiOverride*)UserParam)->FilterModuleListParseLine(FileName,pszLine,dwLineNumber,FALSE);

    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: FilterModuleListParseLine
// Object: parse line of a Module List file
//          and set each module state depending of AddToNotLogged
// Parameters :
//     in : TCHAR* FileName : name of file beeing parsed
//          TCHAR* pszLine : line content
//          DWORD dwLineNumber : line number
//          BOOL AddToList : TRUE to add to filter list, FALSE to remove from filter list
//-----------------------------------------------------------------------------
void CApiOverride::FilterModuleListParseLine(TCHAR* FileName,TCHAR* pszLine,DWORD dwLineNumber,BOOL AddToList)
{
    UNREFERENCED_PARAMETER(FileName);
    UNREFERENCED_PARAMETER(dwLineNumber);
    TCHAR pszFileName[MAX_PATH];
    TCHAR pszPath[MAX_PATH];
    *pszPath=0;

    CTrimString::TrimString(pszLine);
    // empty line
    if (*pszLine==0)
        return;
    // comment line
    if (*pszLine==';')
        return;

    // check application path directory
    if (_tcschr(pszLine,'\\')==0)
    {
        // we don't get full path, so add current exe path
        _tcscpy(pszFileName,this->pszAppPath);
        _tcscat(pszFileName,pszLine);
    }

    // check <windir> flag
    else if (_tcsnicmp(pszLine,_T("<windir>"),8)==0)
    {
        SHGetFolderPath(NULL,CSIDL_WINDOWS,NULL,SHGFP_TYPE_CURRENT,pszPath);

        _tcscpy(pszFileName,pszPath);
        _tcscat(pszFileName,&pszLine[8]);
    }

    // check <system> flag
    else if (_tcsnicmp(pszLine,_T("<system>"),8)==0)
    {
        SHGetFolderPath(NULL,CSIDL_SYSTEM,NULL,SHGFP_TYPE_CURRENT,pszPath);

        _tcscpy(pszFileName,pszPath);
        _tcscat(pszFileName,&pszLine[8]);
    }

    // check <ProgramFiles> flag
    else if (_tcsnicmp(pszLine,_T("<ProgramFiles>"),14)==0)
    {
        SHGetFolderPath(NULL,CSIDL_PROGRAM_FILES,NULL,SHGFP_TYPE_CURRENT,pszPath);

        _tcscpy(pszFileName,pszPath);
        _tcscat(pszFileName,&pszLine[14]);
    }

    // check <ProgramFilesCommon> flag
    else if (_tcsnicmp(pszLine,_T("<ProgramFilesCommon>"),20)==0)
    {
        SHGetFolderPath(NULL,CSIDL_PROGRAM_FILES_COMMON,NULL,SHGFP_TYPE_CURRENT,pszPath);

        _tcscpy(pszFileName,pszPath);
        _tcscat(pszFileName,&pszLine[20]);
    }

    // check <TargetDir> flag
    else if (_tcsnicmp(pszLine,_T("<TargetDir>"),11)==0)
    {
        _tcscpy(pszFileName,this->ProcessPath);
        _tcscat(pszFileName,&pszLine[11+1]);// +1 as this->ProcessPath contains '\'
    }

    else
        // we get full path only copy file name
        _tcscpy(pszFileName,pszLine);

    // don't check that module exists to allow the use of '*' and '?' jokers in name

    // set the log state of the module depending ShouldBeLogged
    this->SetModuleLogState(pszFileName,AddToList);
}

//-----------------------------------------------------------------------------
// Name: AddToFiltersModuleList
// Object: add all modules of a Module List file to filtering modules list
//         use it both for only hooked filters or not hooked
// Parameters :
//     in : TCHAR* FileName : Module List file 
// Return : TRUE on success, FALSE on error
//-----------------------------------------------------------------------------
BOOL CApiOverride::AddToFiltersModuleList(TCHAR* FileName)
{
    return CTextFile::ParseLines(FileName,this->hevtFreeProcess,CApiOverride::AddModuleListParseLineStatic,this);
}

//-----------------------------------------------------------------------------
// Name: RemoveFromFiltersModuleList
// Object: remove all modules of a Module List file from filtering modules list
//         use it both for only hooked filters or not hooked
// Parameters :
//     in : TCHAR* FileName : Module List file 
// Return : TRUE on success, FALSE on error
//-----------------------------------------------------------------------------
BOOL CApiOverride::RemoveFromFiltersModuleList(TCHAR* FileName)
{
    return CTextFile::ParseLines(FileName,this->hevtFreeProcess,RemoveModuleListParseLineStatic,this);
}

//-----------------------------------------------------------------------------
// Name: ClearFiltersModuleList
// Object: clear the not logged modules list --> all modules will be logged
// Parameters :
//     in : 
// Return : TRUE on success, FALSE on error
//-----------------------------------------------------------------------------
BOOL CApiOverride::ClearFiltersModuleList()
{
    if (!this->bAPIOverrideDllLoaded)
    {
        this->ShowApiOverrideNotStartedMsg();
        return FALSE;
    }

    STRUCT_COMMAND Cmd;
    Cmd.dwCommand_ID=CMD_CLEAR_LOGGED_MODULE_LIST_FILTERS;
    if (!this->pMailSlotClient->Write(&Cmd,sizeof(STRUCT_COMMAND)))
    {
        ReportError(_T("Error setting module logging option.\r\nMailSlot write error"));
        return FALSE;
    }
    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: SetModuleLogState
// Object: Allow to log or stop logging calls done by modules
// Parameters :
//     in : TCHAR* pszModuleFullPath : full path of the module
//          BOOL bLog : TRUE to log the specified module
//                      FALSE to stop logging the specified module
//-----------------------------------------------------------------------------
BOOL CApiOverride::SetModuleLogState(TCHAR* pszModuleFullPath,BOOL bLog)
{
    if (!this->bAPIOverrideDllLoaded)
    {
        this->ShowApiOverrideNotStartedMsg();
        return FALSE;
    }

    STRUCT_COMMAND Cmd;
    if (bLog)
        Cmd.dwCommand_ID=CMD_START_MODULE_LOGGING;
    else
        Cmd.dwCommand_ID=CMD_STOP_MODULE_LOGGING;
    _tcsncpy(Cmd.pszStringParam,pszModuleFullPath,MAX_PATH);
    if (!this->pMailSlotClient->Write(&Cmd,sizeof(STRUCT_COMMAND)))
    {
        ReportError(_T("Error setting module logging option.\r\nMailSlot write error"));
        return FALSE;
    }
    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: SetModuleFilteringWay
// Object: Set modules filtering way (inclusion or exclusion)
// Parameters :
//     in : 
//          tagFilteringWay FilteringWay : FILTERING_WAY_ONLY_SPECIFIED_MODULES
//                                         or FILTERING_WAY_NOT_SPECIFIED_MODULES
//-----------------------------------------------------------------------------
BOOL CApiOverride::SetModuleFilteringWay(tagFilteringWay FilteringWay)
{
    if (!this->bAPIOverrideDllLoaded)
    {
        this->ShowApiOverrideNotStartedMsg();
        return FALSE;
    }

    STRUCT_COMMAND Cmd;
    Cmd.dwCommand_ID=CMD_SET_LOGGED_MODULE_LIST_FILTERS_WAY;
    Cmd.Param[0]=(DWORD)FilteringWay;
    if (!this->pMailSlotClient->Write(&Cmd,sizeof(STRUCT_COMMAND)))
    {
        ReportError(_T("Error setting filtering option.\r\nMailSlot write error"));
        return FALSE;
    }
    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: GetNotLoggedModuleList
// Object: Allow to retrieve a list of not loaded modules
// Parameters :
//     out : TCHAR*** pArrayNotLoggedModulesNames : pointer filled by a TCHAR[*pdwArrayNotLoggedModulesNamesSize][MAX_PATH]
//                                                 MUST BE FREE if *pdwArrayNotLoggedModulesNamesSize>0 by delete[] *pArrayNotLoggedModulesNames;
//                      sample of use
//                                TCHAR** pNotLoggedArray=NULL;
//                                DWORD dwNbNotLoggedModules=0;
//                                GetNotLoggedModuleList(&pNotLoggedArray,&dwNbNotLoggedModules);
//                                if (pNotLoggedArray) //  in case of dwNbNotLoggedModules==0
//                                        delete[] pNotLoggedArray;
//           DWORD* pdwArrayNotLoggedModulesNamesSize : number of module names
// Return : FALSE on error, TRUE on success
//-----------------------------------------------------------------------------
BOOL CApiOverride::GetNotLoggedModuleList(TCHAR*** pArrayNotLoggedModulesNames,DWORD* pdwArrayNotLoggedModulesNamesSize)
{
    // check parameters
    if (IsBadWritePtr(pArrayNotLoggedModulesNames,sizeof(TCHAR**))
        ||IsBadWritePtr(pdwArrayNotLoggedModulesNamesSize,sizeof(DWORD)))
        return FALSE;

    // init vars in case of failure
    *pdwArrayNotLoggedModulesNamesSize=0;
    *pArrayNotLoggedModulesNames=NULL;

    // assume dll is loaded
    if (!this->bAPIOverrideDllLoaded)
    {
        this->ShowApiOverrideNotStartedMsg();
        return FALSE;
    }

    // reset events
    ResetEvent(this->hevtGetNotLoggedModulesReply);
    ResetEvent(this->hevtError);

    // send query command
    STRUCT_COMMAND Cmd;
    Cmd.dwCommand_ID=CMD_NOT_LOGGED_MODULE_LIST_QUERY;
    if (!this->pMailSlotClient->Write(&Cmd,sizeof(STRUCT_COMMAND)))
    {
        ReportError(_T("Error setting module logging option.\r\nMailSlot write error"));
        return FALSE;
    }

    // wait until list reply or error
    HANDLE ph[2]={this->hevtGetNotLoggedModulesReply,this->hevtError};
    if (WaitForMultipleObjects(2,ph,FALSE,APIOVERRIDE_CMD_REPLY_MAX_TIME_IN_MS)!=WAIT_OBJECT_0)
        return FALSE;

    // fill returned vars
    *pdwArrayNotLoggedModulesNamesSize=this->NotLoggedModulesArraySize;
    *pArrayNotLoggedModulesNames=(TCHAR**)this->NotLoggedModulesArray;

    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: Stop
// Object: stop monitoring and faking and eject all dll of the current used process
// Parameters :
//     in : 
// Return : FALSE on error, TRUE if success
//-----------------------------------------------------------------------------
BOOL CApiOverride::Stop()
{
    return this->Stop(FALSE);
}

//-----------------------------------------------------------------------------
// Name: Stop
// Object: stop monitoring and faking and eject all dll of the current used process
// Parameters :
//     in : BOOL bCalledByhThreadWatchingEvents : TRUE if called inside thread hThreadWatchingEvents
//                                                flag to avoid deadlocks
// Return : FALSE on error, TRUE if success
//-----------------------------------------------------------------------------
BOOL CApiOverride::Stop(BOOL bCalledByhThreadWatchingEvents)
{
    TCHAR psz[2*MAX_PATH];
    int iMsgBoxRes=IDYES;
    DWORD dwRes;

    // assume Stop function is not called simultaneously by multiple threads
    WaitForSingleObject(this->hStopUnlocked,INFINITE);

    // reset event of injected dll 
    ResetEvent(this->hevtProcessFree);

    // ask the injected dll to stop its job / or 
    SetEvent(this->hevtFreeProcess);

    // avoid to wait if hooked process has crashed or has been killed
    if(CProcessHelper::IsAlive(this->dwCurrentProcessId))
    {
        // if api override is loaded wait for its hevtProcessFree event
        if (this->bAPIOverrideDllLoaded)
        {
            while(iMsgBoxRes==IDYES)
            {
                
                dwRes=WaitForSingleObject(this->hevtProcessFree,TIME_REQUIERED_TO_UNLOAD);
                
                switch(dwRes)
                {
                case WAIT_OBJECT_0:
                case WAIT_FAILED:
                    // end while loop
                    iMsgBoxRes=IDNO;
                    break;
                default:
                    // put the user aware and hope he will do actions that unlock fake api
                    // a good sample of blocking fake api are MessageBox
                    _stprintf(psz,
                            _T("Warning %s seems to be still not unloaded from host process 0x")
                            _T("%.8X"),
                            API_OVERRIDE_DLL_NAME,
                            this->dwCurrentProcessId);
                    if (this->ProcessName)
                    {
                        _tcscat(psz,_T(" ("));
                        _tcscat(psz,this->ProcessName);
                        _tcscat(psz,_T(")"));
                    }
                    _tcscat(psz,_T("\r\nAssume that Overrided API are not in a blocking state.\r\nDo you want to wait more time ?"));
                    iMsgBoxRes=MessageBox(this->hParentWindow,psz,_T("Warning"),MB_YESNO|MB_ICONWARNING|MB_TOPMOST);
                    break;
                }
            }
        }
        // eject apioverride DLL
        if (this->pEjectLib)
        {
            _tcscpy(psz,this->pszAppPath);
            _tcscat(psz,API_OVERRIDE_DLL_NAME);
            this->pEjectLib(this->dwCurrentProcessId,psz);
        }
    }

    // if watching thread events has been launched
    if (this->hThreadWatchingEvents)
    {
        // if Stop not called internally by hThreadWatchingEvents
        if (!bCalledByhThreadWatchingEvents)
        {
            // wait the end of watching thread events
            // to assume that DllUnloadedCallBack has finished to be executed
            WaitForSingleObject(this->hThreadWatchingEvents,TIME_REQUIERED_TO_UNLOAD);
        }
    }

    if (this->pMailSlotServer)
    {
        delete this->pMailSlotServer;
        this->pMailSlotServer=NULL;
    }
    if (this->pMailSlotClient)
    {
        delete this->pMailSlotClient;
        this->pMailSlotClient=NULL;
    }

    // close handle associated with thread
    CleanCloseHandle(&this->hThreadWatchingEvents);
    CleanCloseHandle(&this->hThreadLogging);

    // close events handle
    CleanCloseHandle(&this->hevtStartMonitoring);
    CleanCloseHandle(&this->hevtStopMonitoring);
    CleanCloseHandle(&this->hevtStartFaking);
    CleanCloseHandle(&this->hevtStopFaking);
    CleanCloseHandle(&this->hevtFreeProcess);

    CleanCloseHandle(&this->hevtAPIOverrideDllProcessAttachCompleted);
    CleanCloseHandle(&this->hevtAPIOverrideDllProcessDetachCompleted);
    CleanCloseHandle(&this->hevtProcessFree);
    CleanCloseHandle(&this->hevtMonitoringFileLoaded);
    CleanCloseHandle(&this->hevtMonitoringFileUnloaded);
    CleanCloseHandle(&this->hevtFakeAPIDLLLoaded);
    CleanCloseHandle(&this->hevtFakeAPIDLLUnloaded);
    CleanCloseHandle(&this->hevtError);

    // set unloaded state
    this->bAPIOverrideDllLoaded=FALSE;

    // unlock calls to Stop
    SetEvent(this->hStopUnlocked);

    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: Start
// Object: inject API Override dll in selected process ID to allow monitoring and faking
// Parameters :
//     in : DWORD dwPID : PID of process fully loaded. If Nt loader don't have finished to load process
//                        this func will probably failed
// Return : FALSE on error, TRUE if success
//-----------------------------------------------------------------------------
BOOL CApiOverride::Start(DWORD dwPID)
{
    if(!this->InitializeStart(dwPID))
        return FALSE;

    if(!this->InjectDllByCreateRemoteThread(dwPID))
        return FALSE;

    // wait for load events
    if (!this->WaitForInjectedDllToBeLoaded())
        return FALSE;

    // send settings
    this->SetOptions();

    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: InjectDllByCreateRemoteThread
// Object: inject API Override dll in selected process ID to allow monitoring and faking
// Parameters :
//     in : DWORD dwPID : PID of process fully loaded. If Nt loader don't have finished to load process
//                        this func will probably failed
// Return : FALSE on error, TRUE if success
//-----------------------------------------------------------------------------
BOOL CApiOverride::InjectDllByCreateRemoteThread(DWORD dwPID)
{
    if (!this->pInjectLib)
        return FALSE;

    TCHAR psz[MAX_PATH];
    TCHAR pszMsg[MAX_PATH];
    
    // make injected full path
    _tcscpy(psz,this->pszAppPath);
    _tcscat(psz,API_OVERRIDE_DLL_NAME);

    // reset load events
    this->ResetInjectedDllLoadEvents();

    // try to inject library
    if (!this->pInjectLib(dwPID,psz))
    {
        _sntprintf(pszMsg,MAX_PATH,_T("Error injecting library %s"),API_OVERRIDE_DLL_NAME);
        ReportError(pszMsg);
        this->Stop();
        return FALSE;
    }

    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: SetOptions
// Object: Set options after successful dll loading
// Parameters :
//     in : 
// Return : 
//-----------------------------------------------------------------------------
void CApiOverride::SetOptions()
{
    this->SetAutoAnalysis(this->AutoAnalysis);
    this->LogOnlyBaseModule(this->bOnlyBaseModule);
    this->SetCallSackRetrieval(this->bLogCallStack,this->CallStackEbpRetrievalSize);
    this->BreakDialogDontBreakApioverrideThreads(this->bBreakDialogDontBreakApioverrideThreads);
    this->SetMonitoringFileDebugMode(this->bMonitoringFileDebugMode);

    this->SetCOMOptions(&this->ComHookingOptions);
    if (this->bComAutoHookingEnabled)
    {
        // set com hooking options before starting com monitoring
        this->EnableCOMAutoHooking(this->bComAutoHookingEnabled);
    }
}

//-----------------------------------------------------------------------------
// Name: ResetInjectedDllLoadEvents
// Object: Reset event before a call to WaitForInjectedDllToBeLoaded
//          call order 1) ResetInjectedDllLoadEvents
//                     2) Do an action that loads the dll in remote process
//                     3) call WaitForInjectedDllToBeLoaded
// Parameters :
//     in : 
// Return : FALSE on error, TRUE if success
//-----------------------------------------------------------------------------
void CApiOverride::ResetInjectedDllLoadEvents()
{
    ResetEvent(this->hevtAPIOverrideDllProcessAttachCompleted);
    ResetEvent(this->hevtError);
    ResetEvent(this->hevtFreeProcess);
    ResetEvent(this->hevtProcessFree);
}
//-----------------------------------------------------------------------------
// Name: WaitForInjectedDllToBeLoaded
// Object: wait for the injected library to become ready and create mailslot client
// Parameters :
//     in : 
// Return : FALSE on error, TRUE if success
//-----------------------------------------------------------------------------
BOOL CApiOverride::WaitForInjectedDllToBeLoaded()
{
    TCHAR pszMsg[MAX_PATH];
    TCHAR psz[MAX_PATH];
    HANDLE pH[4];
    DWORD dwRet;

    // define events
    pH[0]=this->hevtAPIOverrideDllProcessAttachCompleted;
    pH[1]=this->hevtError;
    pH[2]=this->hevtFreeProcess;
    pH[3]=this->hevtProcessFree;

    // library is supposed to be loaded now
    this->bAPIOverrideDllLoaded=TRUE;

WaitEvent:
    // wait for Ready to Work event
    dwRet=WaitForMultipleObjects(4,pH,FALSE,TIME_REQUIERED_TO_LOAD);
    switch(dwRet)
    {
        case WAIT_TIMEOUT:    // time out
            _sntprintf(pszMsg,MAX_PATH,_T("Error %s don't become ready\r\nDo you want to wait more ?"),API_OVERRIDE_DLL_NAME);
            if (this->UserMessage(pszMsg,_T("Question"),MB_YESNO|MB_ICONQUESTION|MB_TOPMOST)==IDYES)
                goto WaitEvent;
            this->Stop();
            return FALSE;
        case WAIT_OBJECT_0:   // all is ok
            break;
        case WAIT_OBJECT_0+1: // error dll is no more loaded
            this->bAPIOverrideDllLoaded=FALSE;
            this->Stop();
            return FALSE;
        case WAIT_OBJECT_0+2: 
        case WAIT_OBJECT_0+3: 
            return FALSE;
        default:// wait failed
            this->Stop();
            return FALSE;
    }

    // start mailslot client for giving instructions (it can't be open before the Ready to Work event)
    TCHAR pszPID[32];
    // pid -> string
    _stprintf(pszPID,_T("0x%X"),this->dwCurrentProcessId);
    _tcscpy(psz,APIOVERRIDE_MAILSLOT_FROM_INJECTOR);
    _tcscat(psz,pszPID);
    this->pMailSlotClient=new CMailSlotClient(psz);
    if (!pMailSlotClient->Open())
    {
        ReportError(_T("Can't open MailSlot"));
        this->Stop();
        return FALSE;
    }

    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: Start
// Object: initialize all named event and mailslots
// Parameters :
//     in : DWORD dwPID
// Return : FALSE on error, TRUE if success
//-----------------------------------------------------------------------------
BOOL CApiOverride::InitializeStart(DWORD dwPID)
{
    TCHAR psz[MAX_PATH];
    TCHAR pszMsg[MAX_PATH];
    TCHAR pszPID[32];

    // store pid
    this->dwCurrentProcessId=dwPID;

    *this->ProcessName=0;
    CProcessHelper::GetProcessFullPath(dwPID,psz);
    
    _tcscpy(this->ProcessName,CStdFileOperations::GetFileName(psz));
    CStdFileOperations::GetFilePath(psz,this->ProcessPath,MAX_PATH);

    // check if we are started
    if (this->bAPIOverrideDllLoaded)
        this->Stop();

    // check if injlib dll is loaded
    if ((this->pInjectLib==NULL)||(this->pEjectLib==NULL))
    {
        _sntprintf(pszMsg,MAX_PATH,_T("Error loading %s. Make sure file exists and restart application"),INJECTLIB_DLL_NAME);
        ReportError(pszMsg);
        return FALSE;
    }

    // check if apioverride dll exists avoid lost of time
    _tcscpy(psz,this->pszAppPath);
    _tcscat(psz,API_OVERRIDE_DLL_NAME);

    if (!CStdFileOperations::DoesFileExists(psz))
    {
        _sntprintf(pszMsg,MAX_PATH,_T("Error %s not found. Make sure file exists and restart application"),API_OVERRIDE_DLL_NAME);
        ReportError(pszMsg);
        return FALSE;
    }
   
    // pid -> string
    _stprintf(pszPID,_T("0x%X"),dwPID);

    // create interprocess communication events

    //HANDLE CreateEvent(
    //    LPSECURITY_ATTRIBUTES lpEventAttributes,
    //    BOOL bManualReset,
    //    BOOL bInitialState,
    //    LPCTSTR lpName
    //    );

    // set event accessible for all account. Doing this allow to event to be opened by other user
    // --> we can inject dll into processes running under other users accounts
    SECURITY_DESCRIPTOR sd={0};
    sd.Revision=SECURITY_DESCRIPTOR_REVISION;
    sd.Control=SE_DACL_PRESENT;
    sd.Dacl=NULL; // assume everyone access
    SECURITY_ATTRIBUTES SecAttr={0};
    SecAttr.bInheritHandle=FALSE;
    SecAttr.nLength=sizeof(SECURITY_ATTRIBUTES);
    SecAttr.lpSecurityDescriptor=&sd;


    //(Injector -> APIOverride.dll)
    _tcscpy(psz,APIOVERRIDE_EVENT_START_MONITORING);
    _tcscat(psz,pszPID);
    
    this->hevtStartMonitoring=CreateEvent(&SecAttr,FALSE,TRUE,psz);
    if (GetLastError()==ERROR_ALREADY_EXISTS)
    {
        CleanCloseHandle(&this->hevtStartMonitoring);
        _sntprintf(pszMsg,MAX_PATH,_T("Error another application seems to have inject API override"),pszPID);
        ReportError(pszMsg);
        return FALSE;
    }
    _tcscpy(psz,APIOVERRIDE_EVENT_STOP_MONITORING);
    _tcscat(psz,pszPID);
    this->hevtStopMonitoring=CreateEvent(&SecAttr,FALSE,FALSE,psz);
    _tcscpy(psz,APIOVERRIDE_EVENT_START_FAKING);
    _tcscat(psz,pszPID);
    this->hevtStartFaking=CreateEvent(&SecAttr,FALSE,TRUE,psz);
    _tcscpy(psz,APIOVERRIDE_EVENT_STOP_FAKING);
    _tcscat(psz,pszPID);
    this->hevtStopFaking=CreateEvent(&SecAttr,FALSE,FALSE,psz);
    _tcscpy(psz,APIOVERRIDE_EVENT_FREE_PROCESS);
    _tcscat(psz,pszPID);
    this->hevtFreeProcess=CreateEvent(&SecAttr,TRUE,FALSE,psz);// must be manual reset event, even for injected dll
        
    // (APIOverride.dll -> Injector)
    _tcscpy(psz,APIOVERRIDE_EVENT_DLLPROCESS_ATTACH_COMPLETED);
    _tcscat(psz,pszPID);
    this->hevtAPIOverrideDllProcessAttachCompleted=CreateEvent(&SecAttr,FALSE,FALSE,psz);
    _tcscpy(psz,APIOVERRIDE_EVENT_DLL_DETACHED_COMPLETED);
    _tcscat(psz,pszPID);
    this->hevtAPIOverrideDllProcessDetachCompleted=CreateEvent(&SecAttr,FALSE,FALSE,psz);
    _tcscpy(psz,APIOVERRIDE_EVENT_PROCESS_FREE);
    _tcscat(psz,pszPID);
    this->hevtProcessFree=CreateEvent(&SecAttr,TRUE,FALSE,psz);
    _tcscpy(psz,APIOVERRIDE_EVENT_MONITORING_FILE_LOADED);
    _tcscat(psz,pszPID);
    this->hevtMonitoringFileLoaded=CreateEvent(&SecAttr,FALSE,FALSE,psz);
    _tcscpy(psz,APIOVERRIDE_EVENT_MONITORING_FILE_UNLOADED);
    _tcscat(psz,pszPID);
    this->hevtMonitoringFileUnloaded=CreateEvent(&SecAttr,FALSE,FALSE,psz);
    _tcscpy(psz,APIOVERRIDE_EVENT_FAKE_API_DLL_LOADED);
    _tcscat(psz,pszPID);
    this->hevtFakeAPIDLLLoaded=CreateEvent(&SecAttr,FALSE,FALSE,psz);
    _tcscpy(psz,APIOVERRIDE_EVENT_FAKE_API_DLL_UNLOADED);
    _tcscat(psz,pszPID);
    this->hevtFakeAPIDLLUnloaded=CreateEvent(&SecAttr,FALSE,FALSE,psz);
    _tcscpy(psz,APIOVERRIDE_EVENT_ERROR);
    _tcscat(psz,pszPID);
    this->hevtError=CreateEvent(&SecAttr,FALSE,FALSE,psz);


    if (!(this->hevtStartMonitoring&&this->hevtStopMonitoring&&this->hevtStartFaking&&this->hevtStopFaking&&this->hevtFreeProcess
            &&this->hevtAPIOverrideDllProcessAttachCompleted&&this->hevtAPIOverrideDllProcessDetachCompleted&&this->hevtProcessFree
            &&this->hevtMonitoringFileLoaded&&this->hevtMonitoringFileUnloaded
            &&this->hevtFakeAPIDLLLoaded&&this->hevtFakeAPIDLLUnloaded
            &&this->hevtError
            ))
    {
        ReportError(_T("Error creating named events"));
        return FALSE;
    }

    // start mailslot server for monitoring event logging (must be start before injecting API_OVERRIDE_DLL)
    _tcscpy(psz,APIOVERRIDE_MAILSLOT_TO_INJECTOR);
    _tcscat(psz,pszPID);
    pMailSlotServer=new CMailSlotServer(psz,StaticMailSlotServerCallback,this);
    if (!pMailSlotServer->Start(TRUE))
    {
        _sntprintf(pszMsg,MAX_PATH,_T("Error starting mailslot server %s"),psz);
        ReportError(pszMsg);
        this->Stop();
        return FALSE;
    }

    // start thread to watch hevtAPIOverrideDllProcessDetachCompleted
    this->hThreadWatchingEvents=CreateThread(NULL,0,CApiOverride::DllUnloadedThreadListener,this,0,NULL);

    return TRUE;
}
//-----------------------------------------------------------------------------
// Name: Start
// Object: start the software specified by pszFileName, inject API Override dll at start up
// Parameters :
//     in : TCHAR* pszFileName : path of software to start
// Return : FALSE on error, TRUE if success
//-----------------------------------------------------------------------------
BOOL CApiOverride::Start(TCHAR* pszFileName)
{
    return this->Start(pszFileName,NULL,NULL);
}

//-----------------------------------------------------------------------------
// Name: Start
// Object: start the software specified by pszFileName, inject API Override dll at start up,
//         call pCallBackFunc function  to allow to configure monitoring and faking
//         resume process when callback function returns
// Parameters :
//     in : TCHAR* pszFileName : path of software to start
//          FARPROC pCallBackFunc : instruction to do after pszFileName loading and before we resume the process
//                                          let us load monitoring file and fake api dll before software startup
//          LPVOID pUserParam : parameter for the callback
// Return : FALSE on error, TRUE if success
//-----------------------------------------------------------------------------
BOOL CApiOverride::Start(TCHAR* pszFileName,tagpCallBackBeforeAppResume pCallBackFunc,LPVOID pUserParam)
{
    return this->Start(pszFileName,_T(""),pCallBackFunc,pUserParam);
}

//-----------------------------------------------------------------------------
// Name: Start
// Object: start the software specified by pszFileName, inject API Override dll at start up,
//         call pCallBackFunc function  to allow to configure monitoring and faking
//         resume process when callback function returns
// Parameters :
//     in : TCHAR* pszFileName : path of software to start
//          TCHAR* pszCmdLine  : command line
//          FARPROC pCallBackFunc : instruction to do after pszFileName loading and before we resume the process
//                                          let us load monitoring file and fake api dll before software startup
//          LPVOID pUserParam : parameter for the callback
// Return : FALSE on error, TRUE if success
//-----------------------------------------------------------------------------
BOOL CApiOverride::Start(TCHAR* pszFileName,TCHAR* pszCmdLine,tagpCallBackBeforeAppResume pCallBackFunc,LPVOID pUserParam)
{
    return this->Start(pszFileName,pszCmdLine,pCallBackFunc,pUserParam,CApiOverride::StartWaySuspended,0);
}


//-----------------------------------------------------------------------------
// Name: Start
// Object: start the software specified by pszFileName, inject API Override dll at start up,
//         call pCallBackFunc function  to allow to configure monitoring and faking
//         Process is resume at Startup during dwResumeTimeAtStartup ms
//         resume process when callback function returns
// Parameters :
//     in : TCHAR* pszFileName : path of software to start
//          TCHAR* pszCmdLine  : command line
//          FARPROC pCallBackFunc : instruction to do after pszFileName loading and before we resume the process
//                                          let us load monitoring file and fake api dll before software startup
//          LPVOID pUserParam : parameter for the callback
//          StartWays StartMethod : Suspended, Sleep
//          DWORD dwResumeTimeAtStartup : Time in ms during which process will be resumed at startup
// Return : FALSE on error, TRUE if success
//-----------------------------------------------------------------------------
BOOL CApiOverride::Start(TCHAR* pszFileName,TCHAR* pszCmdLine,tagpCallBackBeforeAppResume pCallBackFunc,LPVOID pUserParam,StartWays StartMethod,DWORD dwResumeTimeAtStartup)
{
    STARTUPINFO StartupInfo;
    PROCESS_INFORMATION ProcessInformation;
    TCHAR* pszFileNameDirectory;
    TCHAR* pszLastSep=NULL;
    TCHAR* pszDir;
    BOOL bRet;
    TCHAR pszMsg[2*MAX_PATH];
    TCHAR* pszCmdLineWithSpace;

    // check if file exists
    if (!CStdFileOperations::DoesFileExists(pszFileName))
    {
        _sntprintf(pszMsg,2*MAX_PATH,_T("File %s not found"),pszFileName);
        ReportError(pszMsg);
        return FALSE;
    }


    memset(&ProcessInformation,0,sizeof(PROCESS_INFORMATION));
    memset(&StartupInfo,0,sizeof(STARTUPINFO));
    StartupInfo.cb=sizeof(STARTUPINFO);

    // get software directory 
    pszDir=_tcsdup(pszFileName);
    pszLastSep=_tcsrchr(pszDir,'\\');
    if (pszLastSep)
    {
        *pszLastSep=0;
        pszFileNameDirectory=pszDir;
    }
    else // work in current dir
        pszFileNameDirectory=NULL;


    switch (StartMethod)
    {
    case CApiOverride::StartWaySleep:
        // add a space before cmd line because CreateProcess sucks a little (first arg is lost by launched app)
        pszCmdLineWithSpace=new TCHAR[_tcslen(pszCmdLine)+2];
        _tcscpy(pszCmdLineWithSpace,_T(" "));
        _tcscat(pszCmdLineWithSpace,pszCmdLine);

        // Load Process in a suspended mode
        bRet=CreateProcess( pszFileName,                //LPCTSTR lpApplicationName,
                            pszCmdLineWithSpace,        //LPTSTR lpCommandLine,
                            NULL,                       //LPSECURITY_ATTRIBUTES lpProcessAttributes,
                            NULL,                       //LPSECURITY_ATTRIBUTES lpThreadAttributes,
                            FALSE,                      //BOOL bInheritHandles,
                            CREATE_DEFAULT_ERROR_MODE,  //DWORD dwCreationFlags,
                            NULL,                       //LPVOID lpEnvironment,
                            pszFileNameDirectory,       //LPCTSTR lpCurrentDirectory,
                            &StartupInfo,               //LPSTARTUPINFO lpStartupInfo,
                            &ProcessInformation         //LPPROCESS_INFORMATION lpProcessInformation
                            );
        delete pszCmdLineWithSpace;
        free(pszDir);
        if (!bRet)
        {
            // show last error
            CAPIError::ShowLastError();
            return FALSE;
        }
        // sleep if necessary
        if (dwResumeTimeAtStartup)
            Sleep(dwResumeTimeAtStartup);

        // suspend Process main thread
        if (SuspendThread(ProcessInformation.hThread)==0xFFFFFFFF)
        {
            // show last error
            CAPIError::ShowLastError();
            TerminateProcess(ProcessInformation.hProcess,0xFFFFFFFF);
            CloseHandle(ProcessInformation.hThread);
            CloseHandle(ProcessInformation.hProcess);
            return FALSE;
        }

        // Do all work
        if (!this->Start(ProcessInformation.dwProcessId))
        {
            TerminateProcess(ProcessInformation.hProcess,0xFFFFFFFF);
            CloseHandle(ProcessInformation.hThread);
            CloseHandle(ProcessInformation.hProcess);
            return FALSE;
        }


        break;
    case CApiOverride::StartWaySuspended:
        // add a space before cmd line because CreateProcess sucks a little (first arg is lost by launched app)
        pszCmdLineWithSpace=new TCHAR[_tcslen(pszCmdLine)+2];
        _tcscpy(pszCmdLineWithSpace,_T(" "));
        _tcscat(pszCmdLineWithSpace,pszCmdLine);

        // Load Process in a suspended mode
        bRet=CreateProcess( pszFileName,                //LPCTSTR lpApplicationName,
                            pszCmdLineWithSpace,        //LPTSTR lpCommandLine,
                            NULL,                       //LPSECURITY_ATTRIBUTES lpProcessAttributes,
                            NULL,                       //LPSECURITY_ATTRIBUTES lpThreadAttributes,
                            FALSE,                      //BOOL bInheritHandles,
                            CREATE_SUSPENDED | CREATE_DEFAULT_ERROR_MODE,           //DWORD dwCreationFlags,
                            NULL,                       //LPVOID lpEnvironment,
                            pszFileNameDirectory,       //LPCTSTR lpCurrentDirectory,
                            &StartupInfo,               //LPSTARTUPINFO lpStartupInfo,
                            &ProcessInformation         //LPPROCESS_INFORMATION lpProcessInformation
                            );
        delete pszCmdLineWithSpace;
        free(pszDir);
        if (!bRet)
        {
            // show last error
            CAPIError::ShowLastError();
            return FALSE;
        }

        // initialize events
        this->InitializeStart(ProcessInformation.dwProcessId);

        // set process name as InitializeStart failed to set it
        _tcscpy(this->ProcessName,CStdFileOperations::GetFileName(pszFileName));
        CStdFileOperations::GetFilePath(pszFileName,this->ProcessPath,MAX_PATH);

        // reset load events
        this->ResetInjectedDllLoadEvents();

        // load library at entry point
        if(!this->HookEntryPoint(pszFileName,ProcessInformation.dwProcessId,ProcessInformation.hThread))
        {
            // free data allocated by HookEntryPoint
            ResumeThread(ProcessInformation.hThread);
            this->HookEntryPointFree();

            // close handle to launched process
            CloseHandle(ProcessInformation.hThread);
            CloseHandle(ProcessInformation.hProcess);

            return FALSE;
        }

        // wait for the library to be loaded
        if (!this->WaitForInjectedDllToBeLoaded())
        {
            // free data allocated by HookEntryPoint
            ResumeThread(ProcessInformation.hThread);
            this->HookEntryPointFree();

            // close handle to launched process
            CloseHandle(ProcessInformation.hThread);
            CloseHandle(ProcessInformation.hProcess);

            return FALSE;
        }

        break;
    default:
        return FALSE;
    }

    // send settings
    this->SetOptions();

    // call the call back if any (let us load monitoring file and fake api dll before software startup)
     if (!IsBadCodePtr((FARPROC)pCallBackFunc))
        pCallBackFunc(this->dwCurrentProcessId,pUserParam);


    // Resume Process main thread
    if (ResumeThread(ProcessInformation.hThread)==((DWORD)-1))
    {
        // show last error
        CAPIError::ShowLastError();
        this->Stop();
        TerminateProcess(ProcessInformation.hProcess,0xFFFFFFFF);
        CloseHandle(ProcessInformation.hThread);
        CloseHandle(ProcessInformation.hProcess);
        return FALSE;
    }

    if (StartMethod==CApiOverride::StartWaySuspended)
    {
        this->HookEntryPointFree();
    }

    CloseHandle(ProcessInformation.hThread);
    CloseHandle(ProcessInformation.hProcess);
    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: StaticMailSlotServerCallback
// Object: callback for log events
// Parameters :
//     in : PVOID pData : pointer to a tagLogEntry struct
//          PVOID pUserData : pointer to CApiOverride object belonging the MailSlotServer which reach the event
// Return : 
//-----------------------------------------------------------------------------
void CApiOverride::StaticMailSlotServerCallback(PVOID pData,DWORD dwDataSize,PVOID pUserData)
{
    if (dwDataSize==0)
        return;
    // re enter object oriented programming
    ((CApiOverride*)pUserData)->MailSlotServerCallback(pData,dwDataSize);
}

//-----------------------------------------------------------------------------
// Name: MailSlotServerCallback
// Object: internal callback for log events
// Parameters :
//     in : PVOID pData : pointer to a buffer send by injected dll
//          DWORD dwDataSize : pData size 
// Return : 
//-----------------------------------------------------------------------------
void CApiOverride::MailSlotServerCallback(PVOID pData,DWORD dwDataSize)
{
    DWORD msgCmd;
    DWORD ReplySize;
    PBYTE pbData=(PBYTE)pData;
    

    // check message size
    if (dwDataSize<sizeof(DWORD))
        return;

    memcpy(&msgCmd,pData,sizeof(DWORD));
    pbData+=sizeof(DWORD);
    switch (msgCmd)
    {
    case CMD_PROCESS_INTERNAL_CALL_REPLY:
        {
            CLinkListItem* pItem;
            REMOTE_CALL_INFOS* pRemoteCallItem;
            BOOL bFound=FALSE;

            // check message size
            if (dwDataSize<(2*sizeof(DWORD)))
                return;

            memcpy(&ReplySize,pbData,sizeof(DWORD));
            // point after reply size
            pbData+=sizeof(DWORD);

            // check message size
            if (dwDataSize<(sizeof(DWORD)+ReplySize))// reply size include the ReplySize Field
                return;

            // check if user still waits for function return
            // (= ID is still in pCurrentRemoteCalls list)
            pItem=this->pCurrentRemoteCalls->Head;
            while(pItem)
            {
                if (pItem->ItemData==*((PVOID*)pbData))
                {
                    bFound=TRUE;
                    break;
                }
                pItem=pItem->NextItem;
            }
            if (!bFound)
                return;

            // ID is still in list --> memory is still valid
            pRemoteCallItem=*((REMOTE_CALL_INFOS**)pbData);

            pRemoteCallItem->ProcessInternalCallReply=new BYTE[ReplySize];

            // restore pbData value (point before reply size as it's needed for decoding)
            pbData-=sizeof(DWORD);
            memcpy(pRemoteCallItem->ProcessInternalCallReply,pbData,ReplySize);
            SetEvent(pRemoteCallItem->hevtProcessInternalCallReply);
            return;
        }
    case CMD_NOT_LOGGED_MODULE_LIST_REPLY:
        // check message size
        if (dwDataSize<(2*sizeof(DWORD)))
                return;

        memcpy(&ReplySize,pbData,sizeof(DWORD));
        pbData+=sizeof(DWORD);

        // check message size
        if (dwDataSize<(sizeof(DWORD)+ReplySize))// reply size include the ReplySize Field
                return;

        this->NotLoggedModulesArraySize=ReplySize;
        if (ReplySize>0)
        {
            this->NotLoggedModulesArray=new BYTE[ReplySize*MAX_PATH*sizeof(TCHAR)];
            memcpy(this->NotLoggedModulesArray,pbData,ReplySize*MAX_PATH*sizeof(TCHAR));
        }
        else
            this->NotLoggedModulesArray=NULL;
        SetEvent(this->hevtGetNotLoggedModulesReply);
        return;
    case CMD_MONITORING_LOG:
        {
            // check message size
            if (dwDataSize<(2*sizeof(DWORD)))
                return;

            memcpy(&ReplySize,pbData,sizeof(DWORD));
            pbData+=sizeof(DWORD);

            // check message size
            if (dwDataSize<(2*sizeof(DWORD)+ReplySize))// reply size don't include the ReplySize Field
                return;

            // call monitoring call back
            this->MonitoringCallback(pbData);

            return;
        }
    case CMD_REPORT_MESSAGE:
        {
            // check message size
            if (dwDataSize<(2*sizeof(DWORD)+sizeof(TCHAR)))
                return;

            DWORD ReportMessageType;
            DWORD StringLength; // string length in bytes

            memcpy(&ReportMessageType,pbData,sizeof(DWORD));
            pbData+=sizeof(DWORD);

            memcpy(&StringLength,pbData,sizeof(DWORD));
            pbData+=sizeof(DWORD);

            // check message size
            if (dwDataSize<(2*sizeof(DWORD)+StringLength))
                return;

            // call report callback
            if (!IsBadCodePtr((FARPROC)this->pCallBackReportMessage))
                this->pCallBackReportMessage((tagReportMessageType)ReportMessageType,(TCHAR*)pbData,this->pCallBackReportMessagesUserParam);

        }
        return;
    }
}
//-----------------------------------------------------------------------------
// Name: SetMonitoringLogHeap
// Object: allow to specify heap used for monitoring logs memory allocation
// Parameters :
//      in: HANDLE Heap : new heap
// Return : 
//-----------------------------------------------------------------------------
void CApiOverride::SetMonitoringLogHeap(HANDLE Heap)
{
    this->MonitoringHeap=Heap;
}
//-----------------------------------------------------------------------------
// Name: MonitoringCallback
// Object: call on each new monitoring event, parse the log buffer to put it in usable structure
// Parameters :
//      in: PBYTE LogBuffer : undecoded log buffer
// Return : 
//-----------------------------------------------------------------------------
void CApiOverride::MonitoringCallback(PBYTE LogBuffer)
{
    //NOTICE : See encoding in LogAPI.cpp of InjectedDLL project to understand decoding

    ////////////////////////////////////////////////////////////////
    // convert the log buffer into a log entry structure
    ////////////////////////////////////////////////////////////////

    PLOG_ENTRY pLogEntry=(PLOG_ENTRY)HeapAlloc(this->MonitoringHeap,0,sizeof(LOG_ENTRY));

    DWORD ItemSize;
    WORD Cnt;

    // retrieve fixed size info
    pLogEntry->pHookInfos=(PLOG_ENTRY_FIXED_SIZE)HeapAlloc(this->MonitoringHeap,0,sizeof(LOG_ENTRY_FIXED_SIZE));
    memcpy(pLogEntry->pHookInfos,LogBuffer,sizeof(LOG_ENTRY_FIXED_SIZE));
    LogBuffer+=sizeof(LOG_ENTRY_FIXED_SIZE);

    // size of pszModuleName including \0;
    memcpy(&ItemSize,LogBuffer,sizeof(DWORD));
    LogBuffer+=sizeof(DWORD);

    // we could directly point to local buffer, but to make same memory 
    // allocation and deletion as done in load file, we allocate new buffer
    pLogEntry->pszModuleName=(TCHAR*)HeapAlloc(this->MonitoringHeap,0,ItemSize);
    memcpy(pLogEntry->pszModuleName,LogBuffer,ItemSize);
    LogBuffer+=ItemSize;

    // size of pszApiName including \0;
    memcpy(&ItemSize,LogBuffer,sizeof(DWORD));
    LogBuffer+=sizeof(DWORD);

    // we could directly point to local buffer, but to make same memory 
    // allocation and deletion as done in load file, we allocate new buffer
    pLogEntry->pszApiName=(TCHAR*)HeapAlloc(this->MonitoringHeap,0,ItemSize);
    memcpy(pLogEntry->pszApiName,LogBuffer,ItemSize);
    LogBuffer+=ItemSize;

    // size of pszCallingModuleName including \0
    memcpy(&ItemSize,LogBuffer,sizeof(DWORD));
    LogBuffer+=sizeof(DWORD);

    // we could directly point to local buffer, but to make same memory 
    // allocation and deletion as done in load file, we allocate new buffer
    pLogEntry->pszCallingModuleName=(TCHAR*)HeapAlloc(this->MonitoringHeap,0,ItemSize);
    memcpy(pLogEntry->pszCallingModuleName,LogBuffer,ItemSize);
    LogBuffer+=ItemSize;

    pLogEntry->ParametersInfoArray=NULL;
    // if func has params
    if (pLogEntry->pHookInfos->bNumberOfParameters>0)
    {
        // create array
        pLogEntry->ParametersInfoArray=(PARAMETER_LOG_INFOS*)HeapAlloc(this->MonitoringHeap,0,sizeof(PARAMETER_LOG_INFOS)*pLogEntry->pHookInfos->bNumberOfParameters);

        // fill array info for each parameter
        for (Cnt=0;Cnt<pLogEntry->pHookInfos->bNumberOfParameters;Cnt++)
        {
            // copy all parameters but pbPointedValue
            memcpy(&pLogEntry->ParametersInfoArray[Cnt],LogBuffer,sizeof(PARAMETER_LOG_INFOS)-sizeof(BYTE*));
            LogBuffer+=sizeof(PARAMETER_LOG_INFOS)-sizeof(BYTE*);

            // if pointed data
            if (pLogEntry->ParametersInfoArray[Cnt].dwSizeOfPointedValue)
            {
                pLogEntry->ParametersInfoArray[Cnt].pbValue=(BYTE*)HeapAlloc(this->MonitoringHeap,0,pLogEntry->ParametersInfoArray[Cnt].dwSizeOfPointedValue);
                memcpy(pLogEntry->ParametersInfoArray[Cnt].pbValue,LogBuffer,pLogEntry->ParametersInfoArray[Cnt].dwSizeOfPointedValue);
                LogBuffer+=pLogEntry->ParametersInfoArray[Cnt].dwSizeOfPointedValue;
            }
            // if more than 4 bytes param
            else if (pLogEntry->ParametersInfoArray[Cnt].dwSizeOfData>sizeof(DWORD))
            {
                pLogEntry->ParametersInfoArray[Cnt].pbValue=(BYTE*)HeapAlloc(this->MonitoringHeap,0,pLogEntry->ParametersInfoArray[Cnt].dwSizeOfData);
                memcpy(pLogEntry->ParametersInfoArray[Cnt].pbValue,LogBuffer,pLogEntry->ParametersInfoArray[Cnt].dwSizeOfData);
                LogBuffer+=pLogEntry->ParametersInfoArray[Cnt].dwSizeOfData;
            }
            else
            {
                pLogEntry->ParametersInfoArray[Cnt].pbValue=0;
            }
            
        }
    }

    pLogEntry->CallSackInfoArray=NULL;
    // if func has params
    if (pLogEntry->pHookInfos->CallStackSize>0)
    {
        pLogEntry->CallSackInfoArray=(CALLSTACK_ITEM_INFO*)HeapAlloc(this->MonitoringHeap,0,sizeof(CALLSTACK_ITEM_INFO)*pLogEntry->pHookInfos->CallStackSize);
        if (pLogEntry->CallSackInfoArray)
        {
            // fill array info for each call info
            for (Cnt=0;Cnt<pLogEntry->pHookInfos->CallStackSize;Cnt++)
            {
                // copy address
                memcpy(&pLogEntry->CallSackInfoArray[Cnt].Address,LogBuffer,sizeof(PBYTE));
                LogBuffer+=sizeof(PBYTE);
                // copy relative address
                memcpy(&pLogEntry->CallSackInfoArray[Cnt].RelativeAddress,LogBuffer,sizeof(PBYTE));
                LogBuffer+=sizeof(PBYTE);
                // copy length of module name
                memcpy(&ItemSize,LogBuffer,sizeof(DWORD));
                LogBuffer+=sizeof(DWORD);
                
                // copy module name
                if (ItemSize>sizeof(TCHAR))// if there's more than '\0'
                {
                    pLogEntry->CallSackInfoArray[Cnt].pszModuleName=(TCHAR*)HeapAlloc(this->MonitoringHeap,0,ItemSize);
                    if (pLogEntry->CallSackInfoArray[Cnt].pszModuleName)
                        memcpy(pLogEntry->CallSackInfoArray[Cnt].pszModuleName,LogBuffer,ItemSize);
                    else
                    {
#ifdef _DEBUG
                        if (IsDebuggerPresent())// avoid to crash application if no debugger
                            DebugBreak();
#endif
                        pLogEntry->CallSackInfoArray[Cnt].pszModuleName=NULL;
                    }
                }
                else
                    pLogEntry->CallSackInfoArray[Cnt].pszModuleName=NULL;
                LogBuffer+=ItemSize;

                // copy stack parameters
                if (pLogEntry->pHookInfos->CallStackEbpRetrievalSize==0)
                    pLogEntry->CallSackInfoArray[Cnt].Parameters=NULL;
                else
                {
                    pLogEntry->CallSackInfoArray[Cnt].Parameters=(BYTE*)HeapAlloc(this->MonitoringHeap,0,pLogEntry->pHookInfos->CallStackEbpRetrievalSize);
                    if (pLogEntry->CallSackInfoArray[Cnt].Parameters)
                    {
                        memcpy(pLogEntry->CallSackInfoArray[Cnt].Parameters,LogBuffer,pLogEntry->pHookInfos->CallStackEbpRetrievalSize);
                    }
                    else
                    {
#ifdef _DEBUG
                        if (IsDebuggerPresent())// avoid to crash application if no debugger
                            DebugBreak();
#endif
                    }
                    LogBuffer+=pLogEntry->pHookInfos->CallStackEbpRetrievalSize;
                }
            }
        }
        else
        {
            pLogEntry->CallSackInfoArray=0;
#ifdef _DEBUG
            if (IsDebuggerPresent())// avoid to crash application if no debugger
                DebugBreak();
#endif
        }
    }

    // call the monitoring call back using decoded struct
    this->MonitoringCallback(pLogEntry);

    // free memory if log is no more required
    if (!this->bManualFreeLogEntry)
        CApiOverride::FreeLogEntry(pLogEntry,this->MonitoringHeap);
}

//-----------------------------------------------------------------------------
// Name: FreeLogEntry
// Object: Free a log entry (use it only if you've specified 
//          a manual free in SetMonitoringCallback call
// Parameters :
//      in: LOG_ENTRY* pLog : Log entry to free
// Return : 
//-----------------------------------------------------------------------------
void CApiOverride::FreeLogEntry(LOG_ENTRY* pLog)
{
    return CApiOverride::FreeLogEntry(pLog,GetProcessHeap());
}

//-----------------------------------------------------------------------------
// Name: FreeLogEntry
// Object: Free a log entry (use it only if you've specified 
//          a manual free in SetMonitoringCallback call
// Parameters :
//      in: LOG_ENTRY* pLog : Log entry to free
//          HANDLE Heap : heap specified by SetMonitoringLogHeap.
//                        if you don't call SetMonitoringLogHeap, use CApiOverride::FreeLogEntry(LOG_ENTRY* pLog)
// Return : 
//-----------------------------------------------------------------------------
void CApiOverride::FreeLogEntry(LOG_ENTRY* pLog,HANDLE Heap)
{
    WORD cnt;
    // free parameter array
    for (cnt=0;cnt<pLog->pHookInfos->bNumberOfParameters;cnt++)
    {
        if (pLog->ParametersInfoArray[cnt].pbValue)
        {
            HeapFree(Heap,0, pLog->ParametersInfoArray[cnt].pbValue);
            pLog->ParametersInfoArray[cnt].pbValue=NULL;
        }
    }
    if (pLog->ParametersInfoArray)
        HeapFree(Heap,0,pLog->ParametersInfoArray);

    // free call stack array
    for (cnt=0;cnt<pLog->pHookInfos->CallStackSize;cnt++)
    {
        if (pLog->CallSackInfoArray[cnt].pszModuleName)
        {
            HeapFree(Heap,0,pLog->CallSackInfoArray[cnt].pszModuleName);
            pLog->CallSackInfoArray[cnt].pszModuleName=NULL;
        }
        if (pLog->CallSackInfoArray[cnt].Parameters)
        {
            HeapFree(Heap,0,pLog->CallSackInfoArray[cnt].Parameters);
            pLog->CallSackInfoArray[cnt].Parameters=NULL;
        }
    }
    if (pLog->CallSackInfoArray)
        HeapFree(Heap,0,pLog->CallSackInfoArray);

    HeapFree(Heap,0,pLog->pszModuleName);
    HeapFree(Heap,0,pLog->pszApiName);
    HeapFree(Heap,0,pLog->pszCallingModuleName);

    // free allocated buffer
    HeapFree(Heap,0,pLog->pHookInfos);
    
    // delete log entry itself
    HeapFree(Heap,0,pLog);
}


//-----------------------------------------------------------------------------
// Name: MonitoringCallback
// Object: call on each new monitoring event
// Parameters :
//      in: LOG_ENTRY* pLog : new monitored Log entry
// Return : 
//-----------------------------------------------------------------------------
void CApiOverride::MonitoringCallback(LOG_ENTRY* pLog)
{
    if (IsBadCodePtr((FARPROC)this->pCallBackLogFunc))
    {
#if 0
        if (this->pListview)
        {
            LOG_LIST_ENTRY lle;

            // fill LOG_LIST_ENTRY struct
            lle.dwId=this->pListview->GetItemCount();
            lle.pLog=pLog;
            lle.Type=ENTRY_LOG;
            lle.pUserMsg=NULL;

            this->AddLogEntry(&lle,FALSE);
        }
#endif
    }
    else
    // if a callback has been specified
        this->pCallBackLogFunc(pLog,this->pCallBackLogFuncUserParam);
}

//-----------------------------------------------------------------------------
// Name: AddLogEntry
// Object: add a log entry to listview
// Parameters :
//      in: LOG_LIST_ENTRY* pLogEntry : new Log entry
//          BOOL bStorePointerInListViewItemUserData : TRUE to store pLogEntry
//                  in listview item user data (and allow a speed way to get log entry data from a listview item)
// Return : 
//-----------------------------------------------------------------------------
void CApiOverride::AddLogEntry(LOG_LIST_ENTRY* pLogEntry,BOOL bStorePointerInListViewItemUserData)
{
#if 0
    this->AddLogEntry(pLogEntry,bStorePointerInListViewItemUserData,0);
#endif
}

//-----------------------------------------------------------------------------
// Name: AddLogEntry
// Object: add a log entry to listview
// Parameters :
//      in: LOG_LIST_ENTRY* pLogEntry : new Log entry
//          BOOL bStorePointerInListViewItemUserData : TRUE to store pLogEntry
//                  in listview item user data (and allow a speed way to get log entry data from a listview item)
//          int Increment : number or INCREMENT_STRING put before api name and parameters
// Return : 
//-----------------------------------------------------------------------------
void CApiOverride::AddLogEntry(LOG_LIST_ENTRY* pLogEntry,BOOL bStorePointerInListViewItemUserData,int Increment)
{
#if 0
    if (!this->pListview)
        return;

    TCHAR* pp[LastColumIndex];
    BYTE Cnt;
    LOG_ENTRY* pLog=pLogEntry->pLog;

    // if log
    if (pLogEntry->Type==ENTRY_LOG)
    {
        TCHAR ppc[LastColumIndex][MAX_PATH+1];
        TCHAR* pc;
        DWORD CallSize;
        TCHAR* ParamString;

        // Id
        _itot(pLogEntry->dwId,ppc[ColumnsIndexId],10);

        // param direction
        switch (pLog->pHookInfos->bParamDirectionType)
        {
        case PARAM_DIR_TYPE_IN:
            _tcscpy(ppc[ColumnsIndexDirection],_T("In"));
            break;
        case PARAM_DIR_TYPE_OUT:
            _tcscpy(ppc[ColumnsIndexDirection],_T("Out"));
            break;
        case PARAM_DIR_TYPE_IN_NO_RETURN:
            _tcscpy(ppc[ColumnsIndexDirection],_T("InNoRet"));
            break;
        }

        // api name
        _tcsncpy(ppc[ColumnsIndexAPIName],pLog->pszApiName,MAX_PATH);
        ppc[ColumnsIndexAPIName][MAX_PATH]=0;

        // ret value
        if (pLog->pHookInfos->bParamDirectionType==PARAM_DIR_TYPE_IN_NO_RETURN)
            *ppc[ColumnsIndexReturnValue]=0;
        else
            _sntprintf(ppc[ColumnsIndexReturnValue],MAX_PATH,_T("0x%p"),pLog->pHookInfos->ReturnValue);


        // origin address
        _sntprintf(ppc[ColumnsIndexCallerAddress],MAX_PATH,_T("0x%p"),pLog->pHookInfos->pOriginAddress);

        // caller relative address

        // get short name
        pc=_tcsrchr(pLog->pszCallingModuleName,'\\');
        if (pc)
            pc++;
        else
            pc=pLog->pszCallingModuleName;

        if (pLog->pHookInfos->RelativeAddressFromCallingModuleName!=0)
        {
            _sntprintf(ppc[ColumnsIndexCallerRelativeIndex],MAX_PATH,_T("%s + 0x%p"),
                        pc,
                        pLog->pHookInfos->RelativeAddressFromCallingModuleName
                        );
            _tcscpy(ppc[ColumnsIndexCallerFullPath],pLog->pszCallingModuleName);
        }
        else
        {
            _tcscpy(ppc[ColumnsIndexCallerRelativeIndex],_T("Not Found"));
            *ppc[ColumnsIndexCallerFullPath]=0;
        }


        // process ID
        _sntprintf(ppc[ColumnsIndexProcessID],MAX_PATH,_T("0x%.8X") ,pLog->pHookInfos->dwProcessId);

        // Thread ID
        _sntprintf(ppc[ColumnsIndexThreadID],MAX_PATH,_T("0x%.8X") ,pLog->pHookInfos->dwThreadId);

        // module name
        _tcsncpy(ppc[ColumnsIndexModuleName],pLog->pszModuleName,MAX_PATH);
        ppc[ColumnsIndexModuleName][MAX_PATH]=0;


        // last error
        _sntprintf(ppc[ColumnsIndexLastError],MAX_PATH,_T("0x%.8x"),pLog->pHookInfos->dwLastError);

        // registers before call
        _sntprintf(ppc[ColumnsIndexRegistersBeforeCall],
                    MAX_PATH,
                    _T("EAX=0x%.8x, EBX=0x%.8x, ECX=0x%.8x, EDX=0x%.8x, ESI=0x%.8x, EDI=0x%.8x, EFL=0x%.8x, ESP=0x%.8x"),
                    pLog->pHookInfos->RegistersBeforeCall.eax,
                    pLog->pHookInfos->RegistersBeforeCall.ebx,
                    pLog->pHookInfos->RegistersBeforeCall.ecx,
                    pLog->pHookInfos->RegistersBeforeCall.edx,
                    pLog->pHookInfos->RegistersBeforeCall.esi,
                    pLog->pHookInfos->RegistersBeforeCall.edi,
                    pLog->pHookInfos->RegistersBeforeCall.efl,
                    pLog->pHookInfos->RegistersBeforeCall.esp
                    );

        // registers after call
        if (pLog->pHookInfos->bParamDirectionType==PARAM_DIR_TYPE_IN_NO_RETURN)
            *ppc[ColumnsIndexRegistersAfterCall]=0;
        else
            _sntprintf(ppc[ColumnsIndexRegistersAfterCall],
                    MAX_PATH,
                    _T("EAX=0x%.8x, EBX=0x%.8x, ECX=0x%.8x, EDX=0x%.8x, ESI=0x%.8x, EDI=0x%.8x, EFL=0x%.8x, ESP=0x%.8x"),
                    pLog->pHookInfos->RegistersAfterCall.eax,
                    pLog->pHookInfos->RegistersAfterCall.ebx,
                    pLog->pHookInfos->RegistersAfterCall.ecx,
                    pLog->pHookInfos->RegistersAfterCall.edx,
                    pLog->pHookInfos->RegistersAfterCall.esi,
                    pLog->pHookInfos->RegistersAfterCall.edi,
                    pLog->pHookInfos->RegistersAfterCall.efl,
                    pLog->pHookInfos->RegistersAfterCall.esp
                    );

        if (pLog->pHookInfos->bParamDirectionType==PARAM_DIR_TYPE_IN_NO_RETURN)
            *ppc[ColumnsIndexFloatingReturnValue]=0;
        else
            _stprintf(ppc[ColumnsIndexFloatingReturnValue],_T("%.19g"), pLog->pHookInfos->DoubleResult);

        // Call time
        // Copy the time into a quadword.
        ULONGLONG ul;
        ul = (((ULONGLONG) pLog->pHookInfos->CallTime.dwHighDateTime) << 32) + pLog->pHookInfos->CallTime.dwLowDateTime;
        int Nano100s=(int)(ul%10);
        int MicroSeconds=(int)((ul/10)%1000);
        int MilliSeconds=(int)((ul/10000)%1000);
        int Seconds=(int)((ul/_SECOND)%60);
        int Minutes=(int)((ul/_MINUTE)%60);
        int Hours=(int)((ul/_HOUR)%24);
        _sntprintf(ppc[ColumnsIndexCallTime],MAX_PATH,_T("%.2u:%.2u:%.2u:%.3u:%.3u,%.1u"),
                            Hours,
                            Minutes,
                            Seconds,
                            MilliSeconds,
                            MicroSeconds,
                            Nano100s
                            );

        // Call duration
        _sntprintf(ppc[ColumnsIndexCallDuration],MAX_PATH,_T("%u"),pLog->pHookInfos->dwCallDuration);

        //////////////////////////
        // api name and parameters
        //////////////////////////

        // add api name

        *ppc[ColumnsIndexCall]=0;

        while (Increment>0)
        {
            _tcsncat(ppc[ColumnsIndexCall],INCREMENT_STRING,MAX_PATH-1-_tcslen(ppc[ColumnsIndexCall]));
            Increment--;
        }
 
        _tcsncat(ppc[ColumnsIndexCall],pLog->pszApiName,MAX_PATH-1-_tcslen(ppc[ColumnsIndexCall]));
        ppc[ColumnsIndexCall][MAX_PATH-1]=0;
        // add (
        _tcscat(ppc[ColumnsIndexCall],_T("("));

        CallSize=(DWORD)_tcslen(ppc[ColumnsIndexCall]);
        for (Cnt=0;Cnt<pLog->pHookInfos->bNumberOfParameters;Cnt++)
        {
            if (Cnt!=0)
            {
                // add param splitter
                _tcscat(ppc[ColumnsIndexCall],_T(","));
                CallSize++;
            }

            // translate param to string
            CSupportedParameters::ParameterToString(&pLog->ParametersInfoArray[Cnt],&ParamString,APIOVERRIDE_MAX_ONE_PARAM_STRING_SIZE_FOR_CALL_COLUMN);

            // put a limit to parameter size to avoid a big param hide over members in preview
            if (_tcslen(ParamString)>APIOVERRIDE_MAX_ONE_PARAM_STRING_SIZE_FOR_CALL_COLUMN)
            {
                ParamString[APIOVERRIDE_MAX_ONE_PARAM_STRING_SIZE_FOR_CALL_COLUMN-4]='.';
                ParamString[APIOVERRIDE_MAX_ONE_PARAM_STRING_SIZE_FOR_CALL_COLUMN-3]='.';
                ParamString[APIOVERRIDE_MAX_ONE_PARAM_STRING_SIZE_FOR_CALL_COLUMN-2]='.';
                ParamString[APIOVERRIDE_MAX_ONE_PARAM_STRING_SIZE_FOR_CALL_COLUMN-1]=0;
            }

            // add it to ppc[ColumnsIndexCall]
            _tcsncat(ppc[ColumnsIndexCall],ParamString,MAX_PATH-4-CallSize);

            // free string allocated by ParameterToString
            delete ParamString;

            // compute call size
            CallSize=(DWORD)_tcslen(ppc[ColumnsIndexCall]);

            // check size
            if (CallSize>=MAX_PATH-4)
            {
                // add ... at the end of string
                ppc[ColumnsIndexCall][MAX_PATH-4]='.';
                ppc[ColumnsIndexCall][MAX_PATH-3]='.';
                ppc[ColumnsIndexCall][MAX_PATH-2]='.';
                ppc[ColumnsIndexCall][MAX_PATH-1]=0;

                //avoid to add ")"
                CallSize=MAX_PATH;

                // stop parsing parameters
                break;
            }
        }
        if (CallSize<MAX_PATH-1)
            _tcscat(ppc[ColumnsIndexCall],_T(")"));


        // logging to listview
        for (int cnt=0;cnt<LastColumIndex;cnt++)// conversion from TCHAR[][] to TCHAR**
            pp[cnt]=(TCHAR*)ppc+cnt*(MAX_PATH+1);

    }

    // if user message
    else
    {
        TCHAR psz[20];

        for (Cnt=0;Cnt<LastColumIndex;Cnt++)
            pp[Cnt]=0;

        // Id to string
        _itot(pLogEntry->dwId,psz,10);
        pp[ColumnsIndexId]=psz;

        // log type
        switch(pLogEntry->Type)
        {
        case ENTRY_MSG_WARNING:
            pp[ColumnsIndexDirection]=LISTVIEW_ITEM_TEXT_WARNING;
            break;
        case ENTRY_MSG_ERROR:
            pp[ColumnsIndexDirection]=LISTVIEW_ITEM_TEXT_ERROR;
            break;
        case ENTRY_MSG_INFORMATION:
        default:
            pp[ColumnsIndexDirection]=LISTVIEW_ITEM_TEXT_INFORMATION;
            break;
        }

        // log message
        pp[ColumnsIndexCall]=pLogEntry->pUserMsg;
    }


    int ItemIndex=this->pListview->GetItemCount();

    // sort by date in listview, so only id will be inverted remove this part if you dislike it
    // as id are already attributed it's the only sort we can do
    if (pLogEntry->Type==ENTRY_LOG)
    {
        LONGLONG PreviousTimeQuadPart;
        LONGLONG TimeQuadPart;
        LOG_LIST_ENTRY* pPreviousLogEntry;
        while (ItemIndex>0)
        {
            // on error getting value
            if (!pListview->GetItemUserData(ItemIndex-1,(LPVOID*)(&pPreviousLogEntry)))
            break;

            // if bad pointer
            if (pPreviousLogEntry==0)
                break;

            if (IsBadReadPtr(pPreviousLogEntry,sizeof(LOG_LIST_ENTRY)))
                break;

            // if not a log entry
            if (pPreviousLogEntry->Type!=ENTRY_LOG)
                break;

            // if bas pointer
            if (IsBadReadPtr(pPreviousLogEntry->pLog,sizeof(LOG_ENTRY)))
                break;

            // if previous date is lower than current one order is ok --> break;
            PreviousTimeQuadPart=(((LONGLONG)pPreviousLogEntry->pLog->pHookInfos->CallTime.dwHighDateTime)<<32)
                                            +pPreviousLogEntry->pLog->pHookInfos->CallTime.dwLowDateTime;
            TimeQuadPart=(((LONGLONG)pLogEntry->pLog->pHookInfos->CallTime.dwHighDateTime)<<32)
                                        +pLogEntry->pLog->pHookInfos->CallTime.dwLowDateTime;

            if (PreviousTimeQuadPart<=TimeQuadPart)
                break;

            // else current item must be inserted before previous one
            // check the next previous func to do same checking
            ItemIndex--;
        }
    }
    // end of sort by date in listview, so only id will be inverted remove this part if you dislike it

    if (bStorePointerInListViewItemUserData)
        this->pListview->AddItemAndSubItems(LastColumIndex,pp,ItemIndex,TRUE,pLogEntry);
    else
        // don't add the pLog as userparam because it will be invalid memory
        this->pListview->AddItemAndSubItems(LastColumIndex,pp,ItemIndex,TRUE);

#endif
}




//-----------------------------------------------------------------------------
// Name: ProcessInternalCall
// Object: call specified function with parameters specified in pParams in the remote process
//          and store function return (eax) in pRet
// Parameters :
//      in: LPTSTR LibName : function address
//          LPTSTR FuncName
//          DWORD NbParams : nb params in pParams
//          PSTRUCT_FUNC_PARAM pParams : array of STRUCT_FUNC_PARAM. Can be null if no params
//      out : PBYTE* pReturnValue : returned value
// Return : 
//-----------------------------------------------------------------------------
BOOL CApiOverride::ProcessInternalCall(LPTSTR LibName,LPTSTR FuncName,DWORD NbParams,PSTRUCT_FUNC_PARAM pParams,PBYTE* pReturnValue)
{
    return this->ProcessInternalCall(LibName,FuncName,NbParams,pParams,pReturnValue,INFINITE);
}
//-----------------------------------------------------------------------------
// Name: ProcessInternalCall
// Object: call specified function with parameters specified in pParams in the remote process
//          and store function return (eax) in pRet
// Parameters :
//      in: LPTSTR LibName : function address
//          LPTSTR FuncName
//          DWORD NbParams : nb params in pParams
//          PSTRUCT_FUNC_PARAM pParams : array of STRUCT_FUNC_PARAM. Can be null if no params
//          DWORD dwTimeOutMs : max time in ms to wait for function reply (0xFFFFFFFF for INFINITE)
//      out : PBYTE* pReturnValue : returned value
// Return : 
//-----------------------------------------------------------------------------
BOOL CApiOverride::ProcessInternalCall(LPTSTR LibName,LPTSTR FuncName,DWORD NbParams,PSTRUCT_FUNC_PARAM pParams,PBYTE* pReturnValue,DWORD dwTimeOutMs)
{
    REGISTERS Registers;
    return this->ProcessInternalCall(LibName,FuncName,NbParams,pParams,&Registers,pReturnValue,dwTimeOutMs);
}

//-----------------------------------------------------------------------------
// Name: ProcessInternalCall
// Object: call specified function with parameters specified in pParams in the remote process
//          and store function return (eax) in pRet
// Parameters :
//      in: LPTSTR LibName : function address
//          LPTSTR FuncName
//          DWORD NbParams : nb params in pParams
//          PSTRUCT_FUNC_PARAM pParams : array of STRUCT_FUNC_PARAM. Can be null if no params
//          DWORD dwTimeOutMs : max time in ms to wait for function reply (0xFFFFFFFF for INFINITE)
//      in out : REGISTERS* pRegisters : in : register before call, out : registers after call
//      out : PBYTE* ReturnValue : returned value
// Return : 
//-----------------------------------------------------------------------------
BOOL CApiOverride::ProcessInternalCall(LPTSTR LibName,LPTSTR FuncName,DWORD NbParams,PSTRUCT_FUNC_PARAM pParams,REGISTERS* pRegisters,PBYTE* pReturnValue,DWORD dwTimeOutMs)
{
    double d;
    return this->ProcessInternalCall(LibName,FuncName,NbParams,pParams,pRegisters,pReturnValue,&d,dwTimeOutMs,0);
}
//-----------------------------------------------------------------------------
// Name: ProcessInternalCall
// Object: call specified function with parameters specified in pParams in the remote process
//          and store function return (eax) in pRet
// Parameters :
//      in: LPTSTR LibName : function address
//          LPTSTR FuncName
//          DWORD NbParams : number of parameters in pParams
//          PSTRUCT_FUNC_PARAM pParams : array of STRUCT_FUNC_PARAM. Can be null if no params
//          DWORD dwTimeOutMs : max time in ms to wait for function reply (0xFFFFFFFF for INFINITE)
//          DWORD ThreadID : thread id into which call must be done, 0 if no thread preference
//      in out : REGISTERS* pRegisters : in : register before call, out : registers after call
//      out : PBYTE* ReturnValue : returned value
//            double* FloatingReturn : floating result
// Return : 
//-----------------------------------------------------------------------------
BOOL CApiOverride::ProcessInternalCall(LPTSTR LibName,LPTSTR FuncName,DWORD NbParams,PSTRUCT_FUNC_PARAM pParams,REGISTERS* pRegisters,PBYTE* pReturnValue,double* FloatingReturn,DWORD dwTimeOutMs,DWORD ThreadId)
{
    TCHAR pszMsg[2*MAX_PATH];
    PBYTE pb;
    BOOL bRet;
    DWORD dwRet;
    DWORD dw;
    REMOTE_CALL_INFOS RemoteCallInfos;
    CApiOverrideFuncAndParams* pApiOverrideFuncAndParams;
    CLinkListItem* pRemoteCallItem;
    DWORD dwCnt;
    HANDLE pH[3];
    RemoteCallInfos.ProcessInternalCallReply=NULL;

    if (!this->bAPIOverrideDllLoaded)
    {
        this->ShowApiOverrideNotStartedMsg();
        return FALSE;
    }

    if (IsBadReadPtr(pReturnValue,sizeof(PBYTE)))// don't check pParams because it can be NULL if no params
        return FALSE;

    RemoteCallInfos.hevtProcessInternalCallReply=CreateEvent(NULL,FALSE,FALSE,NULL);
    if (!RemoteCallInfos.hevtProcessInternalCallReply)
        return FALSE;

    // encode params and func name
    pApiOverrideFuncAndParams=new CApiOverrideFuncAndParams();
    if (!pApiOverrideFuncAndParams->Encode(&RemoteCallInfos,LibName,FuncName,NbParams,pParams,pRegisters,ThreadId,dwTimeOutMs))
    {
        delete pApiOverrideFuncAndParams;
        CloseHandle(RemoteCallInfos.hevtProcessInternalCallReply);
        return FALSE;
    }

    // send cmd buffer to injected lib
    pb=new BYTE[pApiOverrideFuncAndParams->EncodedBufferSize+2*sizeof(DWORD)];
    dw=CMD_PROCESS_INTERNAL_CALL_QUERY;
    memcpy(pb,&dw,sizeof(DWORD));
    memcpy(&pb[sizeof(DWORD)],pApiOverrideFuncAndParams->EncodedBuffer,pApiOverrideFuncAndParams->EncodedBufferSize);
    
    // define events
    pH[0]=RemoteCallInfos.hevtProcessInternalCallReply;
    pH[1]=this->hevtFreeProcess;
    pH[2]=this->hevtProcessFree;

    // add address of RemoteCallInfos to current pCurrentRemoteCalls list
    pRemoteCallItem=this->pCurrentRemoteCalls->AddItem(&RemoteCallInfos);

    bRet=this->pMailSlotClient->Write(pb,pApiOverrideFuncAndParams->EncodedBufferSize+sizeof(DWORD));
    if (!bRet)
    {
        delete pb;
        delete pApiOverrideFuncAndParams;
        CloseHandle(RemoteCallInfos.hevtProcessInternalCallReply);
        return FALSE;
    }
WaitEvent:
    // wait for injected lib reply
    dwRet=WaitForMultipleObjects(3,pH,FALSE,dwTimeOutMs);
    switch(dwRet)
    {
        case WAIT_TIMEOUT:
            _sntprintf(pszMsg,2*MAX_PATH,_T("Error no reply for %s:%s call in %d sec\r\nDo you want to wait more ?"),FuncName,LibName,dwTimeOutMs/1000);
            // report message in default window, as this function may not called
            // by parent window (in winapioverride it's avoid to brings main window upper than the call window 
            // which do the call)
            if (this->UserMessage(NULL,pszMsg,_T("Question"),MB_YESNO|MB_ICONQUESTION|MB_TOPMOST)==IDYES)
                goto WaitEvent;

            // remove address of RemoteCallInfos to current pCurrentRemoteCalls list
            this->pCurrentRemoteCalls->RemoveItem(pRemoteCallItem);
            delete pb;
            delete pApiOverrideFuncAndParams;
            CloseHandle(RemoteCallInfos.hevtProcessInternalCallReply);
            return FALSE;

        case WAIT_OBJECT_0:
            break;
        case WAIT_OBJECT_0+1:
        case WAIT_OBJECT_0+2:
        default:
            // remove address of RemoteCallInfos to current pCurrentRemoteCalls list
            this->pCurrentRemoteCalls->RemoveItem(pRemoteCallItem);
            delete pb;
            delete pApiOverrideFuncAndParams;
            CloseHandle(RemoteCallInfos.hevtProcessInternalCallReply);
            return FALSE;
    }

    // remove address of RemoteCallInfos to current pCurrentRemoteCalls list
    this->pCurrentRemoteCalls->RemoveItem(pRemoteCallItem);

    // decode reply
    bRet=pApiOverrideFuncAndParams->Decode(RemoteCallInfos.ProcessInternalCallReply);
    if ((!bRet)
        ||(pApiOverrideFuncAndParams->DecodedCallSuccess==FALSE)
        ||(NbParams!=pApiOverrideFuncAndParams->DecodedNbParams))
    {
        _sntprintf(pszMsg,2*MAX_PATH,_T("Error during the call of %s:%s"),FuncName,LibName);
        ReportError(NULL,pszMsg);// report error in default window, as this function may not called
        // by parent window (in winapioverride it's avoid to brings main window upper than the call window 
        // which do the call)
        delete pb;
        delete pApiOverrideFuncAndParams;
        if (RemoteCallInfos.ProcessInternalCallReply)
            delete RemoteCallInfos.ProcessInternalCallReply;
        CloseHandle(RemoteCallInfos.hevtProcessInternalCallReply);
        return FALSE;
    }

    // copy data of received buffer
    *pReturnValue=pApiOverrideFuncAndParams->DecodedReturnedValue;

    // copy pParams
    for (dwCnt=0;dwCnt<pApiOverrideFuncAndParams->DecodedNbParams;dwCnt++)
    {
        // avoid buffer overflow here
        if (pApiOverrideFuncAndParams->DecodedParams[dwCnt].dwDataSize>pParams[dwCnt].dwDataSize)
            pApiOverrideFuncAndParams->DecodedParams[dwCnt].dwDataSize=pParams[dwCnt].dwDataSize;
        memcpy(pParams[dwCnt].pData,
            pApiOverrideFuncAndParams->DecodedParams[dwCnt].pData,
            pApiOverrideFuncAndParams->DecodedParams[dwCnt].dwDataSize=pParams[dwCnt].dwDataSize
            );
    }

    // copy Registers
    memcpy(pRegisters,&pApiOverrideFuncAndParams->DecodedRegisters,sizeof(REGISTERS));

    // copy floating return
    *FloatingReturn=pApiOverrideFuncAndParams->DecodedFloatingReturn;

    delete pb;
    delete pApiOverrideFuncAndParams;
    if (RemoteCallInfos.ProcessInternalCallReply)
        delete RemoteCallInfos.ProcessInternalCallReply;
    CloseHandle(RemoteCallInfos.hevtProcessInternalCallReply);
    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: ShowApiOverrideNotStartedMsg
// Object: show a standart error msg
// Parameters :
//     in : 
// Return : 
//-----------------------------------------------------------------------------
void CApiOverride::ShowApiOverrideNotStartedMsg()
{
    ReportError(_T("Error ApiOverride not Started"));
}

//-----------------------------------------------------------------------------
// Name: SetUnexpectedUnload
// Object: Set call back for unexpected unload
//         This call back will be call if host process unload the dll without we ask it to do
//         It is call when host process close
// Parameters :
//     in : - FARPROC pCallBackFunc : callback function
//          - LPVOID pUserParam : parameter for the callback
// Return : 
//-----------------------------------------------------------------------------
void CApiOverride::SetUnexpectedUnloadCallBack(tagCallBackUnexpectedUnload pCallBackFunc,LPVOID pUserParam)
{
    this->pCallBackUnexpectedUnloadFunc=pCallBackFunc;
    this->pCallBackUnexpectedUnloadFuncUserParam=pUserParam;
}

//-----------------------------------------------------------------------------
// Name: SetReportMessagesCallBack
// Object: Set call back for report messages
// Parameters :
//     in : - FARPROC pCallBackFunc : callback function
//          - LPVOID pUserParam : parameter for the callback
// Return : 
//-----------------------------------------------------------------------------
void CApiOverride::SetReportMessagesCallBack(tagCallBackReportMessages pCallBackFunc,LPVOID pUserParam)
{
    this->pCallBackReportMessage=pCallBackFunc;
    this->pCallBackReportMessagesUserParam=pUserParam;
}

//-----------------------------------------------------------------------------
// Name: DllUnloadedCallBack
// Object: object callBack for dll unloading
// Parameters :
//     in : 
// Return : 
//-----------------------------------------------------------------------------
void CApiOverride::DllUnloadedCallBack()
{
    // signal that the dll is no more loaded (must be done before calling Stop)
    this->bAPIOverrideDllLoaded=FALSE;

    // wait the end of message retrieval
    this->pMailSlotServer->WaitUntilNoMessageDuringSpecifiedTime(
                                            APIOVERRIDE_NO_MORE_MESSAGE_IF_NO_MESSAGE_DURING_TIME_IN_MS,
                                            this->hevtFreeProcess);

    // Stop all threads and mailslots
    this->Stop(TRUE);

    // else call process exit associated callback
    if (!IsBadCodePtr((FARPROC)this->pCallBackUnexpectedUnloadFunc))
        this->pCallBackUnexpectedUnloadFunc(this->dwCurrentProcessId,this->pCallBackUnexpectedUnloadFuncUserParam);
}
//-----------------------------------------------------------------------------
// Name: ShowApiOverrideNotStartedMsg
// Object: watch for dll unloading and call associated object method
// Parameters :
//     in : LPVOID lpParam : CApiOverride*
// Return : 
//-----------------------------------------------------------------------------
DWORD WINAPI CApiOverride::DllUnloadedThreadListener(LPVOID lpParam)
{
    CApiOverride* pCApiOverride=(CApiOverride*)lpParam;
    DWORD dwRes;
    HANDLE ph[2]={pCApiOverride->hevtAPIOverrideDllProcessDetachCompleted,pCApiOverride->hevtFreeProcess};
    
    dwRes=WaitForMultipleObjects(2,ph,FALSE,INFINITE);
    switch (dwRes)
    {
    case WAIT_OBJECT_0:// hevtAPIOverrideDllProcessDetachCompleted
        // dll is unloading, but we don't have ask it
        pCApiOverride->DllUnloadedCallBack();
        return 0;
    case WAIT_OBJECT_0+1:// hevtFreeProcess
        // we have ask to free process
        return 0;
    default:// error occurs
        CAPIError::ShowLastError();
        return 0xFFFFFFFF;
    }
}


//-----------------------------------------------------------------------------
// Name: HookEntryPoint
// Object: hook entry point of a process created with CREATE_SUSPENDED arg
//          to free memory you have to call HookEntryPointFree after having resuming thread
//          call order  1)HookEntryPoint
//                      2)ResumeProcess
//                      3)HookEntryPointFree
// Parameters : 
//     in : TCHAR* pszFileName : name of exe launched in suspended mode
//          DWORD dwProcessId : process id of the exe launched (returned by CreateProcess)
//          HANDLE hThreadHandle : thread handle of the exe launched (returned by CreateProcess)
// Return : 
//-----------------------------------------------------------------------------
BOOL CApiOverride::HookEntryPoint(TCHAR* pszFileName, DWORD dwProcessId,HANDLE hThreadHandle)
{
    // we can't directly change the eip as VirtualQueryEx returns PAGE_NO_ACCESS
    // we may could play with SetThreadContext for the main thread of the application, 
    // but if it works as the GetThreadContext I don't want to try it (quite work or not according to patchs)

    CPE Pe(pszFileName);
    Pe.Parse();

    #define SIZEOF_HOOK_PROXY (1+sizeof(PBYTE)) // better to compute size for this 
    #define SIZEOF_HOOK 2000 // something enough (don't need to compute size)
    #define HOOK_END_POOLING_IN_MS 50
    #define MAX_POOLING_TIME_IN_MS 20000
    DWORD dwHookEndFlag=0xBADCAFE;
    DWORD dw=0;

#if (defined(UNICODE)||defined(_UNICODE))
    FARPROC pLoadLibrary=GetProcAddress(GetModuleHandle(_T("kernel32.dll")),"LoadLibraryW");
#else
    FARPROC pLoadLibrary=GetProcAddress(GetModuleHandle(_T("kernel32.dll")),"LoadLibraryA");
#endif

    FARPROC pGetCurrentThread=GetProcAddress(GetModuleHandle(_T("kernel32.dll")),"GetCurrentThread");
    FARPROC pSuspendThread=GetProcAddress(GetModuleHandle(_T("kernel32.dll")),"SuspendThread");

    TCHAR LocalLibName[MAX_PATH];
    SIZE_T dwTransferedSize=0;
    
    BYTE BufferIndex;

    BYTE LocalOriginalOpCode[SIZEOF_HOOK_PROXY];
    BYTE LocalProxy[SIZEOF_HOOK_PROXY];
    BYTE LocalHook[SIZEOF_HOOK];

    PBYTE RemoteHook;
    PBYTE RemoteLibName;
    DWORD ElapsedTime;

    _tcscpy(LocalLibName,this->pszAppPath);
    _tcscat(LocalLibName,API_OVERRIDE_DLL_NAME);

    PBYTE EntryPointAddress=(PBYTE)Pe.NTHeader.OptionalHeader.ImageBase+Pe.NTHeader.OptionalHeader.AddressOfEntryPoint;

    // check if .Net application
    if (Pe.NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress!=0)
    {
        // in case of .Net app, Entry point is a 6 bytes absolute jmp, and on some OS
        // these first bytes are not executed (nt loader doesn't use provided entry point)

        // Current Fix : do polling (this fix may will be changed in next versions for a cleanest way using ICoreProfilerInfo) 
        // resume process

        SetThreadPriority(GetCurrentThread(),THREAD_PRIORITY_TIME_CRITICAL);
        this->HookEntryPointpProcessMemory=NULL;

        // wait first module loading before injection
        ElapsedTime=0;
        // resume suspended process
        ResumeThread(hThreadHandle);
        while (!CProcessHelper::IsFirstModuleLoaded(dwProcessId))
        {
            Sleep(1);
            ElapsedTime++;
            if (ElapsedTime>MAX_POOLING_TIME_IN_MS)
            {
                MessageBox(this->hParentWindow,_T("Error hooking application at startup"),_T("Error"),MB_OK|MB_ICONERROR|MB_TOPMOST);
                return FALSE;
            }
        }
        this->InjectDllByCreateRemoteThread(dwProcessId);
        SuspendThread(hThreadHandle);
        SetThreadPriority(GetCurrentThread(),THREAD_PRIORITY_NORMAL);

        return TRUE;

    }
    // else
    this->HookEntryPointpProcessMemory=new CProcessMemory(dwProcessId,FALSE);

    // read original entry opcode
    if (!this->HookEntryPointpProcessMemory->Read(
                                                    (LPVOID)EntryPointAddress,
                                                    LocalOriginalOpCode,
                                                    SIZEOF_HOOK_PROXY,
                                                    &dwTransferedSize)
        )
        return FALSE;

    // allocate memory for the Hook
    RemoteHook=(PBYTE)this->HookEntryPointpProcessMemory->Alloc(SIZEOF_HOOK);
    if (!RemoteHook)
        return FALSE;

    // allocate memory in remote process to store Library name
    RemoteLibName=(PBYTE)this->HookEntryPointpProcessMemory->Alloc((_tcslen(LocalLibName)+1)*sizeof(TCHAR));
    if (!RemoteLibName)
        return FALSE;

    // copy Library name in remote process
    if (!this->HookEntryPointpProcessMemory->Write(
                                                    (LPVOID)RemoteLibName,
                                                    LocalLibName,
                                                    (_tcslen(LocalLibName)+1)*sizeof(TCHAR),
                                                    &dwTransferedSize)
        )
        return FALSE;

    //// code for absolute jump
    // #define SIZEOF_HOOK_PROXY 7
    // // jump Hook Address
    // LocalProxy[0]=0xB8;// mov eax,
    // memcpy(&LocalProxy[1],&RemoteHook,sizeof(DWORD));// Hook Address
    // LocalProxy[5]=0xFF;LocalProxy[6]=0xE0;//jmp eax absolute 

    // make a relative jump
    dw=(DWORD)(RemoteHook-EntryPointAddress-SIZEOF_HOOK_PROXY);
    // jump relative
    LocalProxy[0]=0xE9;
    memcpy(&LocalProxy[1],&dw,sizeof(DWORD));// Hook Address


    ///////////////////////
    // fill hook data
    // algorithm is the following :
    //
    //      reserve stack for return address
    //      save registers and flag registers
    //      fill return address
    //
    //      ///////////////////////////////////////
    //      ///// specifics operations to do 
    //      ///////////////////////////////////////
    //
    //      // load our spy library
    //      LoadLibrary(RemoteLibName)
    //
    //      ///////////////////////////////////////
    //      ///// End of specifics operations to do 
    //      ///////////////////////////////////////
    //
    //      //do some action that can tell the calling process that the hook is ending
    //      //  so it can free memory
    //      
    //      // suspend thread to allow monitoring files and overriding dll loading
    //
    //
    //      // restore registers and flag registers
    //
    //      // jump to Entry point
    //
    ///////////////////////

    BufferIndex=0;

    // reserve stack for return address
    LocalHook[BufferIndex++]=0x50;// push eax

    // save registers and flag registers
    LocalHook[BufferIndex++]=0x60;//pushad
    LocalHook[BufferIndex++]=0x9c;//pushfd

    //////////////////////////////////
    // fill return address
    //////////////////////////////////

    //mov eax, esp
    //add eax, 0x24 // sizeof pushad+pushfd
    //mov ebx, return address (Entry point)
    //mov [eax],ebx

    //mov eax, esp
    LocalHook[BufferIndex++]=0x8B;
    LocalHook[BufferIndex++]=0xC4;

    //add eax, 0x24
    LocalHook[BufferIndex++]=0x83;
    LocalHook[BufferIndex++]=0xC0;
    LocalHook[BufferIndex++]=0x24;

    //mov ebx, return address (Entry point)
    LocalHook[BufferIndex++]=0xBB;
    memcpy(&LocalHook[BufferIndex],&EntryPointAddress,sizeof(DWORD)); // return address (Entry point)   
    BufferIndex+=sizeof(DWORD);

    //mov [eax],ebx
    LocalHook[BufferIndex++]=0x89;
    LocalHook[BufferIndex++]=0x18;
    

    //////////////////////////////////
    // push libname
    //////////////////////////////////
    LocalHook[BufferIndex++]=0xB8; // mov eax,
    memcpy(&LocalHook[BufferIndex],&RemoteLibName,sizeof(DWORD)); // LibName Address   
    BufferIndex+=sizeof(DWORD);
    LocalHook[BufferIndex++]=0x50;// push eax

    // call load library
    LocalHook[BufferIndex++]=0xB8;// mov eax,
    memcpy(&LocalHook[BufferIndex],&pLoadLibrary,sizeof(DWORD)); // LoadLibrary Address
    BufferIndex+=sizeof(DWORD);
    LocalHook[BufferIndex++]=0xFF;LocalHook[BufferIndex++]=0xD0; // call eax

    // we are in stdcall --> parameters are removed from stack
     
    //////////////////////////////////////////////////////////////////////
    //do some action that can tell the calling process that the hook is ending
    //////////////////////////////////////////////////////////////////////

    //////////////////////////////////////////////////////////////////////
    // here we change some remotely allocated memory to signal end of hook
    // it's allow for remote process to do polling on this memory pointer
    // (Notice you can use Named event or whatever you want if you dislike
    // this way of doing)
    //
    //  so here we use the begin of RemoteHook and put first DWORD to dwHookEndFlag
    //////////////////////////////////////////////////////////////////////

    // mov eax,RemoteHook
    LocalHook[BufferIndex++]=0xB8;// mov eax,
    memcpy(&LocalHook[BufferIndex],&RemoteHook,sizeof(DWORD));
    BufferIndex+=sizeof(DWORD);

    // mov ebx,dwHookEndFlag
    LocalHook[BufferIndex++]=0xBB;// mov ebx,
    memcpy(&LocalHook[BufferIndex],&dwHookEndFlag,sizeof(DWORD));
    BufferIndex+=sizeof(DWORD);

    // *RemoteHook=dwHookEndFlag
    LocalHook[BufferIndex++]=0x89;LocalHook[BufferIndex++]=0x18;// mov dword ptr[eax],ebx


    //////////////////////////////////////////////////////////////////////
    // suspend thread until all injections are done
    //////////////////////////////////////////////////////////////////////

    // mov eax,pGetCurrentThread
    LocalHook[BufferIndex++]=0xB8;// mov eax,
    memcpy(&LocalHook[BufferIndex],&pGetCurrentThread,sizeof(DWORD));
    BufferIndex+=sizeof(DWORD);

    // call GetCurrentThread
    LocalHook[BufferIndex++]=0xFF;LocalHook[BufferIndex++]=0xD0; // call eax

    // we are in stdcall --> parameters are removed from stack

    // push eax (contains the thread handle
    LocalHook[BufferIndex++]=0x50;// push eax

    // mov eax,pSuspendThread
    LocalHook[BufferIndex++]=0xB8;// mov eax,
    memcpy(&LocalHook[BufferIndex],&pSuspendThread,sizeof(DWORD));
    BufferIndex+=sizeof(DWORD);

    // call SuspendThread
    LocalHook[BufferIndex++]=0xFF;LocalHook[BufferIndex++]=0xD0; // call eax


    // we are in stdcall --> parameters are removed from stack


    //////////////////////////////////////////////////////////////////////
    // restore registers and flag registers
    //////////////////////////////////////////////////////////////////////
    LocalHook[BufferIndex++]=0x9D;//popfd
    LocalHook[BufferIndex++]=0x61;//popad

    //////////////////////////////////////////////////////////////////////
    // jmp EntryPointAddress remember we have push return address on the stack
    // so just use ret
    //////////////////////////////////////////////////////////////////////
    LocalHook[BufferIndex++]=0xC3;//ret

    DWORD OldProtectionFlag;
    // copy hook data
    if (!this->HookEntryPointpProcessMemory->Write(
                                                    (LPVOID)RemoteHook,
                                                    LocalHook,
                                                    SIZEOF_HOOK,
                                                    &dwTransferedSize)
        )
        return FALSE;
    // mark new allocated memory as Executable
    if (!VirtualProtectEx(this->HookEntryPointpProcessMemory->GetProcessHandle(),
        RemoteHook,
        SIZEOF_HOOK,
        PAGE_EXECUTE_READWRITE,
        &OldProtectionFlag)
        )
        return FALSE;



    // remove memory protection
    if (!VirtualProtectEx(this->HookEntryPointpProcessMemory->GetProcessHandle(),
                            EntryPointAddress,
                            SIZEOF_HOOK_PROXY,
                            PAGE_EXECUTE_READWRITE,
                            &OldProtectionFlag)
        )
        return FALSE;

    // copy proxy data (assume that our hook is in remote process before jumping to it)
    if (!this->HookEntryPointpProcessMemory->Write(
                                                    (LPVOID)EntryPointAddress,
                                                    LocalProxy,
                                                    SIZEOF_HOOK_PROXY,
                                                    &dwTransferedSize)
        )
        return FALSE;

    // resume thread a first time to run our hook
    if(ResumeThread(hThreadHandle)==((DWORD)-1))
        return FALSE;

    // wait until hook has done it's job
    DWORD OriginalTickCount=GetTickCount();
    DWORD CurrentTickCount;
    for(;;)
    {
        Sleep(HOOK_END_POOLING_IN_MS);
        // this injection way can fails for applications (like .net exe)
        CurrentTickCount=GetTickCount();
        if (OriginalTickCount+MAX_POOLING_TIME_IN_MS<CurrentTickCount)
        {
            TCHAR pszMsg[2*MAX_PATH];
            _stprintf(pszMsg,
                _T("Error hooking application %s in suspended way\r\n")
                _T("Use the \"Only After\" option"),
                pszFileName);
            MessageBox(this->hParentWindow,pszMsg,_T("Error"),MB_OK|MB_ICONERROR|MB_TOPMOST);
            return FALSE;
        }
        this->HookEntryPointpProcessMemory->Read( RemoteHook,&dw,sizeof(DWORD),&dwTransferedSize);

        if (dw==dwHookEndFlag)
            break;

        // if process has crash don't wait infinite
        if (!CProcessHelper::IsAlive(dwProcessId))
        {
            TCHAR pszMsg[2*MAX_PATH];
            _stprintf(pszMsg,_T("Error application %s seems to be closed"),pszFileName);
            MessageBox(this->hParentWindow,pszMsg,_T("Error"),MB_OK|MB_ICONERROR|MB_TOPMOST);
            return FALSE;
        }
    }

    // restore original opcode
    if (!this->HookEntryPointpProcessMemory->Write(
                                                    (LPVOID)EntryPointAddress,
                                                    LocalOriginalOpCode,
                                                    SIZEOF_HOOK_PROXY,
                                                    &dwTransferedSize)
        )
        return FALSE;

    // restore memory protection
    if (!VirtualProtectEx(this->HookEntryPointpProcessMemory->GetProcessHandle(),
                            EntryPointAddress,
                            SIZEOF_HOOK_PROXY,
                            OldProtectionFlag,
                            &OldProtectionFlag)
        )
        return FALSE;

    this->HookEntryPointRemoteHook          =RemoteHook;
    this->HookEntryPointRemoteLibName       =RemoteLibName;
    return TRUE;
}
//-----------------------------------------------------------------------------
// Name: HookEntryPointFree
// Object: free memory allocated in remote process after a call of HookEntryPoint
//          must be called after caller of HookEntryPoint has call ResumeProcess
// Parameters :
//     in : 
// Return : 
//-----------------------------------------------------------------------------
BOOL CApiOverride::HookEntryPointFree()
{
    // don't use IsBadWritePointer here because this is remote process allocated memory
    if (this->HookEntryPointpProcessMemory==NULL)
        return FALSE;


    // wait a little to assume process don't need allocated memory anymore (only to be sure that the 3 asm instructions
    // required after the ResumeProcess are executed)
    Sleep(100);

    // free memory
    if (this->HookEntryPointRemoteHook)
        this->HookEntryPointpProcessMemory->Free(this->HookEntryPointRemoteHook);
    if (this->HookEntryPointRemoteLibName)
        this->HookEntryPointpProcessMemory->Free(this->HookEntryPointRemoteLibName);

    this->HookEntryPointRemoteHook=NULL;
    this->HookEntryPointRemoteLibName=NULL;

    delete this->HookEntryPointpProcessMemory;
    this->HookEntryPointpProcessMemory=NULL;

    return TRUE;
}