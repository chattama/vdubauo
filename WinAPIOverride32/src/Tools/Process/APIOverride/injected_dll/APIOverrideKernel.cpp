/*
Copyright (C) 2004 Jacquelin POTIER <jacquelin.potier@free.fr>
Dynamic aspect ratio code Copyright (C) 2004 Jacquelin POTIER <jacquelin.potier@free.fr>
originaly based from APISpy32 v2.1 from Yariv Kaplan @ WWW.INTERNALS.COM

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
// Object: kernel of monitoring and overriding
//-----------------------------------------------------------------------------

#include "APIOverrideKernel.h"
#pragma intrinsic (memcpy,memset,memcmp)
APIOVERRIDE_INTERNAL_MODULELIMITS APIOverrideInternalModulesLimits[MAX_APIOVERRIDE_MODULESLIMITS];
DWORD APIOverrideInternalModulesLimitsIndex=0;

//extern BOOL bMonitoring;
extern BOOL bFaking;
//extern BOOL bFiltersApplyToMonitoring;
//extern BOOL bFiltersApplyToFaking;
extern CLinkList* pLinkListAPIInfos;
//extern CLinkList* pLinkListAPIInfosToBeFree;
//extern CCOM_Manager* pComManager;
//extern CLogAPI* pLogAPI;
//extern DWORD dwSystemPageSize;
//extern CModulesFilters* pModulesFilters;
//extern HANDLE hevtAllAPIUnhookedDllFreeAll;
//extern HANDLE hevtFreeAPIInfo;
//extern HANDLE hevtWaitForUnlocker;
//extern HANDLE hevtUnload;
extern DWORD dwCurrentProcessID;
//extern BOOL FreeingThreadGracefullyClosed;
//extern double dFloatingNotSet;
extern tagFirstBytesAutoAnalysis FirstBytesAutoAnalysis;
//extern BOOL bDebugMonitoringFile;
//extern LARGE_INTEGER PerformanceFrequency;
//extern LARGE_INTEGER ReferenceCounter;
//extern LARGE_INTEGER ReferenceTime;
//extern HANDLE ApiOverrideLogHeap;

#define asm_memcpy(Dest,Source,ln) __asm     \
{                                            \
    __asm cld                                \
    __asm mov esi, [Source]                  \
    __asm mov edi, [Dest]                    \
    __asm mov ecx, [ln]                      \
                                             \
    __asm shr ecx, 2                         \
    __asm rep movsd                          \
                                             \
    __asm mov ecx, [ln]                      \
    __asm and ecx, 3                         \
    __asm rep movsb                          \
}

enum tagApiOverrideExceptionType
{
    ApiOverrideExceptionType_NONE,
    ApiOverrideExceptionType_HARDWARE,
    ApiOverrideExceptionType_SOFTWARE
};

#define PRE_HOOK_USED_STACK_SIZE 48 // stack size used by pre hook to push registers (asm opcodes called before APIHandler)


__declspec(naked) void APIHandlerNaked()
{
    __asm
    {
        // store current exception filter
        push        fs:[0]

        // push flags
        pushfd

        // push registers
        push        eax  
        push        ebx  
        push        ecx  
        push        edx  
        push        esi  
        push        edi  
        push        es   
        push        fs
        push        gs

        jmp APIHandler
    }
}

#pragma runtime_checks( "", off ) // don't check stack
#pragma check_stack(off)  // don't check stack
//////////////////////////////////////////////////////////////////////
// APIHandler :
// function call at API start
//
// WARNING if you don't filter APIOverride.dll call, call order of function used
//         inside APIHandler and subroutine can be false
//         by the way if you hook ReadFile and WriteFile and do a call to ReadFile, as APIHandler call WriteFile
//         the log of WriteFile will be send before the one of ReadFile
//
//////////////////////////////////////////////////////////////////////
void APIHandler()
{
// assume there's no buffer security check (no "/Gs" option) [To remove it go to 
//   project properties - c/c++ - code generation - Buffer Security Check -> No]

    API_INFO *pAPIInfo;
    PVOID pSource;
    PVOID pDest;
    DWORD dwSize;
    HANDLE ThreadHandle;
    int ThreadPriority;
    BYTE Cnt;

    PBYTE pbAfterCall;
    PDWORD pdwParam;
    DWORD dwParamSize;
    DWORD dwRealParamSize;
    DWORD dwESPReservedSize;
    DWORD dwESPSecuritySize;
    DWORD dwESPSizeToFree;
    PDWORD pdwESP;
    PDWORD pdwESPAfterFuncCall;
    PDWORD pdwESPAfterFuncCallCalleeCleans;
    DWORD CallerEbp;
    DWORD OriginalExceptionHandler;
    DWORD CurrentEsp;
    BOOL bStackCleanedByCallee;
    PBYTE ReturnAddr;
    PBYTE ReturnValue;
    PBYTE RelativeAddressFromCallingModule;
    TCHAR szCallingModuleName[MAX_PATH];
    FARPROC FunctionAddress;
    LARGE_INTEGER TickCountBeforeCall;
    LARGE_INTEGER TickCountAfterCall;
    FILETIME CallTime;

    REGISTERS LogOriginalRegisters;
    REGISTERS LogAfterCallRegisters;
    REGISTERS OriginalRegisters;
    REGISTERS AfterCallRegisters;
    REGISTERS LocalRegisters;

    BOOL bLogInputParameters;
    BOOL bLogOuputParameters;
    BOOL bLogInputParametersWithoutReturn;
    BOOL bMatchFilters;
    BOOL bFakeCurrentCall;
    BOOL bFunctionFail;
    BOOL bBreak;
    BOOL PrePostApiHookCallContinueChain;

    LOG_INFOS LogInfoIn;
    LOG_INFOS LogInfoOut;
    BYTE NumberOfParameterForLogInfoIn;
    DWORD dwLastErrorCode;

    HANDLE BlockingCallThread;
    BLOCKING_CALL BlockingCallArg;
    TCHAR* pszUnhookCheck;
    PBYTE EbpAtAPIHandler;

    double DoubleResult;
    double DoubleLogResult;
    WORD wFPUStatusRegister;
    BOOL bEmptyFloatStack;

    CLinkListItem* pItem;
    PRE_POST_API_CALL_CHAIN_DATA* pCallChainData;
    HMODULE CallingModuleHandle;
    PRE_POST_API_CALL_HOOK_INFOS HookInfos;

    tagApiOverrideExceptionType ExceptionType;
    EXCEPTION_POINTERS* pExceptionInformation;
    TCHAR psz[3*MAX_PATH];

    // try to don't call functions before restoring original opcode of current pAPIInfo (avoid infinite hook reentering)

    //////////////////////////////////////////////////////////////////////
    // get informations from the stack
    //////////////////////////////////////////////////////////////////////
    //Each function call creates a new stack frame with the following layout, note that high memory is at the top of the list: 
    // Function parameters 
    // Function return address 
 
    // call order was
    //      1) push API params
    //      2) call API --> push return address of hooked func
    //      3) code modification of first bytes of API
    //          jmp buffered hook (a buffered hook is needed to push pAPIInfo --> different for each hook)
    //      4) buffered hook
    //          push pAPIInfo
    //          jmp APIHandlerNaked
    //      5) APIHandlerNaked
    //          a) push fs:[0]
    //          b) pushfd
    //          c) push other registers (notice you can push all data you want that a generated c function code will destroy)
    //          d) jump to APIHandler
    __asm
    {

        // get registers pushed by second hook
        Mov EAX, 0

        Mov AX, [EBP + 4]
        Mov [OriginalRegisters.gs], EAX

        Mov AX, [EBP + 8]
        Mov [OriginalRegisters.fs], EAX

        Mov AX, [EBP + 12]
        Mov [OriginalRegisters.es], EAX

        Mov EAX, [EBP + 16]
        Mov [OriginalRegisters.edi], EAX

        Mov EAX, [EBP + 20]
        Mov [OriginalRegisters.esi], EAX

        Mov EAX, [EBP + 24]
        Mov [OriginalRegisters.edx], EAX

        Mov EAX, [EBP + 28]
        Mov [OriginalRegisters.ecx], EAX

        Mov EAX, [EBP + 32]
        Mov [OriginalRegisters.ebx], EAX

        Mov EAX, [EBP + 36]
        Mov [OriginalRegisters.eax], EAX


        Mov EAX, [EBP + 40]
        Mov [OriginalRegisters.efl], EAX

        Mov EAX, [EBP + 44]
        Mov [OriginalExceptionHandler], EAX

        Mov EAX, [EBP + 48]
        Mov [pAPIInfo], EAX

        Mov EAX, [EBP + 52] // <-- return address of hooked func
        Mov [ReturnAddr], EAX

        Lea EAX, [EBP + 52]
        Mov [OriginalRegisters.esp], EAX // "OriginalRegisters.esp" CONTAINS ESP of the caller (ESP WITH THE PUSHED RETURN VALUE)

        Lea EAX, [EBP + 56]
        Mov [pdwParam], EAX // <-- get api parameters
        Mov [OriginalRegisters.esp], EAX

        mov [EbpAtAPIHandler],ebp // get current ebp
        
        // save current ebp content (caller's ebp)
        Mov EAX, [EBP]
        Mov [CallerEbp],EAX

        // insert data into stack to keep trace of APIHandler
        // to do a stack retrieval later (ebp=*ebp ret addr=*(ebp+4))
        lea eax,[ebp+8]
        mov [ebp],eax

        mov eax,[APIHandler]
        mov [ebp+4],eax

        mov eax,[CallerEbp]
        mov [ebp+8],eax

        // restore real ebp+4 value (return address) to avoid call stack retrieval holes
        mov eax,[ReturnAddr]
        // mov [ebp+4],eax // if no fake trace
        mov [ebp+12],eax
    }

    // do the first important first : setting lock to avoid unhooking
    // and set thread priority to the max

    // must be before hook removal
    pAPIInfo->dwUseCount++;


    /////////////////////////////////////////////
    // if (pAPIInfo->FirstBytesCanExecuteAnywhereSize || pAPIInfo->bFunctionPointer)
    // hook is let, we don't write original code back, 
    // but we have to check for potential infinite loop
    ////////////////////////////////////////////
    if (pAPIInfo->FirstBytesCanExecuteAnywhereSize
        || pAPIInfo->bFunctionPointer
        )
    {
        /////////////////////////////////////////////
        // avoid infinite loop
        ////////////////////////////////////////////

        // if function is already inside hook 1 time
        if (pAPIInfo->dwUseCount>1)
        {
            // if call comes from current dll or from a faking dll, call only the original function 
            // to avoid infinite loop
            // (else loop can appear for each function used by this APIHandler and all its subroutine)
            if (IsAPIOverrideInternalCall(ReturnAddr,EbpAtAPIHandler))
            {
                // WE MUST NOT USE OTHER API/FUNCTIONS (else we can re-enter this loop)

                // we have to call original function only (without spying or faking) to avoid infinite hook loop
                if (pAPIInfo->bFunctionPointer)
                    // original opcode contains the real function address
                    FunctionAddress=(FARPROC)(*((PBYTE*)pAPIInfo->Opcodes));
                else
                    FunctionAddress=(FARPROC)&pAPIInfo->OpcodesExecutedAtAnotherPlace;

                // decrease use counter, incremented at the begin of the hook
                pAPIInfo->dwUseCount--;

                __asm
                {
                    // restore original exception handler
                    Mov EAX, [OriginalExceptionHandler]
                    mov fs:[0],EAX

                    // restore original ebp content
                    mov eax,[CallerEbp]
                    mov [ebp],eax

                    // restore stack before APIHandler
                    mov esp,ebp

                    //  Theoretically we have to do 
                    // Pop EBP
                    //  but if we do this, we can't access our function local var
                    //  caller' s ebp is already stored in CallerEbp
                    Pop EAX

                    ////////////////////////////////
                    // restore registers like they were at the begin of hook
                    ////////////////////////////////
                    mov eax, [OriginalRegisters.eax]
                    mov ebx, [OriginalRegisters.ebx]
                    mov ecx, [OriginalRegisters.ecx]
                    mov edx, [OriginalRegisters.edx]
                    mov esi, [OriginalRegisters.esi]
                    mov edi, [OriginalRegisters.edi]
                    push [OriginalRegisters.efl]
                    popfd

                    // remove flags registers,pAPIInfo param,hook return addr 
                    // DONT REMOVE API RETURN ADDRESS (differ from classical return see end of func)
                    Add ESP,PRE_HOOK_USED_STACK_SIZE 

                    // stack is now like it were before the hook

                    // push function address
                    push FunctionAddress
                    // restore esp
                    add esp,4

                    // restore ebp at least
                    Mov ebp,[CallerEbp] // from now you can't access your function local var

                    ////////////////////////////////
                    // call real or faked API
                    // do a jump instead of a call :
                    // the Ret instruction of original function
                    // will bring back to correct address
                    ////////////////////////////////
                    jmp dword ptr [esp-4]

                }
            }
#ifdef _DEBUG
            else
            {
                if (IsDebuggerPresent())// avoid to crash application if no debugger
                    DebugBreak();
            }
#endif
        }
        /////////////////////////////////////////////
        // end of avoid infinite loop
        ////////////////////////////////////////////


        // avoid to loose last error code
        dwLastErrorCode=GetLastError();

        // Reset end of hook event
        ResetEvent(pAPIInfo->evtEndOfHook);
    }
    else // (!pAPIInfo->FirstBytesCanExecuteAnywhereSize) && (!pAPIInfo->bFunctionPointer)
    {
        //////////////////////////////////////
        // restore original opcode
        //////////////////////////////////////

        // put flag to know we are restoring original opcode (in case of dump)
        pAPIInfo->bOriginalOpcodes=TRUE;
        // copy original stored instructions to execute original API func after the hook
        //memcpy(pAPIInfo->APIAddress, pAPIInfo->Opcodes, pAPIInfo->OpcodeReplacementSize);
        pDest=(PVOID)pAPIInfo->APIAddress;
        pSource=(PVOID)pAPIInfo->Opcodes;
        dwSize=pAPIInfo->OpcodeReplacementSize;
        asm_memcpy(pDest, pSource, dwSize);

        // avoid to loose last error code
        dwLastErrorCode=GetLastError();

        // Reset end of hook event
        ResetEvent(pAPIInfo->evtEndOfHook);

        // start boosting thread to try to avoid lost of other threads hook (when original opcodes are restored)
        // we do it after removing hook to avoid troubles hooking following funcs
        ThreadHandle=GetCurrentThread();
        ThreadPriority=GetThreadPriority(ThreadHandle);
        SetThreadPriority(ThreadHandle,THREAD_PRIORITY_TIME_CRITICAL);

    }

#if 0
    if(bMonitoring || bDebugMonitoringFile) // try to speed up a little
    {
        // until GetSystemTimeAsFileTime returned value is updated every ms
        // get execution time (try to call it as soon as possible for log ordering)
        QueryPerformanceCounter(&TickCountBeforeCall);
        // compute number of 100ns (PerformanceFrequency is in count per second)
        TickCountBeforeCall.QuadPart=((TickCountBeforeCall.QuadPart-ReferenceCounter.QuadPart)*1000*1000*10)/PerformanceFrequency.QuadPart;
        TickCountBeforeCall.QuadPart+=ReferenceTime.QuadPart;
        CallTime.dwHighDateTime=(DWORD)TickCountBeforeCall.HighPart;
        CallTime.dwLowDateTime=(DWORD)TickCountBeforeCall.LowPart;
    }
#endif


    //////////////////////////////////////////////////////////////////////
    // copy original information onto the stack
    //////////////////////////////////////////////////////////////////////
    dwParamSize=pAPIInfo->StackSize;

    // pAPIInfo->ParamCount gives a supposed size (size given by the config file)
    // in case of error in your config file you can crash your esp --> adding security size
    dwESPSecuritySize=ESP_SECURITY_SIZE* REGISTER_BYTE_SIZE;

    // ok sometimes stack is not big enough to use full ESP_SECURITY_SIZE
    // so we have to adjust dwESPSecuritySize by checking available space
    while ((IsBadReadPtr(pdwParam,dwParamSize+dwESPSecuritySize))&&dwESPSecuritySize!=0)
        dwESPSecuritySize/=2;

    // compute reserved space
    dwESPReservedSize=dwParamSize+dwESPSecuritySize;

    // duplicate all parameters in the stack for our func
    __asm
    {
        Sub ESP, [dwESPReservedSize] // get enough space in stack frame (remember push=esp-4)
        Mov [pdwESP], ESP            // get ESP pointer
    }
    // asm_memcpy(pdwESP, pdwParam, dwParamSize);// copy params from there original position
    asm_memcpy(pdwESP, pdwParam, dwESPReservedSize); // copy even more param in case of bad config file
    

    /////////////////////////////////////////////////////////////////////
    // initialize var
    /////////////////////////////////////////////////////////////////////
    BlockingCallThread=NULL;
    bBreak=FALSE;
    bLogOuputParameters=FALSE;
    bLogInputParameters=FALSE;
    bMatchFilters=FALSE;

#if 0
    if(   ((bMonitoring||bDebugMonitoringFile) && pAPIInfo->pMonitoringFileInfos) // if monitoring enabled and a monitoring file is defined for the function
       || (bFaking && pAPIInfo->FakeAPIAddress)// if faking enabled and a faking function is defined for the hooked function
       || pAPIInfo->PreApiCallChain // if a pre call chain is defined
       || pAPIInfo->PostApiCallChain // if a post call chain is defined
       ) 
    {
        // check if we have to log item
        if(pModulesFilters->GetModuleNameAndRelativeAddressFromCallerAbsoluteAddress(
            (PBYTE)ReturnAddr,
            &CallingModuleHandle,
            szCallingModuleName,
            &RelativeAddressFromCallingModule,
            &bMatchFilters,
            TRUE,
            FALSE))
        {
            RelativeAddressFromCallingModule-=ASM_CALL_INSRUCTION_SIZE;
        }
        else
        {
            bMatchFilters=TRUE;
            *szCallingModuleName=0;
            RelativeAddressFromCallingModule=0;
        }

	    bMatchFilters=bMatchFilters||pAPIInfo->DontCheckModulesFilters;
    }
#endif

    //////////////////////////////////////////////////////////////////////
    // call pre api call callbacks
    //////////////////////////////////////////////////////////////////////
    if (pAPIInfo->PreApiCallChain)
    {
        HookInfos.Rbp=(PBYTE)CallerEbp;
        HookInfos.OverridingModulesFiltersSuccessfullyChecked=bMatchFilters;
        HookInfos.ReturnAddress=ReturnAddr;
        HookInfos.CallingModuleHandle=CallingModuleHandle;

        __asm
        {
            mov [CurrentEsp],esp
        }

        pAPIInfo->PreApiCallChain->Lock(TRUE);
        for (pItem=pAPIInfo->PreApiCallChain->Head;pItem;pItem=pItem->NextItem)
        {
            pCallChainData=(PRE_POST_API_CALL_CHAIN_DATA*)pItem->ItemData;
            // call callback
            if (IsBadCodePtr((FARPROC)pCallChainData->CallBack))
            {
#ifdef _DEBUG
                if (IsDebuggerPresent())// avoid to crash application if no debugger
                    DebugBreak();
#endif
                continue;
            }

            // gives pdwESP instead of pdwParam to allow user to get changed data that will be used in function call
            PrePostApiHookCallContinueChain=((pfPreApiCallCallBack)pCallChainData->CallBack)((PBYTE)pdwESP,&OriginalRegisters,&HookInfos,pCallChainData->UserParam);

            __asm
            {
                // compare esp to an ebp based value
                cmp esp,[CurrentEsp]
                // if esp is ok go to PreApiCallChainStackSuccessFullyChecked
                je PreApiCallChainStackSuccessFullyChecked
                // else
                // restore esp
                mov esp,[CurrentEsp]
            }
            //ReportBadHookChainBadCallingConvention(pAPIInfo,pCallChainData->CallBack,TRUE);
#ifdef _DEBUG
            if (IsDebuggerPresent())// avoid to crash application if no debugger
                DebugBreak();
#endif
PreApiCallChainStackSuccessFullyChecked:
            if (!PrePostApiHookCallContinueChain)
                break;
        }
        pAPIInfo->PreApiCallChain->Unlock();
    }

#if 0
    if(bMonitoring || bDebugMonitoringFile) // try to speed up a little
    {
        // memset is required for ParseAPIParameters func don't remove it
        memset((PVOID)&LogInfoIn,0,sizeof(LOG_INFOS));
        memset((PVOID)&LogInfoOut,0,sizeof(LOG_INFOS));

        // get tick count before calling
        LogInfoIn.CallTime=CallTime;
        LogInfoOut.CallTime=CallTime;

        memcpy(&LogOriginalRegisters,&OriginalRegisters,sizeof(REGISTERS));

        //////////////////////////////////////////////////////////////////////
        // log input parameters if required
        //////////////////////////////////////////////////////////////////////
        bLogInputParametersWithoutReturn=((pAPIInfo->ParamDirectionType==PARAM_DIR_IN_NO_RETURN)
                                        ||(pAPIInfo->ParamDirectionType==PARAM_DIR_INOUT));
        bLogInputParameters=(pAPIInfo->ParamDirectionType==PARAM_DIR_IN);


        // if we log parameter in
        if ( (pAPIInfo->pMonitoringFileInfos)
             &&( ((bLogInputParameters||bLogInputParametersWithoutReturn)
                 && (!(bFiltersApplyToMonitoring && !bMatchFilters))
                 )
                ||(pAPIInfo->LogBreakWay.BreakBeforeCall && bMatchFilters)
                || bDebugMonitoringFile
                )
            )
        {
            NumberOfParameterForLogInfoIn=pAPIInfo->MonitoringParamCount;
            ParseAPIParameters(pAPIInfo, &LogInfoIn);// calling this way, params are used without consuming them

            // we have to do this before calling CLogAPI::AddLogEntry
            if (pAPIInfo->LogBreakWay.BreakBeforeCall && bMatchFilters)
            {
                // check parameters break filters (as func is quite time consuming, check only if all other conditions are ok)
                if (CheckParamBreakFilters(pAPIInfo, &LogInfoIn))
                {
                    // show BreakUserInterface Dialog
                    // gives pdwESP instead of pdwParam to allow user to change data that will be used in function call
                    Break(pAPIInfo,&LogInfoIn,(PBYTE)pdwESP,&OriginalRegisters,&DoubleResult,(ReturnAddr - ASM_CALL_INSRUCTION_SIZE),EbpAtAPIHandler,TRUE);

                    if (pAPIInfo->LogBreakWay.BreakLogInputAfter)
                    {
                        // param are still on stack
                        //re parse params in case they were modify during break
                        ParseAPIParameters(pAPIInfo, &LogInfoIn);

                        memcpy(&LogOriginalRegisters,&OriginalRegisters,sizeof(REGISTERS));
                    }
                    // copy changes on real stack (else output logging won't see these changes
                    asm_memcpy(pdwParam, pdwESP, dwParamSize); // copy only size of parameter here else you can loose changes done when breaked
                }
            }

            if (bLogInputParametersWithoutReturn || bDebugMonitoringFile)
            {
                // check parameter log filters
                if (CheckParamLogFilters(pAPIInfo, &LogInfoIn))
                    CLogAPI::AddLogEntry(pAPIInfo, &LogInfoIn, 0,0.0,FALSE,
                                        ReturnAddr - ASM_CALL_INSRUCTION_SIZE,// caller address
                                        PARAM_DIR_TYPE_IN_NO_RETURN,
                                        szCallingModuleName,RelativeAddressFromCallingModule,
                                        &OriginalRegisters,&AfterCallRegisters,pAPIInfo->MonitoringParamCount,
                                        EbpAtAPIHandler);
            }
        }
    }
#endif


    //////////////////////////////////////////////////////////////////////
    // call API or api override
    //////////////////////////////////////////////////////////////////////

    pszUnhookCheck=pAPIInfo->szModuleName;

    //bFakeCurrentCall=(bFaking && (!(bFiltersApplyToFaking&&!bMatchFilters)));// if faking is enabled and filters are ok
	bFakeCurrentCall=TRUE;

    // if an api replacement has been configured execute it instead of real api
    if (pAPIInfo->FakeAPIAddress && bFakeCurrentCall)
        FunctionAddress=pAPIInfo->FakeAPIAddress;
    else if (pAPIInfo->FirstBytesCanExecuteAnywhereSize)
        FunctionAddress=(FARPROC)&pAPIInfo->OpcodesExecutedAtAnotherPlace;
    else if (pAPIInfo->bFunctionPointer)
        // original opcode contains the real function address
        FunctionAddress=(FARPROC)(*((PBYTE*)pAPIInfo->Opcodes));
    else
        FunctionAddress=pAPIInfo->APIAddress;

    // if blocking call
    // blocking call is necessary only if not bFirstBytesCanExecuteAnyWhere
    if (pAPIInfo->BlockingCall 
        && (!pAPIInfo->FirstBytesCanExecuteAnywhereSize)
        && (!pAPIInfo->bFunctionPointer)
        )
    {
        BlockingCallArg.evtThreadStop=CreateEvent(NULL,FALSE,FALSE,NULL);
        BlockingCallArg.pApiInfo=pAPIInfo;
        // passing BlockingCallArg as param, we have to assume that thread returns before end of APIHandler
        BlockingCallThread=CreateThread(NULL,0,BlockingCallThreadProc,&BlockingCallArg,0,NULL);
    }

    // critical part no other thread should have restore hook before the call is made
    // --> check use count before restoring hook

    ExceptionType=ApiOverrideExceptionType_NONE;

    // WARNING in case of exception, stack (esp) is restored as it was
    // at function entering, so we MUSN'T recompute it in case of Exception
    try
    {
        CExceptionHardware::RegisterTry();

        // TickCountBeforeCall=GetTickCount(); // for those QueryPerformanceCounter dosen't work
        QueryPerformanceCounter(&TickCountBeforeCall);

        // restore last error
        SetLastError(dwLastErrorCode);
        __asm 
        {
            ////////////////////////////////
            // save local registers
            ////////////////////////////////
            mov [LocalRegisters.eax],eax
            mov [LocalRegisters.ebx],ebx
            mov [LocalRegisters.ecx],ecx
            mov [LocalRegisters.edx],edx
            mov [LocalRegisters.esi],esi
            mov [LocalRegisters.edi],edi
            pushfd
            pop [LocalRegisters.efl]

            ////////////////////////////////
            // restore registers like they were at the begin of hook
            ////////////////////////////////
            mov eax, [OriginalRegisters.eax]
            mov ebx, [OriginalRegisters.ebx]
            mov ecx, [OriginalRegisters.ecx]
            mov edx, [OriginalRegisters.edx]
            mov esi, [OriginalRegisters.esi]
            mov edi, [OriginalRegisters.edi]
            push [OriginalRegisters.efl]
            popfd

            ////////////////////////////////
            // call real or faked API
            ////////////////////////////////
            call FunctionAddress

            ////////////////////////////////
            // save registers after call
            ////////////////////////////////

            // save return
            Mov [ReturnValue], EAX // store func ret in dwReturnValue

            // save registers after call
            mov [AfterCallRegisters.eax],eax
            mov [AfterCallRegisters.ebx],ebx
            mov [AfterCallRegisters.ecx],ecx
            mov [AfterCallRegisters.edx],edx
            mov [AfterCallRegisters.esi],esi
            mov [AfterCallRegisters.edi],edi
            pushfd
            pop [AfterCallRegisters.efl]

            push es
            pop [AfterCallRegisters.es]
            push fs
            pop [AfterCallRegisters.fs]
            push gs
            pop [AfterCallRegisters.gs]

            //////////////////////////////////////////////////////////////////////
            // Check stack to know calling convention
            //////////////////////////////////////////////////////////////////////

            // checking stack
            Mov ECX,ESP
            // get ESP pointer after func call to known calling convention (stdcall or cdecl) and so if you have to clean the stack or not
            Mov [pdwESPAfterFuncCall], ECX

            // compute esp in case of callee cleaning to check the config file number of args
            Sub ECX,[dwParamSize]
            Mov [pdwESPAfterFuncCallCalleeCleans], ECX

            //////////////////////////////////////
            // compute real parameters stack size
            //////////////////////////////////////

            // real parameters stack size=pdwESPAfterFuncCall-pdwESP
            Mov ECX, [pdwESPAfterFuncCall]
            Sub ECX, [pdwESP]
            Mov [dwRealParamSize],ECX // store real param size
            // dwESPSizeToFree=dwESPReservedSize-real param size
            Mov ECX,[dwESPReservedSize]
            Sub ECX,[dwRealParamSize]
            Mov [dwESPSizeToFree],ECX

            // don't free local stack yet, else as we call other functions before 
            // parsing parameters again, output logging can be lost
            //Add ESP, [dwESPSizeToFree]

            ////////////////////////////////
            // restore local registers
            ////////////////////////////////
            mov eax, [LocalRegisters.eax]
            mov ebx, [LocalRegisters.ebx]
            mov ecx, [LocalRegisters.ecx]
            mov edx, [LocalRegisters.edx]
            mov esi, [LocalRegisters.esi]
            mov edi, [LocalRegisters.edi]
            push [LocalRegisters.efl]
            popfd

        }

        // check if there's data in the floating stack
        __asm
        {
            // store current flags
            fstsw [wFPUStatusRegister]
        }
        // top of stack is in bits 13,12,11
        // so if top of stack is not empty
        if (wFPUStatusRegister & 0x3800)
        {
            __asm
            {
                fstp qword ptr [DoubleResult] // we pop the floating register in case user wants to modify it's return value
                                            // will push it back just before returning
            }
            bEmptyFloatStack=FALSE;
        }
        else
            bEmptyFloatStack=TRUE;

        // GetLastError MUST BE THE FIRST FUNC CALL
        dwLastErrorCode=GetLastError();
    }
    catch( CExceptionHardware e )
    {
        ExceptionType=ApiOverrideExceptionType_HARDWARE;
        pExceptionInformation=e.pExceptionInformation;
#if 0
		_sntprintf(psz,3*MAX_PATH,_T("%s Thrown by %s (%s)"),
                    e.ExceptionText,
                    pAPIInfo->szAPIName,
                    pAPIInfo->szModuleName);
        CReportMessage::ReportMessage(REPORT_MESSAGE_ERROR,psz);
#endif
		// do not use goto !!! compiler will use a nice ret restoring esp
        __asm
        {
            jmp outofcatch
        }
    }
    catch (...)
    {
        ExceptionType=ApiOverrideExceptionType_SOFTWARE;
#if 0
		_sntprintf(psz,3*MAX_PATH,_T("Software Exception thrown by %s (%s)"),
            pAPIInfo->szAPIName,
            pAPIInfo->szModuleName);
        CReportMessage::ReportMessage(REPORT_MESSAGE_ERROR,psz);
#endif

        // "throw" function args are on stack, so we can do a direct call to throw in current context by
        // "throw;"
        // but as we have to do some finally operation,
        // we have to keep current stack, for a later throw call, and go out of catch(...)
        // the stack will be restored by upper try/catch block

        // do not use goto !!! compiler will use a nice ret restoring esp
        __asm
        {
            jmp outofcatch
        }
    }
outofcatch:

    // restore original exception handler
    __asm
    {
        Mov EAX, [OriginalExceptionHandler]
        mov fs:[0],EAX
    }

    if (ExceptionType!=ApiOverrideExceptionType_NONE)
    {
        // default some values
        ReturnValue=(PBYTE)-1;
        memcpy(&AfterCallRegisters,&OriginalRegisters,sizeof(REGISTERS));
    }

#if 0
    if(bMonitoring || bDebugMonitoringFile) // try to speed up a little
    {
        if (bEmptyFloatStack)
            DoubleResult=dFloatingNotSet;

        LogInfoIn.dwLastErrorCode=dwLastErrorCode;
        LogInfoOut.dwLastErrorCode=dwLastErrorCode;

        // get tick count after call, only few us have been taken by register saving
        QueryPerformanceCounter(&TickCountAfterCall);
        // compute number of us (PerformanceFrequency is in count per second)
        TickCountAfterCall.QuadPart=((TickCountAfterCall.QuadPart-TickCountBeforeCall.QuadPart)*1000*1000)/PerformanceFrequency.QuadPart;
        LogInfoIn.dwCallDuration = TickCountAfterCall.LowPart;
        LogInfoOut.dwCallDuration=LogInfoIn.dwCallDuration;
    }
#endif

    if (ExceptionType==ApiOverrideExceptionType_NONE)
    {
        ////////////////////////////////
        // get Calling convention
        ////////////////////////////////
        if (pdwESPAfterFuncCall==pdwESP)//if stack cleaned by caller or no params
            bStackCleanedByCallee=FALSE;
        else
        {
            bStackCleanedByCallee=TRUE;
            // check given param size
            if (pdwESPAfterFuncCallCalleeCleans!=pdwESP)
            {
                // bogus config file
                // signal it
                //BadParameterNumber(pAPIInfo,dwParamSize,dwRealParamSize);
                // update dwParamSize
                dwParamSize=dwRealParamSize;
            }
        }
    }
   
#if 0
    // allow break only if we are currently monitoring
    if (bMonitoring || bDebugMonitoringFile)// try to speed up a little if we are not monitoring
    {
        // check if we have to log output
        bLogOuputParameters=(pAPIInfo->ParamDirectionType==PARAM_DIR_OUT)||(pAPIInfo->ParamDirectionType==PARAM_DIR_INOUT);

        // update bLogOuputParameters and bLogInputParameters
        // depending result
        if (pAPIInfo->LogBreakWay.LogIfNullResult)
        {
            bLogInputParameters=bLogInputParameters&&(ReturnValue==0);
            bLogOuputParameters=bLogOuputParameters&&(ReturnValue==0);
        }
        if (pAPIInfo->LogBreakWay.LogIfNotNullResult)
        {
            bLogInputParameters=bLogInputParameters&&(ReturnValue!=0);
            bLogOuputParameters=bLogOuputParameters&&(ReturnValue!=0);
        }

        bBreak=pAPIInfo->LogBreakWay.BreakAfterCall
            ||(pAPIInfo->LogBreakWay.BreakAfterCallIfNullResult && (ReturnValue==0))
            ||(pAPIInfo->LogBreakWay.BreakAfterCallIfNotNullResult && (ReturnValue!=0));

        // check function failure
        if (ExceptionType!=ApiOverrideExceptionType_NONE)
            bFunctionFail=TRUE;
        else
            bFunctionFail=DoFunctionFail(pAPIInfo,ReturnValue,DoubleResult,dwLastErrorCode);

        // adjust bLog and bBreak depending function failure
        if (pAPIInfo->LogBreakWay.LogOnFailure)
        {
            bLogInputParameters=bFunctionFail;
            bLogOuputParameters=bFunctionFail;
        }
        if (pAPIInfo->LogBreakWay.LogOnSuccess)
        {
            bLogInputParameters=!bFunctionFail;
            bLogOuputParameters=!bFunctionFail;
        }
        if (pAPIInfo->LogBreakWay.BreakOnFailure)
            bBreak=bFunctionFail;
        if (pAPIInfo->LogBreakWay.BreakOnSuccess)
            bBreak=!bFunctionFail;

        //////////////////////////////////////////////////////////////////////
        // log output parameters if required (do the same as input parameters)
        //////////////////////////////////////////////////////////////////////
        AfterCallRegisters.esp=OriginalRegisters.esp+dwRealParamSize;
        memcpy(&LogAfterCallRegisters,&AfterCallRegisters,sizeof(REGISTERS));

        DoubleLogResult=DoubleResult;

        if ( ( (pAPIInfo->pMonitoringFileInfos) 
               && (bLogOuputParameters && (!(bFiltersApplyToMonitoring && !bMatchFilters))
               || (bBreak && bMatchFilters)
               || bDebugMonitoringFile)
              )
        )
        {
            // we get original parameters and parse them again because only pointer content as been changed,
            // not the pointer itself. Pointer content parsing is done by ParseAPIParameters, so let it do the job

            // duplicate all parameters in the stack for our func
            _asm
            {
                Sub ESP, [dwParamSize] // get enough space in stack frame (remember push=esp--)
                Mov [pdwESP], ESP      // get ESP pointer
            }
            asm_memcpy(pdwESP, pdwParam, dwParamSize);// copy params from their original position
            ParseAPIParameters(pAPIInfo, &LogInfoOut);// parse parameters (calling this way, params are used without being consumed)
            if (bMatchFilters && bBreak)
            {
                // check parameters break filters (as func is quite time consuming, check only if all other conditions are ok)
                if (CheckParamBreakFilters(pAPIInfo, &LogInfoOut))
                {
                    Break(pAPIInfo,&LogInfoOut,(PBYTE)pdwESP,&AfterCallRegisters,&DoubleResult,(ReturnAddr - ASM_CALL_INSRUCTION_SIZE),EbpAtAPIHandler,FALSE);
                    if (pAPIInfo->LogBreakWay.BreakLogOutputAfter)
                    {
                        // param are still on stack
                        // re parse params in case they were modified during break
                        ParseAPIParameters(pAPIInfo, &LogInfoOut);

                        memcpy(&LogAfterCallRegisters,&AfterCallRegisters,sizeof(REGISTERS));

                        // update returned value if eax register as been changed
                        ReturnValue=(PBYTE)AfterCallRegisters.eax;

                        // update log returned value
                        DoubleLogResult=DoubleResult;
                    }
                }

            }
            // as we don't call any func, free stack
            _asm
            {
                Add ESP, [dwParamSize]
            }
        }
    }
#endif


#if 0
    //////////////////////////////////////////////////////////////////////
    // send logging information to monitoring application
    //////////////////////////////////////////////////////////////////////
    if(bMonitoring || bDebugMonitoringFile) // if monitoring is not disabled
    {
        if ((pAPIInfo->pMonitoringFileInfos)// if a monitoring informations are defined
            && (!(bFiltersApplyToMonitoring && !bMatchFilters)|| bDebugMonitoringFile) // if filters are (not activated) or (activated and match)
            )
        {
            if (bLogInputParameters // if we log input parameters
                && (!bDebugMonitoringFile) // if bDebugMonitoringFile, we already have logged the InNoRet
                )
            {
                // check parameters log filters (as func is quite time consuming, check only if all other conditions are ok)
                if (CheckParamLogFilters(pAPIInfo, &LogInfoIn))
                    CLogAPI::AddLogEntry(pAPIInfo, &LogInfoIn, ReturnValue,DoubleLogResult,bFunctionFail,
                                        ReturnAddr - ASM_CALL_INSRUCTION_SIZE,// caller address
                                        PARAM_DIR_TYPE_IN, szCallingModuleName,RelativeAddressFromCallingModule,
                                        &LogOriginalRegisters,&LogAfterCallRegisters,NumberOfParameterForLogInfoIn,
                                        EbpAtAPIHandler);
            }
            else if (bLogOuputParameters // if we log output parameters
                     || bDebugMonitoringFile // or we are in debug mode
                    )
            {
                // check parameters log filters (as func is quite time consuming, check only if all other conditions are ok)
                if (CheckParamLogFilters(pAPIInfo, &LogInfoOut))
                    CLogAPI::AddLogEntry(pAPIInfo, &LogInfoOut, ReturnValue,DoubleLogResult,bFunctionFail,
                                        ReturnAddr - ASM_CALL_INSRUCTION_SIZE,// caller address
                                        PARAM_DIR_TYPE_OUT,szCallingModuleName,RelativeAddressFromCallingModule,
                                        &LogOriginalRegisters,&LogAfterCallRegisters,pAPIInfo->MonitoringParamCount,
                                        EbpAtAPIHandler);
            }
        }
    

        // free allocated memory by ParseAPIParameters
        //   MAKE SURE THE FOLLOWING CODE IS USED ONLY IF YOU HAVE INTIALIZE LOGINFOIN AND LOGINFOOUT WITH
        //           memset((PVOID)&LogInfoIn,0,sizeof(LOG_INFOS));
        //           memset((PVOID)&LogInfoOut,0,sizeof(LOG_INFOS));
        for (Cnt = 0; Cnt < pAPIInfo->MonitoringParamCount; Cnt++)
        {
            // if memory has been allocated
            if (LogInfoIn.ParamLogList[Cnt].pbValue)
                HeapFree(ApiOverrideLogHeap, 0,LogInfoIn.ParamLogList[Cnt].pbValue);
            // if memory has been allocated
            if (LogInfoOut.ParamLogList[Cnt].pbValue)
                HeapFree(ApiOverrideLogHeap, 0,LogInfoOut.ParamLogList[Cnt].pbValue);
        }
    }
#endif

    //////////////////////////////////////////////////////////////////////
    // call post api call callbacks
    //////////////////////////////////////////////////////////////////////
    if (pAPIInfo->PostApiCallChain
        && (ExceptionType==ApiOverrideExceptionType_NONE))
    {
        HookInfos.Rbp=(PBYTE)CallerEbp;
        HookInfos.OverridingModulesFiltersSuccessfullyChecked=bMatchFilters;
        HookInfos.ReturnAddress=ReturnAddr;
        HookInfos.CallingModuleHandle=CallingModuleHandle;

        __asm
        {
            mov [CurrentEsp],esp
        }

        pAPIInfo->PostApiCallChain->Lock(TRUE);
        for (pItem=pAPIInfo->PostApiCallChain->Head;pItem;pItem=pItem->NextItem)
        {
            pCallChainData=(PRE_POST_API_CALL_CHAIN_DATA*)pItem->ItemData;
            // call callback
            if (IsBadCodePtr((FARPROC)pCallChainData->CallBack))
            {
#ifdef _DEBUG
                if (IsDebuggerPresent())// avoid to crash application if no debugger
                    DebugBreak();
#endif
                continue;
            }

            // gives pdwParam to allow user to see param changes
            PrePostApiHookCallContinueChain=((pfPostApiCallCallBack)pCallChainData->CallBack)((PBYTE)pdwParam,&AfterCallRegisters,&HookInfos,pCallChainData->UserParam);

            __asm
            {
                // compare esp to an ebp based value
                cmp esp,[CurrentEsp]
                // if esp is ok go to PostApiCallChainStackSuccessFullyChecked
                je PostApiCallChainStackSuccessFullyChecked
                // else
                // restore esp
                mov esp,[CurrentEsp]
            }
            //ReportBadHookChainBadCallingConvention(pAPIInfo,pCallChainData->CallBack,FALSE);
#ifdef _DEBUG
            if (IsDebuggerPresent())// avoid to crash application if no debugger
                DebugBreak();
#endif
PostApiCallChainStackSuccessFullyChecked:
            if (!PrePostApiHookCallContinueChain)
                break;// break if callback query it
        }
        pAPIInfo->PostApiCallChain->Unlock();
    }

    // in case of exception, stack is restored as it was
    // at API_Handler function entering, so we MUSN'T restore it
    if(ExceptionType==ApiOverrideExceptionType_NONE)
    {
        // restore esp only now (after output logging and post api call)
        __asm
        {
            Add ESP, [dwESPSizeToFree]
        }
    }



    //////////////////////////////////////////////////////////////////////
    // Restore Hook
    //////////////////////////////////////////////////////////////////////

    // for blocking call, check if remote thread has restore original opcode
    // notice: if ((!pAPIInfo->FirstBytesCanExecuteAnyWhereSize) || (!pAPIInfo->bFunctionPointer))
    //              BlockingCallThread is null
    if (pAPIInfo->BlockingCall&&BlockingCallThread)
    {
        // query thread to stop
        SetEvent(BlockingCallArg.evtThreadStop);

        // wait for thread to finish before restoring hook 
        // it's avoid lots of thread creation
        // and troubles if WaitForSingleObject is hooked
        WaitForSingleObject(BlockingCallThread,INFINITE);

        // close thread handle
        CloseHandle(BlockingCallThread);
    }
    
    if ((!pAPIInfo->FirstBytesCanExecuteAnywhereSize)&&(!pAPIInfo->bFunctionPointer))
        // stop boosting thread before restoring protection to avoid SetThreadPriority hook troubles
        SetThreadPriority(ThreadHandle,ThreadPriority);

    if (pAPIInfo->dwUseCount==1)
    {
        // set end of hook event.
        // after setting this event use only local vars. Not pAPIInfo ones
        SetEvent(pAPIInfo->evtEndOfHook);
    }

    // RESTORE LAST ERROR (no func must be called after this)
    SetLastError(dwLastErrorCode);

    // decrease only when pAPIInfo is no more useful
    pAPIInfo->dwUseCount--;

    // restore hook for the next API call
    // (restore only if not in use by another thread)
    if (pAPIInfo->dwUseCount==0)
    {
        // restore original bytes only if !bFirstBytesCanExecuteAnyWhere and !pAPIInfo->bFunctionPointer
        if (pAPIInfo->bOriginalOpcodes)
        {
            // restore only if we don't have query to Unhook the function
            if (!pAPIInfo->AskedToRemove)
            {
                // flag to know we are restoring hook (in case of dump)
                pAPIInfo->bOriginalOpcodes=FALSE;

                pDest=pAPIInfo->APIAddress;
                pSource=pAPIInfo->pbHookCodes;
                dwSize=pAPIInfo->OpcodeReplacementSize;
                asm_memcpy(pDest, pSource, dwSize);
            }
        }
    }
    // AVOID TO CALL FUNC FROM HERE TO AVOID INFINITE LOOP if it's hooked

    // the 2 following function are called in some circumstances only,
    // that means there is no loop threat
    if (ExceptionType==ApiOverrideExceptionType_HARDWARE)
    {
        // translate exception to upper context
        // we can call RaiseException because dwLastErrorCode and SetLastError have no meaning in this case
        RaiseException(pExceptionInformation->ExceptionRecord->ExceptionCode,
            pExceptionInformation->ExceptionRecord->ExceptionFlags,
            pExceptionInformation->ExceptionRecord->NumberParameters,
            pExceptionInformation->ExceptionRecord->ExceptionInformation);
    }
    else if (ExceptionType==ApiOverrideExceptionType_SOFTWARE)
    {
        // stack is in the same state as it was inside the catch(...) block
        // so throw args are correctly on the stack and we can call throw directly
        // as we do in catch block to translate error to upper try/catch block
        throw;
    }

    //////////////////////////////////////////////////////////////////////
    // Restore Stack (make the same job real Api do without hooking)
    //////////////////////////////////////////////////////////////////////

    __asm
    {
        // if floating stack is not empty goto AfterFloatReturnRestored
        cmp [bEmptyFloatStack],0
        jne AfterFloatReturnRestored

        // else restore floating return
        fld qword ptr [DoubleResult]

AfterFloatReturnRestored:

        // restore original ebp content
        mov eax,[CallerEbp]
        mov [ebp],eax

        Mov ESP, EBP
        //  Theoretically we have to do 
        // Pop EBP
        //  but if we do this, we can't access our function local var
        //  caller' s ebp is already stored in CallerEbp
        Pop EAX

        // remove flags registers,pAPIInfo param,hook return addr and API return addr from stack
        Add ESP,PRE_HOOK_USED_STACK_SIZE + 4 // +4 for return address

        // now esp points to second ret address --> ret will use return address of hooked func

        // if (!bStackCleanedByCallee)
        //      goto AfterRemovingParams
        cmp [bStackCleanedByCallee],0
        je AfterRemovingParams

        // remove params from stack (make same esp delta as original function)
        Add ESP, [dwParamSize]

AfterRemovingParams:
        // restore registers like they were after API call
        mov eax, [AfterCallRegisters.eax]
        mov ebx, [AfterCallRegisters.ebx]
        mov ecx, [AfterCallRegisters.ecx]
        mov edx, [AfterCallRegisters.edx]
        mov esi, [AfterCallRegisters.esi]
        mov edi, [AfterCallRegisters.edi]
        push [AfterCallRegisters.efl]
        popfd

        // push return address
        push [ReturnAddr]
        // restore ebp at least
        Mov ebp,[CallerEbp] // from now you can't access your function local var

        Ret
    }
}
#pragma runtime_checks( "", restore )


//-----------------------------------------------------------------------------
// Name: BlockingCallThreadProc
// Object: Restore originals opcode before the end of function
// Parameters :
//     in  : LPVOID lpParameter : BLOCKING_CALL* struc
// Return : TRUE
//-----------------------------------------------------------------------------
DWORD WINAPI BlockingCallThreadProc(LPVOID lpParameter)
{
    PBLOCKING_CALL pBlockingCallArg=(PBLOCKING_CALL)lpParameter;

    // wait for hook end private event
    WaitForSingleObject(pBlockingCallArg->evtThreadStop,1);

    // restore hook even if in use by another thread
    // as Blocking call is dedicated for slow function call, being here
    // means other threads are in a waiting state and have executed first bytes

    // if remove hook has not been called
    if (!pBlockingCallArg->pApiInfo->AskedToRemove)
    {
        pBlockingCallArg->pApiInfo->bOriginalOpcodes=FALSE;
        // restore hook
        PVOID pDest=pBlockingCallArg->pApiInfo->APIAddress;
        PVOID pSource=pBlockingCallArg->pApiInfo->pbHookCodes;
        DWORD dwSize=pBlockingCallArg->pApiInfo->OpcodeReplacementSize;
        asm_memcpy(pDest, pSource, dwSize);
    }

    return 0;
}


//-----------------------------------------------------------------------------
// Name: RemoveProtection
// Object: Remove protection of pAPIInfo->APIAddress, and store old Protection flags in
//               pAPIInfo->dwOldProtectionFlags
// Parameters :
//     in out  : API_INFO *pAPIInfo
// Return : TRUE
//-----------------------------------------------------------------------------
BOOL RemoveProtection(API_INFO *pAPIInfo)
{
    // Get page protection of API
    // MEMORY_BASIC_INFORMATION mbi;
    // VirtualQuery(pAPIInfo->APIAddress, &mbi, sizeof(mbi));
    // DWORD dwProtectionFlags = mbi.Protect;
    // Remove page protection from API

    //dwProtectionFlags &= ~PAGE_EXECUTE;
    //dwProtectionFlags &= ~PAGE_EXECUTE_READ;
    //dwProtectionFlags &= ~PAGE_EXECUTE_WRITECOPY;
    //dwProtectionFlags &= ~PAGE_NOACCESS;
    //dwProtectionFlags &= ~PAGE_READONLY;
    //dwProtectionFlags &= ~PAGE_WRITECOPY;

    // only gives full rights
    // dwProtectionFlags = PAGE_EXECUTE_READWRITE;

    // as pAPIInfo->APIAddress is not system page rounded, do not use "if (!VirtualProtect(pAPIInfo->APIAddress, dwSystemPageSize,..."
    if (!VirtualProtect(pAPIInfo->APIAddress, pAPIInfo->OpcodeReplacementSize, PAGE_EXECUTE_READWRITE, &pAPIInfo->dwOldProtectionFlags))
    {
#if 0
        TCHAR psz[3*MAX_PATH];
        _stprintf(psz,_T("Error removing memory protection at 0x%p for function %s in module %s. Hook won't be installed for this function"),
                pAPIInfo->APIAddress,pAPIInfo->szAPIName,pAPIInfo->szModuleName);
        CReportMessage::ReportMessage(REPORT_MESSAGE_ERROR,psz);
#endif
        return FALSE;
    }
    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: GetAssociatedItemAPIInfo
// Object: Get List Item containing APIInfo Struct Associated to given API address
// Parameters :
//     in  : PBYTE pbAPI virtual address of func to hook 
//     out : BOOL* pbAlreadyHooked : true if func is already hooked
// Return : NULL on error
//          on success 
//               - if Hook was not existing Allocate and return a new List Item containing an empty APIInfo struct
//               - else return the old List Item containing APIInfo struct to allow update of some fields
//-----------------------------------------------------------------------------
CLinkListItem* __stdcall GetAssociatedItemAPIInfo(PBYTE pbAPI,BOOL* pbAlreadyHooked)
{
    API_INFO *pAPIInfo;
    CLinkListItem* pItemAPIInfo;

    if ((pbAPI==NULL)||(pbAlreadyHooked==NULL))
        return NULL;
    *pbAlreadyHooked=FALSE;
    // Is it already hooked ?
    
CheckIfHooked:
    pLinkListAPIInfos->Lock();
    for (pItemAPIInfo=pLinkListAPIInfos->Head; pItemAPIInfo; pItemAPIInfo=pItemAPIInfo->NextItem)
    {
        pAPIInfo=(API_INFO*)pItemAPIInfo->ItemData;
        if (pAPIInfo->APIAddress == (FARPROC)pbAPI)
        {
            // In case of monitoring file reload, assume the pAPIInfo is not the one being unloading
            if (pAPIInfo->FreeingMemory||pAPIInfo->AskedToRemove)
            {
                pLinkListAPIInfos->Unlock();
                Sleep(UNHOOK_SECURITY_WAIT_TIME_BEFORE_MEMORY_FREEING*4);
                // check again in case item is still freeing
                goto CheckIfHooked;
            }
            else
            {
                // return old hook to allow update some API_INFO fields
                *pbAlreadyHooked=TRUE;
                pLinkListAPIInfos->Unlock();
                return pItemAPIInfo;
            }
        }
        
    }
    
    // No, so add a new item
    pItemAPIInfo =pLinkListAPIInfos->AddItem(TRUE);

    // store api address
    pAPIInfo=(API_INFO*)pItemAPIInfo->ItemData;
    pAPIInfo->APIAddress=(FARPROC)pbAPI;

    pLinkListAPIInfos->Unlock();

    return pItemAPIInfo;
}

//-----------------------------------------------------------------------------
// Name: HookAPIFunction
// Object: Patch Opcode located at pAPIInfo->APIAddress to make a call to APIHandler
//         Save original bytes in pAPIInfo->Opcodes
//         Save modified bytes in pAPIInfo->pbHookCodes to avoid recomputing on each hook restoration
// Parameters :
//     in out  : API_INFO *pAPIInfo : pAPIInfo->APIAddress contains virtual address of API to patch
// Return : FALSE on error, TRUE if success
//
// Warning depending of hook code you have to update HOOK_NUMBER_OF_EBP_PUSH
//-----------------------------------------------------------------------------
BOOL __stdcall HookAPIFunction(API_INFO *pAPIInfo)
{
    PBYTE* pAPI;
    BOOL Result;
    DWORD Index;
    DWORD dwOldProtectionFlags;
    BOOL bFirstBytesCanExecuteAnywhere=FALSE;
    CHookAvailabilityCheck::IsFunctionHookableResult CheckResult;
    CHookAvailabilityCheck::STRUCT_FIRST_BYTES_CAN_BE_EXECUTED_ANYWHERE_RESULT FirstBytesCanExecuteAnywhereResult;

    if (pAPIInfo == NULL)
        return FALSE;

    // if pAPIInfo->Opcodes are defined, that means function can already be hooked
    // and in this case if hook is installed,
    // the instruction
    // memcpy(pAPIInfo->Opcodes, pAPIInfo->APIAddress, pAPIInfo->OpcodeReplacementSize);
    // will store hook opcodes in pAPIInfo->Opcodes and we get an infinite loop :
    // APIHandler is always reentering when trying to execute original opcodes
    if (*pAPIInfo->Opcodes)
    {
#ifdef _DEBUG
        if (IsDebuggerPresent())// avoid to crash application if no debugger
            DebugBreak();
#endif
        return FALSE;
    }

    if (IsBadCodePtr((FARPROC)pAPIInfo->APIAddress))
    {
#if 0
        TCHAR psz[3*MAX_PATH];
        _sntprintf(psz,3*MAX_PATH,_T("Bad code pointer 0x%p for function %s in module %s"),pAPIInfo->APIAddress,pAPIInfo->szAPIName,pAPIInfo->szModuleName);
        CReportMessage::ReportMessage(REPORT_MESSAGE_ERROR,psz);
#endif
        return FALSE;
    }

    // if we are patching function pointer
    if (pAPIInfo->bFunctionPointer)
    {
        // code replacement size is the size of a pointer
        pAPIInfo->OpcodeReplacementSize=sizeof(PBYTE);
        if (IsBadCodePtr((FARPROC)*((PBYTE*)pAPIInfo->APIAddress)))
        {
#if 0
			TCHAR psz[3*MAX_PATH];
            _sntprintf(psz,3*MAX_PATH,_T("Bad code pointer 0x%p for function %s in module %s"),pAPIInfo->APIAddress,pAPIInfo->szAPIName,pAPIInfo->szModuleName);
            CReportMessage::ReportMessage(REPORT_MESSAGE_ERROR,psz);
#endif
            return FALSE;
        }
    }
    else
        // else, code replacement size is the size of our hook
        pAPIInfo->OpcodeReplacementSize=OPCODE_REPLACEMENT_SIZE;

    // allow write access to memory
    Result = RemoveProtection(pAPIInfo);
    if (Result == FALSE)
        return FALSE;

    pAPIInfo->dwUseCount=0;


    // Save first pAPIInfo->OpcodeReplacementSize bytes of API
    memcpy(pAPIInfo->Opcodes, pAPIInfo->APIAddress, pAPIInfo->OpcodeReplacementSize);

    if (!pAPIInfo->bFunctionPointer)
    {

        // check FirstBytesCanExecuteAnywhereSize value
        // should be -1,0 or OPCODE_REPLACEMENT_SIZE<=FirstBytesCanExecuteAnywhereSize<=FIRST_OPCODES_MAX_SIZE
        if (  ((pAPIInfo->FirstBytesCanExecuteAnywhereSize<OPCODE_REPLACEMENT_SIZE)
            &&(pAPIInfo->FirstBytesCanExecuteAnywhereSize!=0))
            ||((pAPIInfo->FirstBytesCanExecuteAnywhereSize>FIRST_OPCODES_MAX_SIZE)
            &&(pAPIInfo->FirstBytesCanExecuteAnywhereSize!=(DWORD)-1))
            )
            pAPIInfo->FirstBytesCanExecuteAnywhereSize=0;

        // if first byte can be executed anywhere, 
        if ((pAPIInfo->FirstBytesCanExecuteAnywhereSize!=(DWORD)-1)
            &&(FirstBytesAutoAnalysis!=FIRST_BYTES_AUTO_ANALYSIS_NONE)
            )
        {
            Result=FALSE;

            // if size is specified
            if (pAPIInfo->FirstBytesCanExecuteAnywhereSize!=0)
                bFirstBytesCanExecuteAnywhere=TRUE;

            else// in case of generic monitoring files, we have to check if function is hookable and if first bytes can be executed anywhere
            {
                // set default value
                bFirstBytesCanExecuteAnywhere=FALSE;

                // do first byte checking to verify that function can be hooked
                Result=CHookAvailabilityCheck::IsFunctionHookable((PBYTE)pAPIInfo->APIAddress,&CheckResult);

                if (Result)
                {
                    if (CheckResult==CHookAvailabilityCheck::IS_FUNCTION_HOOKABLE_RESULT_NOT_HOOKABLE)
                    {
                        // if function seems to be not hookable query the user the action to do
#if 0
                        Result=FALSE;
                        TCHAR psz[3*MAX_PATH];
                        _stprintf(psz,
                                _T("Function %s seems to be not hookable.\r\n")
                                _T("If you try to hook it, your targeted application may will crash")
                                _T("Do you want to try to hook it anyway ?\r\n(check function first bytes if you're not sure)\r\n\r\n")
                                _T("Notice: To remove this warning, disable function in monitoring file, or use a %s/%s option"),
                                pAPIInfo->szAPIName,
                                OPTION_FIRST_BYTES_CAN_EXECUTE_ANYWHERE,
                                OPTION_FIRST_BYTES_CANT_EXECUTE_ANYWHERE);
                        if (DynamicMessageBoxInDefaultStation(NULL,psz,_T("Warning"),MB_ICONWARNING|MB_TOPMOST|MB_YESNO)==IDYES)
#endif
							Result=TRUE;
                    }
                    else if ((CheckResult==CHookAvailabilityCheck::IS_FUNCTION_HOOKABLE_RESULT_MAY_NOT_HOOKABLE)
                            ||(Result==FALSE))
                    {
                        // if function seems to be not hookable query the user the action to do
#if 0
                        Result=FALSE;
                        TCHAR psz[3*MAX_PATH];
                        _stprintf(psz,
                            _T("Function %s could be not hookable.\r\n")
                            _T("Look at function first bytes to check if you can hook it.\r\n")
                            _T("Do you want to hook it ?\r\n\r\n")
                            _T("Notice: To remove this warning add a %s or %s option to your monitoring file"),
                            pAPIInfo->szAPIName,
                            OPTION_FIRST_BYTES_CAN_EXECUTE_ANYWHERE,
                            OPTION_FIRST_BYTES_CANT_EXECUTE_ANYWHERE);
                        if (DynamicMessageBoxInDefaultStation(NULL,psz,_T("Warning"),MB_ICONWARNING|MB_TOPMOST|MB_YESNO)==IDYES)
#endif
							Result=TRUE;
                    }
                }

                // if function is hookable
                if (Result)
                {
                    // check if first bytes can be executed anywhere
                    Result=CHookAvailabilityCheck::CanFirstBytesBeExecutedAnyWhere((PBYTE)pAPIInfo->APIAddress,&FirstBytesCanExecuteAnywhereResult);
                    if (Result)
                    {
                        // in case of insecure first bytes analysis
                        if (FirstBytesAutoAnalysis==FIRST_BYTES_AUTO_ANALYSIS_INSECURE)
                        {
                            if (FirstBytesCanExecuteAnywhereResult.FirstBytesCanBeExecutedAnyWhereResult==CHookAvailabilityCheck::CAN_FIRST_BYTES_BE_EXECUTED_ANYWHERE_RESULT_MAY)
                                FirstBytesCanExecuteAnywhereResult.FirstBytesCanBeExecutedAnyWhereResult=CHookAvailabilityCheck::CAN_FIRST_BYTES_BE_EXECUTED_ANYWHERE_RESULT_YES;
                            else if (FirstBytesCanExecuteAnywhereResult.FirstBytesCanBeExecutedAnyWhereResult==CHookAvailabilityCheck::CAN_FIRST_BYTES_BE_EXECUTED_ANYWHERE_RESULT_MAY_NEED_RELATIVE_ADDRESS_CHANGES)
                                FirstBytesCanExecuteAnywhereResult.FirstBytesCanBeExecutedAnyWhereResult=CHookAvailabilityCheck::CAN_FIRST_BYTES_BE_EXECUTED_ANYWHERE_RESULT_YES_NEED_RELATIVE_ADDRESS_CHANGES;
                        }

                        // update pAPIInfo with first bytes analysis result
                        if (FirstBytesCanExecuteAnywhereResult.FirstBytesCanBeExecutedAnyWhereResult==CHookAvailabilityCheck::CAN_FIRST_BYTES_BE_EXECUTED_ANYWHERE_RESULT_YES)
                        {
                            bFirstBytesCanExecuteAnywhere=TRUE;
                            pAPIInfo->FirstBytesCanExecuteAnywhereSize=FirstBytesCanExecuteAnywhereResult.NbBytesToExecuteAtAnotherPlace;
                        }
                        else if(FirstBytesCanExecuteAnywhereResult.FirstBytesCanBeExecutedAnyWhereResult==CHookAvailabilityCheck::CAN_FIRST_BYTES_BE_EXECUTED_ANYWHERE_RESULT_YES_NEED_RELATIVE_ADDRESS_CHANGES)
                        {
                            bFirstBytesCanExecuteAnywhere=TRUE;
                            pAPIInfo->FirstBytesCanExecuteAnywhereSize=FirstBytesCanExecuteAnywhereResult.NbBytesToExecuteAtAnotherPlace;
                            pAPIInfo->FirstBytesCanExecuteAnywhereNeedRelativeAddressChange=TRUE;
                        }
                    }
                }
            }
        }

        // if first bytes can be executed anywhere
        if (bFirstBytesCanExecuteAnywhere)
        {
            // get first bytes of API
            memcpy(pAPIInfo->OpcodesExecutedAtAnotherPlace, pAPIInfo->APIAddress, pAPIInfo->FirstBytesCanExecuteAnywhereSize);

            // begin of function will be executed at pAPIInfo->OpcodesExecutedAtAnotherPlace address
            // so pAPIInfo->OpcodesExecutedAtAnotherPlace must be executable memory, and opcode after OPCODE_REPLACEMENT_SIZE have
            // to do a jump to Original API Address + OPCODE_REPLACEMENT_SIZE

            // mark memory as executable
            // as pExecutedBuffer is not system page rounded, do not use "if (!VirtualProtect(pAPIInfo->OpcodesExecutedAtAnotherPlace, dwSystemPageSize,..."
            VirtualProtect(pAPIInfo->OpcodesExecutedAtAnotherPlace, pAPIInfo->FirstBytesCanExecuteAnywhereSize+REENTER_FUNCTION_FLOW_OPCODE_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtectionFlags);

            Index=pAPIInfo->FirstBytesCanExecuteAnywhereSize;
            // compute jump between pAPIInfo->Opcodes and original address + OPCODE_REPLACEMENT_SIZE
            // jump to handler
            pAPIInfo->OpcodesExecutedAtAnotherPlace[Index++] = 0xE9;// relative jmp asm instruction
            // get pointer for storing call address
            pAPI = (PBYTE*)&pAPIInfo->OpcodesExecutedAtAnotherPlace[Index];
            // compute relative address from current address to begin of API + FirstBytesCanExecuteAnyWhereSize
            pAPI[0] = (PBYTE)((UINT_PTR)pAPIInfo->APIAddress+pAPIInfo->FirstBytesCanExecuteAnywhereSize 
                - (UINT_PTR)(&pAPIInfo->OpcodesExecutedAtAnotherPlace[Index])-sizeof(PBYTE));

            // if there's a relative 32bit address we have to compute new relative address from current position
            if (pAPIInfo->FirstBytesCanExecuteAnywhereNeedRelativeAddressChange)
            {
                PBYTE RelativeAddress;
                // relative address is at FirstBytesCanExecuteAnywhereSize-sizeof(PBYTE)
                pAPI=(PBYTE*)&pAPIInfo->OpcodesExecutedAtAnotherPlace[pAPIInfo->FirstBytesCanExecuteAnywhereSize-sizeof(PBYTE)];
                // get original relative address
                RelativeAddress=*pAPI;
                // compute new relative address = oldRVA+oldRelative-newRVA
                pAPI[0]=(PBYTE)RelativeAddress+(UINT_PTR)pAPIInfo->APIAddress-(UINT_PTR)pAPIInfo->OpcodesExecutedAtAnotherPlace;
            }
        }
        else // first bytes can't be executed anywhere
        {
            // adjust pAPIInfo->FirstBytesCanExecuteAnywhereSize
            pAPIInfo->FirstBytesCanExecuteAnywhereSize=0;
        }

    }
    /////////////////////////
    // first hook : only call second hook to overwrite the lesser byte as possible
    // this buffer is copied at the original address of API func, so code is never executed 
    // at this address --> no need to mark memory as PAGE_EXECUTE_READWRITE
    /////////////////////////
    Index=0;
    if (pAPIInfo->bFunctionPointer)
    {
        // we only have to change address pointed at pAPIInfo->APIAddress
        // by the address of pAPIInfo->pbSecondHook
        // address is absolute --> no need to compute relative address

        // get pointer for storing call address
        pAPI = (PBYTE*)&pAPIInfo->pbHookCodes[Index];
        // fill 
        pAPI[0] = pAPIInfo->pbSecondHook;
    }
    else
    {
        // we have to overwrite first function bytes
        pAPIInfo->pbHookCodes[Index++] = 0xE9;// JMP rel asm instruction
        // get pointer for storing call address
        pAPI = (PBYTE*)&pAPIInfo->pbHookCodes[Index];
        // compute relative address from API address to our second hooking function (pbSecondHook)
        pAPI[0] = (PBYTE)pAPIInfo->pbSecondHook - (UINT_PTR)pAPIInfo->APIAddress - OPCODE_REPLACEMENT_SIZE;
    }


    /////////////////////////
    // second hook : push pApiInfo and registers, and next jump to APIHandler
    // code is executed at pAPIInfo->pbSecondHook address --> we need to set memory as PAGE_EXECUTE_READWRITE
    /////////////////////////
    // VirtualProtect(pAPIInfo->pbSecondHook, dwSystemPageSize, PAGE_EXECUTE_READWRITE, &dwOldProtectionFlags);
    // as pAPIInfo->Opcodes some time needs to be executed, change the page protection for full pAPIInfo
    // as pAPIInfo is not system page rounded, do not use "if (!VirtualProtect(pAPIInfo, dwSystemPageSize,..."
    VirtualProtect(pAPIInfo, sizeof(API_INFO), PAGE_EXECUTE_READWRITE, &dwOldProtectionFlags);

    Index=0;

    // push pAPIInfo
    pAPIInfo->pbSecondHook[Index++] = 0x68; // PUSH asm instruction
    pAPI = (PBYTE*)&pAPIInfo->pbSecondHook[Index];
    pAPI[0]=(PBYTE)pAPIInfo;
    Index+=sizeof(PBYTE);

    // jump to handler
    pAPIInfo->pbSecondHook[Index++] = 0xE9;// relative jmp asm instruction
    // get pointer for storing call address
    pAPI = (PBYTE*)&pAPIInfo->pbSecondHook[Index];

    // compute relative address from pbSecondHook to our API hooking function (APIHandlerNaked)
    // pAPI[0] = APIHandlerNaked - pAPIInfo->pbSecondHook - SECOND_HOOK_SIZE;
    pAPI[0] = (PBYTE)APIHandlerNaked - (UINT_PTR)pAPIInfo->pbSecondHook - (Index+sizeof(PBYTE));

    //////////////////
    // change original code to CALL second hook
    // after this, hook is active
    //////////////////
    // flag to know we are installing hook (in case of dump)
    pAPIInfo->bOriginalOpcodes=FALSE;
    memcpy(pAPIInfo->APIAddress,pAPIInfo->pbHookCodes,pAPIInfo->OpcodeReplacementSize);

    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: UnhookAPIFunction
// Object: try to remove hook (dll in use are not free to avoid crash)
//         should be not called directly use UnHookIfPossible instead
// Parameters :
//     in out  : CLinkListItem *pItemAPIInfo : free on success
// Return : FALSE on error or func is not unhook now, TRUE on success
//-----------------------------------------------------------------------------
BOOL UnhookAPIFunction(CLinkListItem *pItemAPIInfo)
{
    FREE_APIINFO sFreeApiInfo;
    API_INFO *pAPIInfo;
    BOOL Result;
    int iMsgBoxRes;
    TCHAR pszMsg[2*MAX_PATH];
    DWORD dwWaitRes;
    PBYTE pHookCodes[MAX_OPCODE_REPLACEMENT_SIZE];

    if (IsBadReadPtr(pItemAPIInfo,sizeof(CLinkListItem)))
        return FALSE;
    pAPIInfo=(API_INFO*)pItemAPIInfo->ItemData;
    if (IsBadReadPtr(pAPIInfo,sizeof(API_INFO)))
        return FALSE;

    if (pAPIInfo->FreeingMemory)
        return TRUE;

    // inform we want to remove hook
    pAPIInfo->AskedToRemove=TRUE;

    // store hook codes for later checking
    memcpy(pHookCodes,pAPIInfo->pbHookCodes,pAPIInfo->OpcodeReplacementSize);

    // change pbHookCodes to Opcodes to avoid hook to be restore at the end of hooking
    memcpy(pAPIInfo->pbHookCodes, pAPIInfo->Opcodes, pAPIInfo->OpcodeReplacementSize);

    // restore original opcode to avoid hook entering 

    // flag to know we are restoring original opcodes (in case of dump)
    pAPIInfo->bOriginalOpcodes=TRUE;

    // if dll has been unloaded without hook removal
    // or if pAPIInfo has never been hooked
    if (IsBadCodePtr((FARPROC)pAPIInfo->APIAddress))
    {
        // free API_INFO associated to hook
        ReleaseAndFreeApiInfo(pItemAPIInfo);
        return TRUE;
    }
    // restore bytes only if not already done
    if (memcmp(pAPIInfo->APIAddress, pAPIInfo->Opcodes, pAPIInfo->OpcodeReplacementSize))
    {
        // assume opcodes is our one !
        // it can appear that for COM dll are unloaded and next reloaded at the same space,
        // if it's done too quickly or during COM unhooking, we can have original bytes
        // with original memory protection (due to reloading of dll), so pAPIInfo->APIAddress can be write protected
        if (memcmp(pAPIInfo->APIAddress,pHookCodes, pAPIInfo->OpcodeReplacementSize)==0)
        {
            // restore original opcodes
            if (!IsBadWritePtr(pAPIInfo->APIAddress,pAPIInfo->OpcodeReplacementSize))
                memcpy(pAPIInfo->APIAddress, pAPIInfo->Opcodes, pAPIInfo->OpcodeReplacementSize);
        }
    }

    Result=TRUE;
    // Make sure we are not in hooking func
    iMsgBoxRes=IDYES;

    // wait end of hook
    // monitoring could be unhooked without waiting, but this can cause trouble because we can't know
    // if we can unload this dll or not (if we unload it and a monitoring hook is in use, the return
    // address will be in our unloaded dll --> beautiful crash)

    Result=FALSE;
    while(iMsgBoxRes==IDYES)
    {
        // set event to go out of our WaitForMultiple(xx,INFINITE) in ThreadFreeingHooksProc (it can avoid API freeing lock)
        //SetEvent(hevtWaitForUnlocker);

        // assume API is not currently hooked, or if in use wait for the end of hook 
        dwWaitRes=WaitForSingleObject(pAPIInfo->evtEndOfHook,UNHOOK_MAX_WAIT_TIME);
        if (dwWaitRes==WAIT_OBJECT_0)
        {
            // wait a while that the hook ends for the last called functions
            // can be the case for func called between SetEvent (included) and pAPIInfo->dwUseCount--
            while (pAPIInfo->dwUseCount!=0)
                Sleep(50);

            // put flag to indicate we are going to free hook
            pAPIInfo->FreeingMemory=TRUE;
            // add an item to the list of item to be free
#if 0
            sFreeApiInfo.InitialTickCount=GetTickCount();
            sFreeApiInfo.pItemAPIInfo=pItemAPIInfo;
            pLinkListAPIInfosToBeFree->AddItem(&sFreeApiInfo);
            // set an event to signal to the thread charged of hook freeing that there's new data to free
            SetEvent(hevtFreeAPIInfo);
#endif

            Result=TRUE;
            break;
        }
        else if (dwWaitRes==WAIT_TIMEOUT)
        {
#if 0
            // put the user aware and hope he will do actions that unlock fake api
            // a good sample of blocking call are DynamicMessageBox
            _sntprintf(pszMsg,2*MAX_PATH,_T("Warning %s in module %s\r\n is in use.\r\nDo you want to wait more time ?"),pAPIInfo->szAPIName,pAPIInfo->szModuleName);
            iMsgBoxRes=DynamicMessageBoxInDefaultStation(NULL,pszMsg,_T("Warning"),MB_YESNO|MB_ICONWARNING|MB_TOPMOST);
#endif
		}
        else
            break;
    }

    return Result;
}
DWORD WINAPI ThreadFreeingHooksProc(LPVOID lpParameter)
{
    //HANDLE ph[3]={hevtAllAPIUnhookedDllFreeAll,hevtWaitForUnlocker,hevtFreeAPIInfo};
    CLinkListItem* pItem;
    CLinkListItem* pNextItem;
    PFREE_APIINFO pFreeAPIInfo;
    DWORD dwWaitRes;
    BOOL bContinue=TRUE;
    BOOL bApplicationUnload=(BOOL)lpParameter;
    
    while(bContinue)
    {
        // if application is being unload
        if (bApplicationUnload)
            // don't wait, ask only to free all hooks
            dwWaitRes=WAIT_OBJECT_0+2;
        else
            dwWaitRes=WAIT_OBJECT_0+2;
#if 0
            // wait for unlocking event, item added to list event, thread closing query event
            dwWaitRes=WaitForMultipleObjects(3,ph,FALSE,INFINITE);
#endif

        switch (dwWaitRes)
        {
        case WAIT_OBJECT_0: // hevtAllAPIUnhookedDllFreeAll
            // all api are unhooked and dll must detach --> just go out of current thread
            bContinue=FALSE;
            break;
        case WAIT_OBJECT_0+1: // hevtWaitForUnlocker
            // just event to wake up WaitForMultipleObjects and unlock it
            break;
        case WAIT_OBJECT_0+2: // hevtFreeAPIInfo
            // some data have to be free
begin:        
#if 0
			if (pLinkListAPIInfosToBeFree)
            {
                for (pItem=pLinkListAPIInfosToBeFree->Head;pItem;pItem=pNextItem)
                {
                    pFreeAPIInfo=(PFREE_APIINFO)pItem->ItemData;

                    // assume we have waited UNHOOK_SECURITY_WAIT_TIME_BEFORE_MEMORY_FREEING
                    if ((GetTickCount()-pFreeAPIInfo->InitialTickCount)<UNHOOK_SECURITY_WAIT_TIME_BEFORE_MEMORY_FREEING)
                        Sleep(UNHOOK_SECURITY_WAIT_TIME_BEFORE_MEMORY_FREEING);

                    // get next item now (before freeing pItem)
                    pNextItem=pItem->NextItem;

                    // free API_INFO associated to hook
                    ReleaseAndFreeApiInfo(pFreeAPIInfo->pItemAPIInfo);

                    // remove item from list
                    pLinkListAPIInfosToBeFree->RemoveItem(pItem);

                    if (IsBadReadPtr(pNextItem,sizeof(CLinkListItem)))
                        goto begin;
                }
                
            }
#endif

            // if application is unloading, we are not in a thread but in func
            if (bApplicationUnload)
                // just go out of this func
                bContinue=FALSE;

            break;
        default: // error --> go out of thread (useless to loop on failing WaitForMultipleObjects)
            // don't close handles because they may will be use by other threads
            return 0xFFFFFFFF;
        }
    }
    //CleanCloseHandle(&hevtFreeAPIInfo);
    //CleanCloseHandle(&hevtAllAPIUnhookedDllFreeAll);
    //FreeingThreadGracefullyClosed=TRUE;
    return 0;
}

//-----------------------------------------------------------------------------
// Name: WaitForAllHookFreeing
// Object: assume there's no more item being freeing
// Parameters :
// Return : 
//-----------------------------------------------------------------------------
#if 0
void WaitForAllHookFreeing()
{
    // if dll unload as begin, other threads are already destroyed
    // so hThreadFreeingHooks is already close and we'll get no chance to unhook
    // remaining func. So we can wait indefinitely
    // to avoid this just check the hevtUnload event state
    //if (WaitForSingleObject(hevtUnload,0)==WAIT_OBJECT_0)
    //    return;// dll as begin to unload --> just return

    while (pLinkListAPIInfosToBeFree->GetItemsCount()!=0)
    {
        // wait for item unload
        Sleep(UNHOOK_SECURITY_WAIT_TIME_BEFORE_MEMORY_FREEING*4);
    }
}
#endif

//-----------------------------------------------------------------------------
// Name: UnhookAllAPIFunctions
// Object: try to remove all hooks (dll in use are not free to avoid crash)
// Parameters :
// Return : 
//-----------------------------------------------------------------------------
#if 0
void UnhookAllAPIFunctions()
{
    BOOL bSuccess=TRUE;
    BOOL bRet;

    // remove all remaining hooks 
    if (pLinkListAPIInfos==NULL)
        return;
    
    // remove com hooks first
    if (pComManager)
    {
        pComManager->StopHookingCreatedCOMObjects();
        pComManager->UnHookAllComObjects();
    }

    // remove monitoring file hooks
    bRet=UnloadAllMonitoringFiles();
    bSuccess=bSuccess&&bRet;

    // unload all fake api dll hooks
    bRet=UnloadAllFakeApiDlls();
    bSuccess=bSuccess&&bRet;

    // wait until all item are freed (all handler successfully unhooked)
    // this should not wait as WaitForAllHookFreeing is called by
    // each UnloadFakeApiDll and each UnloadFakeApiDll
    WaitForAllHookFreeing();

    // in case there's still remain some func (can appear in case of deadlock)
    if ((!bSuccess) || pLinkListAPIInfos->Head)
    {
        if (WaitForSingleObject(hevtUnload,0)!=WAIT_OBJECT_0)// avoid 2 message 1 for warning and the over for unexpected unload
        {
            DynamicMessageBoxInDefaultStation(NULL,
                            _T("Warning all functions are not unhooked and injected dll is going to be unload.\r\n")
                            _T("This will probably crash your target application.\r\n")
                            _T("So save all your target application work, and when done click OK"),
                            _T("WARNING"),
                            MB_OK|MB_ICONWARNING|MB_TOPMOST);
        }
    }
}
#endif


//-----------------------------------------------------------------------------
// Name: GetFuncAddr
// Object: Load Library specified by pszModuleName only if not already loaded and
//          get function address of specified func name pszAPIName
// Parameters :
//      in: TCHAR* pszModuleName : dll name
//          TCHAR* pszAPIName : function name
//      out : HMODULE* phModule module handle 
// Return : func pointer on success, NULL on error
//-----------------------------------------------------------------------------
PBYTE GetFuncAddr(TCHAR* pszModuleName,TCHAR* pszAPIName,HMODULE* phModule)
{
    PBYTE pbAPI;
#if (defined(UNICODE)||defined(_UNICODE))
    CHAR pcFuncName[MAX_PATH];
    int iStringSize;
#endif
    BOOL bLibraryLoaded=FALSE;
    if (phModule == NULL)
        return NULL;

    // get module handle
    *phModule = GetModuleHandle(pszModuleName);
    if (*phModule == NULL)
    {
        // if module handle not found load library
        *phModule=LoadLibrary(pszModuleName);
        if (*phModule == NULL)
            return NULL;
        bLibraryLoaded=TRUE;
    }
#if (defined(UNICODE)||defined(_UNICODE))
    // convert into ansi until GetProcAddress don't support unicode
    iStringSize=WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)pszAPIName, (int)wcslen(pszAPIName)+1, pcFuncName, MAX_PATH, NULL, NULL);
    if (!iStringSize)
        *pcFuncName=0;
    else
    {
        if (iStringSize>=MAX_PATH)
            iStringSize=MAX_PATH-1;
        pcFuncName[iStringSize] = 0;
    }
    pbAPI = (PBYTE)GetProcAddress(*phModule, pcFuncName);
#else
    pbAPI = (PBYTE)GetProcAddress(*phModule, pszAPIName);
#endif
    if (pbAPI == NULL)
    {
        if (bLibraryLoaded)
            FreeLibrary(*phModule);
        return NULL;
    }
    return pbAPI;
}

//-----------------------------------------------------------------------------
// Name: GetWinAPIOverrideFunctionDescriptionAddress
// Object: Load Library specified by pszModuleName only if not already loaded and
//          get function address of specified func name pszAPIName
// Parameters :
//      in: TCHAR* pszModuleName : dll name
//          TCHAR* pszAPIName : function name
//      out : BOOL* pbExeDllInternalHook 
//            BOOL* pbFunctionPointer 
// Return : func pointer on success, NULL on error
//-----------------------------------------------------------------------------
PBYTE __stdcall GetWinAPIOverrideFunctionDescriptionAddress(TCHAR* pszModuleName,TCHAR* pszAPIName,BOOL* pbExeDllInternalHook,BOOL* pbFunctionPointer)
{
    PBYTE pbAPI=NULL;
    *pbExeDllInternalHook=FALSE;
    *pbFunctionPointer=FALSE;

    // check if address is specified
    if (_tcsnicmp(pszModuleName,EXE_INTERNAL_PREFIX,_tcslen(EXE_INTERNAL_PREFIX))==0)
    {
        // remove prefix and get value
        pbAPI=0;
        _stscanf(&pszModuleName[_tcslen(EXE_INTERNAL_PREFIX)],_T("%p"),&pbAPI);
        *pbExeDllInternalHook=TRUE;// allow function to be callback (called by system dll)
    }
    else if (_tcsnicmp(pszModuleName,DLL_INTERNAL_PREFIX,_tcslen(DLL_INTERNAL_PREFIX))==0)
    {
        TCHAR pszDllName[MAX_PATH];
        *pszDllName=0;
        PBYTE pbRvaFromDllBase=0;
        _stscanf(&pszModuleName[_tcslen(DLL_INTERNAL_PREFIX)],_T("%p@%s"),&pbRvaFromDllBase,(TCHAR*)pszDllName);
        pbAPI=GetExeRvaFromDllRva(pszDllName,pbRvaFromDllBase);
        *pbExeDllInternalHook=TRUE;// allow function to be callback (called by system dll)
    }
    else if (_tcsnicmp(pszModuleName,DLL_ORDINAL_PREFIX,_tcslen(DLL_ORDINAL_PREFIX))==0)
    {
        TCHAR pszDllName[MAX_PATH];
        *pszDllName=0;
        PBYTE pbOrdinalValue=0;
        _stscanf(&pszModuleName[_tcslen(DLL_ORDINAL_PREFIX)],_T("%p@%s"),&pbOrdinalValue,(TCHAR*)pszDllName);
        // get module handle
        HMODULE hModule = GetModuleHandle(pszDllName);
        if (hModule == NULL)
            // if module handle not found load library
            hModule=LoadLibrary(pszDllName);

        if (hModule == NULL)
            pbAPI= NULL;
        else
            pbAPI=(PBYTE)GetProcAddress(hModule,(LPCSTR)pbOrdinalValue);
    }
    else if (_tcsnicmp(pszModuleName,EXE_INTERNAL_POINTER_PREFIX,_tcslen(EXE_INTERNAL_POINTER_PREFIX))==0)
    {
        // remove prefix and get value
        pbAPI=0;
        _stscanf(&pszModuleName[_tcslen(EXE_INTERNAL_POINTER_PREFIX)],_T("%p"),&pbAPI);
        *pbExeDllInternalHook=TRUE;// allow function to be callback (called by system dll)
        *pbFunctionPointer=TRUE;
    }
    else if (_tcsnicmp(pszModuleName,DLL_INTERNAL_POINTER_PREFIX,_tcslen(DLL_INTERNAL_POINTER_PREFIX))==0)
    {
        TCHAR pszDllName[MAX_PATH];
        *pszDllName=0;
        PBYTE pbRvaFromDllBase=0;
        _stscanf(&pszModuleName[_tcslen(DLL_INTERNAL_POINTER_PREFIX)],_T("%p@%s"),&pbRvaFromDllBase,(TCHAR*)pszDllName);
        pbAPI=GetExeRvaFromDllRva(pszDllName,pbRvaFromDllBase);
        *pbExeDllInternalHook=TRUE;// allow function to be callback (called by system dll)
        *pbFunctionPointer=TRUE;
    }
    else
        // get address with loadlibrary + getprocaddress
        pbAPI=GetFuncAddr(pszModuleName,pszAPIName);

    return pbAPI;
}

//-----------------------------------------------------------------------------
// Name: GetFuncAddr
// Object: Load Library specified by pszModuleName only if not already loaded and
//          get function address of specified func name pszAPIName
// Parameters :
//      in: TCHAR* pszModuleName : dll name
//          TCHAR* pszAPIName : function name
// Return : func pointer on success, NULL on error
//-----------------------------------------------------------------------------
PBYTE GetFuncAddr(TCHAR* pszModuleName,TCHAR* pszAPIName)
{
    HMODULE hModule;
    return GetFuncAddr(pszModuleName,pszAPIName,&hModule);
}

//-----------------------------------------------------------------------------
// Name: GetExeRvaFromDllRva
// Object: Convert a dll Rva address to current process Rva
//          add pbRvaFromDllBase to the real dll base address (the loaded one not prefered one)
// Parameters :
//      in: TCHAR* pszDllName : dll name
//          TCHAR* pbRvaFromDllBase : Rva from Dll bas address
// Return : process Rva on success, NULL on error
//-----------------------------------------------------------------------------
PBYTE GetExeRvaFromDllRva(TCHAR* pszDllName,PBYTE pbRvaFromDllBase)
{
    PBYTE pbHook;
    TCHAR* psz;
    MODULEENTRY32 me32 = {0}; 
    HANDLE hModuleSnap =CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,dwCurrentProcessID);

    if (hModuleSnap == INVALID_HANDLE_VALUE) 
        return NULL;

    // remove path from pszDllName if any to only keep module name
    psz=_tcsrchr(pszDllName,'\\');
    if (psz)
        pszDllName=psz+1;


    // Fill the size of the structure before using it. 
    me32.dwSize = sizeof(MODULEENTRY32); 
 
    // Walk the module list of the process
    if (!Module32First(hModuleSnap, &me32))
    {
        CloseHandle(hModuleSnap);
        return NULL;
    }

    do 
    { 
        // if we have found the corresponding module name
        if (_tcsicmp(me32.szModule,pszDllName)==0)
        {
            // check if given relative address is valid
            if ((UINT_PTR)pbRvaFromDllBase>me32.modBaseSize)
            {
#if 0
                // show user error message
                TCHAR pszMsg[MAX_PATH];
                _stprintf(  pszMsg,
                            _T("0x%p is an invalid relative address for module %s"),
                            pbRvaFromDllBase,
                            pszDllName);

                DynamicMessageBoxInDefaultStation(NULL,pszMsg,_T("Error"),MB_OK|MB_ICONERROR|MB_TOPMOST);
#endif

                // close snapshot handle
                CloseHandle(hModuleSnap);

                return NULL;
            }

            // compute exe RVA from dll RVA
            pbHook=(PBYTE)((UINT_PTR)pbRvaFromDllBase+(UINT_PTR)me32.modBaseAddr);

            // close snapshot handle
            CloseHandle(hModuleSnap);

            return pbHook;
        }
    } 
    while (Module32Next(hModuleSnap, &me32));

    // close handle
    CloseHandle(hModuleSnap);

    // not found
    return NULL;
}


//-----------------------------------------------------------------------------
// Name: Break
// Object: Make a break dialog avoiding new in APIHandler func
// Parameters :
//      in: PAPI_INFO pAPIInfo: associated pAPIInfo
//      out : 
// Return : 
//-----------------------------------------------------------------------------
void Break(PAPI_INFO pAPIInfo,LOG_INFOS* pLogInfo,PBYTE StackParamtersPointer,PREGISTERS pRegisters,double* pDoubleResult,PBYTE CallerAddress,PBYTE EbpAtAPIHandler,BOOL BeforeCall)
{
#if 0
    CBreakUserInterface* pBreakUI;
    // show BreakUserInterface Dialog
    pBreakUI=new CBreakUserInterface(pAPIInfo,pLogInfo,StackParamtersPointer,pRegisters,pDoubleResult,CallerAddress,EbpAtAPIHandler,BeforeCall);
    pBreakUI->ShowDialog();
    delete pBreakUI;
#endif
}

//-----------------------------------------------------------------------------
// Name: BadParameterNumber
// Object: show message in case of bad parameter numbers in config file or faking dll
// Parameters :
//      in: PAPI_INFO pAPIInfo: associated pAPIInfo
//          DWORD dwCurrentParamSize : param size currently store in pAPIInfo struct
//          DWORD dwRealParamSize : real number of params
//      out : 
// Return : 
//-----------------------------------------------------------------------------
#if 0
void BadParameterNumber(PAPI_INFO pAPIInfo,DWORD dwCurrentParamSize,DWORD dwRealParamSize)
{
    TCHAR szMsg[3*MAX_PATH];
    int RealNbParam;
    int cnt;

    // update stack size
    pAPIInfo->StackSize=dwRealParamSize;

    if (dwRealParamSize>dwCurrentParamSize)
    {
        // compute real nb parameter generally dwParamSize/4 in 32 bit world
        // try to take into account parameters info in case of struct, double ... params (more than 4 bytes)
        RealNbParam=pAPIInfo->MonitoringParamCount+(dwRealParamSize-dwCurrentParamSize)/REGISTER_BYTE_SIZE;
    }
    else
        // compute real nb parameter generally dwParamSize/4 in 32 bit world
        RealNbParam=dwRealParamSize/REGISTER_BYTE_SIZE;

    _stprintf(szMsg,
              _T("Error in config file : %d parameters are required. ")
              _T("Stack size should be %d. (Current stack size was %d)"),
              RealNbParam,
              dwRealParamSize,
              dwCurrentParamSize);

    _tcscat(szMsg,_T(" Api: "));
    _tcscat(szMsg,pAPIInfo->szAPIName);

    //////////////////////////
    // try to give configuration file responsible of the error
    // look first for monitoring file and next for faking api
    // (but it can be false if the fake dll was loaded before the monitoring file)
    //////////////////////////

    // if monitoring file
    if (pAPIInfo->pMonitoringFileInfos)
    {
        //////////////////////////////////
        // adjust optional parameter list
        //////////////////////////////////

        if (pAPIInfo->MonitoringParamCount<RealNbParam)
        {
            // allocate memory if not enough param
            for (cnt=pAPIInfo->MonitoringParamCount;(cnt<RealNbParam) && (cnt<MAX_PARAM);cnt++)
            {
                // set pAPIInfo->ParamList[cnt] fields to default
                pAPIInfo->ParamList[cnt].dwSizeOfPointedData=0;
                pAPIInfo->ParamList[cnt].dwType=PARAM_UNKNOWN;
            }
        }
        else // RealNbParam < MonitoringParamCount
        {   
            // we have to free too much allocated memory
            FreeOptionalParametersMemory(pAPIInfo,(BYTE)RealNbParam,pAPIInfo->MonitoringParamCount-1);
        }

        // apply changes to struct
        pAPIInfo->MonitoringParamCount=(BYTE)RealNbParam;

        //////////////////////////////////
        // get monitoring file name
        //////////////////////////////////

        TCHAR pszModuleName[MAX_PATH];
        if (GetMonitoringFileName(pAPIInfo->pMonitoringFileInfos,pszModuleName))
        {
            _tcscat(szMsg,_T(" Config File: "));
            _tcscat(szMsg,pszModuleName);
        }
    }
    else if (pAPIInfo->pFakeDllInfos)// fake API
    {
        // get faking dll file name
        TCHAR pszModuleName[MAX_PATH];
        if (GetFakeApiDllName(pAPIInfo->pFakeDllInfos,pszModuleName))
        {
            _tcscat(szMsg,_T(" Fake API Dll: "));
            _tcscat(szMsg,pszModuleName);
        }
    }
    else if (pAPIInfo->PreApiCallChain)
    {
        // get faking dll file name

        // the first item should be responsible of stack size (if no item removed else it will fail)
        if (pAPIInfo->PreApiCallChain->Head)
        {
            TCHAR pszModuleName[MAX_PATH];
            if (GetModuleFileName(((PRE_POST_API_CALL_CHAIN_DATA*)pAPIInfo->PreApiCallChain->Head->ItemData)->OwnerModule,pszModuleName,MAX_PATH))
            {
                _tcscat(szMsg,_T(" Fake API Dll: "));
                _tcscat(szMsg,pszModuleName);
            }
        }
    }
    else if (pAPIInfo->PostApiCallChain)
    {
        // get faking dll file name

        // the first item should be responsible of stack size (if no item removed else it will fail)
        if (pAPIInfo->PostApiCallChain->Head)
        {
            TCHAR pszModuleName[MAX_PATH];
            if (GetModuleFileName(((PRE_POST_API_CALL_CHAIN_DATA*)pAPIInfo->PostApiCallChain->Head->ItemData)->OwnerModule,pszModuleName,MAX_PATH))
            {
                _tcscat(szMsg,_T(" Fake API Dll: "));
                _tcscat(szMsg,pszModuleName);
            }
        }
    }

    _tcscat(szMsg,_T(" Module: "));
    _tcscat(szMsg,pAPIInfo->szModuleName);

    // // as we change parameter size in pAPIInfo struct, only 1 warning will be done, so we can use a messagebox
    // // DynamicMessageBoxInDefaultStation(NULL,szMsg,_T("API Override Warning"),MB_ICONWARNING|MB_OK|MB_TOPMOST);
    // report message instead of messagebox
    CReportMessage::ReportMessage(REPORT_MESSAGE_WARNING,szMsg);
}
#endif



//-----------------------------------------------------------------------------
// Name: RemoveAPIOverrideInternalModule
// Object: signal a module removed from APIOverride framework (APIOverride.dll + faking dll)
// Parameters :
//      in: HMODULE hModule : module handle
//      out : 
// Return : TRUE on success
//-----------------------------------------------------------------------------
BOOL RemoveAPIOverrideInternalModule(HMODULE hModule)
{
    DWORD Cnt;
    for (Cnt=0;Cnt<APIOverrideInternalModulesLimitsIndex;Cnt++)
    {
        if (APIOverrideInternalModulesLimits[Cnt].hModule==hModule)
        {
            // replace current element by last one
            APIOverrideInternalModulesLimits[Cnt]=APIOverrideInternalModulesLimits[APIOverrideInternalModulesLimitsIndex-1];
            // decrease APIOverrideInternalModulesLimitsIndex
            APIOverrideInternalModulesLimitsIndex--;
            return TRUE;
        }
    }
    return FALSE;
}

//-----------------------------------------------------------------------------
// Name: AddAPIOverrideInternalModule
// Object: signal a module belonging to APIOverride framework (APIOverride.dll + faking dll)
// Parameters :
//      in: HMODULE hModule : new module handle
//      out : 
// Return : TRUE on success
//-----------------------------------------------------------------------------
BOOL AddAPIOverrideInternalModule(HMODULE hModule)
{
    if (APIOverrideInternalModulesLimitsIndex>=MAX_APIOVERRIDE_MODULESLIMITS)
        return FALSE;

    BOOL bRet=FALSE;
    MODULEENTRY32 me32 = {0}; 
    HANDLE hModuleSnap =CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,dwCurrentProcessID);

    if (hModuleSnap == INVALID_HANDLE_VALUE) 
        return FALSE; 

    // Fill the size of the structure before using it. 
    me32.dwSize = sizeof(MODULEENTRY32); 

    // Walk the module list of the process
    if (!Module32First(hModuleSnap, &me32))
    {
        CloseHandle(hModuleSnap);
        return FALSE; 
    }
    do 
    { 
        // if we have found module
        if (me32.hModule==hModule)
        {
            // get it's address space limits
            APIOverrideInternalModulesLimits[APIOverrideInternalModulesLimitsIndex].hModule=hModule;
            APIOverrideInternalModulesLimits[APIOverrideInternalModulesLimitsIndex].Start=me32.modBaseAddr;
            APIOverrideInternalModulesLimits[APIOverrideInternalModulesLimitsIndex].End=me32.modBaseAddr+me32.modBaseSize;

            // increase array index
            APIOverrideInternalModulesLimitsIndex++;

            // signal success
            bRet=TRUE;

            // go out of while
            break;
        }
    } 
    while (Module32Next(hModuleSnap, &me32));
    CloseHandle(hModuleSnap);

    return bRet;
}

//-----------------------------------------------------------------------------
// Name: IsAPIOverrideInternalCall
// Object: check if call is originated from a module of APIOverride framework (APIOverride.dll + faking dll)
// Parameters :
//      in: PBYTE Address : address to check
//          PBYTE EbpAtAPIHandler
//      out : 
// Return : TRUE if address comes from APIOverride.dll or a faking dll
//-----------------------------------------------------------------------------
BOOL IsAPIOverrideInternalCall(PBYTE Address,PBYTE EbpAtAPIHandler)
{

    DWORD Cnt;
    // check return address
    for (Cnt=0;Cnt<APIOverrideInternalModulesLimitsIndex;Cnt++)
    {
        if ((APIOverrideInternalModulesLimits[Cnt].Start<=Address)
            &&(Address<=APIOverrideInternalModulesLimits[Cnt].End))
        {
            return TRUE;
        }
    }

    // for each address of stack, check it

    // Why we have to do it ?
    // Imagine you're hooking NtClearEvent.
    // for the first NtClearEvent hooked, we go inside APIHandler function which call ResetEvent.
    // And ResetEvent calls NtClearEvent, which is hooked (has we don't remove hook if first bytes can be executed anywhere)
    // So you see a call with a return address not coming from ApiOverride module but from kernel32...
    // so to avoid an infinite loop, you have to check the full stack, and that's why we add a pseudo return 
    // address with APIHandler address at the begin of the hook : to see a trace of it here !

    // parse call stack
    PBYTE PreviousEbp;
    PBYTE Ebp=0;
    PBYTE RetAddress=0;

    Ebp=EbpAtAPIHandler;
    // NOTICE: IsBadReadPtr can be called until it doesn't call hooked subfunctions
    // currently IsBadReadPtr is pure asm code so we don't need to worry
    while (!(IsBadReadPtr(Ebp,REGISTER_BYTE_SIZE)))
    {
        // get previous ebp (call -1 ebp)
        PreviousEbp=*(PBYTE*)(Ebp);

        // if no previous ebp
        if (IsBadReadPtr(PreviousEbp,REGISTER_BYTE_SIZE))
            // stop
            break;

        // return address is at current ebp+REGISTER_BYTE_SIZE
        // so get it
        RetAddress=*(PBYTE*)(Ebp+REGISTER_BYTE_SIZE);

        // update ebp
        Ebp=PreviousEbp;

        for (Cnt=0;Cnt<APIOverrideInternalModulesLimitsIndex;Cnt++)
        {
            if ((APIOverrideInternalModulesLimits[Cnt].Start<=RetAddress)
                &&(RetAddress<=APIOverrideInternalModulesLimits[Cnt].End))
            {
                return TRUE;
            }
        }
    }


    return FALSE;
}


//-----------------------------------------------------------------------------
// Name: ParseAPIParameters
// Object: parse parameters and put them to pszLogString
// Parameters :
//      in: API_INFO *pAPIInfo : API hook info
//      out : LOG_INFOS* pLogInfo : struct containing params values
// Return : 
//-----------------------------------------------------------------------------
void ParseAPIParameters(API_INFO *pAPIInfo, LOG_INFOS* pLogInfo,...)
{
#if 0

    va_list Marker;
    PBYTE ParamValue;
    BYTE cIndex;
    int iStringSize;
    DWORD dwPointedDataSize;
    DWORD dwDefaultSize;

    BYTE ParamNeedingSecondPass[MAX_PARAM];
    BYTE NbParamNeedingSecondPass=0;
    BYTE Index;
    BYTE IndexOfParamDefiningSize;
    BOOLEAN BadPointer;
    
    // argument retrieval
    va_start(Marker, pLogInfo);

    // loop through parameters
    for (cIndex = 0; cIndex < pAPIInfo->MonitoringParamCount; cIndex++)
    {
        // free memory if a call to ParseAPIParameters has already done (see break re parsing after param modification)
        if (pLogInfo->ParamLogList[cIndex].pbValue)
        {
            HeapFree(ApiOverrideLogHeap, 0,pLogInfo->ParamLogList[cIndex].pbValue);
            pLogInfo->ParamLogList[cIndex].pbValue=NULL;
        }

        // retrieve type from pAPIInfo
        pLogInfo->ParamLogList[cIndex].dwType=pAPIInfo->ParamList[cIndex].dwType;

        // default param Log fields
        pLogInfo->ParamLogList[cIndex].dwSizeOfData=0;
        pLogInfo->ParamLogList[cIndex].dwSizeOfPointedValue=0;
        pLogInfo->ParamLogList[cIndex].pbValue=0;
        pLogInfo->ParamLogList[cIndex].Value=0;

        /////////////////////////////////////////
        // retrieve value or pointer value from pAPIInfo
        /////////////////////////////////////////

        // if pLogInfo->ParamLogList[cIndex].Value can contain data
        if (pAPIInfo->ParamList[cIndex].dwSizeOfData<=sizeof(PBYTE))
        {
            ParamValue = va_arg(Marker, PBYTE);

            // retrieve value or pointer value from pAPIInfo
            pLogInfo->ParamLogList[cIndex].Value=ParamValue;
            pLogInfo->ParamLogList[cIndex].dwSizeOfData=pAPIInfo->ParamList[cIndex].dwSizeOfData;

            /////////////////////////////////////////
            // check if parameter is pointer parameter
            /////////////////////////////////////////

            // if parameter pointed value size depends of another parameter
            if (pAPIInfo->ParamList[cIndex].bSizeOfPointedDataDefinedByAnotherParameter)
            {
                // get index of argument containing size
                if (pAPIInfo->ParamList[cIndex].dwSizeOfPointedData>=pAPIInfo->MonitoringParamCount)
                    continue;

                ParamNeedingSecondPass[NbParamNeedingSecondPass]=cIndex;
                NbParamNeedingSecondPass++;
                continue;
            }
            // else

            // check for a standard pointer
            dwPointedDataSize=0;


            ///////////////////////////////////
            // Get pointed data size
            ///////////////////////////////////

            // PARAM_UNKNOWN has no default size of pointed data
            if (pAPIInfo->ParamList[cIndex].dwType==PARAM_UNKNOWN)
            {
                dwPointedDataSize=pAPIInfo->ParamList[cIndex].dwSizeOfPointedData;
            }
            else
            {
                // retrieve default size of pointed data
                dwDefaultSize=CSupportedParameters::GetParamPointedSize(pAPIInfo->ParamList[cIndex].dwType);

                // special case for PARAM_PVOID
                if (pAPIInfo->ParamList[cIndex].dwType==PARAM_PVOID)
                {
                    // if a size is given
                    if (pAPIInfo->ParamList[cIndex].dwSizeOfPointedData)
                    {
                        // don't check it
                        dwPointedDataSize=pAPIInfo->ParamList[cIndex].dwSizeOfPointedData;
                    }
                    else
                        dwPointedDataSize=dwDefaultSize;
                }
                else
                {
                    if (dwDefaultSize!=0)// if item is a pointer
                    {
                        // assume the specified size is enough to support at least one item
                        if (pAPIInfo->ParamList[cIndex].dwSizeOfPointedData<dwDefaultSize)
                            // get default pointed data size
                            dwPointedDataSize=dwDefaultSize;
                        else
                            dwPointedDataSize=pAPIInfo->ParamList[cIndex].dwSizeOfPointedData;
                    }// else data is not a pointer and it's default size is 0
                }
            }

            /////////////////////////////////////////
            // at this point if dwPointedDataSize is not null we have to get pointed data
            // else dwSizeOfData is not null
            // --> get data
            /////////////////////////////////////////

            // next algorithm is quite always the same :
            //  1) check if memory address is valid
            //  2) allocated memory to store parameters
            //  3) copy data in allocated buffer
            BadPointer=FALSE;

            switch (pAPIInfo->ParamList[cIndex].dwType)
            {
            case PARAM_PANSI_STRING:
                if (IsBadReadPtr((PVOID)ParamValue, sizeof(ANSI_STRING)))
                    break;
                if (((PANSI_STRING)ParamValue)->Length==0)
                {
                    pLogInfo->ParamLogList[cIndex].pbValue=(PBYTE)HeapAlloc(ApiOverrideLogHeap, 0,sizeof(ANSI_STRING)+sizeof(char));
                    if (!pLogInfo->ParamLogList[cIndex].pbValue)
                        break;
                    pLogInfo->ParamLogList[cIndex].dwSizeOfPointedValue=sizeof(ANSI_STRING)+sizeof(char);
                    memcpy(pLogInfo->ParamLogList[cIndex].pbValue,(PVOID)ParamValue,sizeof(UNICODE_STRING));
                    memset(&pLogInfo->ParamLogList[cIndex].pbValue[sizeof(ANSI_STRING)],0,sizeof(char));
                    break;
                }
                iStringSize=CSupportedParameters::SecureStrlen(((PANSI_STRING)ParamValue)->Buffer);
                if (iStringSize<0)
                {
                    BadPointer=TRUE;
                    iStringSize=11+1;// strlen("Bad Pointer")+1;
                }

                dwPointedDataSize=sizeof(ANSI_STRING)+(iStringSize+1);
                pLogInfo->ParamLogList[cIndex].pbValue=(PBYTE)HeapAlloc(ApiOverrideLogHeap, 0,dwPointedDataSize);
                if (pLogInfo->ParamLogList[cIndex].pbValue)
                {
                    pLogInfo->ParamLogList[cIndex].dwSizeOfPointedValue=dwPointedDataSize;
                    memcpy(pLogInfo->ParamLogList[cIndex].pbValue,(PVOID)ParamValue,sizeof(ANSI_STRING));
                    if (BadPointer)
                        memcpy(&pLogInfo->ParamLogList[cIndex].pbValue[sizeof(ANSI_STRING)],"Bad Pointer",(iStringSize+1));
                    else
                        memcpy(&pLogInfo->ParamLogList[cIndex].pbValue[sizeof(ANSI_STRING)],((PANSI_STRING)ParamValue)->Buffer,(iStringSize+1));
                }

                break;
            case PARAM_PSTR:
                iStringSize=CSupportedParameters::SecureStrlen((LPSTR)ParamValue);
                if (iStringSize<0)
                    break;

                dwPointedDataSize=(iStringSize+1);
                // allocate and copy pointed data
                pLogInfo->ParamLogList[cIndex].pbValue=(PBYTE)HeapAlloc(ApiOverrideLogHeap, 0,dwPointedDataSize);
                if (pLogInfo->ParamLogList[cIndex].pbValue)
                {
                    pLogInfo->ParamLogList[cIndex].dwSizeOfPointedValue=dwPointedDataSize;
                    memcpy(pLogInfo->ParamLogList[cIndex].pbValue,(PVOID)ParamValue,dwPointedDataSize);
                }

                break;

            case PARAM_PUNICODE_STRING:
                if (IsBadReadPtr((PVOID)ParamValue, sizeof(UNICODE_STRING)))
                    break;

                if (((PUNICODE_STRING)ParamValue)->Length==0)
                {
                    pLogInfo->ParamLogList[cIndex].pbValue=(PBYTE)HeapAlloc(ApiOverrideLogHeap, 0,sizeof(UNICODE_STRING)+sizeof(wchar_t));
                    if (!pLogInfo->ParamLogList[cIndex].pbValue)
                        break;
                    pLogInfo->ParamLogList[cIndex].dwSizeOfPointedValue=sizeof(UNICODE_STRING)+sizeof(wchar_t);
                    memcpy(pLogInfo->ParamLogList[cIndex].pbValue,(PVOID)ParamValue,sizeof(UNICODE_STRING));
                    memset(&pLogInfo->ParamLogList[cIndex].pbValue[sizeof(UNICODE_STRING)],0,sizeof(wchar_t));
                    break;
                }
                iStringSize=CSupportedParameters::SecureWstrlen(((PUNICODE_STRING)ParamValue)->Buffer);
                if (iStringSize<0)
                {
                    BadPointer=TRUE;
                    iStringSize=11+1;// wcslen(L"Bad Pointer")+1;
                }
                dwPointedDataSize=sizeof(UNICODE_STRING)+(iStringSize+1)*sizeof(wchar_t);

                // allocate and copy pointed data
                pLogInfo->ParamLogList[cIndex].pbValue=(PBYTE)HeapAlloc(ApiOverrideLogHeap, 0,dwPointedDataSize);
                if (pLogInfo->ParamLogList[cIndex].pbValue)
                {
                    pLogInfo->ParamLogList[cIndex].dwSizeOfPointedValue=dwPointedDataSize;
                    memcpy(pLogInfo->ParamLogList[cIndex].pbValue,(PVOID)ParamValue,sizeof(UNICODE_STRING));
                    if (BadPointer)
                        memcpy(&pLogInfo->ParamLogList[cIndex].pbValue[sizeof(UNICODE_STRING)],L"Bad Pointer",(iStringSize+1)*sizeof(wchar_t));
                    else
                        memcpy(&pLogInfo->ParamLogList[cIndex].pbValue[sizeof(UNICODE_STRING)],((PUNICODE_STRING)ParamValue)->Buffer,(iStringSize+1)*sizeof(wchar_t));
                }
                break;

            case PARAM_PWSTR:
            case PARAM_BSTR:
                iStringSize=CSupportedParameters::SecureWstrlen((LPWSTR)ParamValue);
                if (iStringSize<0)
                    break;

                dwPointedDataSize=(iStringSize+1)*sizeof(wchar_t);

                // allocate and copy pointed data
                pLogInfo->ParamLogList[cIndex].pbValue=(PBYTE)HeapAlloc(ApiOverrideLogHeap, 0,dwPointedDataSize);
                if (pLogInfo->ParamLogList[cIndex].pbValue)
                {
                    pLogInfo->ParamLogList[cIndex].dwSizeOfPointedValue=dwPointedDataSize;
                    memcpy(pLogInfo->ParamLogList[cIndex].pbValue,(PVOID)ParamValue,dwPointedDataSize);
                }

                break;
            case PARAM_PVARIANT:
                if (IsBadReadPtr((PVOID)ParamValue, sizeof(VARIANT)))
                    break;
                CSupportedParameters::GetVariantFromStack(ApiOverrideLogHeap,
                                                (VARIANT*)ParamValue,
                                                dwPointedDataSize,
                                                TRUE,
                                                &pLogInfo->ParamLogList[cIndex]);
                break;
            case PARAM_PSAFEARRAY:
                if (IsBadReadPtr((PVOID)ParamValue, sizeof(SAFEARRAY)))
                    break;
                CSupportedParameters::GetSafeArrayFromStack(ApiOverrideLogHeap,
                                                (SAFEARRAY*)ParamValue,
                                                dwPointedDataSize,
                                                TRUE,
                                                &pLogInfo->ParamLogList[cIndex]);
                break;
            case PARAM_PDISPPARAMS:
                if (IsBadReadPtr((PVOID)ParamValue, sizeof(DISPPARAMS)))
                    break;
                CSupportedParameters::GetDispparamsFromStack(ApiOverrideLogHeap,
                                                (DISPPARAMS*)ParamValue,
                                                dwPointedDataSize,
                                                TRUE,
                                                &pLogInfo->ParamLogList[cIndex]);
                break;
            case PARAM_PEXCEPINFO:
                if (IsBadReadPtr((PVOID)ParamValue, sizeof(EXCEPINFO)))
                    break;
                CSupportedParameters::GetExcepinfoFromStack(ApiOverrideLogHeap,
                                                (EXCEPINFO*)ParamValue,
                                                dwPointedDataSize,
                                                TRUE,
                                                &pLogInfo->ParamLogList[cIndex]);
                break;
            default:
                // allocate and copy pointed data
                if (dwPointedDataSize)
                {
                    if (!IsBadReadPtr((PVOID)ParamValue, dwPointedDataSize))
                    {
                        pLogInfo->ParamLogList[cIndex].pbValue=(PBYTE)HeapAlloc(ApiOverrideLogHeap, 0,dwPointedDataSize);
                        if (pLogInfo->ParamLogList[cIndex].pbValue)
                        {
                            pLogInfo->ParamLogList[cIndex].dwSizeOfPointedValue=dwPointedDataSize;
                            memcpy(pLogInfo->ParamLogList[cIndex].pbValue,(PVOID)ParamValue,dwPointedDataSize);
                        }
                    }
                }
                break;
            }

        }
        else // param value size (pAPIInfo->ParamList[cIndex].dwSizeOfData) 
             //   is more than 4 bytes (struct passed directly throw stack)
        {
            // in this case dwParamValue is a pointer to the stack position of the param
            ParamValue=(PBYTE)Marker;

            // adjust marker for next value
            Marker+=pAPIInfo->ParamList[cIndex].dwSizeOfData;

            if (!IsBadReadPtr((PVOID)ParamValue, pAPIInfo->ParamList[cIndex].dwSizeOfData))
            {
                switch (pAPIInfo->ParamList[cIndex].dwType)
                {
                case PARAM_VARIANT:
                    CSupportedParameters::GetVariantFromStack(ApiOverrideLogHeap,(VARIANT*)(ParamValue),pAPIInfo->ParamList[cIndex].dwSizeOfData,FALSE,&pLogInfo->ParamLogList[cIndex]);
                    break;
                case PARAM_SAFEARRAY:
                    CSupportedParameters::GetSafeArrayFromStack(ApiOverrideLogHeap,(SAFEARRAY*)(ParamValue),pAPIInfo->ParamList[cIndex].dwSizeOfData,FALSE,&pLogInfo->ParamLogList[cIndex]);
                    break;
                case PARAM_EXCEPINFO:
                    CSupportedParameters::GetExcepinfoFromStack(ApiOverrideLogHeap,(EXCEPINFO*)(ParamValue),pAPIInfo->ParamList[cIndex].dwSizeOfData,FALSE,&pLogInfo->ParamLogList[cIndex]);
                    break;
                case PARAM_DISPPARAMS:
                    CSupportedParameters::GetDispparamsFromStack(ApiOverrideLogHeap,(DISPPARAMS*)ParamValue,pAPIInfo->ParamList[cIndex].dwSizeOfData,FALSE,&pLogInfo->ParamLogList[cIndex]);
                    break;
                default:
                    pLogInfo->ParamLogList[cIndex].pbValue=(PBYTE)HeapAlloc(ApiOverrideLogHeap, 0,pAPIInfo->ParamList[cIndex].dwSizeOfData);
                    if (pLogInfo->ParamLogList[cIndex].pbValue)
                    {
                        pLogInfo->ParamLogList[cIndex].dwSizeOfData=pAPIInfo->ParamList[cIndex].dwSizeOfData;
                        memcpy(pLogInfo->ParamLogList[cIndex].pbValue,(PVOID)ParamValue,pAPIInfo->ParamList[cIndex].dwSizeOfData);
                    }
                    break;
                }
            }
        }
    }
    va_end(Marker);

    // second pass for pointed size defined by other args
    for(cIndex=0;cIndex<NbParamNeedingSecondPass;cIndex++)
    {
        // default dwPointedDataSize
        dwPointedDataSize=0;

        Index=ParamNeedingSecondPass[cIndex];
        // get index of argument containing size
        IndexOfParamDefiningSize=(BYTE)pAPIInfo->ParamList[Index].dwSizeOfPointedData;

        // if argument containing size is not a pointed one
        if (pLogInfo->ParamLogList[IndexOfParamDefiningSize].dwSizeOfData)
        {
            // if argument containing size has a size more than DWORD
            if (pLogInfo->ParamLogList[IndexOfParamDefiningSize].dwSizeOfData>sizeof(DWORD))
                // as x86 are in little endian, we can cast ULONG64 pointer to DWORD pointer to get less significant DWORD
                dwPointedDataSize=*((DWORD*)pLogInfo->ParamLogList[IndexOfParamDefiningSize].pbValue);
            else
                dwPointedDataSize=(DWORD)pLogInfo->ParamLogList[IndexOfParamDefiningSize].Value;
        }
        else
        {
            if (pLogInfo->ParamLogList[IndexOfParamDefiningSize].dwSizeOfPointedValue<sizeof(DWORD))
            {
                
                // as we are in little endian, less significant bits come first in DWORD pointer
                // --> we can directly copy memory to get value regardless of its type
                memcpy(&dwPointedDataSize,
                    pLogInfo->ParamLogList[IndexOfParamDefiningSize].pbValue,
                    pLogInfo->ParamLogList[IndexOfParamDefiningSize].dwSizeOfPointedValue);

            }
            else
            {
                // as x86 are in little endian, we can cast ULONG64 pointers to DWORD pointers to get less significant DWORD
                // so even if type is ULONG64 we get its less significant part;
                // and in case of DWORD pointer,  all is ok
                dwPointedDataSize=*((DWORD*)pLogInfo->ParamLogList[IndexOfParamDefiningSize].pbValue);
            }
        }

        // allocate and copy pointed data
        if (dwPointedDataSize)
        {
            // as dwValue has already been field with pointer value, we only need to copy data from it
            if (!IsBadReadPtr((PVOID)pLogInfo->ParamLogList[Index].Value, dwPointedDataSize))
            {
                pLogInfo->ParamLogList[Index].pbValue=(PBYTE)HeapAlloc(ApiOverrideLogHeap, 0,dwPointedDataSize);
                if (pLogInfo->ParamLogList[Index].pbValue)
                {
                    pLogInfo->ParamLogList[Index].dwSizeOfPointedValue=dwPointedDataSize;
                    memcpy(pLogInfo->ParamLogList[Index].pbValue,(PVOID)pLogInfo->ParamLogList[Index].Value,dwPointedDataSize);
                }
            }
        }
    }

#endif
}


//-----------------------------------------------------------------------------
// Name: CheckParamLogFilters
// Object: check parameters log filters
// Parameters :
//      in: API_INFO *pAPIInfo : API hook info
//          LOG_INFOS* pLogInfo : struct containing params values
// Return : TRUE if filters match, FALSE else
//-----------------------------------------------------------------------------
BOOL CheckParamLogFilters(API_INFO *pAPIInfo, LOG_INFOS* pLogInfo)
{
    return CheckParamFilters(pAPIInfo,pLogInfo,TRUE);
}
//-----------------------------------------------------------------------------
// Name: CheckParamBreakFilters
// Object: check parameters break filters
// Parameters :
//      in: API_INFO *pAPIInfo : API hook info
//          LOG_INFOS* pLogInfo : struct containing params values
// Return : TRUE if filters match, FALSE else
//-----------------------------------------------------------------------------
BOOL CheckParamBreakFilters(API_INFO *pAPIInfo, LOG_INFOS* pLogInfo)
{
    return CheckParamFilters(pAPIInfo,pLogInfo,FALSE);
}

//-----------------------------------------------------------------------------
// Name: CheckParamFilters
// Object: check parameters filters (Log filters or break filters depending bLogFilters)
//          done because code for break and log filtering is 99% the same
// Parameters :
//      in: API_INFO *pAPIInfo : API hook info
//          LOG_INFOS* pLogInfo : struct containing params values
//          BOOL bLogFilters : TRUE to check logging filters, FALSE to check Break filters
// Return : TRUE if filters match, FALSE else
//-----------------------------------------------------------------------------
BOOL CheckParamFilters(API_INFO *pAPIInfo, LOG_INFOS* pLogInfo,BOOL bLogFilters)
{
    BYTE cnt;
    CLinkListItem* pItem;
    CLinkList* pList;
    MONITORING_PARAMETER_OPTIONS* pParamOption;
    BOOL bMatch;
    for (cnt=0;cnt<pAPIInfo->MonitoringParamCount;cnt++)
    {
        if (bLogFilters)
        {
            if (!pAPIInfo->ParamList[cnt].pConditionalLogContent)
                continue;
            pList=pAPIInfo->ParamList[cnt].pConditionalLogContent;
        }
        else
        {
            if (!pAPIInfo->ParamList[cnt].pConditionalLogContent)
                continue;
            pList=pAPIInfo->ParamList[cnt].pConditionalBreakContent;
        }

        pList->Lock();
        // if no filters defined for parameter
        if (!pList->Head)
        {
            pList->Unlock();
            // check next parameter
            continue;
        }

        // else : parameter should match at least one condition
        bMatch=FALSE;
        for(pItem=pList->Head;pItem;pItem=pItem->NextItem)
        {
            pParamOption=((MONITORING_PARAMETER_OPTIONS*)pItem->ItemData);
            // if we have to check pointed data
            if (pParamOption->dwPointedValueSize)
            {
                // if log pointed data is smaller than data to check
                // we are sure condition doesn't match, so check next condition
                if (pLogInfo->ParamLogList[cnt].dwSizeOfPointedValue<pParamOption->dwPointedValueSize)
                    continue;
                // check if logged pointer can be read
                if(IsBadReadPtr(pLogInfo->ParamLogList[cnt].pbValue,pParamOption->dwPointedValueSize))
                    continue;

                // if pointed data match filters
                if (memcmp(pLogInfo->ParamLogList[cnt].pbValue,
                            pParamOption->pbPointedValue,
                            pParamOption->dwPointedValueSize)==0)
                // at soon a filter match, check next parameter
                {
                    bMatch=TRUE;
                    break;// go out of for
                }

            }
            // if we have to check value size
            else if (pParamOption->dwValueSize>REGISTER_BYTE_SIZE)
            {
                // if log pointed data is smaller than data to check
                // we are sure condition doesn't match, so check next condition
                if (pLogInfo->ParamLogList[cnt].dwSizeOfData<pParamOption->dwValueSize)
                    continue;
                // check if logged pointer can be read
                if(IsBadReadPtr(pLogInfo->ParamLogList[cnt].pbValue,pParamOption->dwValueSize))
                    continue;

                // if pointed data match filters
                if (memcmp(pLogInfo->ParamLogList[cnt].pbValue,
                            pParamOption->pbPointedValue,
                            pParamOption->dwValueSize)==0)
                // at soon a filter match, check next parameter
                {
                    bMatch=TRUE;
                    break;// go out of for
                }
            }
            else // we check value
            {
                if (pLogInfo->ParamLogList[cnt].Value==pParamOption->Value)
                // at soon a filter match, check next parameter
                {
                    bMatch=TRUE;
                    break;// go out of for
                }
            }
        }
        pList->Unlock();

        // if no one condition match
        if (!bMatch)
            return FALSE;
    }
    return TRUE;
}

//-----------------------------------------------------------------------------
// Name: DoFunctionCallFail
// Object: check failure conditions depending the return of the function
// Parameters :
//      in: API_INFO *pAPIInfo : API hook info
//          PBYTE Return : return of the func
//          double FloatingReturn : float/double return of the func
//          DWORD dwLastErrorCode : LastErrorCode
// Return : TRUE if returned value match failure condition, FALSE if returned value don't match
//-----------------------------------------------------------------------------
BOOL DoFunctionFail(API_INFO *pAPIInfo,PBYTE Return,double FloatingReturn,DWORD dwLastErrorCode)
{

    // check last error failure
    BOOL bLastErrorCodeFailure;
    BOOL bLastErrorCodeFailureSignificant;
    if (pAPIInfo->LogBreakWay.FailureIfLastErrorValue)
    {
        bLastErrorCodeFailure=(dwLastErrorCode==pAPIInfo->FailureLastErrorValue);
        bLastErrorCodeFailureSignificant=TRUE;
    }
    else if (pAPIInfo->LogBreakWay.FailureIfNotLastErrorValue)
    {
        bLastErrorCodeFailure=(dwLastErrorCode!=pAPIInfo->FailureLastErrorValue);
        bLastErrorCodeFailureSignificant=TRUE;
    }
    else if (pAPIInfo->LogBreakWay.FailureIfLastErrorValueLess)
    {
        bLastErrorCodeFailure=(dwLastErrorCode<pAPIInfo->FailureLastErrorValue);
        bLastErrorCodeFailureSignificant=TRUE;
    }
    else if (pAPIInfo->LogBreakWay.FailureIfLastErrorValueUpper)
    {
        bLastErrorCodeFailure=(dwLastErrorCode>pAPIInfo->FailureLastErrorValue);
        bLastErrorCodeFailureSignificant=TRUE;
    }
    else
    {
        bLastErrorCodeFailure=FALSE;
        bLastErrorCodeFailureSignificant=FALSE;
    }

    if (pAPIInfo->LogBreakWay.FailureIfNullRet)
    {
        if (Return==0)
        {
            if (bLastErrorCodeFailureSignificant)
                return bLastErrorCodeFailure;
            // else
            return TRUE;
        }
    }
    // else if as only one failure param is allowed
    else if (pAPIInfo->LogBreakWay.FailureIfNotNullRet)
    {
        if (Return!=0)
        {
            if (bLastErrorCodeFailureSignificant)
                return bLastErrorCodeFailure;
            // else
            return TRUE;
        }
    }
    else if (pAPIInfo->LogBreakWay.FailureIfRetValue)
    {
        if (Return==pAPIInfo->FailureValue)
        {
            if (bLastErrorCodeFailureSignificant)
                return bLastErrorCodeFailure;
            // else
            return TRUE;
        }
    }
    else if (pAPIInfo->LogBreakWay.FailureIfNotRetValue)
    {
        if (Return!=pAPIInfo->FailureValue)
        {
            if (bLastErrorCodeFailureSignificant)
                return bLastErrorCodeFailure;
            // else
            return TRUE;
        }
    }
    else if (pAPIInfo->LogBreakWay.FailureIfNegativeRetValue)
    {
        if (((int)Return)<0)
        {
            if (bLastErrorCodeFailureSignificant)
                return bLastErrorCodeFailure;
            // else
            return TRUE;
        }
    }
    else if (pAPIInfo->LogBreakWay.FailureIfPositiveRetValue)
    {
        if (((int)Return)>0)
        {
            if (bLastErrorCodeFailureSignificant)
                return bLastErrorCodeFailure;
            // else
            return TRUE;
        }
    }

    else if (pAPIInfo->LogBreakWay.FailureIfNullFloatingRet)
    {
        if (FloatingReturn==0.0)
        {
            if (bLastErrorCodeFailureSignificant)
                return bLastErrorCodeFailure;
            // else
            return TRUE;
        }
    }
    else if (pAPIInfo->LogBreakWay.FailureIfNotNullFloatingRet)
    {
        if (FloatingReturn!=0.0)
        {
            if (bLastErrorCodeFailureSignificant)
                return bLastErrorCodeFailure;
            // else
            return TRUE;
        }
    }
    else if (pAPIInfo->LogBreakWay.FailureIfFloatingRetValue)
    {
        if (FloatingReturn==pAPIInfo->FloatingFailureValue)
        {
            if (bLastErrorCodeFailureSignificant)
                return bLastErrorCodeFailure;
            // else
            return TRUE;
        }
    }
    else if (pAPIInfo->LogBreakWay.FailureIfNotFloatingRetValue)
    {
        if (FloatingReturn!=pAPIInfo->FloatingFailureValue)
        {
            if (bLastErrorCodeFailureSignificant)
                return bLastErrorCodeFailure;
            // else
            return TRUE;
        }
    }
    else if (pAPIInfo->LogBreakWay.FailureIfFloatingNegativeRetValue)
    {
        if (FloatingReturn<0.0)
        {
            if (bLastErrorCodeFailureSignificant)
                return bLastErrorCodeFailure;
            // else
            return TRUE;
        }
    }
    else if (pAPIInfo->LogBreakWay.FailureIfFloatingPositiveRetValue)
    {
        if (FloatingReturn>0.0)
        {
            if (bLastErrorCodeFailureSignificant)
                return bLastErrorCodeFailure;
            // else
            return TRUE;
        }
    }

    else if (pAPIInfo->LogBreakWay.FailureIfSignedRetLess)
    {
        if (((int)Return)<((int)pAPIInfo->FailureValue))
        {
            if (bLastErrorCodeFailureSignificant)
                return bLastErrorCodeFailure;
            // else
            return TRUE;
        }
    }
    else if (pAPIInfo->LogBreakWay.FailureIfSignedRetUpper)
    {
        if (((int)Return)>((int)pAPIInfo->FailureValue))
        {
            if (bLastErrorCodeFailureSignificant)
                return bLastErrorCodeFailure;
            // else
            return TRUE;
        }
    }
    else if (pAPIInfo->LogBreakWay.FailureIfUnsignedRetLess)
    {
        if (Return<pAPIInfo->FailureValue)
        {
            if (bLastErrorCodeFailureSignificant)
                return bLastErrorCodeFailure;
            // else
            return TRUE;
        }
    }
    else if (pAPIInfo->LogBreakWay.FailureIfUnsignedRetUpper)
    {
        if (Return>pAPIInfo->FailureValue)
        {
            if (bLastErrorCodeFailureSignificant)
                return bLastErrorCodeFailure;
            // else
            return TRUE;
        }
    }
    else if (pAPIInfo->LogBreakWay.FailureIfFloatingRetLess)
    {
        if (FloatingReturn<pAPIInfo->FloatingFailureValue)
        {
            if (bLastErrorCodeFailureSignificant)
                return bLastErrorCodeFailure;
            // else
            return TRUE;
        }
    }
    else if (pAPIInfo->LogBreakWay.FailureIfFloatingRetUpper)
    {
        if (FloatingReturn>pAPIInfo->FloatingFailureValue)
        {
            if (bLastErrorCodeFailureSignificant)
                return bLastErrorCodeFailure;
            // else
            return TRUE;
        }
    }

    return FALSE;
}

//-----------------------------------------------------------------------------
// Name: IsCOMHookDefinition
// Object: check is hook definition is for a com hook definition
// Parameters :
//      in: TCHAR* pszModuleDefinition : hook definition or module hook definition
// Return : TRUE hook definition is for a COM hook definition
//-----------------------------------------------------------------------------
#if 0
BOOL IsCOMHookDefinition(TCHAR* pszModuleDefinition)
{
    // check if module definition begins with COM_DEFINITION_PREFIX
    return (_tcsnicmp(pszModuleDefinition,COM_DEFINITION_PREFIX,_tcslen(COM_DEFINITION_PREFIX))==0);
}
#endif

//-----------------------------------------------------------------------------
// Name: ReportBadHookChainBadCallingConvention
// Object: check is hook definition is for a com hook definition
// Parameters :
//      in: API_INFO *pAPIInfo : pointer to api info
//          PBYTE PrePostHookCallBack : pointer to pre/post hook callback function
//          BOOL bPreHook : TRUE for Pre hook, FALSE for Post hook
// Return : TRUE hook definition is for a COM hook definition
//-----------------------------------------------------------------------------
#if 0
void ReportBadHookChainBadCallingConvention(API_INFO *pAPIInfo,PBYTE PrePostHookCallBack,BOOL bPreHook)
{
    TCHAR pszMsg[MAX_PATH];
    TCHAR pszPrePosHook[20];
    if (bPreHook)
        _tcscpy(pszPrePosHook,_T("pre hook"));
    else
        _tcscpy(pszPrePosHook,_T("post hook"));

    _sntprintf(pszMsg,MAX_PATH,_T("Bad calling convention for %s %p of %s. Calling convention must be stdcall."),
                pszPrePosHook,PrePostHookCallBack,pAPIInfo->szAPIName);
    CReportMessage::ReportMessage(REPORT_MESSAGE_ERROR,pszMsg);
}
#endif
