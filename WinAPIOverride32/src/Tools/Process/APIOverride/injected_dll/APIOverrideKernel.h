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

#pragma once

//#include "../SupportedParameters.h"
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#include <windows.h>
#include "defines.h"
#include "struct.h"
#include "ApiInfo.h"
//#include "APIMonitoringFileLoader.h"
#include "FakeAPILoader.h"
//#include "COM_Manager.h"
//#include "LogAPI.h"
#include "../../../LinkList/LinkList.h"
//#include "DynamicLoadedFuncs.h"
//#include "../../../CleanCloseHandle/CleanCloseHandle.h"
#include "../HookAvailabilityCheck/HookAvailabilityCheck.h"
//#include "BreakUserInterface.h"
//#include "ReportMessage.h"
#include "../../../Exception/HardwareException.h"


///////////////////////////////////////////////////////
//////////////          functions        //////////////
///////////////////////////////////////////////////////
void APIHandler();
PBYTE GetFuncAddr(TCHAR* pszModuleName,TCHAR* pszAPIName);
PBYTE GetFuncAddr(TCHAR* pszModuleName,TCHAR* pszAPIName,HMODULE* phModule);
PBYTE __stdcall GetWinAPIOverrideFunctionDescriptionAddress(TCHAR* pszModuleName,TCHAR* pszAPIName,BOOL* pbExeDllInternalHook,BOOL* pbFunctionPointer);
CLinkListItem* __stdcall GetAssociatedItemAPIInfo(PBYTE pbAPI,BOOL* pbAlreadyHooked);
BOOL __stdcall HookAPIFunction(API_INFO *pAPIInfo);
BOOL UnhookAPIFunction(CLinkListItem *pItemAPIInfo);
void UnhookAllAPIFunctions();
PBYTE GetExeRvaFromDllRva(TCHAR* pszDllName,PBYTE pbRvaFromDllBase);
DWORD WINAPI BlockingCallThreadProc(LPVOID lpParameter);
DWORD WINAPI ThreadFreeingHooksProc(LPVOID lpParameter);


void WaitForAllHookFreeing();
void ParseAPIParameters(API_INFO *pAPIInfo, LOG_INFOS* pLogInfo,...);
void Break(PAPI_INFO pAPIInfo,LOG_INFOS* pLogInfo,PBYTE StackParamtersPointer,PREGISTERS pRegisters,double* pDoubleResult,PBYTE CallerAddress,PBYTE EbpAtAPIHandler,BOOL BeforeCall);
void BadParameterNumber(PAPI_INFO pAPIInfo,DWORD dwCurrentParamSize,DWORD dwRealParamSize);

BOOL CheckParamLogFilters(API_INFO *pAPIInfo, LOG_INFOS* pLogInfo);
BOOL CheckParamBreakFilters(API_INFO *pAPIInfo, LOG_INFOS* pLogInfo);
BOOL CheckParamFilters(API_INFO *pAPIInfo, LOG_INFOS* pLogInfo,BOOL bLogFilters);
BOOL DoFunctionFail(API_INFO *pAPIInfo,PBYTE Return,double FloatingReturn,DWORD dwLastErrorCode);
BOOL IsAPIOverrideInternalCall(PBYTE Address,PBYTE EbpAtAPIHandler);
BOOL AddAPIOverrideInternalModule(HMODULE hModule);
BOOL RemoveAPIOverrideInternalModule(HMODULE hModule);
BOOL IsCOMHookDefinition(TCHAR* pszModuleDefinition);
void ReportBadHookChainBadCallingConvention(API_INFO *pAPIInfo,PBYTE PrePostHookCallBack,BOOL bPreHook);