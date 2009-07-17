// WinAPIOverride32
// http://jacquelin.potier.free.fr/winapioverride32/

#include "APIOverrideKernel.h"
#include "FakeApiLoader.h"
#include "../../SingleInstance/CSingleInstance.h"

DWORD dwSystemPageSize = 4096;
DWORD dwCurrentProcessID = 0;
BOOL bFaking = TRUE;
HANDLE ApiOverrideHeap = NULL;
CLinkList* pLinkListAPIInfos = NULL;
CSingleInstance* pSingleInstance = NULL;
tagFirstBytesAutoAnalysis FirstBytesAutoAnalysis = FIRST_BYTES_AUTO_ANALYSIS_NONE;

BOOL WinAPIOverride32Init(HINSTANCE hInst) {
	TCHAR psz[MAX_PATH+32];
	TCHAR pszPID[32];
	SYSTEM_INFO siSysInfo;

	DisableThreadLibraryCalls(hInst);

	dwCurrentProcessID = GetCurrentProcessId();

	wsprintf(pszPID, "0x%X", dwCurrentProcessID);
	lstrcpy(psz, APIOVERRIDE_MUTEX);
	lstrcat(psz, pszPID);

	pSingleInstance = new CSingleInstance(psz);
	if (pSingleInstance->IsAnotherInstanceRunning()) {
		delete pSingleInstance;
		return FALSE;
	}

	GetSystemInfo(&siSysInfo); 
	dwSystemPageSize = siSysInfo.dwPageSize;

	ApiOverrideHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE | HEAP_GROWABLE, dwSystemPageSize, 0);

	pLinkListAPIInfos = new CLinkList(sizeof(API_INFO));
	pLinkListAPIInfos->SetHeap(ApiOverrideHeap);

	return TRUE;
}

void LoadFakeAPIDefinitionArray(STRUCT_FAKE_API_WITH_USERPARAM *FakeApi) {
	for (STRUCT_FAKE_API_WITH_USERPARAM *FakeApiInfo = FakeApi; FakeApiInfo->FakeAPI; FakeApiInfo++) {
		FAKING_DLL_INFOS FakingDllInfos;

		FakingDllInfos.hModule = GetModuleHandle(FakeApiInfo->pszModuleName);
		FakingDllInfos.pCOMObjectCreationCallBack = NULL;

		LoadFakeAPIDefinition(&FakingDllInfos, FakeApiInfo, FAKING_DLL_ARRAY_FAKING);
	}
}
