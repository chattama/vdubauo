
#include <windows.h>
#include <commdlg.h>

#include "FakeApiLoader.h"

#include "resource.h"

extern void GetServerName(char *sname);
extern void InitVDubAuoMenu(HMENU hMainMenu);
extern INT_PTR CALLBACK __Frameserver_StatusDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

extern bool g_bOutput;
extern DLGPROC __Frameserver_StatusDlgProcOrig;

HMENU WINAPI __LoadMenuA(HINSTANCE hInstance, LPCSTR lpMenuName) {
	HMENU hmenu = LoadMenuA(hInstance, lpMenuName);
	if (lpMenuName == MAKEINTRESOURCEA(IDR_MAIN_MENU)) {
		InitVDubAuoMenu(hmenu);
	}
	return hmenu;
}

HMENU WINAPI __LoadMenuW(HINSTANCE hInstance, LPCWSTR lpMenuName) {
	HMENU hmenu = LoadMenuW(hInstance, lpMenuName);
	if (lpMenuName == MAKEINTRESOURCEW(IDR_MAIN_MENU)) {
		InitVDubAuoMenu(hmenu);
	}
	return hmenu;
}

INT_PTR WINAPI __DialogBoxParamA(HINSTANCE hInstance, LPCSTR lpTemplateName, HWND hWndParent, DLGPROC lpDialogFunc, LPARAM dwInitParam) {
	if (g_bOutput) {
		if (lpTemplateName == MAKEINTRESOURCEA(IDD_SERVER_SETUP)) {
			GetServerName((char*)dwInitParam);
			return TRUE;
		}
	}
	return DialogBoxParamA(hInstance, lpTemplateName, hWndParent, lpDialogFunc, dwInitParam);
}

INT_PTR WINAPI __DialogBoxParamW(HINSTANCE hInstance, LPCWSTR lpTemplateName, HWND hWndParent, DLGPROC lpDialogFunc, LPARAM dwInitParam) {
	if (g_bOutput) {
		if (lpTemplateName == MAKEINTRESOURCEW(IDD_SERVER_SETUP)) {
			GetServerName((char*)dwInitParam);
			return TRUE;
		}
	}
	return DialogBoxParamW(hInstance, lpTemplateName, hWndParent, lpDialogFunc, dwInitParam);
}

HWND WINAPI __CreateDialogParamA(HINSTANCE hInstance, LPCSTR lpTemplateName, HWND hWndParent, DLGPROC lpDialogFunc, LPARAM dwInitParam) {
	DLGPROC proc = lpDialogFunc;
	if (g_bOutput && (lpTemplateName == MAKEINTRESOURCEA(IDD_SERVER))) {
		__Frameserver_StatusDlgProcOrig = lpDialogFunc;
		proc = __Frameserver_StatusDlgProc;
	}
	return CreateDialogParamA(hInstance, lpTemplateName, hWndParent, proc, dwInitParam);
}

HWND WINAPI __CreateDialogParamW(HINSTANCE hInstance, LPCWSTR lpTemplateName, HWND hWndParent, DLGPROC lpDialogFunc, LPARAM dwInitParam) {
	DLGPROC proc = lpDialogFunc;
	if (g_bOutput && (lpTemplateName == MAKEINTRESOURCEW(IDD_SERVER))) {
		__Frameserver_StatusDlgProcOrig = lpDialogFunc;
		proc = __Frameserver_StatusDlgProc;
	}
	return CreateDialogParamW(hInstance, lpTemplateName, hWndParent, proc, dwInitParam);
}

BOOL WINAPI __GetSaveFileNameA(LPOPENFILENAMEA lpofn) {
	if (g_bOutput)
		if (!strcmp(lpofn->lpstrTitle, "Save .VDR signpost for AVIFile handler"))
			return FALSE;
	return GetSaveFileNameA(lpofn);
}

BOOL WINAPI __GetSaveFileNameW(LPOPENFILENAMEW lpofn) {
	if (g_bOutput)
		if (!wcscmp(lpofn->lpstrTitle, L"Save .VDR signpost for AVIFile handler"))
			return FALSE;
	return GetSaveFileNameW(lpofn);
}

STRUCT_FAKE_API_WITH_USERPARAM FakeApiInfos[] = {
	{ _T("user32.dll"),		_T("LoadMenuA"),			(FARPROC)__LoadMenuA,			StackSizeOf(HINSTANCE)+StackSizeOf(LPCSTR ), 0, 0 },
	{ _T("User32.dll"),		_T("LoadMenuW"),			(FARPROC)__LoadMenuW,			StackSizeOf(HINSTANCE)+StackSizeOf(LPCWSTR), 0, 0 },
	{ _T("user32.dll"),		_T("DialogBoxParamA"),		(FARPROC)__DialogBoxParamA,		StackSizeOf(HINSTANCE)+StackSizeOf(LPCSTR )+StackSizeOf(HWND)+StackSizeOf(DLGPROC)+StackSizeOf(LPARAM), 0, 0 },
	{ _T("user32.dll"),		_T("DialogBoxParamW"),		(FARPROC)__DialogBoxParamW,		StackSizeOf(HINSTANCE)+StackSizeOf(LPCWSTR)+StackSizeOf(HWND)+StackSizeOf(DLGPROC)+StackSizeOf(LPARAM), 0, 0 },
	{ _T("user32.dll"),		_T("CreateDialogParamA"),	(FARPROC)__CreateDialogParamA,	StackSizeOf(HINSTANCE)+StackSizeOf(LPCSTR )+StackSizeOf(HWND)+StackSizeOf(DLGPROC)+StackSizeOf(LPARAM), 0, 0 },
	{ _T("user32.dll"),		_T("CreateDialogParamW"),	(FARPROC)__CreateDialogParamW,	StackSizeOf(HINSTANCE)+StackSizeOf(LPCWSTR)+StackSizeOf(HWND)+StackSizeOf(DLGPROC)+StackSizeOf(LPARAM), 0, 0 },
	{ _T("comdlg32.dll"),	_T("GetSaveFileNameA"),		(FARPROC)__GetSaveFileNameA,	StackSizeOf(LPOPENFILENAMEA), 0,0},
	{ _T("comdlg32.dll"),	_T("GetSaveFileNameW"),		(FARPROC)__GetSaveFileNameW,	StackSizeOf(LPOPENFILENAMEW), 0,0},
	NULL,
};
