
#include <windows.h>
#include <process.h>
#include <vector>
#include <string>

#include "FakeApiLoader.h"

#include "vdub.h"
#include "aviutl.h"

#include "resource.h"
#include "debug.h"

extern STRUCT_FAKE_API_WITH_USERPARAM FakeApiInfos[];
extern BOOL WinAPIOverride32Init(HINSTANCE hInstDLL);
extern void LoadFakeAPIDefinitionArray(STRUCT_FAKE_API_WITH_USERPARAM *FakeApi);

UINT_PTR CALLBACK OutputFileDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK HookMsgProc(int nCode, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK __VDProjectUI_MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK __Frameserver_StatusDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

typedef struct {
	std::string path, name;
} MenuItem;

typedef std::vector<MenuItem*> MenuItemList;

typedef struct {
	char info[256], video[256], audio[256];
	BOOL bHasAudio, bSaveConfig, bNoAudio;
	HMODULE hDll;
	BOOL (*config)(HWND hwnd, HINSTANCE hdll);
} OutputFileDlgParam;

WNDPROC __VDProjectUI_MainWndProcOrig	= 0;
DLGPROC __Frameserver_StatusDlgProcOrig = 0;

MenuItem	*g_menu = 0;
MenuItemList g_menuList;

HMODULE	g_hDll			= 0;
HHOOK	g_hHook			= 0;
HWND	g_hWndVDub		= 0;
HWND	g_hWndServer	= 0;
HMENU	g_hMenu			= 0;
HMENU	g_hMenuFile		= 0;
HMENU	g_hMenuAuo		= 0;
DWORD	g_dwThreadId	= 0;
HANDLE	g_hWorkThread	= 0;
bool	g_bOutput		= false;
bool	g_bInitWindow	= false;
bool	g_bInitOutput	= false;
bool	g_bStartServer	= false;
bool	g_bAPIOverride	= false;

void GetServerName(char *sname) {
	wsprintf(sname, "VDubAuo%d", g_dwThreadId);
}

unsigned int __stdcall OutputThread(void* args) {
	char sname[256];

	VDubToAviUtl *v2a = new VDubToAviUtl(g_hWndServer);

	PostMessage(g_hWndServer, WM_OUTPUT_START, 0, (LPARAM)v2a);

	GetServerName(sname);
	VDubFrameServer *server = new VDubFrameServer(sname);

	if (server->Init()) {
		AviUtlPlugin *auo = new AviUtlPlugin(g_menu->path.c_str());

		if (auo->Init()) {
			char file[MAX_PATH], ext[MAX_PATH];
			OutputFileDlgParam ofp;
			OPENFILENAME ofn;

			file[0] = '\0';
			ext[0] = '\0';
			ofp.audio[0] = '\0';

			ofp.hDll		= auo->hDll;
			ofp.config		= auo->opt->tbl->func_config;
			ofp.bSaveConfig	= FALSE;
			ofp.bNoAudio	= FALSE;
			ofp.bHasAudio	= server->fHasAudio;
			if (server->aFormat)
				ofp.bHasAudio &= (server->aFormat->wFormatTag == WAVE_FORMAT_PCM);

			float fps = (float)server->vStreamInfo.dwRate / (float)server->vStreamInfo.dwScale;
			float len = (float)server->vStreamInfo.dwLength / fps;
			long w = server->vFormat->biWidth;
			long h = server->vFormat->biHeight;
			long m = (long)len / 60;
			long s = (long)len % 60;

			sprintf(ofp.info, " %dx%d  %0.3ffps  %d:%02d", w, h, fps, m, s);
			sprintf(ofp.video, "%s", auo->opt->tbl->name);

			if (ofp.bHasAudio) {
				float khz = (float)server->aStreamInfo.dwRate / (float)server->aStreamInfo.dwScale / (float)1000;
				long ch = server->aFormat->nChannels;
				sprintf(ofp.audio, "PCM %0.3fkHz %dch", khz, ch);
			}

			memset(&ofn, 0, sizeof(OPENFILENAME));
			ofn.lStructSize		= sizeof(OPENFILENAME);
			ofn.hwndOwner		= g_hWndServer;
			ofn.hInstance		= g_hDll;
			ofn.lpstrFilter		= auo->opt->tbl->filefilter;
			ofn.nFilterIndex	= 1;
			ofn.lpstrFile		= file;
			ofn.lpstrDefExt		= ext;
			ofn.nMaxFile		= MAX_PATH;
			ofn.lpTemplateName	= MAKEINTRESOURCE(IDD_SAVE_OPTION);
			ofn.Flags			= OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY | OFN_ENABLEHOOK | OFN_ENABLETEMPLATE | OFN_EXPLORER;
			ofn.FlagsEx			= OFN_EX_NOPLACESBAR;
			ofn.lCustData		= (LPARAM)&ofp;
			ofn.lpfnHook		= OutputFileDlgProc;

			if (GetSaveFileName(&ofn))
				v2a->Start(server, auo, file, ofp.bNoAudio);
		}
		delete auo;
	}
	delete server;

	PostMessage(g_hWndServer, WM_OUTPUT_END, 0, 0);

	delete v2a;

	_endthreadex(0);
	return 0;
}

void LoadPlugins() {
	char vdub[MAX_PATH], drv[MAX_PATH], dir[MAX_PATH], find[MAX_PATH], path[MAX_PATH];

	GetModuleFileName(NULL, vdub, MAX_PATH);

	_splitpath(vdub, drv, dir, NULL, NULL);
	wsprintf(find, "%s%s%s%s", drv, dir, "plugins\\", "*.auo");

	HANDLE hFind;
	WIN32_FIND_DATA fd;

	if ((hFind = FindFirstFile(find, &fd)) == INVALID_HANDLE_VALUE)
		return;

	g_menuList.clear();

	do {
		sprintf(path, "%s%s%s%s", drv, dir, "plugins\\", fd.cFileName);
		AviUtlPlugin *auo = new AviUtlPlugin(path);

		if (auo->Init()) {
			MenuItem *item = new MenuItem;

			item->path = std::string(path);
			item->name = std::string(auo->opt->tbl->name);

			g_menuList.push_back(item);
		}
		delete auo;

	} while (FindNextFile(hFind, &fd));

	FindClose(hFind);
}

void UpdateMenu() {
	if (!g_hMenuFile || !g_hMenuAuo) return;

	MENUITEMINFO mii;
	memset(&mii, 0, sizeof(MENUITEMINFO));
	mii.cbSize = sizeof(MENUITEMINFO);
	mii.fMask = MIIM_STATE;

	GetMenuItemInfo(g_hMenuFile, ID_FILE_STARTSERVER, FALSE, &mii);

	mii.fState = (mii.fState & MF_GRAYED) ? MF_GRAYED : MF_ENABLED;

	for (int i=0; i<GetMenuItemCount(g_hMenuAuo); i++) {
		SetMenuItemInfo(g_hMenuAuo, i, TRUE, &mii);
	}
}

void InitVDubAuoMenu(HMENU hMainMenu) {
	if (!hMainMenu) return;
	g_hMenu = hMainMenu;
	g_hMenuFile = 0;
	g_hMenuAuo = 0;

	MENUITEMINFO mii;
	memset(&mii, 0, sizeof(MENUITEMINFO));
	mii.cbSize = sizeof(MENUITEMINFO);

	for (int i=0; i<GetMenuItemCount(g_hMenu) && !g_hMenuFile; i++) {
		HMENU sub = GetSubMenu(g_hMenu, i);
		if (GetMenuItemInfo(sub, ID_FILE_STARTSERVER, FALSE, &mii))
			g_hMenuFile = sub;
	}

	g_hMenuAuo = CreatePopupMenu();

	mii.fMask = MIIM_TYPE | MIIM_STATE | MIIM_SUBMENU | MIIM_ID;
	mii.fType = MFT_STRING;
	mii.dwTypeData = "VDubAuo";
	mii.fState = MFS_ENABLED;
	mii.wID = ID_AUO_BASE;
	mii.hSubMenu = g_hMenuAuo;

	InsertMenuItem(g_hMenu, GetMenuItemCount(g_hMenu)+1, TRUE, &mii);

	char path[MAX_PATH], name[256];
	int i = 0;
	for (MenuItemList::iterator it = g_menuList.begin(); it != g_menuList.end(); it++) {
		MenuItem *item = *it;

		strcpy(path, item->path.c_str());
		strcpy(name, item->name.c_str());

		mii.fMask = MIIM_TYPE | MIIM_STATE | MIIM_ID;
		mii.fType = MFT_STRING;
		mii.dwTypeData = name;
		mii.fState = MFS_ENABLED;
		mii.wID = ID_AUO_BASE+1 + i;

		InsertMenuItem(g_hMenuAuo, i, TRUE, &mii);
		i++;
	}

	DrawMenuBar(g_hWndVDub);
}

void InitMenu() {
	if (!g_hWndVDub) return;
	InitVDubAuoMenu(GetMenu(g_hWndVDub));
}

bool IsWindowClassA(HWND hwnd, const char *cn) {
	char cna[256];
	if (!GetClassNameA(hwnd, cna, sizeof(cna))) return false;
	return (!strcmp(cna, cn));
}

bool IsWindowClassW(HWND hwnd, const wchar_t *cn) {
	wchar_t cnw[256];
	if (!GetClassNameW(hwnd, cnw, sizeof(cnw))) return false;
	return (!wcscmp(cnw, cn));
}

void InitMainWindow(HWND hwnd) {
	BOOL isUnicode = IsWindowUnicode(hwnd);
	if (isUnicode) {
		if (IsWindowClassW(hwnd, L"VirtualDub")) {
			g_hWndVDub = hwnd;
			__VDProjectUI_MainWndProcOrig = (WNDPROC)GetWindowLongPtrW(hwnd, GWLP_WNDPROC);
		}
	} else {
		if (IsWindowClassA(hwnd, "VirtualDub")) {
			g_hWndVDub = hwnd;
			__VDProjectUI_MainWndProcOrig = (WNDPROC)GetWindowLongPtrA(hwnd, GWLP_WNDPROC);
		}
	}
	if (g_hWndVDub) {

		LoadPlugins();

		if (!g_bAPIOverride) {
			HINSTANCE hInst = (HINSTANCE)GetWindowLongPtr(g_hWndVDub, GWLP_HINSTANCE);
			if (hInst) {
				if (WinAPIOverride32Init(hInst)) {
					LoadFakeAPIDefinitionArray(FakeApiInfos);
					g_bAPIOverride = true;
				}
			}
		}

		if (__VDProjectUI_MainWndProcOrig) {
			if (isUnicode)
				SetWindowLongPtrW(g_hWndVDub, GWLP_WNDPROC, (LONG)__VDProjectUI_MainWndProc);
			else
				SetWindowLongPtrA(g_hWndVDub, GWLP_WNDPROC, (LONG)__VDProjectUI_MainWndProc);
		}

		PostMessage(g_hWndVDub, WM_NULL, 0, 0);
	}
}

void UnHookMsg() {
	if (g_hHook)
		UnhookWindowsHookEx(g_hHook);
	g_hHook = 0;
}

bool HookMsg(DWORD id) {
	UnHookMsg();
	g_hHook = SetWindowsHookEx(WH_CALLWNDPROC, (HOOKPROC)HookMsgProc, g_hDll, id);
	if (!g_hHook)
		return false;
	return true;
}

UINT_PTR CALLBACK OutputFileDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
	OutputFileDlgParam *ofp = (OutputFileDlgParam*)GetWindowLongPtr(hwnd, DWLP_USER);
	switch (msg) {
	case WM_INITDIALOG:
		{
			LPOPENFILENAME ofn = (LPOPENFILENAME)lParam;
			ofp = (OutputFileDlgParam*)ofn->lCustData;

			SetDlgItemText(hwnd, IDC_TXT_INFO, ofp->info);
			SetDlgItemText(hwnd, IDC_TXT_VIDEO, ofp->video);
			SetDlgItemText(hwnd, IDC_TXT_AUDIO, ofp->audio);

			EnableWindow(GetDlgItem(hwnd, IDC_TXT_AUDIO  ), ofp->bHasAudio);
			EnableWindow(GetDlgItem(hwnd, IDC_CHK_NOAUDIO), ofp->bHasAudio);

			if (!ofp->bHasAudio)
				CheckDlgButton(hwnd, IDC_CHK_NOAUDIO, BST_CHECKED);

			SetWindowLongPtr(hwnd, DWLP_USER, (LONG)ofp);
		}
		break;
	case WM_COMMAND:
		if (LOWORD(wParam) == IDC_BTN_VIDEO_COMPRESS)
			if (ofp->config)
				ofp->bSaveConfig = ofp->config(hwnd, ofp->hDll);
		break;
	case WM_NOTIFY:
		if (((LPNMHDR)lParam)->code == CDN_FILEOK)
			ofp->bNoAudio = SendMessage(GetDlgItem(hwnd, IDC_CHK_NOAUDIO), BM_GETCHECK, 0, 0);
		break;
	}
	return 0;
}

LRESULT CALLBACK HookMsgProc(int nCode, WPARAM wParam, LPARAM lParam) {
	const CWPSTRUCT* p = (const CWPSTRUCT*)lParam;
	if ((nCode >= 0) && (nCode == HC_ACTION)) {
		if (g_hWndVDub == 0)
			InitMainWindow(p->hwnd);

		if (g_bInitWindow && !g_hMenuAuo)
			InitMenu();

		if (g_bInitOutput && g_bOutput && g_bStartServer) {
			g_bOutput = false;
			g_hWorkThread = (HANDLE)_beginthreadex(NULL, 0, OutputThread, NULL, 0, NULL);
		}
	}
	return CallNextHookEx(g_hHook, nCode, wParam, lParam);
}

LRESULT CALLBACK __VDProjectUI_MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
	switch (msg) {
	case WM_NULL:
		{
			g_bInitWindow = true;
		}
		break;
	case WM_MENUSELECT:
		{
			UpdateMenu();
		}
		break;
	case WM_COMMAND:
		{
			int pos = LOWORD(wParam) - ID_AUO_BASE - 1;
			if ((0 <= pos) && (pos < g_menuList.size())) {
				g_menu = g_menuList.at(pos);
				g_bOutput = true;
				g_bInitOutput = false;
				g_bStartServer = false;
				PostMessage(hwnd, WM_COMMAND, ID_FILE_STARTSERVER, 0);
				break;
			}
		}
		break;
	}
	return CallWindowProc(__VDProjectUI_MainWndProcOrig, hwnd, msg, wParam, lParam);
}

INT_PTR CALLBACK __Frameserver_StatusDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
	switch (msg) {
	case WM_INITDIALOG:
		{
			CreateWindow("BUTTON", "", WS_CHILD, 0, 0, 0, 0, hwnd, (HMENU)IDC_VDUBAUO_CTRL, NULL ,NULL);
			EnableWindow(GetDlgItem(hwnd, IDOK), FALSE);
			SetWindowText(hwnd, "VDubAuo initializing...");
			SetDlgItemText(hwnd, IDOK, "Stop");
			g_hWndServer = hwnd;
			g_bInitOutput = true;
		}
		break;
	case WM_TIMER:
		{
			g_bStartServer = true;
		}
		break;
	case WM_CLOSE:
		{
			if (g_hWorkThread) {
				PostMessage(hwnd, WM_COMMAND, IDOK, 0);
				return 0;
			}
			g_bStartServer = false;
		}
		break;
	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK) {
			EnableWindow(GetDlgItem(hwnd, IDOK), FALSE);
			VDubToAviUtl *v2a = (VDubToAviUtl*)GetWindowLongPtr(GetDlgItem(hwnd, IDC_VDUBAUO_CTRL), GWLP_USERDATA);
			v2a->Stop();
		}
		break;
	case WM_OUTPUT_START:
		{
			SetWindowLongPtr(GetDlgItem(hwnd, IDC_VDUBAUO_CTRL), GWLP_USERDATA, lParam);
			EnableWindow(GetDlgItem(hwnd, IDOK), TRUE);
		}
		break;
	case WM_OUTPUT_END:
		{
			EnableWindow(GetDlgItem(hwnd, IDOK), FALSE);
			WaitForSingleObject(g_hWorkThread, INFINITE);
			CloseHandle(g_hWorkThread);
			g_hWorkThread = 0;
			PostMessage(hwnd, WM_CLOSE, 0, 0);
		}
		break;
	}
	return __Frameserver_StatusDlgProcOrig(hwnd, msg, wParam, lParam);
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		g_hDll = (HMODULE)hInst;
		g_dwThreadId = GetCurrentThreadId();
		HookMsg(GetCurrentThreadId());
	}
	return TRUE;
}
