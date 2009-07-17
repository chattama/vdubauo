#pragma once

#include <windows.h>
#include <map>

#include "output.h"
#include "vdub.h"

//////////////////////////////////////////////////////////////////////////////
// from warpsharp

class CriticalSection {
private:
	CRITICAL_SECTION _cs;
public:
	CriticalSection() { InitializeCriticalSection(&_cs); }
	~CriticalSection() { DeleteCriticalSection(&_cs); }
	void Enter() { EnterCriticalSection(&_cs); }
	void Leave() { LeaveCriticalSection(&_cs); }
};

class CriticalLock {
private:
	CriticalSection& _cs;
public:
	CriticalLock(CriticalSection& cs) : _cs(cs) { _cs.Enter(); }
	~CriticalLock() { _cs.Leave(); }
};

//////////////////////////////////////////////////////////////////////////////

class AviUtlOutputPluginTable {
public:
	OUTPUT_PLUGIN_TABLE *tbl;

	AviUtlOutputPluginTable(OUTPUT_PLUGIN_TABLE *tbl) {
		this->tbl = tbl;
	}

	~AviUtlOutputPluginTable() {}

	BOOL init();
	BOOL exit();
	BOOL output(OUTPUT_INFO *oip);
	BOOL config(HWND hwnd, HINSTANCE hdll);
	int GetDataSize();
	int GetData(void *data, int size);
	int SetData(void *data, int size);
	void SaveConfig();
};

//////////////////////////////////////////////////////////////////////////////

typedef OUTPUT_PLUGIN_TABLE *(__stdcall *GetOutputPluginTableProc)( void );

class AviUtlPlugin {
private:
	char path[MAX_PATH];

	GetOutputPluginTableProc pfnGetOutputPluginTable;

	OUTPUT_PLUGIN_TABLE* GetOutputPluginTable();

public:
	HMODULE hDll;
	AviUtlOutputPluginTable *opt;

	AviUtlPlugin(const char *path) {
		pfnGetOutputPluginTable = NULL;
		hDll = NULL;
		opt = NULL;
		strcpy(this->path, path);
	}

	~AviUtlPlugin() {
		if (opt) {
			opt->exit();
			delete opt;
		}
		if (hDll)
			FreeLibrary(hDll);
	}

	BOOL Init();
};

//////////////////////////////////////////////////////////////////////////////

class VDubToAviUtl {
private:
	static CriticalSection cs;
	static std::map<DWORD, VDubToAviUtl*> context;

	HWND hwnd;
	VDubFrameServer *server;
	AviUtlPlugin *auo;
	OUTPUT_INFO *oip;
	BYTE *rgb, *yuv, *pcm;
	BOOL bStopOutput, bIsMMXEnabled;

	BOOL IsCPUIDEnabled();
	BOOL IsMMXEnabled();

public:
	VDubToAviUtl(HWND h) {
		hwnd = h;
		server = NULL;
		auo = NULL;
		oip = NULL;
		rgb = NULL;
		yuv = NULL;
		pcm = NULL;
		bStopOutput = FALSE;
		bIsMMXEnabled = FALSE;
	}

	~VDubToAviUtl() {}

	static VDubToAviUtl* GetContext() {
		CriticalLock lock(cs);
		return context[0];
	}

	static void Attach(VDubToAviUtl* self) {
		CriticalLock lock(cs);
		context[0] = self;
	}

	static void Detach() {
		CriticalLock lock(cs);
		context.erase(0);
	}

	static void* __cdecl func_get_video(int frame)
	{ return GetContext()->GetVideoRGB24(frame); }

	static void* __cdecl func_get_audio(int start, int length, int *readed)
	{ return GetContext()->GetAudio(start, length, readed); }

	static BOOL __cdecl func_is_abort()
	{ return GetContext()->IsAbort(); }

	static BOOL __cdecl func_rest_time_disp(int now, int total)
	{ return GetContext()->RestTimeDisp(now, total); }

	static int __cdecl func_get_flag(int frame)
	{ return GetContext()->GetFlag(frame); }

	static BOOL __cdecl func_update_preview()
	{ return GetContext()->UpdatePreview(); }

	static void* __cdecl func_get_video_ex(int frame, DWORD format)
	{ return GetContext()->GetVideoEx(frame, format); }

	void* GetVideoRGB24(int frame);
	void* GetVideoYUY2(int frame);
	void* GetVideoEx(int frame, DWORD format);
	void* GetAudio(int start, int length, int *readed);
	int GetFlag(int frame);
	BOOL IsAbort();
	BOOL RestTimeDisp(int now, int total);
	BOOL UpdatePreview();

	BOOL VDubToAviUtl::Start(VDubFrameServer *s, AviUtlPlugin *a, char *file, BOOL bNoAudio);
	BOOL Stop();
};
