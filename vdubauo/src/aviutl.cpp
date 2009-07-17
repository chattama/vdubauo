
#include "aviutl.h"
#include "debug.h"

extern void mmx_ConvertRGB32toYUY2(const unsigned int *src,unsigned int *dst,int src_pitch, int dst_pitch,int w, int h);
extern void mmx_ConvertRGB24toYUY2(const unsigned char *src,unsigned char *dst,int src_pitch, int dst_pitch,int w, int h);

//////////////////////////////////////////////////////////////////////////////

BOOL AviUtlPlugin::Init() {
	hDll = LoadLibrary(path);
	if (!hDll) return FALSE;

	pfnGetOutputPluginTable = (GetOutputPluginTableProc) GetProcAddress(hDll, "GetOutputPluginTable");
	if (!pfnGetOutputPluginTable) return FALSE;

	OUTPUT_PLUGIN_TABLE *tbl = GetOutputPluginTable();
	if (!tbl) return FALSE;

	opt = new AviUtlOutputPluginTable(tbl);
	if (!opt->init()) return FALSE;

	return TRUE;
}

OUTPUT_PLUGIN_TABLE *AviUtlPlugin::GetOutputPluginTable() {
	return (pfnGetOutputPluginTable) ? pfnGetOutputPluginTable() : NULL;
}

//////////////////////////////////////////////////////////////////////////////

BOOL AviUtlOutputPluginTable::init() {
	return (tbl->func_init) ? tbl->func_init() : TRUE;
}

BOOL AviUtlOutputPluginTable::exit() {
	return (tbl->func_exit) ? tbl->func_exit() : TRUE;
}

BOOL AviUtlOutputPluginTable::output(OUTPUT_INFO *oip) {
	return (tbl->func_output) ? tbl->func_output(oip) : FALSE;
}

BOOL AviUtlOutputPluginTable::config(HWND hwnd, HINSTANCE hdll)	{
	return (tbl->func_config) ? tbl->func_config(hwnd, hdll) : TRUE;
}

int AviUtlOutputPluginTable::GetDataSize() {
	return GetData(0, 0);
}

int AviUtlOutputPluginTable::GetData(void *data, int size) {
	return (tbl->func_config_get) ? tbl->func_config_get(data, size) : 0;
}

int AviUtlOutputPluginTable::SetData(void *data, int size) {
	return (tbl->func_config_set) ? tbl->func_config_get(data, size) : 0;
}

void AviUtlOutputPluginTable::SaveConfig() {
	int size = GetDataSize();
	void *data = (void*)new BYTE[size];
	GetData(data, size);
	SetData(data, size);
	delete [] data;
}

//////////////////////////////////////////////////////////////////////////////

CriticalSection VDubToAviUtl::cs;
std::map<DWORD, VDubToAviUtl*> VDubToAviUtl::context;

inline BOOL VDubToAviUtl::IsCPUIDEnabled() {
	int flag1, flag2;
	_asm {
		pushfd
		pop		eax
		mov		flag1, eax

		xor		eax, 00200000h
		push	eax
		popfd

		pushfd
		pop		eax
		mov		flag2, eax
	}
	return !(flag1 == flag2);
}

inline BOOL VDubToAviUtl::IsMMXEnabled() {
	int flag;

	if (!IsCPUIDEnabled())
		return false;

	_asm {
		mov		eax, 1
		cpuid
		and		edx, 00800000h
		mov		flag, edx
	}
	return flag;
}

// VirtualDub patch for debug mode
/*
Index: VirtualDub-1.7.8/src/vdsvrlnk/main.cpp
===================================================================
--- VirtualDub-1.7.8/src/vdsvrlnk/main.cpp	(original)x
+++ VirtualDub-1.7.8/src/vdsvrlnk/main.cpp	(working copy)
@@ -335,7 +335,7 @@
 	if (VDSRVERR_OK != (err = SendMessage((HWND)LongToHandle(frameserver->hwndServer), VDSRVM_REQ_FRAME, lSample, dwSessionID)))
 		return err;
 
-	_RPT2(0,"Copying %ld bytes to user buffer from arena %P\n", lFrameSize, arena);
+	_RPT2(0,"Copying %ld bytes to user buffer from arena %p\n", lFrameSize, arena);
 	memcpy(lpBuffer, arena, lFrameSize);
 	_RPT0(0,"Copy completed.\n");
*/
void* VDubToAviUtl::GetVideoRGB24(int frame) {
	if (server->GetVideo(frame, rgb) < 0)
		return NULL;
	return rgb;
}

void* VDubToAviUtl::GetVideoYUY2(int frame) {
	if (server->GetVideo(frame, rgb) < 0)
		return NULL;
	if (!bIsMMXEnabled)
		return NULL;
	mmx_ConvertRGB24toYUY2(rgb, yuv, oip->w * 3, oip->w * 2, oip->w, oip->h);
	return yuv;
}

void* VDubToAviUtl::GetVideoEx(int frame, DWORD format) {
	switch (format) {
	case BI_RGB:
	case comptypeDIB:
		return GetVideoRGB24(frame);
		break;
	case mmioFOURCC('Y','U','Y','2'):
		return GetVideoYUY2(frame);
		break;
	}
	return NULL;
}

void* VDubToAviUtl::GetAudio(int start, int length, int *readed) {
	if (server->GetAudio(start, length, readed, pcm, server->aFormat->nAvgBytesPerSec))
		return NULL;
	return pcm;
}

BOOL VDubToAviUtl::IsAbort() {
	return bStopOutput;
}

BOOL VDubToAviUtl::RestTimeDisp(int now, int total) {
	char text[256];
	wsprintf(text, "VDubAuo output... %d%% [%d/%d]", (unsigned int)(((float)(now+1)/(float)total)*100), now+1, total);
	SetWindowText(hwnd, text);
	return TRUE;
}

int VDubToAviUtl::GetFlag(int frame) {
	return OUTPUT_INFO_FRAME_FLAG_KEYFRAME;
}

BOOL VDubToAviUtl::UpdatePreview() {
	return TRUE;
}

BOOL VDubToAviUtl::Start(VDubFrameServer *s, AviUtlPlugin *a, char *file, BOOL bNoAudio) {
	bIsMMXEnabled = IsMMXEnabled();

	OUTPUT_INFO oi;

	server = s;
	auo = a;
	oip = &oi;

	memset(&oi, 0, sizeof(OUTPUT_INFO));
	oi.savefile				= file;
	oi.flag					= OUTPUT_INFO_FLAG_VIDEO;
	oi.w					= server->vFormat->biWidth;
	oi.h					= server->vFormat->biHeight;
	oi.size					= server->vFormat->biSizeImage;
	oi.rate					= server->vStreamInfo.dwRate;
	oi.scale				= server->vStreamInfo.dwScale;
	oi.n					= server->vStreamInfo.dwLength;

	oi.func_get_video		= VDubToAviUtl::func_get_video;
	oi.func_get_audio		= VDubToAviUtl::func_get_audio;
	oi.func_is_abort		= VDubToAviUtl::func_is_abort;
	oi.func_rest_time_disp	= VDubToAviUtl::func_rest_time_disp;
	oi.func_get_flag		= VDubToAviUtl::func_get_flag;
	oi.func_update_preview	= VDubToAviUtl::func_update_preview;
	oi.func_get_video_ex	= VDubToAviUtl::func_get_video_ex;

	if (server->fHasAudio && (server->aFormat->wFormatTag == WAVE_FORMAT_PCM) && !bNoAudio) {
		oi.flag				|= OUTPUT_INFO_FLAG_AUDIO;
		oi.audio_ch			= server->aFormat->nChannels;
		oi.audio_size		= server->aStreamInfo.dwSampleSize;
		oi.audio_rate		= server->aStreamInfo.dwRate / server->aStreamInfo.dwScale;
		oi.audio_n			= server->aStreamInfo.dwLength;
	}

	rgb = new BYTE[oi.w * oi.h * 3];
	yuv = new BYTE[oi.w * oi.h * 2];
	if (server->aFormat)
		pcm = new BYTE[server->aFormat->nAvgBytesPerSec];

	VDubToAviUtl::Attach(this);

	auo->opt->SaveConfig();
	auo->opt->output(&oi);

	VDubToAviUtl::Detach();

	delete [] rgb;
	delete [] yuv;
	delete [] pcm;

	rgb = NULL;
	yuv = NULL;
	pcm = NULL;

	return TRUE;
}

BOOL VDubToAviUtl::Stop() {
	bStopOutput = TRUE;
	return TRUE;
}
