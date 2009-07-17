#pragma once

#include <windows.h>

#include "vdserver.h"
#include "vdplugin.h"

typedef IVDubServerLink *(__cdecl *GetDubServerInterfaceProc)();

class VDubFrameServer {
private:
	IVDubServerLink *ivdsl;

	CRITICAL_SECTION cs;

	char m_sname[256];
	HMODULE vdsvrlnk;
	GetDubServerInterfaceProc GetDubServerInterface;

	void lock();
	void unlock();

public:
	IVDubAnimConnection *ivdac;
	AVISTREAMINFO vStreamInfo;
	AVISTREAMINFO aStreamInfo;
	BITMAPINFOHEADER *vFormat;
	WAVEFORMATEX *aFormat;
	LONG vFormatLen, vSampleFirst, vSampleLast;
	LONG aFormatLen, aSampleFirst, aSampleLast;
	BOOL fHasAudio;

	VDubFrameServer(const char *sname);
	~VDubFrameServer();

	BOOL Init();

	int GetVideo(int sample, void *buf);
	int GetAudio(int start, int length, int *readed, void *buf, long size);
};
