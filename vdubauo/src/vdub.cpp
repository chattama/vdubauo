
#include "vdub.h"
#include "debug.h"

//////////////////////////////////////////////////////////////////////////////

const VDPluginInfo *const kPlugins[] = {
	NULL,
};

extern "C" __declspec(dllexport) const VDPluginInfo *const *VDXAPIENTRY VDGetPluginInfo() {
	return kPlugins;
}

//////////////////////////////////////////////////////////////////////////////

VDubFrameServer::VDubFrameServer(const char *sname) {
	lstrcpy(m_sname, sname);
	GetDubServerInterface = NULL;
	vdsvrlnk = NULL;
	ivdsl = NULL;
	ivdac = NULL;
	vFormat = NULL;
	aFormat = NULL;

	InitializeCriticalSection(&cs);
}

VDubFrameServer::~VDubFrameServer() {
	DeleteCriticalSection(&cs);

	if (ivdac)
		ivdsl->FrameServerDisconnect(ivdac);

	if (vdsvrlnk)
		FreeLibrary(vdsvrlnk);
}

BOOL VDubFrameServer::Init() {
	BOOL final = TRUE;
	try {
		vdsvrlnk = LoadLibrary("vdsvrlnk.dll");
		if (!vdsvrlnk) throw (BOOL)FALSE;

		GetDubServerInterface = (GetDubServerInterfaceProc) GetProcAddress(vdsvrlnk, "GetDubServerInterface");
		if (!GetDubServerInterface) throw (BOOL)FALSE;

		ivdsl = GetDubServerInterface();
		if (!ivdsl) throw (BOOL)FALSE;

		ivdac = ivdsl->FrameServerConnect(m_sname);
		if (!ivdac) throw (BOOL)FALSE;

		fHasAudio = ivdac->hasAudio();

		if (!ivdac->readStreamInfo(&vStreamInfo, FALSE, &vSampleFirst, &vSampleLast))
			throw (BOOL)FALSE;

		if ((vFormatLen = ivdac->readFormat(NULL, FALSE))<=0)
			throw (BOOL)FALSE;

		if (!(vFormat = (BITMAPINFOHEADER *)malloc(vFormatLen)))
			throw (HRESULT)E_OUTOFMEMORY;

		if (ivdac->readFormat(vFormat, FALSE)<=0)
			throw (BOOL)FALSE;

		if (fHasAudio) {
			if (!ivdac->readStreamInfo(&aStreamInfo, TRUE, &aSampleFirst, &aSampleLast))
				throw (BOOL)FALSE;

			if ((aFormatLen = ivdac->readFormat(NULL, TRUE))<=0)
				throw (BOOL)FALSE;

			if (!(aFormat = (WAVEFORMATEX *)malloc(aFormatLen)))
				throw (HRESULT)E_OUTOFMEMORY;

			if (ivdac->readFormat(aFormat, TRUE)<=0)
				throw (BOOL)FALSE;
		}
	} catch (BOOL res) {
		final = res;
	}
	return final;
}

int VDubFrameServer::GetVideo(int sample, void *buf) {
	lock();
	int r = ivdac->readVideo(sample, buf);
	unlock();
	return r;
}

int VDubFrameServer::GetAudio(int start, int length, int *readed, void *buf, long size) {
	long rb = 0;
	lock();
	int r = ivdac->readAudio(start, length, buf, size, &rb, (long*)readed);
	unlock();
	return r;
}

void VDubFrameServer::lock() {
	EnterCriticalSection(&cs);
}

void VDubFrameServer::unlock() {
	LeaveCriticalSection(&cs);
}
