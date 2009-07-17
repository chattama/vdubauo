#ifndef DEBUG_H
#define DEBUG_H
#ifdef _DEBUG
#include <windows.h>
#include <stdio.h>
void DebugPrintA(const char* format, ...) {
	char buf[4096];
	va_list val;
	va_start(val, format);
	wvsprintfA(buf, format, val);
	va_end(val);
	OutputDebugStringA(buf);
}
void DebugPrintW(const wchar_t* format, ...) {
    wchar_t buf[1024];
    va_list val;
    va_start(val, format);
    wvsprintfW(buf, format, val);
    va_end(val);
	OutputDebugStringW(buf);
}
#endif
#endif
