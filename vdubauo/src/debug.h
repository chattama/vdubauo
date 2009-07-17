#ifndef DEBUG_H
#define DEBUG_H

#ifdef _DEBUG

void DebugPrintA(const char* format, ...);
void DebugPrintW(const wchar_t* format, ...);
#if (defined(UNICODE)||defined(_UNICODE))
#define DebugPrint DebugPrintW
#else
#define DebugPrint DebugPrintA
#endif

#else
#define DebugPrint (0)
#endif

#endif
