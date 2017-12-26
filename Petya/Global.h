#pragma once
#include <windows.h>

#include "ZVector.h"

extern HMODULE g_hModule ;
extern BOOL g_nFreeSelfMark ;
extern DWORD g_dwBeginTickCount ;
extern BYTE g_btCurPrivilege;
extern DWORD g_dwFindProcess;
extern WCHAR g_pszFileName[780];
extern BYTE *g_bSelfFileData;
extern DWORD g_dwSelfFileBufSize;
extern PIMAGE_DOS_HEADER g_pSelfMemData;
extern WSADATA g_wsaData;
extern DWORD g_dwShutTime;
extern DWORD g_dwError;
extern WCHAR *g_pszDllhostPath;
extern WCHAR g_szAccountInfo[8181];

extern char g_szCharTable[];

extern CZVector	*g_pObj1;
extern CZVector	*g_pObj2;
extern CZVector	*g_pAryString;
extern CRITICAL_SECTION	g_csCriticalSection;
extern BOOL g_bGetAccount;
