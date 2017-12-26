#include "Global.h"
HMODULE g_hModule = NULL;
BOOL g_nFreeSelfMark = FALSE;
DWORD g_dwBeginTickCount = 0;
BYTE g_btCurPrivilege = 0;
DWORD g_dwFindProcess = 0;
WCHAR g_pszFileName[780];
BYTE *g_bSelfFileData = NULL;
DWORD g_dwSelfFileBufSize = 0;
PIMAGE_DOS_HEADER g_pSelfMemData = NULL;
WSADATA g_wsaData;
DWORD g_dwShutTime = 0;
DWORD g_dwError = 0;
WCHAR *g_pszDllhostPath = NULL;
WCHAR g_szAccountInfo[8181];

char g_szCharTable[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

CZVector	*g_pObj1;
CZVector	*g_pObj2;
CZVector	*g_pAryString;
CRITICAL_SECTION	g_csCriticalSection;
BOOL g_bGetAccount = FALSE;
