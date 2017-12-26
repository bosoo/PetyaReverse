#pragma once
#include "Global.h"

BOOL CheckIsWow64Process();
BOOL InitCmdLineForAcsii(WCHAR *pData);
int InitCmdLine(LPCWSTR lpCmdLine);
BOOL CheckSystemSupport();
BOOL RunCmd(WCHAR *pCmd, DWORD dwSleep);
BOOL Shutdown();
DWORD GetRunTime();