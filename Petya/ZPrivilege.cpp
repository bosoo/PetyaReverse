#include "ZPrivilege.h"
#include "ZSystemCmd.h"

#include <TlHelp32.h>


BOOL SetPrivilege(WCHAR *szPrivilegName)
{
	BOOL bRet = FALSE;
	HANDLE hCurHandle = NULL;
	struct _TOKEN_PRIVILEGES tagNewState;
	DWORD dwErrCode = 0;
	HANDLE hTokenHandle = NULL;

	memset(&tagNewState, 0, sizeof(tagNewState));

	hCurHandle = GetCurrentProcess();
	if (OpenProcessToken(hCurHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTokenHandle))
	{
		if (LookupPrivilegeValueW(0, szPrivilegName, (PLUID)tagNewState.Privileges))
		{
			tagNewState.PrivilegeCount = 1;
			tagNewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			bRet = AdjustTokenPrivileges(hTokenHandle, 0, &tagNewState, 0, 0, 0);
			dwErrCode = GetLastError();
			if (dwErrCode)
			{
				bRet = FALSE;
			}
		}
	}
	SetLastError(dwErrCode);
	return bRet;
}


BOOL FindDwordElement(DWORD * pdwAryElements, int iCount, DWORD dwSrc)
{
	BOOL bRet = FALSE;
	if (NULL != pdwAryElements)
	{
		for (int i = 0; i < iCount; i++)
		{
			if (pdwAryElements[i] == dwSrc)
			{
				bRet = TRUE;
				break;
			}
		}
	}
	return bRet;
}

DWORD DuplicateAllToken(DWORD *pAryOutSecurityHandle)
{
	int iCount = 0;
	DWORD dwRet = 0;
	DWORD dwArg0offset = 0;
	BOOL bAuthenticationIdRepeat = FALSE;
	DWORD pdwArySessionIds[1024] = { 0 };
	BOOL bSystemSupport = CheckSystemSupport();
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE != hSnapshot)
	{
		PROCESSENTRY32W tagProcessEntry;
		for (BOOL bFind = Process32FirstW(hSnapshot, &tagProcessEntry); bFind && dwRet < 64; bFind = Process32NextW(hSnapshot, &tagProcessEntry))
		{
			HANDLE hProcess = OpenProcess(CREATE_NEW_CONSOLE | IDLE_PRIORITY_CLASS | CREATE_UNICODE_ENVIRONMENT, FALSE, tagProcessEntry.th32ProcessID);
			if (hProcess)
			{
				HANDLE hTokenHandle = NULL;
				DWORD dwTokenSessionId = 0; 
				if (OpenProcessToken(hProcess, TOKEN_ALL_ACCESS_P, &hTokenHandle))
				{
					DWORD dwReturnedSize = 0;
					if (GetTokenInformation(hTokenHandle, TokenSessionId, &dwTokenSessionId, sizeof(DWORD), &dwReturnedSize))
					{
						if (bSystemSupport || 0 != dwTokenSessionId)
						{
							HANDLE hNewToken;
							if (DuplicateTokenEx(hTokenHandle, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hNewToken))
							{
								TOKEN_STATISTICS tagTokenStatistics = { 0 };
								if (GetTokenInformation(hNewToken, TokenStatistics, &tagTokenStatistics, sizeof(TOKEN_STATISTICS), &dwReturnedSize))
								{
									if (!FindDwordElement(pdwArySessionIds, iCount, tagTokenStatistics.AuthenticationId.LowPart))
									{
										if (SetTokenInformation(hNewToken, TokenSessionId, &dwTokenSessionId, sizeof(DWORD)))
										{
											pAryOutSecurityHandle[iCount] = (DWORD)hNewToken;
											pdwArySessionIds[iCount] = (DWORD)tagTokenStatistics.AuthenticationId.LowPart;
											iCount++;
											dwRet++;
										}
									}
								}
							}
						}
					}
					CloseHandle(hProcess);
				}
				CloseHandle(hTokenHandle);
			}
		}
	}
	CloseHandle(hSnapshot);
	return dwRet;
}