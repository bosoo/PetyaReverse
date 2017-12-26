#include "ZFile.h"

BOOL ZWriteFile(WCHAR *pszFilePath, LPVOID pData, DWORD dwSize)
{
	BOOL bRet = FALSE;
	HANDLE hFile = CreateFileW(pszFilePath, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		DWORD dwWrited = 0;
		if (WriteFile(hFile, pData, dwSize, &dwWrited, NULL))
		{
			if (dwWrited == dwSize)
			{
				bRet = TRUE;
			}
		}
		CloseHandle(hFile);
	}
	return bRet;
}


BOOL ZWriteHiddenFile(WCHAR* pszFilePath, LPVOID pData, DWORD dwDataSize)
{
	BOOL bRet = FALSE;
	HANDLE hFile = CreateFileW(pszFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
	if (INVALID_HANDLE_VALUE != hFile)
	{
		DWORD dwWriteReturned = 0;
		if (WriteFile(hFile, pData, dwDataSize, &dwWriteReturned, NULL))
		{
			if (dwWriteReturned == dwDataSize)
			{
				bRet = TRUE;
			}
		}
		CloseHandle(hFile);
	}
	return bRet;
}


BOOL ZWriteNormalFile(WCHAR* pszFilePath, LPVOID pData, DWORD dwDataSize, BOOL bOverlay)
{
	BOOL bRet = FALSE;
	HANDLE hFile = CreateFileW(pszFilePath, GENERIC_WRITE, 0, NULL, bOverlay ? CREATE_ALWAYS : CREATE_NEW, 0, NULL);
	if (INVALID_HANDLE_VALUE != hFile)
	{
		DWORD dwWriteReturned = 0;
		if (WriteFile(hFile, pData, dwDataSize, &dwWriteReturned, NULL))
		{
			if (dwWriteReturned == dwDataSize)
			{
				bRet = TRUE;
			}
		}
		CloseHandle(hFile);
	}
	return bRet;
}