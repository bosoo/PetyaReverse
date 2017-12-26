#include "ZString.h"

#include <Shlwapi.h>

BOOL x_StrCmpIW_Arrary(WCHAR** pAryData, WCHAR **szBuf)
{
	if (0 == StrCmpIW(pAryData[0], szBuf[0])
		&& 0 == StrCmpW(pAryData[1], szBuf[1]))
	{
		return TRUE;
	}
	return FALSE;
}

void x_HeapFree_Array(WCHAR** pAryData)
{
	if (NULL != pAryData)
	{
		if (NULL != pAryData[0])
		{
			delete[]pAryData[0];
		}

		if (NULL != pAryData[1])
		{
			delete[]pAryData[1];
		}
	}
}

BOOL x_StrCmpIW(WCHAR**str1, WCHAR**str2)
{
	BOOL bRet = FALSE;
	if (NULL != str1
		&& NULL != str2)
	{
		bRet = StrCmpIW(*str1, *str2) == 0;
	}

	return bRet;
}

BOOL x_strcmp(WCHAR** pStr1, WCHAR** pStr2)
{
	return wcscmp((WCHAR*)pStr1, (WCHAR*)pStr2) == 0;
}


WCHAR *ZA2W(char* pSrc)
{
	WCHAR *pRet = NULL;
	DWORD dwCount = MultiByteToWideChar(CP_UTF8, 0, pSrc, -1, NULL, 0);
	if (dwCount)
	{
		pRet = new WCHAR[dwCount];
		dwCount = MultiByteToWideChar(CP_UTF8, 0, pSrc, -1, pRet, dwCount);
		if (!dwCount)
		{
			delete[]pRet;
			pRet = NULL;
		}
	}
	return pRet;
}

DWORD RandByteAry(BYTE *szBuf, int nSize)
{
	HCRYPTPROV hCrypt = NULL;
	if (CryptAcquireContextA(&hCrypt, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		if (!CryptGenRandom(hCrypt, nSize, szBuf))
		{
			g_dwError = (int)GetLastError() <= 0 ? GetLastError() : GetLastError() & 0xffff | 0x80070000;
		}

		CryptReleaseContext(hCrypt, 0);
	}
	else
	{
		g_dwError = (int)GetLastError() <= 0 ? GetLastError() : GetLastError() & 0xffff | 0x80070000;
	}

	return g_dwError;
}