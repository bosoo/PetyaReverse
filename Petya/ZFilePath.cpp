#include "ZFilePath.h"
#include <Shlwapi.h>

BOOL GetFileLastName(WCHAR *pszFileName)
{
	BOOL bRet = FALSE;
	if (NULL != pszFileName)
	{
		WCHAR *pName = PathFindFileNameW(g_pszFileName);
		if (NULL != pName)
		{
			wcscpy(pszFileName, pName);
			bRet = TRUE;
		}
	}
	return bRet;
}

BOOL GetCurrentPathFile(WCHAR *pOut)
{
	BOOL bRet = FALSE;
	if (NULL != PathCombineW(pOut, L"C:\\Windows\\", PathFindFileNameW(g_pszFileName)))
	{
		WCHAR *pExtension = PathFindExtensionW(pOut);
		if (NULL != pExtension)
		{
			*pExtension = 0;
			bRet = TRUE;
		}
	}
	return bRet;
}
