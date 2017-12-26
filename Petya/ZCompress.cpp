#include "ZCompress.h"
#include <zlib.h>

BOOL UncompressResource(PBYTE *lpUncompressData, PDWORD pdwUnCompressSize, HRSRC hResInfo)
{
	BOOL bRet = FALSE;
	HGLOBAL hGlobal = LoadResource(g_hModule, hResInfo);
	if (NULL != hGlobal)
	{
		PBYTE pSrcData = (PBYTE)LockResource(hGlobal);
		if (NULL != pSrcData)
		{
			DWORD dwResSize = SizeofResource(g_hModule, hResInfo);
			if (0 != dwResSize)
			{
				DWORD dwDstSize = *(DWORD*)pSrcData;
				PBYTE pData = new BYTE[dwDstSize];
				*(DWORD*)lpUncompressData = (DWORD)pData;
				if (NULL != pData)
				{
					if (0 == uncompress(pData, &dwDstSize, pSrcData + 4, dwResSize - 4))
					{
						if (NULL != pdwUnCompressSize)
						{
							*pdwUnCompressSize = dwDstSize;
						}
						bRet = TRUE;
					}
					else
					{
						delete[]pData;
					}
				}
			}
		}
	}

	return bRet;
}
