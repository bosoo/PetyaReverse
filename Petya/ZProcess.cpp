#include "ZProcess.h"

#include <TlHelp32.h>

DWORD FindProcess()
{
	DWORD dwRet = 0xffffffff;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (INVALID_HANDLE_VALUE != hSnapshot)
	{
		PROCESSENTRY32W tagProcss = { 0 };
		for (BOOL bFind = Process32FirstW(hSnapshot, &tagProcss);
			bFind;
			bFind = Process32NextW(hSnapshot, &tagProcss))
		{
			DWORD dwHash = 0x12345678;
			for (int i = 0; i < 3; i++)
			{
				int nLen = wcslen(tagProcss.szExeFile);
				for (int j = 0, z = 0; j < nLen; j++, z++)
				{
					((BYTE*)&dwHash)[z % 4] ^= tagProcss.szExeFile[j] - 1;
				}
			}

			if (dwHash == 0x2E214B44)
			{
				dwRet &= 0xFFFFFFF7;
			}
			else if (dwHash == 0x6403527E || dwHash == 0x651B3005)
			{
				dwRet &= 0xFFFFFFFB;
			}
		}
		CloseHandle(hSnapshot);
	}
	return dwRet;
}