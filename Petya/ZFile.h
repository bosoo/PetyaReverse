#pragma once
#include "Global.h"

BOOL ZWriteFile(WCHAR *pszFilePath, LPVOID pData, DWORD dwSize);

BOOL ZWriteHiddenFile(WCHAR* pszFilePath, LPVOID pData, DWORD dwDataSize);

BOOL ZWriteNormalFile(WCHAR* pszFilePath, LPVOID pData, DWORD dwDataSize, BOOL bOverlay);