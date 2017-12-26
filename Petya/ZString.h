#pragma once
#include "Global.h"

BOOL x_strcmp(WCHAR** pStr1, WCHAR** pStr2);

BOOL x_StrCmpIW(WCHAR**str1, WCHAR**str2);

void x_HeapFree_Array(WCHAR** pAryData);

BOOL x_StrCmpIW_Arrary(WCHAR** pAryData, WCHAR **szBuf);

WCHAR *ZA2W(char* pSrc);

DWORD RandByteAry(BYTE *szBuf, int nSize);