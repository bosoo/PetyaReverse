#pragma once
#include "Global.h"

BOOL SetPrivilege(WCHAR *szPrivilegName);

DWORD DuplicateAllToken(DWORD *pAryOutSecurityHandle);