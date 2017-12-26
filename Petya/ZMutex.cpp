#include "ZMutex.h"
#include "ZFilePath.h"

#include <Shlwapi.h>


BOOL CheckMutileRun()
{
	BOOL bRet = FALSE;
	WCHAR szPath[780] = { 0 };
	if (FALSE != GetCurrentPathFile(szPath))
	{
		if (FALSE == PathFileExistsW(szPath))
		{
			bRet = CreateFileW(szPath, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, NULL) != INVALID_HANDLE_VALUE;
		}
	}
	return bRet;
}