#pragma once
#include "Global.h"


BOOL ReadSelfData();

DWORD V2F(PIMAGE_NT_HEADERS pNtHeader, DWORD dwAddr);

BOOL RepairBaseRelocation(LPVOID pBase, PIMAGE_BASE_RELOCATION pRelocAddr);

BOOL InitImportTable();

BOOL DeleteSelfRun(int nArg, DWORD dwErrCode, WCHAR* pCommandLine, HANDLE hThread);

BOOL RestorePageAttr(LPVOID hModule, PIMAGE_NT_HEADERS pNtHeader);

LPVOID AllocAndCopySelfData(HMODULE hModule);

PIMAGE_BASE_RELOCATION GetRelocation(HMODULE hModule);

void DeleteSelfReEntry(int nArg, DWORD dwErrCode, WCHAR* pCommandLine);