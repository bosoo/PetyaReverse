#pragma once
#include <windows.h>


struct StringInfo
{
	WCHAR	**m_pAryStrs;
	DWORD	m_dwMark;
};


class CZVector
{
private:
	typedef BOOL( *ZCALLBACK)(PWCHAR*, PWCHAR*);
	typedef void( *x_HeapFree_Array)(PWCHAR*);

public:
	struct iterator
	{
		DWORD	m_dwBegin;
		DWORD	m_dwMark;
	};


	CZVector(DWORD dwParamSize, ZCALLBACK pfnFun1, x_HeapFree_Array pfnFun2, DWORD dwMaxParamCount);

	~CZVector();

	void Release();

	BOOL AddString(WCHAR *pszData, int nCount);

	BOOL AddData(WCHAR **pszData, int nCount);

	BOOL Exsit(iterator *pFindInfo, WCHAR* pszData);

	BOOL Exsit(iterator *pFindInfo, WCHAR **pszData);

	void Expand(DWORD dwSize);

	iterator* GetString(WCHAR* pszOut);
	iterator* GetString(int nIndex, StringInfo**pOut);
	BOOL GetString(iterator *pFindInfo, StringInfo**pOut2);

private:
	DWORD CallBack(int nIndex, WCHAR **pData, StringInfo** pRet);

	CRITICAL_SECTION	m_pcsLock;
	StringInfo**	m_pParamtAry;
	DWORD	m_dwParamSize;
	DWORD	m_dwMaxParamCount;
	DWORD	m_dwParamCount;
	DWORD	field_28;
	ZCALLBACK	m_pfnFun1;
	x_HeapFree_Array	m_pfnFun2;
};