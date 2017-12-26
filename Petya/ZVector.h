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

	BOOL SetInfected(iterator *pFindInfo, WCHAR* pszData);

	BOOL SetInfected(iterator *pFindInfo, WCHAR **pszData);

	void Expand(DWORD dwSize);
	
	void SetCollectComplete();

	iterator* GetString(WCHAR* pszOut);
	BOOL GetString(iterator *it, WCHAR* pszOut);
	iterator* GetString(int nIndex, StringInfo**pOut);
	BOOL GetString(iterator *pFindInfo, StringInfo**pOut2);

private:
	DWORD CallBack(int nIndex, WCHAR **pData, StringInfo** pRet);

	CRITICAL_SECTION	m_pcsLock;
	StringInfo**	m_pParamtAry;
	DWORD	m_dwParamSize;
	DWORD	m_dwMaxParamCount;
	DWORD	m_dwParamCount;
	DWORD	m_bCollectComplete;
	ZCALLBACK	m_pfnFun1;
	x_HeapFree_Array	m_pfnFun2;
};