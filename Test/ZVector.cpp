#include "ZVector.h"



CZVector::CZVector(DWORD dwParamSize, ZCALLBACK pfnFun1, x_HeapFree_Array pfnFun2, DWORD dwMaxParamCount) :m_dwParamSize(dwParamSize), m_pfnFun1(pfnFun1), m_pfnFun2(pfnFun2), m_dwMaxParamCount(dwMaxParamCount)
{
	InitializeCriticalSection(&m_pcsLock);
	m_pParamtAry = new StringInfo*[dwMaxParamCount];
	memset(m_pParamtAry, 0, dwMaxParamCount * sizeof(StringInfo*));
}

CZVector::~CZVector()
{
	Release();
}

void CZVector::Release()
{
	if (m_pParamtAry)
	{
		for (int i = 0; i < m_dwParamCount; i++)
		{
			if (NULL != m_pParamtAry[i])
			{
				if (NULL != m_pParamtAry[i]->m_pAryStrs
					&& NULL != m_pfnFun2)
				{
					m_pfnFun2(m_pParamtAry[i]->m_pAryStrs);
					delete[](m_pParamtAry[i]->m_pAryStrs);
				}
				delete m_pParamtAry[i];
			}
		}
		delete[]m_pParamtAry;
		m_pParamtAry = NULL;
	}
}


BOOL CZVector::AddString(WCHAR *pszData, int nCount)
{
	BOOL bRet = FALSE;
	if (NULL != pszData)
	{
		WCHAR wcsSrc[16];
		wcscpy(wcsSrc, pszData);
		bRet = AddData((WCHAR**)&wcsSrc, nCount);
	}
	return bRet;
}

BOOL CZVector::AddData(WCHAR **pszData, int nCount)
{
	BOOL bRet = FALSE;
	if (NULL != pszData)
	{
		EnterCriticalSection(&m_pcsLock);
		if (CallBack(0, pszData, NULL) == 0)
		{
			if (m_dwParamCount < m_dwMaxParamCount)
			{
				StringInfo *pTagData = m_pParamtAry[m_dwParamCount] = new StringInfo();
				pTagData->m_pAryStrs = new WCHAR*[m_dwParamSize / sizeof(WCHAR*)];
				pTagData->m_dwMark = nCount;
				memcpy(pTagData->m_pAryStrs, pszData, m_dwParamSize);
				m_dwParamCount++;
				bRet = TRUE;
			}
			else
			{
				Expand(255);
				AddData(pszData, nCount);
			}
		}

		LeaveCriticalSection(&m_pcsLock);
	}
	return bRet;
}

BOOL CZVector::Exsit(iterator *pFindInfo, WCHAR* pszData)
{
	WCHAR szBuf[16];
	wcscpy(szBuf, pszData);
	return Exsit(pFindInfo, (WCHAR**)&szBuf);
}

BOOL CZVector::Exsit(iterator *pFindInfo, WCHAR **pszData)
{
	EnterCriticalSection(&m_pcsLock);
	StringInfo *pRet = NULL;
	int nIndex = NULL == pFindInfo ? 0 : pFindInfo->m_dwBegin;
	BOOL bRet = CallBack(nIndex, pszData, &pRet);
	pRet->m_dwMark = 1;
	LeaveCriticalSection(&m_pcsLock);
	return bRet;
}

void CZVector::Expand(DWORD dwSize)
{
	StringInfo **pNew = new StringInfo*[m_dwMaxParamCount + dwSize];
	memcpy(pNew, m_pParamtAry, sizeof(StringInfo *)* m_dwMaxParamCount);
	delete[]m_pParamtAry;
	m_pParamtAry = pNew;
	m_dwMaxParamCount += dwSize;
}

DWORD CZVector::CallBack(int nIndex, WCHAR **pData, StringInfo** pRet)
{
	DWORD dwRet = 0;
	EnterCriticalSection(&m_pcsLock);

	for (int i = nIndex; i < m_dwParamCount + nIndex; i++)
	{
		m_pParamtAry[i % m_dwParamCount];
		dwRet = m_pfnFun1(pData, m_pParamtAry[i % m_dwParamCount]->m_pAryStrs);
		if (0 != dwRet)
		{
			if (pRet)
			{
				*pRet = m_pParamtAry[i % m_dwParamCount];
			}
			break;
		}

	}

	LeaveCriticalSection(&m_pcsLock);
	return dwRet;
}

CZVector::iterator* CZVector::GetString(WCHAR* pszOut)
{
	StringInfo *pRet = NULL;
	CZVector::iterator* it = GetString(0, &pRet);
	if (NULL != it)
	{
		wcscpy(pszOut, pRet->m_pAryStrs[0]);
	}
	return it;
}

CZVector::iterator* CZVector::GetString(int nIndex, StringInfo**pOut)
{
	CZVector::iterator *it = new CZVector::iterator;
	it->m_dwBegin = nIndex;
	it->m_dwMark = 0;
	if (FALSE == GetString(it, pOut))
	{
		delete it;
	}
	return it;
}

BOOL CZVector::GetString(iterator *it, StringInfo**pOut2)
{
	BOOL bFind = FALSE;
	if (NULL != it)
	{
		while (TRUE)
		{
			EnterCriticalSection(&m_pcsLock);

			for (; it->m_dwBegin < m_dwParamCount
				&& !bFind; it->m_dwBegin++)
			{
				DWORD dwMark = m_pParamtAry[it->m_dwBegin]->m_dwMark;
				if ((0 != dwMark) && (it->m_dwMark == dwMark))
				{
					bFind = FALSE;
				}
				else
				{
					bFind = TRUE;
					if (pOut2)
					{
						*pOut2 = m_pParamtAry[it->m_dwBegin];
					}
				}
			}

			LeaveCriticalSection(&m_pcsLock);

			if (!bFind && (0 == field_28))
			{
				Sleep(10000);
			}
		} 
	}

	return bFind;
}
