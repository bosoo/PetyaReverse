#include <iostream>
#include <windows.h>
#include <WinCred.h>
#include <Shlwapi.h>
#include <winternl.h>
#include <winternl.h>
#include <IPTypes.h>
#include <IPHlpApi.h>
#include <Lmserver.h>
#include <lmerr.h>
#include <LMAPIbuf.h>
#include <dhcpsapi.h>

#include "ZVector.h"

char g_szCharTable[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

CZVector	*g_pObj1;
CZVector	*g_pObj2;

WCHAR *ZA2W(char* pSrc)
{
	WCHAR *pRet = NULL;
	DWORD dwCount = MultiByteToWideChar(CP_UTF8, 0, pSrc, -1, NULL, 0);
	if (dwCount)
	{
		pRet = new WCHAR[dwCount];
		dwCount = MultiByteToWideChar(CP_UTF8, 0, pSrc, -1, pRet, dwCount);
		if (!dwCount)
		{
			delete[]pRet;
			pRet = NULL;
		}
	}
	return pRet;
}

BOOL CheckIsServer()
{
	BOOL bRet = FALSE;
	PSERVER_INFO_101 p101ServerInfo;
	if (NERR_Success == NetServerGetInfo(NULL, 101, (LPBYTE*)&p101ServerInfo))
	{
		if (SV_TYPE_SERVER_NT != p101ServerInfo->sv101_type
			|| (SV_TYPE_DOMAIN_BAKCTRL | SV_TYPE_DOMAIN_CTRL) != p101ServerInfo->sv101_type)
		{
			bRet = TRUE;
		}
	}

	if (NULL != p101ServerInfo)
	{
		NetApiBufferFree(p101ServerInfo);
	}
	return bRet;
}

BOOL CollectDhcpClientsIP(CZVector *pVector)
{
	BOOL bRet = FALSE;
	WCHAR szComputerName[MAX_PATH] = { 0 };
	DWORD dwSize = MAX_PATH;
	DHCP_RESUME_HANDLE hResumeHandle = NULL;
	LPDHCP_IP_ARRAY  pDhcpIpEnumInfo = NULL;
	DWORD dwElementsReturned = 0;
	DWORD dwElementsTotal = 0;

	GetComputerNameExW(ComputerNamePhysicalNetBIOS, szComputerName, &dwSize);
	if (ERROR_SUCCESS == DhcpEnumSubnets(szComputerName, &hResumeHandle, 0x400, &pDhcpIpEnumInfo, &dwElementsReturned, &dwElementsTotal))
	{
		for (int i = 0; i < pDhcpIpEnumInfo->NumElements; i++)
		{
			LPDHCP_SUBNET_INFO pDhcpSubnetInfo = NULL;
			if (ERROR_SUCCESS == DhcpGetSubnetInfo(NULL, pDhcpIpEnumInfo->Elements[i], &pDhcpSubnetInfo))
			{
				if (DhcpSubnetEnabled != pDhcpSubnetInfo->SubnetState)
				{
					DHCP_RESUME_HANDLE hDhcpResumeHandle = NULL;
					LPDHCP_CLIENT_INFO_ARRAY pAryDhcpClientInfo = NULL;
					DWORD dwClientReturnedCount = 0;
					DWORD dwClientTotal = 0;
					if (ERROR_SUCCESS == DhcpEnumSubnetClients(NULL, pDhcpIpEnumInfo->Elements[i], &hDhcpResumeHandle, 0x10000, &pAryDhcpClientInfo, &dwClientReturnedCount, &dwClientTotal))
					{
						for (int j = 0; j < pAryDhcpClientInfo->NumElements; j++)
						{
							if (NULL != pAryDhcpClientInfo->Clients[j])
							{
								in_addr addr;
								addr.S_un.S_addr = ntohl(pAryDhcpClientInfo->Clients[j]->ClientIpAddress);
								WCHAR *pIP = ZA2W(inet_ntoa(addr));
								if (NULL != pIP)
								{
									pVector->AddString(pIP, 0);
									delete pIP;
								}
							}
						}

						DhcpRpcFreeMemory(pAryDhcpClientInfo);
					}
				}
			}
		}
		DhcpRpcFreeMemory(pDhcpIpEnumInfo);
	}

	return bRet;
}

BOOL CheckIpPort(DWORD dwIp, DWORD dwPort)
{
	sockaddr_in addr;
	fd_set sets;
	timeval timeout;
	BOOL bRet = FALSE;

	memset(sets.fd_array, 0, 0x100);
	sets.fd_count = 0;
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (INVALID_SOCKET != sock)
	{
		DWORD dwArg = 0;
		if (SOCKET_ERROR != ioctlsocket(sock, FIONBIO | IOC_IN  & ~IOC_OUT, &dwArg))
		{
			addr.sin_family = AF_INET;
			addr.sin_addr.S_un.S_addr = dwIp;
			addr.sin_port = htons(dwPort);
			connect(sock, (sockaddr*)&addr, sizeof(sockaddr));

			timeout.tv_sec = 2;
			timeout.tv_usec = 0;
			sets.fd_count = 1;
			sets.fd_array[0] = sock;
			if (SOCKET_ERROR != select(sock + 1, NULL, &sets, NULL, &timeout))
			{
				if (FD_ISSET(sock, &sets))
				{
					bRet = TRUE;
				}
			}
		}
		closesocket(sock);
	}
	return bRet;
}

BOOL CheckPort_445_139(DWORD dwIp)
{
	if (CheckIpPort(dwIp, 445) || CheckIpPort(dwIp, 139))
	{
		return TRUE;
	}
	return FALSE;
}

DWORD __stdcall ScanIpSegmentProc(LPVOID pParam)
{
	DWORD *pAryIpInfo = (DWORD*)pParam;

	
	for (DWORD dwCur = pAryIpInfo[0]; dwCur < pAryIpInfo[1]; dwCur++)
	{
		if (CheckPort_445_139(ntohl(dwCur)))
		{
			in_addr addr;
			addr.S_un.S_addr = ntohl(dwCur);
			WCHAR *pIp = ZA2W(inet_ntoa(addr));
			if (NULL != pIp)
			{
				((CZVector*)pAryIpInfo[2])->AddString(pIp, 0);
				delete[]pIp;
			}
		}
	}
	return 0;
}

struct TagIPInfo
{
	DWORD dwIp;
	DWORD dwMask;
};

DWORD __stdcall CollectIPProc(LPVOID pParam)
{
	CZVector *pVector = (CZVector*)pParam;
	DWORD dwSizePointer = 0;
	TagIPInfo aryIpInfo[1024] = { 0 };
	HANDLE hAryThread[1024] = { NULL };
	if (ERROR_BUFFER_OVERFLOW == GetAdaptersInfo(NULL, &dwSizePointer))
	{
		PIP_ADAPTER_INFO pAdapterBuf = (PIP_ADAPTER_INFO)LocalAlloc(LMEM_ZEROINIT, dwSizePointer);
		if (NULL != pAdapterBuf)
		{
			if (ERROR_SUCCESS  == GetAdaptersInfo((PIP_ADAPTER_INFO)pAdapterBuf, &dwSizePointer))
			{
				PIP_ADAPTER_INFO pNext = pAdapterBuf;
				int nCount = 0;
				for (; nCount < 1024 && (NULL != pNext); nCount++, pNext = pNext->Next)
				{
					DWORD dwIpAddr = inet_addr(pNext->IpAddressList.IpAddress.String);
					DWORD dwMask = inet_addr(pNext->IpAddressList.IpMask.String);
					aryIpInfo[nCount].dwIp = dwIpAddr;
					aryIpInfo[nCount].dwMask = dwMask;
					WCHAR *pIpAddress = ZA2W(pNext->IpAddressList.IpAddress.String);
					pVector->AddString(pIpAddress, 1);
					delete[]pIpAddress;

					if (pNext->DhcpEnabled)
					{
						pIpAddress = ZA2W(pNext->DhcpServer.IpAddress.String);
						pVector->AddString(pIpAddress, 0);
						delete[]pIpAddress;
					}
				}

				if (CheckIsServer())
				{
					CollectDhcpClientsIP(pVector);
				}

				int i = 0;
				for (; i < nCount; i++)
				{
					DWORD *pIpAddr = (DWORD*)LocalAlloc(LMEM_ZEROINIT, 12);
					if (NULL != pIpAddr)
					{
						if (aryIpInfo[i].dwIp & aryIpInfo[i].dwMask)
						{
							pIpAddr[0] = inet_addr("255.255.255.255") ^ aryIpInfo[i].dwMask;
							pIpAddr[0] |= (aryIpInfo[i].dwIp & aryIpInfo[i].dwMask);
							if (pIpAddr[0] != 0)
							{
								pIpAddr[1] = ntohl(pIpAddr[0]);
								pIpAddr[0] = ntohl(aryIpInfo[i].dwIp & aryIpInfo[i].dwMask);
								pIpAddr[2] = (DWORD)pVector;
								hAryThread[i] = CreateThread(NULL, NULL, ScanIpSegmentProc, pIpAddr, NULL, NULL);
							}
						}
					}
				}

				for (i = 0; i < nCount; i++)
				{
					CloseHandle(hAryThread[i]);
				}
			}

			LocalFree(pAdapterBuf);
		}
	}

	return 0;
}

DWORD CollectRemoteConnectIP(CZVector *pVector)
{
	DWORD dwRet = FALSE;
	HMODULE hIphelp = LoadLibraryW(L"iphlpapi.dll");
	if (NULL != hIphelp)
	{
		typedef DWORD(WINAPI *PFNGetExtendedTcpTable)(
			_Out_   PVOID           pTcpTable,
			_Inout_ PDWORD          pdwSize,
			_In_    BOOL            bOrder,
			_In_    ULONG           ulAf,
			_In_    TCP_TABLE_CLASS TableClass,
			_In_    ULONG           Reserved
			);

		PFNGetExtendedTcpTable pfnGetExtendedTcpTable = (PFNGetExtendedTcpTable)GetProcAddress(hIphelp, "GetExtendedTcpTable");
		if (NULL != pfnGetExtendedTcpTable)
		{
			PBYTE pData = new BYTE[0x100000];
			DWORD dwBufSize = 0x100000;
			memset(pData, 0, 0x100000);
			dwRet = pfnGetExtendedTcpTable(pData, &dwBufSize, FALSE, AF_INET, TCP_TABLE_BASIC_CONNECTIONS, 0);
			dwRet = dwRet == 0 ? 1 : 0;
			if (0 != dwRet)
			{
				PMIB_TCPTABLE pTcpTabl = (PMIB_TCPTABLE)pData;
				WCHAR szIp[32] = { 0 };
				for (int i = 0; i < pTcpTabl->dwNumEntries; i++)
				{
					if (MIB_TCP_STATE_ESTAB == pTcpTabl->table[i].State)
					{
						BYTE *pAddr = ((BYTE*)&(pTcpTabl->table[i].dwRemoteAddr));
						wsprintfW(szIp, L"%u.%u.%u.%u", pAddr[0], pAddr[1], pAddr[2], pAddr[3]);
						pVector->AddString(szIp, 0);
					}
				}
			}
			delete[]pData;
		}
		else
		{
			dwRet = GetLastError();
		}

		FreeLibrary(hIphelp);
	}

	return dwRet;
}

BOOL CollectArpIPNet(CZVector *pVector)
{
	BOOL bRet = FALSE;
	ULONG ulSize = 0;
	DWORD dwRet = GetIpNetTable(NULL, &ulSize, FALSE);
	if (ERROR_NO_DATA != dwRet
		&& ERROR_INSUFFICIENT_BUFFER == dwRet)
	{
		PMIB_IPNETTABLE pData = (PMIB_IPNETTABLE)new BYTE[ulSize];
		if (NO_ERROR == GetIpNetTable(pData, &ulSize, FALSE))
		{
			bRet = TRUE;
			WCHAR szIp[32] = { 0 };
			for (int i = 0; i < pData->dwNumEntries; i++)
			{
				BOOL bMark = MIB_IPNET_TYPE_DYNAMIC == pData->table[i].Type ? FALSE : TRUE;
				if (!bMark)
				{
					PBYTE pAddr = (PBYTE)&(pData->table[i].dwAddr);
					wsprintfW(szIp, L"%u.%u.%u.%u", pAddr[0], pAddr[1], pAddr[2], pAddr[3]);
					pVector->AddString(szIp, 0);
				}
			}
		}
		delete[](BYTE*)pData;
	}

	return bRet;
}

DWORD CollectDomainIP(CZVector *pVector, DWORD dwServerType, WCHAR *pDomain)
{
	SERVER_INFO_101 *p101ServerInfo = NULL;
	DWORD dwEntriesread = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;
	BOOL bRet = FALSE;
	NET_API_STATUS nStatus = NetServerEnum(NULL, 101, (PBYTE*)&p101ServerInfo, -1, &dwEntriesread, &dwTotalEntries, dwServerType, pDomain, &dwResumeHandle);

	if ((NERR_Success == nStatus
		|| ERROR_MORE_DATA == nStatus)
		&& (NULL != p101ServerInfo))
	{
		for (int i = 0; i < dwEntriesread; i++)
		{
			if (SV_TYPE_DOMAIN_ENUM != p101ServerInfo->sv101_type)
			{
				CollectDomainIP(pVector, SV_TYPE_WORKSTATION | SV_TYPE_SERVER, p101ServerInfo->sv101_name);
			}
			else
			{
				pVector->AddString(pDomain, 0);
			}
		}
	}

	if (NULL != p101ServerInfo)
	{
		NetApiBufferFree(p101ServerInfo);
	}

	return bRet;
}

DWORD __stdcall CollectAllIPProc(LPVOID pParam)
{
	WCHAR szComputerName[MAX_PATH] = { 0 };
	DWORD dwSize = 0;
	g_pObj1->AddString(L"127.0.0.1", 1);
	g_pObj1->AddString(L"localhost", 1);
	if (GetComputerNameExW(ComputerNamePhysicalNetBIOS, szComputerName, &dwSize))
	{
		g_pObj1->AddString(szComputerName, 1);
	}

	//CloseHandle(CreateThread(NULL, NULL, CollectIPProc, g_pObj1, NULL, NULL));

	BOOL bFirst = TRUE;
	while (TRUE)
	{
		CollectRemoteConnectIP(g_pObj1);
		CollectArpIPNet(g_pObj1);
		if (bFirst)
		{
			CollectDomainIP(g_pObj1, SV_TYPE_DOMAIN_ENUM, NULL);
			bFirst = FALSE;
		}
		Sleep(180000);
	}
	return 0;
}


BOOL x_StrCmpIW_Arrary(WCHAR** pAryData, WCHAR **szBuf)
{
	if (0 == StrCmpIW(pAryData[0], szBuf[0])
		&& 0 == StrCmpW(pAryData[1], szBuf[1]))
	{
		return TRUE;
	}
	return FALSE;
}

void x_HeapFree_Array(WCHAR** pAryData)
{
	if (NULL != pAryData)
	{
		if (NULL != pAryData[0])
		{
			delete[]pAryData[0];
		}

		if (NULL != pAryData[1])
		{
			delete[]pAryData[1];
		}
	}
}

BOOL x_StrCmpIW(WCHAR**str1, WCHAR**str2)
{
	BOOL bRet = FALSE;
	if (NULL != str1
		&& NULL != str2)
	{
		bRet = StrCmpIW((WCHAR*)str1, (WCHAR*)str2) == 0;
	}

	return bRet;
}

int main(int argc, char* argv[])
{
	WSADATA g_wsaData;
	WSAStartup(MAKEWORD(2, 2), &g_wsaData);

	g_pObj1 = new CZVector(0x24, x_StrCmpIW, NULL, 65535);
	g_pObj2 = new CZVector(0x8, x_StrCmpIW_Arrary, x_HeapFree_Array, 255);
	CollectAllIPProc(NULL);
	printf("0x%x", FIONREAD);
	// 	WCHAR **aryData = new WCHAR *[2];
	// 	aryData[0] = new WCHAR[20];
	// 	aryData[1] = new WCHAR[20];
	// 	wcscpy(aryData[0], L"test1");
	// 	wcscpy(aryData[1], L"test444");
	// 
	// 
	// 	WCHAR **aryData2 = new WCHAR *[2];
	// 	aryData2[0] = new WCHAR[20];
	// 	aryData2[1] = new WCHAR[20];
	// 	wcscpy(aryData2[0], L"xxxxx");
	// 	wcscpy(aryData2[1], L"zzzzzz");
	// 	vec.AddData(aryData, 0);
	// 	vec.AddData(aryData2, 0);


	return 0;
}