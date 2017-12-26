#pragma once
#include "Global.h"

struct TagIPInfo
{
	DWORD dwIp;
	DWORD dwMask;
};


int CollectLANIP(CZVector *pVector, LPNETRESOURCEW lpNetResource);

BOOL CheckIsServer();

BOOL CollectDhcpClientsIP(CZVector *pVector);

BOOL CheckIpPort(DWORD dwIp, DWORD dwPort);

BOOL CheckPort_445_139(DWORD dwIp);

DWORD CollectRemoteConnectIP(CZVector *pVector);

BOOL CollectArpIPNet(CZVector *pVector);

DWORD CollectDomainIP(CZVector *pVector, DWORD dwServerType, WCHAR *pDomain);

DWORD __stdcall CollectAllIPProc(LPVOID pParam);