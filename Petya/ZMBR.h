#pragma once
#include "Global.h"

#define DPTNUMBER 4  
#define BOOTRECORDSIZE 440  
#define DPTSIZE 64  

typedef struct _BOOTRECORD
{
	unsigned char BootRecord[BOOTRECORDSIZE];
}BOOTRECORD, *PBOOTRECORD;

typedef struct _DPT
{
	unsigned char Dpt[DPTSIZE];
}DPT, *PDPT;

typedef struct _DP
{
	unsigned char BootSign;        // ������־  
	unsigned char StartHsc[3];      // ��������ʼ��ͷ�š������š������  
	unsigned char PartitionType;    // ��������  
	unsigned char EndHsc[3];       // �����Ľ�����ͷ�š������š������  
	DWORD SectorsPreceding;      // ������֮ǰʹ�õ�������  
	DWORD SectorsInPartition;     // ��������������  
}DP, *PDP;

typedef struct _MBR
{
	BOOTRECORD BootRecord;
	unsigned char ulSigned[4];
	unsigned char sReserve[2];
	DP  Dpt[4];
	unsigned char EndSign[2];
}MBR, *PMBR;

DWORD GetSystemDirectoryDeviceID(char *pszOut);

DWORD GetVolumeStartOffset(char *pszDeviceIdPath, DWORD &dwStartOffset);

DWORD Read512Data(char *pszDeviceIdPath, BYTE *pOut);

DWORD WriteDiskData(DWORD dwSectorIndex, char *pszDeviceIdPath, BYTE *pWriteData);

void OverlayMBR();

DWORD _OverlayMBR();

BOOL ClearMBR();