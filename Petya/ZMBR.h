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
	unsigned char BootSign;        // 引导标志  
	unsigned char StartHsc[3];      // 分区的起始磁头号、扇区号、柱面号  
	unsigned char PartitionType;    // 分区类型  
	unsigned char EndHsc[3];       // 分区的结束磁头号、扇区号、柱面号  
	DWORD SectorsPreceding;      // 本分区之前使用的扇区数  
	DWORD SectorsInPartition;     // 分区的总扇区数  
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