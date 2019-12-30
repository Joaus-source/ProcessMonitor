#pragma once
#include <ntifs.h>
#include <ntddk.h>

VOID DriverUnload(PDRIVER_OBJECT pDriverObject);
NTSTATUS DefDispatchRoutine(PDEVICE_OBJECT pDevObj, PIRP pIrp);
NTSTATUS IoctlDispatchRoutine(PDEVICE_OBJECT pDevObj, PIRP pIrp);
VOID Hook(DWORD32 TargetFunction, ULONG* realAddr,DWORD32 myFunction);
VOID UnHook(DWORD32 TargetFunction, DWORD32 realAddr);
/*
实现只针对exe创建进程的通知，暂时放过DLL的加载；

实现等待队列和处理队列
实现队列操作的同步
*/

BOOLEAN IsExe(HANDLE FileHandle);
BOOLEAN MyCheckUnknowMode(UNICODE_STRING FileName,HANDLE hFile);
void PageProtectClose();
void PageProtectOpen();
//我们将 NtOpenProcess hook 到自己的函数
NTSTATUS NTAPI MyNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
NTSTATUS NTAPI MyZwCreateSection(
	PHANDLE            SectionHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER     MaximumSize,
	ULONG              SectionPageProtection,
	ULONG              AllocationAttributes,
	HANDLE             FileHandle
);
NTSTATUS MyIOgetCTL(PIRP pIrp,ULONG out_size);
NTSTATUS MyIOsetCTL(PIRP pIrp,ULONG in_size);

//根据 ZwXXXX的地址 获取服务函数在 SSDT 中所对应的服务的索引号
#define SYSTEMCALL_INDEX(ServiceFunction) (*(PULONG)((PUCHAR)ServiceFunction + 1))
#define MEM_TAG "pTAG"

PWCHAR userMode = L"ProcessMonitor_usermode.exe";
ULONG oldNtOpenProcess = 0;//之前的NtOpenProcess
ULONG oldAddr = 0;
ULONG ProtectProcessID = 0;//要保护的进程ID
ULONG oldNtCreateSection = 0;//之前的NtCreateSection
KEVENT waitlistevent;
KEVENT dealingListEvent;
KSPIN_LOCK SpinLock;
KIRQL kIrq;



//KeServiceDescriptorTable 中我们感兴趣的结构
typedef struct _KESERVICE_DESCRIPTOR_TABLE
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG NumberOfServices;
	PUCHAR ParamTableBase;
}KESERVICE_DESCRIPTOR_TABLE, * PKESERVICE_DESCRIPTOR_TABLE;

#define ALLOW 1
#define ALWAYS_ALLOW 2
#define DENY 3
#define ALWAYS_DENY 4
int action;
typedef struct GETpack
{
	struct GETpack* prev;
	struct GETpack* next;
	int key;
	int pathLength;
	PKEVENT pEvent;
	int action;
	WCHAR Path[100];
}MyGetPack,*pMyGetPack;//通知应用层的数据

typedef struct SETpack
{
	int key;
	int action;//从应用层接受到的数据
}MySetPack,*pMySetPack;
pMyGetPack WaitQueueHead;
pMyGetPack DealingQueueHead;
pMyGetPack CompleteQueueHead;
pMyGetPack QueueNodeCreate(USHORT pathLength, PWCHAR Path, int key,PKEVENT pEvent);
VOID QueueRealse(pMyGetPack QueueHead);
VOID QueueHeadInit(pMyGetPack InitQueueHead);
VOID InsertQueue(pMyGetPack QueueHead,pMyGetPack InsertPack);
pMyGetPack GetQueue(pMyGetPack QueueHead,int key);


//ntoskrnl.exe (ntoskrnl.lib) 导出的 KeServiceDescriptorTable
extern PKESERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;
