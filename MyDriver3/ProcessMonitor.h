#pragma once
#include <ntifs.h>
#include <ntddk.h>

VOID DriverUnload(PDRIVER_OBJECT pDriverObject);
NTSTATUS DefDispatchRoutine(PDEVICE_OBJECT pDevObj, PIRP pIrp);
NTSTATUS IoctlDispatchRoutine(PDEVICE_OBJECT pDevObj, PIRP pIrp);
VOID Hook(DWORD32 TargetFunction, ULONG* realAddr,DWORD32 myFunction);
VOID UnHook(DWORD32 TargetFunction, DWORD32 realAddr);
/*
ʵ��ֻ���exe�������̵�֪ͨ����ʱ�Ź�DLL�ļ��أ�

ʵ�ֵȴ����кʹ������
ʵ�ֶ��в�����ͬ��
*/

BOOLEAN IsExe(HANDLE FileHandle);
BOOLEAN MyCheckUnknowMode(UNICODE_STRING FileName,HANDLE hFile);
void PageProtectClose();
void PageProtectOpen();
//���ǽ� NtOpenProcess hook ���Լ��ĺ���
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

//���� ZwXXXX�ĵ�ַ ��ȡ�������� SSDT ������Ӧ�ķ����������
#define SYSTEMCALL_INDEX(ServiceFunction) (*(PULONG)((PUCHAR)ServiceFunction + 1))
#define MEM_TAG "pTAG"

PWCHAR userMode = L"ProcessMonitor_usermode.exe";
ULONG oldNtOpenProcess = 0;//֮ǰ��NtOpenProcess
ULONG oldAddr = 0;
ULONG ProtectProcessID = 0;//Ҫ�����Ľ���ID
ULONG oldNtCreateSection = 0;//֮ǰ��NtCreateSection
KEVENT waitlistevent;
KEVENT dealingListEvent;
KSPIN_LOCK SpinLock;
KIRQL kIrq;



//KeServiceDescriptorTable �����Ǹ���Ȥ�Ľṹ
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
}MyGetPack,*pMyGetPack;//֪ͨӦ�ò������

typedef struct SETpack
{
	int key;
	int action;//��Ӧ�ò���ܵ�������
}MySetPack,*pMySetPack;
pMyGetPack WaitQueueHead;
pMyGetPack DealingQueueHead;
pMyGetPack CompleteQueueHead;
pMyGetPack QueueNodeCreate(USHORT pathLength, PWCHAR Path, int key,PKEVENT pEvent);
VOID QueueRealse(pMyGetPack QueueHead);
VOID QueueHeadInit(pMyGetPack InitQueueHead);
VOID InsertQueue(pMyGetPack QueueHead,pMyGetPack InsertPack);
pMyGetPack GetQueue(pMyGetPack QueueHead,int key);


//ntoskrnl.exe (ntoskrnl.lib) ������ KeServiceDescriptorTable
extern PKESERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;
