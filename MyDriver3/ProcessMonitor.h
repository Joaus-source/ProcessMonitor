#pragma once
#include <ntifs.h>
#include <ntddk.h>

VOID DriverUnload(PDRIVER_OBJECT pDriverObject);
NTSTATUS DefDispatchRoutine(PDEVICE_OBJECT pDevObj, PIRP pIrp);
NTSTATUS IoctlDispatchRoutine(PDEVICE_OBJECT pDevObj, PIRP pIrp);
VOID Hook(DWORD32 TargetFunction, ULONG* realAddr,DWORD32 myFunction);
VOID UnHook(DWORD32 TargetFunction, DWORD32 realAddr);

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
//根据 ZwXXXX的地址 获取服务函数在 SSDT 中所对应的服务的索引号
#define SYSTEMCALL_INDEX(ServiceFunction) (*(PULONG)((PUCHAR)ServiceFunction + 1))

ULONG oldNtOpenProcess = 0;//之前的NtOpenProcess
ULONG oldAddr = 0;
ULONG ProtectProcessID = 0;//要保护的进程ID
ULONG oldNtCreateSection = 0;//之前的NtCreateSection

//KeServiceDescriptorTable 中我们感兴趣的结构
typedef struct _KESERVICE_DESCRIPTOR_TABLE
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG NumberOfServices;
	PUCHAR ParamTableBase;
}KESERVICE_DESCRIPTOR_TABLE, * PKESERVICE_DESCRIPTOR_TABLE;

//ntoskrnl.exe (ntoskrnl.lib) 导出的 KeServiceDescriptorTable
extern PKESERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;
