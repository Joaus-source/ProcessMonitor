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
//���� ZwXXXX�ĵ�ַ ��ȡ�������� SSDT ������Ӧ�ķ����������
#define SYSTEMCALL_INDEX(ServiceFunction) (*(PULONG)((PUCHAR)ServiceFunction + 1))

ULONG oldNtOpenProcess = 0;//֮ǰ��NtOpenProcess
ULONG oldAddr = 0;
ULONG ProtectProcessID = 0;//Ҫ�����Ľ���ID
ULONG oldNtCreateSection = 0;//֮ǰ��NtCreateSection

//KeServiceDescriptorTable �����Ǹ���Ȥ�Ľṹ
typedef struct _KESERVICE_DESCRIPTOR_TABLE
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG NumberOfServices;
	PUCHAR ParamTableBase;
}KESERVICE_DESCRIPTOR_TABLE, * PKESERVICE_DESCRIPTOR_TABLE;

//ntoskrnl.exe (ntoskrnl.lib) ������ KeServiceDescriptorTable
extern PKESERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;
