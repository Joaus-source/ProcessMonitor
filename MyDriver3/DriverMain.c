
#include "ProcessMonitor.h"

//�����ioctl������
#define IOCTL1 CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)

typedef struct _DEVICE_EXTENSION {
	UNICODE_STRING SymLinkName;	//���Ƕ�����豸��չ��ֻ��һ��������������Ա
} DEVICE_EXTENSION, * PDEVICE_EXTENSION;


NTSTATUS NTAPI MyNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
	//�ж�Ҫ�򿪵Ľ���ID�ǲ�������Ҫ�����Ľ���
	if (ClientId->UniqueProcess == (HANDLE)ProtectProcessID)
		return STATUS_ACCESS_DENIED;//���ء��ܾ����ʡ�����
	//��������Ҫ�����Ľ��̣�����һ������ָ�� _NtOpenProcess ,���� oldNtOpenProcess ��¼����ʵ�����ĵ�ַ���� Call
	//Ҳ����˵��������ֱ�ӽ�����ϵͳ�� NtOpenProcess ����
	typedef NTSTATUS(NTAPI* _NtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	_NtOpenProcess _oldNtOpenProcess = (_NtOpenProcess)oldNtOpenProcess;
	return _oldNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}
#define SEC_IMAGE 0x1000000
NTSTATUS NTAPI MyZwCreateSection(
	PHANDLE            SectionHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER     MaximumSize,
	ULONG              SectionPageProtection,
	ULONG              AllocationAttributes,
	HANDLE             FileHandle
)
{
	if ((AllocationAttributes == SEC_IMAGE) && (SectionPageProtection & PAGE_EXECUTE)){
		if (FileHandle){
			PFILE_OBJECT FileObject;
			NTSTATUS status;
			if ((status = ObReferenceObjectByHandle(FileHandle, 0, NULL, KernelMode, (PVOID*)&FileObject, NULL)) == STATUS_SUCCESS){
				POBJECT_NAME_INFORMATION FilePath;
				if ((status = IoQueryFileDosDeviceName(FileObject, &FilePath)) == STATUS_SUCCESS){
					DbgPrint("FilePath: %ws\r\n", FilePath->Name.Buffer);
					ExFreePool(FilePath);// IoQueryFileDosDeviceName ��ȡ�� OBJECT_NAME_INFORMATION ��Ҫ�ֶ��ͷ�
				}
				else DbgPrint("E: IoQueryFileDosDeviceName failed with code 0x%X\r\n", status);
				ObDereferenceObject(FileObject);//ʹ��ȡ���� FileObject ���ü�����1
			}
			else DbgPrint("E: ObReferenceObjectByHandle failed with code 0x%X\r\n", status);
		}
		else DbgPrint("E: FileHandle is NULL.\r\n");
	}
 
	//����һ������ָ�� _NtCreateSection, ���� oldNtCreateSection ��¼����ʵ�����ĵ�ַ���� Call
	//Ҳ����˵��������ֱ�ӽ�����ϵͳ�� NtCreateSection ����
	typedef NTSTATUS(NTAPI * _NtCreateSection)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
		PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
	_NtCreateSection _oldNtCreateSection = (_NtCreateSection)oldNtCreateSection;
 
	return _oldNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);

}
VOID Hook(DWORD32 TargetFunction, ULONG* realAddr,DWORD32 myFunction)
{
	PageProtectClose();
	//�õ�ԭ���ĵ�ַ����¼�� oldNtOpenProcess
	oldAddr = KeServiceDescriptorTable->ServiceTableBase[SYSTEMCALL_INDEX(TargetFunction)];
	//�޸�SSDT�� NtOpenProcess �ĵ�ַ��ʹ��ָ�� MyNtOpenProcess
	(ULONG)(*realAddr) = oldAddr;
	KeServiceDescriptorTable->ServiceTableBase[SYSTEMCALL_INDEX(TargetFunction)] = myFunction;
	DbgPrint("Old Addr��0x%X\r\n", oldAddr);
	PageProtectOpen();
}

VOID UnHook(DWORD32 TargetFunction, DWORD32 realAddr)
{
	PageProtectClose();
	//�޸�SSDT�� NtOpenProcess �ĵ�ַ��ʹ��ָ�� oldNtOpenProcess
	//Ҳ����������ж��ʱ�ָ�ԭ���ĵ�ַ
	KeServiceDescriptorTable->ServiceTableBase[SYSTEMCALL_INDEX(TargetFunction)] = realAddr;
	PageProtectOpen();
	DbgPrint("UnhookSuccess!->0x%x", realAddr);
}
void PageProtectClose()
{
	__asm {
		cli
		mov eax, cr0
		and eax, not 10000h
		mov cr0, eax
	}
}

//����ҳ�汣��
void PageProtectOpen()
{
	__asm {
		mov eax, cr0
		or eax, 10000h
		mov cr0, eax
		sti
	}
}
//�ر�ҳ�汣��

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	DbgPrint("DriverEntry\r\n");

	pDriverObject->DriverUnload = DriverUnload;//ע������ж�غ���

	//ע����ǲ����
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DefDispatchRoutine;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DefDispatchRoutine;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoctlDispatchRoutine;

	NTSTATUS status;
	PDEVICE_OBJECT pDevObj;
	PDEVICE_EXTENSION pDevExt;

	//�����豸���Ƶ��ַ���
	UNICODE_STRING devName;
	RtlInitUnicodeString(&devName, L"\\Device\\MySSDTHookDevice");

	//�����豸
	pDevObj = NULL;
	status = IoCreateDevice(pDriverObject, sizeof(DEVICE_EXTENSION), &devName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDevObj);
	if (!NT_SUCCESS(status))
		return status;

	pDevObj->Flags |= DO_BUFFERED_IO;//���豸����Ϊ�����豸
	pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;//�õ��豸��չ

	//������������
	UNICODE_STRING symLinkName;
	RtlInitUnicodeString(&symLinkName, L"\\??\\MySSDTHookDevice_link");
	pDevExt->SymLinkName = symLinkName;
	status = IoCreateSymbolicLink(&symLinkName, &devName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDevObj);
		return status;
	}

	//Hook SSDT
	Hook((DWORD32)ZwOpenProcess,&oldNtOpenProcess,(DWORD32)MyNtOpenProcess);

	return STATUS_SUCCESS;
}



DRIVER_UNLOAD DriverUnload;
VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UnHook((DWORD32)ZwOpenProcess,oldNtOpenProcess);
	PDEVICE_OBJECT pDevObj;
	pDevObj = pDriverObject->DeviceObject;

	PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;//�õ��豸��չ

	//ɾ����������
	UNICODE_STRING pLinkName = pDevExt->SymLinkName;
	IoDeleteSymbolicLink(&pLinkName);

	//ɾ���豸
	IoDeleteDevice(pDevObj);
}

NTSTATUS DefDispatchRoutine(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS IoctlDispatchRoutine(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;

	//�õ�I/O��ջ�ĵ�ǰ��һ�㣬Ҳ����IO_STACK_LOCATION�ṹ��ָ��
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);

	ULONG in_size = stack->Parameters.DeviceIoControl.InputBufferLength;//�õ����뻺�����Ĵ�С
	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;//�õ�������

	PVOID buffer = pIrp->AssociatedIrp.SystemBuffer;//�õ�������ָ��

	switch (code)
	{
	case IOCTL1:
		DbgPrint("Get ioctl code Process Protect\r\n");

		//�� RtlInitUnicodeString ���û����͵� wchar_t* ��װ�� UNICODE_STRING
		UNICODE_STRING temp;
		RtlInitUnicodeString(&temp, (PWSTR)buffer);
		//ת���� Unsigned Long ���ͣ����������Ҫ�����Ľ���
		RtlUnicodeStringToInteger(&temp, 0, &ProtectProcessID);
		DbgPrint("ProtectProcessID: %u\r\n", ProtectProcessID);
		break;
	default:
		status = STATUS_INVALID_VARIANT;
		//�����û�д����IRP���򷵻�STATUS_INVALID_VARIANT������ζ���û�ģʽ��I/O����ʧ�ܣ�������������GetLastError
	}

	// ���IRP
	pIrp->IoStatus.Status = status;//����IRP���״̬���������û�ģʽ�µ�GetLastError
	pIrp->IoStatus.Information = 0;//���ò������ֽ�
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);//���IRP�����������ȼ�
	return status;
}

