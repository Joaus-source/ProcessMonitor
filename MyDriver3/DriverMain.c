
#include "ProcessMonitor.h"

//定义的ioctl控制码
#define IOCTL1 CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_GET CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_SET CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_ANY_ACCESS)
typedef struct _DEVICE_EXTENSION {
	UNICODE_STRING SymLinkName;	//我们定义的设备扩展里只有一个符号链接名成员
} DEVICE_EXTENSION, * PDEVICE_EXTENSION;


NTSTATUS NTAPI MyNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
	//判断要打开的进程ID是不是我们要保护的进程
	if (ClientId->UniqueProcess == (HANDLE)ProtectProcessID)
		return STATUS_ACCESS_DENIED;//返回“拒绝访问”错误
	//不是我们要保护的进程，定义一个函数指针 _NtOpenProcess ,根据 oldNtOpenProcess 记录的真实函数的地址进行 Call
	//也就是说其他进程直接交还给系统的 NtOpenProcess 处理
	typedef NTSTATUS(NTAPI* _NtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	_NtOpenProcess _oldNtOpenProcess = (_NtOpenProcess)oldNtOpenProcess;
	return _oldNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

BOOLEAN IsExe(HANDLE FileHandle)
{
	NTSTATUS status;
	IO_STATUS_BLOCK IoStatus;
	LARGE_INTEGER ByteOffset = { 0 };
	//申请内存，读入文件头部，根据exe文件头部的属性判断是exe还是DLL
	PCHAR pFile = ExAllocatePoolWithTag(NonPagedPool, 0x200, MEM_TAG);
	if (pFile != NULL) {
		status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatus, pFile, 0x200, &ByteOffset, NULL);
		if (NT_SUCCESS(status)) {
			int AddressOfExeHeader = *(int*)(pFile + 0x3c);
			DbgPrint("address of exe header : %d", AddressOfExeHeader);
			USHORT Characteristics = *(USHORT*)(pFile + AddressOfExeHeader+0x16);
			DbgPrint("address of Characteristics : %d", Characteristics);
			if (Characteristics & 0x2000) {
				DbgPrint("this is DLL");
			}
			else {
				DbgPrint("this is exe");
				ExFreePool(pFile);
				return TRUE;
			}
		}
		ExFreePool(pFile);
	}
	return FALSE;
}
BOOLEAN MyCheckUnknowMode(UNICODE_STRING FileName,HANDLE hFile)
{
	pMyGetPack node;
	KEVENT event;
	if (wcsstr(FileName.Buffer, userMode) != NULL)
	{
		return TRUE;
	}
	KeInitializeEvent(&event, SynchronizationEvent, FALSE);

	node = QueueNodeCreate(FileName.Length,FileName.Buffer,(int)hFile,&event);
	if (node == NULL) {
		return FALSE;
	}
	InsertQueue(WaitQueueHead, node);
	KeSetEvent(&waitlistevent,0, FALSE);
	KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, 0);
	if (node->action == ALWAYS_DENY || node->action == DENY) {
		return FALSE;
	}
	return TRUE;

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
					DbgPrint("caller : %d ->FilePath: %ws\r\n",PsGetCurrentProcessId(), FilePath->Name.Buffer);
					if (IsExe(FileHandle)) {	////检测exe文件的加载
						if (!MyCheckUnknowMode(FilePath->Name,FileHandle)) {
							*SectionHandle = NULL;
							ExFreePool(FilePath);
							ObDereferenceObject(FileObject);
							return STATUS_ACCESS_DENIED;
						}
					}

					ExFreePool(FilePath);// IoQueryFileDosDeviceName 获取的 OBJECT_NAME_INFORMATION 需要手动释放
				}
				else DbgPrint("E: IoQueryFileDosDeviceName failed with code 0x%X\r\n", status);
				ObDereferenceObject(FileObject);//使获取到的 FileObject 引用计数减1
			}
			else DbgPrint("E: ObReferenceObjectByHandle failed with code 0x%X\r\n", status);
		}
		else DbgPrint("E: FileHandle is NULL.\r\n");
	}
 
	//定义一个函数指针 _NtCreateSection, 根据 oldNtCreateSection 记录的真实函数的地址进行 Call
	//也就是说其他进程直接交还给系统的 NtCreateSection 处理
	typedef NTSTATUS(NTAPI * _NtCreateSection)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
		PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
	_NtCreateSection _oldNtCreateSection = (_NtCreateSection)oldNtCreateSection;
 
	return _oldNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);

}
VOID Hook(DWORD32 TargetFunction, ULONG* realAddr,DWORD32 myFunction)
{
	PageProtectClose();
	//得到原来的地址，记录在 oldNtOpenProcess
	oldAddr = KeServiceDescriptorTable->ServiceTableBase[SYSTEMCALL_INDEX(TargetFunction)];
	//修改SSDT中 NtOpenProcess 的地址，使其指向 MyNtOpenProcess
	(ULONG)(*realAddr) = oldAddr;
	KeServiceDescriptorTable->ServiceTableBase[SYSTEMCALL_INDEX(TargetFunction)] = myFunction;
	DbgPrint("Old Addr：0x%X\r\n", oldAddr);
	PageProtectOpen();
}

VOID UnHook(DWORD32 TargetFunction, DWORD32 realAddr)
{
	PageProtectClose();
	//修改SSDT中 NtOpenProcess 的地址，使其指向 oldNtOpenProcess
	//也就是在驱动卸载时恢复原来的地址
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
//启用页面保护
void PageProtectOpen()
{
	__asm {
		mov eax, cr0
		or eax, 10000h
		mov cr0, eax
		sti
	}
}
//关闭页面保护
NTSTATUS MyIOgetCTL(PIRP pIrp,ULONG out_size)
{
	pMyGetPack node;
	ULONG packLength;
	PVOID buffer = pIrp->AssociatedIrp.SystemBuffer;
	while((node = GetQueue(WaitQueueHead, 0))==WaitQueueHead)
	{
		KeWaitForSingleObject(&waitlistevent, Executive, KernelMode, FALSE, 0);
	}
	
	packLength = sizeof(MyGetPack);
	if (packLength < out_size)
	{
		InsertQueue(WaitQueueHead, node);
		pIrp->IoStatus.Status = STATUS_INVALID_BUFFER_SIZE;
		pIrp->IoStatus.Information = packLength;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
		return pIrp->IoStatus.Status;
	}
	InsertQueue(DealingQueueHead, node);
	memcpy(buffer, node, sizeof(MyGetPack));
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = packLength;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS MyIOsetCTL(PIRP pIrp,ULONG in_size)
{
	pMyGetPack node;
	ULONG packLength = sizeof(MySetPack);
	pMySetPack SetPack = (pMySetPack)pIrp->AssociatedIrp.SystemBuffer;
	if (in_size < sizeof(MySetPack))
	{
		pIrp->IoStatus.Status = STATUS_INVALID_BUFFER_SIZE;
		pIrp->IoStatus.Information = packLength;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
		return pIrp->IoStatus.Status;
	}
	node = GetQueue(DealingQueueHead, SetPack->key);
	node->action = SetPack->action;
	InsertQueue(CompleteQueueHead, node);
	KeSetEvent(node->pEvent, 0, FALSE);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	DbgPrint("DriverEntry\r\n");

	pDriverObject->DriverUnload = DriverUnload;//注册驱动卸载函数

	//注册派遣函数
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DefDispatchRoutine;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DefDispatchRoutine;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoctlDispatchRoutine;

	NTSTATUS status;
	PDEVICE_OBJECT pDevObj;
	PDEVICE_EXTENSION pDevExt;

	//创建设备名称的字符串
	UNICODE_STRING devName;
	RtlInitUnicodeString(&devName, L"\\Device\\MySSDTHookDevice");

	//创建设备
	pDevObj = NULL;
	status = IoCreateDevice(pDriverObject, sizeof(DEVICE_EXTENSION), &devName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDevObj);
	if (!NT_SUCCESS(status))
		return status;

	pDevObj->Flags |= DO_BUFFERED_IO;//将设备设置为缓冲设备
	pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;//得到设备扩展

	//创建符号链接
	UNICODE_STRING symLinkName;
	RtlInitUnicodeString(&symLinkName, L"\\??\\MySSDTHookDevice_link");
	pDevExt->SymLinkName = symLinkName;
	status = IoCreateSymbolicLink(&symLinkName, &devName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDevObj);
		return status;
	}
	//初始化队列
	WaitQueueHead = QueueNodeCreate(0, NULL, 0,NULL);
	_asm {
		int 3
	}
	DealingQueueHead = QueueNodeCreate(0, NULL, 0,NULL);
	CompleteQueueHead = QueueNodeCreate(0, NULL, 0, NULL);
	KeInitializeEvent(&waitlistevent, SynchronizationEvent, FALSE);
	//Hook SSDT
	Hook((DWORD32)ZwOpenProcess,&oldNtOpenProcess,(DWORD32)MyNtOpenProcess);
	Hook((DWORD32)ZwCreateSection, &oldNtCreateSection, (DWORD32)MyZwCreateSection);
	return STATUS_SUCCESS;
}



DRIVER_UNLOAD DriverUnload;
VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UnHook((DWORD32)ZwOpenProcess,oldNtOpenProcess);
	UnHook((DWORD32)ZwCreateSection, oldNtCreateSection);
	QueueRealse(WaitQueueHead);
	QueueRealse(DealingQueueHead);
	QueueRealse(CompleteQueueHead);
	PDEVICE_OBJECT pDevObj;
	pDevObj = pDriverObject->DeviceObject;

	PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;//得到设备扩展

	//删除符号链接
	UNICODE_STRING pLinkName = pDevExt->SymLinkName;
	IoDeleteSymbolicLink(&pLinkName);

	//删除设备
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

	//得到I/O堆栈的当前这一层，也就是IO_STACK_LOCATION结构的指针
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);

	ULONG in_size = stack->Parameters.DeviceIoControl.InputBufferLength;//得到输入缓冲区的大小
	ULONG out_size = stack->Parameters.DeviceIoControl.OutputBufferLength;//得到输出缓冲区的大小

	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;//得到控制码

	PVOID buffer = pIrp->AssociatedIrp.SystemBuffer;//得到缓冲区指针

	switch (code)
	{
	case IOCTL1:
		DbgPrint("Get ioctl code Process Protect\r\n");

		//用 RtlInitUnicodeString 将用户发送的 wchar_t* 封装成 UNICODE_STRING
		UNICODE_STRING temp;
		RtlInitUnicodeString(&temp, (PWSTR)buffer);
		//转换成 Unsigned Long 类型，这就是我们要保护的进程
		RtlUnicodeStringToInteger(&temp, 0, &ProtectProcessID);
		DbgPrint("ProtectProcessID: %u\r\n", ProtectProcessID);
		break;
	case IOCTL_GET:
		return MyIOgetCTL(pIrp,out_size);//通知用户程序需要判断某一模块
		
	case IOCTL_SET:
		return MyIOsetCTL(pIrp,in_size);//用户程序判断结束，通知驱动层
	default:
		status = STATUS_INVALID_VARIANT;
		//如果是没有处理的IRP，则返回STATUS_INVALID_VARIANT，这意味着用户模式的I/O函数失败，但并不会设置GetLastError
	}

	// 完成IRP
	pIrp->IoStatus.Status = status;//设置IRP完成状态，会设置用户模式下的GetLastError
	pIrp->IoStatus.Information = 0;//设置操作的字节
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);//完成IRP，不增加优先级
	return status;
}


pMyGetPack QueueNodeCreate(USHORT pathLength, PWCHAR Path, int key, PKEVENT event)
{
	pMyGetPack Queuenode = ExAllocatePoolWithTag(NonPagedPool, sizeof(MyGetPack), MEM_TAG);
	if (Queuenode != NULL) {
		QueueHeadInit(Queuenode);
		Queuenode->key = key;
		Queuenode->pathLength = pathLength;
		Queuenode->pEvent = event;
		Queuenode->action = ALWAYS_ALLOW;
		if (Path != NULL) {
			memcpy(Queuenode->Path, Path, 100);
		}
	}
	return Queuenode;
}
VOID QueueNodeRealse(pMyGetPack QueueNode)
{
	if (QueueNode != NULL)
	{
		ExFreePool(QueueNode);
	}
}

VOID QueueRealse(pMyGetPack QueueHead)
{
	pMyGetPack pre;
	pMyGetPack now;
	if (QueueHead == NULL) {
		return;
	}
	pre = QueueHead->prev;
	while (pre != QueueHead)
	{
		now = pre->prev;
		ExFreePool(pre);
		pre = now;
	}
	QueueNodeRealse(QueueHead);
}
VOID QueueHeadInit(pMyGetPack InitQueueHead)
{
	//初始化队列头部
	InitQueueHead->prev = InitQueueHead;
	InitQueueHead->next = InitQueueHead;
}
VOID InsertQueue(pMyGetPack QueueHead, pMyGetPack InsertPack)
{
	// 将节点插入队列尾部
	pMyGetPack pre;
	KeInitializeSpinLock(&SpinLock);
	KeAcquireSpinLock(&SpinLock, &kIrq);
	pre = QueueHead->prev;
	QueueHead->prev = InsertPack;
	InsertPack->prev = pre;
	pre->next = InsertPack;
	InsertPack->next = QueueHead;
	KeReleaseSpinLock(&SpinLock, kIrq);
}
pMyGetPack GetQueue(pMyGetPack QueueHead, int key)
{
	//从队列中获得某一个节点，
	//key=0，直接从头部获取
	//key！=0，就获取对应的节点
	pMyGetPack now;
	pMyGetPack pre;
	pMyGetPack next;
	KeInitializeSpinLock(&SpinLock);
	KeAcquireSpinLock(&SpinLock, &kIrq);
	if (key != 0) {
		now = QueueHead->next;
		while (now != QueueHead) {
			if (key == now->key) {
				pre = now->prev;
				next = now->next;
				pre->next = next;
				next->prev = pre;
				now->prev = now->next = now;
				break;
			}
			now = now->next;
		}
		if (now == QueueHead) {
			now = NULL;
		}
	}
	else
	{
		now = QueueHead->next;
		pre = now->prev;
		next = now->next;
		pre->next = next;
		next->prev = pre;
		now->prev = now->next = now;
	}
	KeReleaseSpinLock(&SpinLock, kIrq);
	return now;
}

