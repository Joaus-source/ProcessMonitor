#include"ProcessMonitor.h"

KSPIN_LOCK SpinLock;
KIRQL kIrq;

pMyGetPack QueueNodeCreate(int pathLength,PWCHAR Path,int key,PKEVENT event)
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
	if (key!=0) {
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
