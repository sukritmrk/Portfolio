#pragma once
#include <Windows.h>
#include <iostream>

using namespace std;

// Macro
#define NTSTATUS LONG               // นิยาม NTSTATUS เป็น Long
#define NTAPI __stdcall             // อันนี้ไม่มีไร นิยาม calling convention เผื่อเรา built เป็น x32 

// ไอ้นี้คือ struct มีไว้เพื่อเป็นกล่องคุม String ระดับ Kernel ที่ไม่พึ่งพา \0 
// แต่บอกความยาวจริงมาให้ (หรือ Length) พร้อมพิกัดชี้ตัวอักษรในแรม (pBuffer)" 
typedef struct _UNICODE_STR {
    USHORT Length;          // ความยาวของข้อความจริง หน่วยเป็น Byte
    USHORT MaximumLength;   // ขนาดรวมของพื้นที่ Buffer ที่จองไว้ หน่วยเป็น Byte
    ULONG Padding;          // ตัวคั่นข้อมูล ใช้จัดเรียง Memory Alignment
    PWSTR pBuffer;          // ตัวชี้ Pointer ไปยังข้อความจริงในหน่วยความจำ;
} UNICODE_STR, * PUNICODE_STR;

typedef struct _LDR_DATA_TABLE_ENTRY_CUSTOM {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID      DllBase;
	PVOID      EntryPoint;
	ULONG      SizeOfImage;
	UNICODE_STR FullDllName;
	UNICODE_STR BaseDllName;
} LDR_DATA_TABLE_ENTRY_CUSTOM, * PLDR_DATA_TABLE_ENTRY_CUSTOM;

typedef struct _EXPORT_TABLES {
	PIMAGE_EXPORT_DIRECTORY pExportDir;
	PDWORD pdwAddressOfNames;
	PWORD  pwAddressOfNameOrdinals;
	PDWORD pdwAddressOfFunctions;
	DWORD  dwNumberOfNames;
} EXPORT_TABLES, * PEXPORT_TABLES;

struct GadgetDetail {
	PBYTE VA;
	DWORD SizeOfRawData;
};

// Struct ของการทำ Freshy Call
struct Freshy_Entry {
	char* FuncName;
	DWORD FuncAddress;
};

// --- Function Prototypes ---

BOOL ManualStrCmp(const char* s1, const char* s2);
BOOL IsNtDll(PWSTR dllName);
ULONG_PTR getNtdllBase();
PIMAGE_NT_HEADERS64 getNtHeader(ULONG_PTR NtDllAddr);
BOOL findTextSection(PIMAGE_NT_HEADERS64 pNtHeader, ULONG_PTR BaseAddr, GadgetDetail& findGadgetBox);
PBYTE findGadget(GadgetDetail& findGadgetBox);
BOOL getExportTables(ULONG_PTR uiBaseAddr, PIMAGE_NT_HEADERS64 pNtHeader, PEXPORT_TABLES pOutTables);

// --- Stub Assembly ---

extern "C" NTSTATUS NtAllocate(
    HANDLE ProcessHandle,       // RCX        (Arg 1)
    PVOID* BaseAddress,         // RDX        (Arg 2)
    ULONG_PTR ZeroBits,         // R8         (Arg 3)
    PSIZE_T RegionSize,         // R9         (Arg 4)
    ULONG AllocationType,       // [RSP+0x28] (Arg 5)
    ULONG Protect,              // [RSP+0x30] (Arg 6)
    DWORD SSN,                  // [RSP+0x38] (Arg 7 | Key 1)
    PVOID SyscallGadget,        // [RSP+0x40] (Arg 8 | Key 2)
    PVOID TrampolineGadget      // [RSP+0x48] (Arg 9 | Key 3)
);

extern "C" NTSTATUS NtWrite(
    HANDLE ProcessHandle,       // RCX        (Arg 1)
    PVOID BaseAddress,          // RDX        (Arg 2)
    PVOID Buffer,               // R8         (Arg 3)
    SIZE_T NumberOfBytesToWrite,// R9         (Arg 4)
    PSIZE_T NumberOfBytesWritten,// [RSP+0x28] (Arg 5)
    DWORD SSN,                  // [RSP+0x30] (Arg 6 | Key 1)
    PVOID SyscallGadget,        // [RSP+0x38] (Arg 7 | Key 2)
    PVOID TrampolineGadget      // [RSP+0x40] (Arg 8 | Key 3)
);

extern "C" NTSTATUS NtProtect(
    HANDLE ProcessHandle,       // RCX        (Arg 1)
    PVOID* BaseAddress,         // RDX        (Arg 2)
    PSIZE_T RegionSize,         // R8         (Arg 3)
    ULONG NewProtection,        // R9         (Arg 4)
    PULONG OldProtection,       // [RSP+0x28] (Arg 5)
    DWORD SSN,                  // [RSP+0x30] (Arg 6 | Key 1)
    PVOID SyscallGadget,        // [RSP+0x38] (Arg 7 | Key 2)
    PVOID TrampolineGadget      // [RSP+0x40] (Arg 8 | Key 3)
);

extern "C" NTSTATUS NtCreate(
    PHANDLE hThread,            // RCX        (Arg 1)
    DWORD AccessMask,           // RDX        (Arg 2)
    PVOID ObjAttrbt,            // R8         (Arg 3)
    HANDLE ProcessHandle,       // R9         (Arg 4)
    PVOID lpStartAddress,       // [RSP+0x28] (Arg 5)
    PVOID lpParameter,          // [RSP+0x30] (Arg 6)
    ULONG Flags,                // [RSP+0x38] (Arg 7)
    SIZE_T StackZeroBits,       // [RSP+0x40] (Arg 8)
    SIZE_T SizeOfStackCommit,   // [RSP+0x48] (Arg 9)
    SIZE_T SizeOfStackReserve,  // [RSP+0x50] (Arg 10)
    PVOID lpBytesBuffer,        // [RSP+0x55] (Arg 11)
    DWORD SSN,                  // [RSP+0x60] (Arg 12 | Key 1)
    PVOID SyscallGadget,        // [RSP+0x68] (Arg 13 | Key 2)
    PVOID TrampolineGadget      // [RSP+0x70] (Arg 14 | Key 3)
);