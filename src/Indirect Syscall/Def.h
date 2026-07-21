#pragma once
#include <windows.h>
#include <iostream>

using namespace std;

#define NTSTATUS LONG
#define NTAPI __stdcall

typedef struct _UNICODE_STR {
	USHORT Length;
	USHORT MaximumLength;
	ULONG Padding;
	PWSTR pBuffer;
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

// Struct ของการทำ Freshy Call
struct Freshy_Entry {
	char* FuncName;
	DWORD FuncAddress;
};

// --- Function Prototypes ---

BOOL IsNtDll(PWSTR dllName);
BOOL ManualStrCmp(const char* s1, const char* s2);
ULONG_PTR getNtdllBase();
PIMAGE_NT_HEADERS64 getNtHeader(ULONG_PTR NtDllAddr);
BOOL getExportTables(ULONG_PTR uiBaseAddr, PIMAGE_NT_HEADERS64 pNtHeader, PEXPORT_TABLES pOutTables);
ULONG_PTR findGadget(PIMAGE_NT_HEADERS64 pNtHeader, ULONG_PTR uiNtDllAddr);
// --- Algorithm SSN Finder ---
DWORD getHellsGateSSN(ULONG_PTR uiNtDllAddr, EXPORT_TABLES ntdllExports, const char* FuncName);
DWORD getHalosGateSSN(ULONG_PTR uiNtDllAddr, EXPORT_TABLES ntdllExports, PIMAGE_NT_HEADERS64 pNtHeader, const char* FuncName);
DWORD getTartarusGateSSN(ULONG_PTR NtDllAddr, EXPORT_TABLES ntdllExports, PIMAGE_NT_HEADERS64 pNtHeader, const char* FuncName);
DWORD getFreshyCallSSN(ULONG_PTR NtDllAddr, EXPORT_TABLES ntdllExports, const char* FuncName);

// --- Stub Assembly ---

extern "C" NTSTATUS NtAlloc(DWORD dwSSN, ULONG_PTR pGadget, ...);
extern "C" NTSTATUS NtWrite(DWORD dwSSN, ULONG_PTR pGadget, ...);
extern "C" NTSTATUS NtProtect(DWORD dwSSN, ULONG_PTR pGadget, ...);
extern "C" NTSTATUS NtCreate(DWORD dwSSN, ULONG_PTR pGadget, ...);
extern "C" NTSTATUS NtFree(DWORD dwSSN, ULONG_PTR pGadget, ...);