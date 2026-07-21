#pragma once

/*__forceinline BOOL IsTargetSection(const BYTE* sectionName, const char* target) {
	for (int i = 0; i < 6; i++) {

		if (target[i] == '\0') {
			return TRUE;
		}

		if (sectionName[i] != (BYTE)target[i]) {
			return FALSE;
		}
	}
	return TRUE;
}*/

__forceinline BOOL ManualStrCmp(const char* s1, const char* s2) {

	// อันนี้ไม่มีไร แค่เทียบ String แบบ char (1 byte) กันไปเลยว่า เป็นตัวเดียวกันไหม
	// *s1 คือ *s1 != \0 แค่เขียนลดรูป ASCII ไม่เป็น 0 แค่นี้มันก็จะเป็น true แล้ว
	// *s1 = *s2 ตรงงตัว ถ้ามันเป็นอักษรเดียวกันใน ASCII ก็เป็น True
	while (*s1 && (*s1 == *s2)) {
		s1++; s2++;
	}
	// ถ้าเลข ASCII ของทั้งหมดเป็นตัวเดียวกัน เอามา - กันต้องได้ 0 
	return *(unsigned char*)s1 - *(unsigned char*)s2 == 0;	// 0 = TRUE เป็นจริง
}

__forceinline BOOL IsNtDll(PWSTR dllName) {
	if (dllName == nullptr) {
		return false;
	}

	wchar_t ntdll[] = { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', 0 };

	// สร้าง indext "i" มาเพื่อใช้เป็นล้อเคลื่อนที่หาคำว่า ntdll.dll 
	int i = 0;
	while (dllName[i] != L'\0' && ntdll[i] != L'\0') {
		wchar_t c1 = dllName[i];
		wchar_t c2 = ntdll[i];

		// อันนี้เรามาตรวจก่อนว่า Case Sensitive ไหม ถ้าจุดนี้เราหา c1 เป็นอะไรมาไม่รู้
		// เราก็ไปต่อไม่ได้ function จะคายทิ้งเป็น Error กลับไปทันที
		// ถ้าเป็น upper-case ก็ +32 เพื่อให็เป็น lower-case
		if (c1 >= L'A' && c1 <= L'Z') c1 += 32;
		if (c2 >= L'A' && c2 <= L'Z') c2 += 32;

		// เช็คว่า ตัวอักษรนั้น ใน i ของทั้งคู่เป็นตัวเดียวกันไหม ถ้าเป็น i++
		if (c1 != c2) { return false; }
		i++;
	}

	// คืนเป็น boolen ว่า Yes เมื่อทั้ง dllName และ ntdll ใน i ขยับถึง \0
	return (dllName[i] == L'\0' && ntdll[i] == L'\0');
}

__forceinline ULONG_PTR getNtdllBase() {

	// เข้าถึง PEB โดยไปที่ 0x60 ของ Loader ตัวเอง
	ULONG_PTR pebAddr = __readgsqword(0x60);

	// + Offset 0x18 เพื่อเจข้าถึง Loader Address
	auto LdrAddr = *reinterpret_cast<ULONG_PTR*>(pebAddr + 0x18);

	// + Offset 0x20 เข้าถึง Header
	auto Head = reinterpret_cast<LIST_ENTRY*>(LdrAddr + 0x20);
	LIST_ENTRY* current = Head->Flink;

	while (current != Head) {

		//ถอยกลับมาที่ InLoadOrderModuleList โดย + 0x10 ตำแหน่ง
		auto pEntry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY_CUSTOM>(
			(PBYTE)current - 0x10);

		// ละเริ่มวนลูปหา ntdll.dll โดยเอาไปเทียบ String ใน IsNtDll
		if (pEntry->BaseDllName.pBuffer != NULL) {
			if (IsNtDll(pEntry->BaseDllName.pBuffer)) {
				return reinterpret_cast<ULONG_PTR>(pEntry->DllBase);
			}
		}
		current = current->Flink;
	}
	return 0;
}

__forceinline PIMAGE_NT_HEADERS64 getNtHeader(ULONG_PTR NtDllAddr) {

	// เข้า DosHeader
	auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(NtDllAddr);
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		cout << "Error: Not a valid DOS Header at the base!" << endl;
	}
	else {
		cout << "pDosHeader is at : 0x" << hex << pDosHeader << endl;
	}

	// เข้าถึง Natvie Header โดยเอา e_lfanew + Native Dll Address เพื่อหา VA ของ NtHeader
	auto pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(pDosHeader->e_lfanew + NtDllAddr);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		cout << "Error: Not a valid NT Header signature!" << endl;
	}
	return pNtHeader;
}

__forceinline BOOL findTextSection(PIMAGE_NT_HEADERS64 pNtHeader, ULONG_PTR BaseAddr, GadgetDetail& findGadgetBox) {
	
	// เอา Native Header มาเก็บไว้ในตัวแปร pSection (ไม่ต้องแปลง เพราะขนาด 8 bytes เท่ากัน)
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeader);

	// ทำ loop i โดย Word คือการเช็คแต่ละ section ไปเรื่อย ๆ เพื่อหา .text
	for (WORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
		if (ManualStrCmp((const char*)pSection[i].Name, ".text")) {

			// หาเจอแล้วก็เอาไปใส่ใน Custom Struct ที่เราเตรีบมไว้ ซี่งนั้นคือ คำนวนให้ได้ VA และขนาดของ .text
			findGadgetBox.VA = (PBYTE)(BaseAddr + pSection[i].VirtualAddress);
			findGadgetBox.SizeOfRawData = pSection[i].Misc.VirtualSize;

			// ถ้าไม่เจอก็ให้ไหลต่อจนกว่าจะเจอ .text
			if (findGadgetBox.VA == NULL) continue;
			
			return TRUE;
		}
	}
	return FALSE;
}

__forceinline BOOL getExportTables(ULONG_PTR NtDllAddr, PIMAGE_NT_HEADERS64 pNtHeader, PEXPORT_TABLES pOutTables) {
	
	// เช็คก่อนด้วย compare ว่า pointer ของทั้ง 2 เป็น 0 ไหม
	if (!pNtHeader || !pOutTables) return false;

	// หา RVA ของ Export Directory ผ่าน OptionalHeader
	DWORD exportDirRVA = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (exportDirRVA == 0) return false;

	// เอา Base Address + RVA ซึ่งเป็น Address ของ Native Dll เพื่อหา VA
	pOutTables->pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(NtDllAddr + exportDirRVA);

	// ทำการดึงเอา Address ทั้งหมด ไปเก็บไว้ใน Struct OutTalbles เพื่อเตรียมหาเลข SSN ต่อไป
	pOutTables->pdwAddressOfNames = reinterpret_cast<PDWORD>(NtDllAddr + pOutTables->pExportDir->AddressOfNames);
	pOutTables->pwAddressOfNameOrdinals = reinterpret_cast<PWORD>(NtDllAddr + pOutTables->pExportDir->AddressOfNameOrdinals);
	pOutTables->pdwAddressOfFunctions = reinterpret_cast<PDWORD>(NtDllAddr + pOutTables->pExportDir->AddressOfFunctions);
	pOutTables->dwNumberOfNames = pOutTables->pExportDir->NumberOfNames;

	return true;
}

__forceinline PBYTE findGadget(GadgetDetail& findGadgetBox) {

	PBYTE pCurrent = findGadgetBox.VA;
	PBYTE pEnd = findGadgetBox.VA + findGadgetBox.SizeOfRawData - 1;
	
	// 0xFF คือกลุ่มของ "Group 5" Extended Instructions ซึ่งใช้สำหรับการทำ JMP / CALL แบบ Indirect
	// 0xE3 (11 100 011 ในฐาน 2) : คือค่า ModR / M Byte	
	// Mod(11) = หมายถึงเรากำลังอ้างอิงถึง Register โดยตรง
	// Reg / Opcode(100) = ในกลุ่ม Group 5 นี่หมายถึงคำสั่ง JMP
	// R / M(011) = รหัสประจำตัวของ RBX Register ใน x64

	// หา jmp rbx (FF E3) หรือ call rbx (FF D3) ก็ได้
	// call rbx เราสำรองไว้เผื่อไปหา Gadget ใน DLL ขนาดเล็กที่ไม่ใช่ kernel32 หรือ ntdll
	while (pCurrent < pEnd) {
		if ((*pCurrent == 0xFF && *(pCurrent + 1) == 0xE3) ||
			(*pCurrent == 0xFF && *(pCurrent + 1) == 0xD3)) {
			return pCurrent;
		}
		pCurrent++;
	}
	return nullptr;
}

__forceinline PBYTE findSyscallGadget(GadgetDetail& findGadgetBox) {

	PBYTE pCurrent = findGadgetBox.VA;
	PBYTE pEnd = findGadgetBox.VA + findGadgetBox.SizeOfRawData - 3; 
	// - 3 เพื่อเมื่อถึงจุดสิ้นสุดของ .text Logic การหาของเราจะได้ไม่หลุดขอบไปอ่านพื้นที่นอก section จน Crash 
	// สมมติ pEnd = 1000 เรา - 3 = 997 หรือก็คือเมื่อถึงตำแหน่ง Byte ที่ 997 โปรแกรมจะหยุดเดิน
	// และอ่านตำแหน่ง 997-998-999 เป็นครั้งสุดท้ายก่อนหลุดจาก Loop เทคนิคนี้ชื่อ "Out-of-bounds Read"

	// หา syscall; (0F, 05) และ ret; (C3)
	while (pCurrent < pEnd) {
		if ((*pCurrent == 0x0F && *(pCurrent + 1) == 0x05 && *(pCurrent + 2) == 0xC3)) {

			return pCurrent;
		}
		pCurrent++;
	}
	return nullptr;
}