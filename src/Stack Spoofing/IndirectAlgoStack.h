#pragma once

__forceinline DWORD getFreshyCallSSN(ULONG_PTR NtDllAddr, EXPORT_TABLES ntdllExports, const char* FuncName) {

	Freshy_Entry SyscallTable[500];		// สร้าง struct เก็บชื่อและเลข SSN ที่ sorted แล้ว
	Freshy_Entry TempTable;				// struct ชั่วคราวสำหรับใช้ตอนย้ายเข้า SyscallTable
	int SyscallCount{ 0 };				// เอาไว้นับจำนวน Native API ในขั้นตอนค้นหา

	for (int i = 0; i < ntdllExports.dwNumberOfNames; i++) {

		// Base Address + AddressOfName ในดัชนีลำดับที่ n [i]
		// szFuncName มีรายชื่อ Function ทั้งหมดมาเก็บไว้แล้ว
		auto szFuncName = reinterpret_cast<char*>(NtDllAddr + ntdllExports.pdwAddressOfNames[i]);

		// เริ่มต้น Freshy Call SSN check
		PBYTE pByteAddr = reinterpret_cast<PBYTE>(szFuncName);
		if (pByteAddr == NULL) return -1;

		if ((pByteAddr[0] == 'Z' && pByteAddr[1] == 'w')) {

			WORD wOrdinal = ntdllExports.pwAddressOfNameOrdinals[i];

			DWORD dwFuncRVA = ntdllExports.pdwAddressOfFunctions[wOrdinal];

			ULONG_PTR uiFuncAddr = NtDllAddr + dwFuncRVA;

			SyscallTable[SyscallCount].FuncName = szFuncName;
			SyscallTable[SyscallCount].FuncAddress = uiFuncAddr;

			SyscallCount++;
		}
	}

	// - 1 เพื่อ ลดรอบการสลับ เช่น มี 10 ลำดับ (A-J แบบมั่วตำแหน่ง) สลับ J ไปท้ายสุดเสร็จ ก็ตัด J ออกจาก loop 
	// 
	// - i - 1 เพื่อลดรอบการสลับ และ ป้องกันเดินเลยขนาดของ memory 
	for (int i = 0; i < SyscallCount - 1; i++) {
		for (int j = 0; j < SyscallCount - i - 1; j++) {

			auto currentAddr = SyscallTable[j].FuncAddress;
			auto nextAddr = SyscallTable[j + 1].FuncAddress;

			if (currentAddr > nextAddr) {

				// A -> Temp
				TempTable = SyscallTable[j];

				// B -> A
				SyscallTable[j] = SyscallTable[j + 1];

				// Temp -> B
				SyscallTable[j + 1] = TempTable;
			}
		}
	}
	for (int i = 0; i < SyscallCount; i++) {
		if (ManualStrCmp((const char*)SyscallTable[i].FuncName + 2, FuncName + 2)) {

			return i;
		}
	}
	return 0;
}