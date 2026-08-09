หลังจากที่ได้ทำการ Bypass Userland hooking จาก EDR หรือ Endpoint Detection and Response ด้วยการค้นหาและใช้ SSN และยืมใช้ชุดคำสั่ง `syscall; ret` หรือภาษาในวงการที่เรียกว่า Gadget จากใน `ntdll.dll` เพื่อปลอมแปลงจุดการเรียกใช้ Native API ซึ่งเป็นเขตแดนสุดท้ายระหว่าง Ring 3 และ Ring 0 หรือที่เราเรียกเทคนิคนี้ว่า `Indirect Syscall` 

หากใครยังไม่ได้อ่าน `Indirect Syscall` สามารถอ่านได้ที่ [Indirect Syscall](Indirect%20Syscall.md)

ประเด็นคือ แม้ว่าเราจะสามารถข้ามการป้องกันในชั้น Ring 3 มาได้ แต่ในขณะเดียวกัน EDR และ Microsoft ก็ยังสามารถหาสารพัดวิธีมาป้องกัน Malware ได้ในชั้น Ring 0 หรือ Kernel Level ซึ่งวิธีการหลักที่ว่าคือการป้องกันด้วยสิ่งที่เรียกว่า `ETW-Ti` และ `Stack Walking` 

หาอ่านตัวเต็มได้ที่ [__Main](__Main.md)

### สรุปรวบรัดกลไกการป้องกันที่ `Indirect Syscall` ยังเอาชนะไม่ได้

#### 1. `ETW-Ti`

เมื่อ Kernel Callback เจอเข้ากับ Malware ที่สามารถซ่อนความผิดปกติของตัวเองได้ดีมาก เช่น **`Indirect Syscall`** ที่เราทำกันไป กลไกการตรวจสอบโดยที่ EDR จะเก็บ **`Log Event + Call Stack`** ของคำสั่งของ Process ที่มี Anomalies Behavior เช่น ถูกโหลดมาจากอินเตอร์เน็ต, ถูกส่งมาใน USB Flash drive, ถูกส่งเข้ามาผ่านทาง port network 

เมื่อเกิดคำสั่งที่น่าสงสัยขึ้น `ETW-Ti` Provider ที่เป็นตัวดักจับจะส่งข้อมูลดังกล่าวให้ `ETW-Ti` Session เพื่อผ่านมือส่งไปให้ EDR อีกที EDR ดังกล่าวมี ELAM หรือ Early Launch Anti-Malware Certificate ที่ออกให้โดย Microsoft ทำการตรวจสอบความผิดปกติของคำสั่งดังกล่าว โดยที่ Malware ไม่สามารถแก้ไขหรือดูระหว่างทางได้ สิ่งที่จะถูกตรวจสอบประกอบด้วย

1. Parameter Signature ตรวจจับหาตำแหน่งข้อมูลระดับ Byte ที่เรียงตัวแบบ Malware
2. `NtWriteVirtualMemory` หรือ `NtCreateThreadEx` ที่มีพฤติกรรมเขียนข้อมูลข้าม Process แบบผิดปกติ
3. `NtReadVirtualMemory` โดยเป้าหมายคือ `lsass.exe`
4. Unbacked Memory จากใน RAM หรือ Disk ที่ไม่มีไฟล์ถูกต้องตามระบบรองรับ

หากเข้าข่าย `ETW-Ti` ก็จะส่งข้อมูลไปให้ EDR จัดการตาม Rule ที่เขียนไว้ หรือ เจ้าหน้าที่ที่ดูแลทำการ Terminate Process นั้นทิ้งได้เลย

#### 2.`Stack Walking` 

EDR สมัยใหม่ไม่ได้ดักจับแค่ตอนที่เราพยายามเรียก API เท่านั้น แต่ยังมีการทำ **Heuristic Scan** (การสแกน Malicious Behavior and Pattern) โดยสุ่มตรวจจับภายใน RAM เป็นระยะ ซึ่งถือเป็นกับดักอีกชั้นที่ต้องรับมือ

ทุกครั้งที่โปรแกรมมีการเรียกใช้งานฟังก์ชัน ระบบจะนำ Return Address ไปวางซ้อนกันไว้บน Stack เพื่อให้ CPU รู้ว่าเมื่อทำงานเสร็จแล้วต้องกระโดดกลับไปที่ไหน

การทำ **Stack Walking** คือการที่กลไกของ EDR เดินย้อนรอยลำดับการเรียกฟังก์ชันเหล่านี้บน Stack เพื่อสืบหาต้นตอว่า ใครเป็นคนสั่งรัน API นี้? และเมื่อ EDR เดินสวนทางเพื่อตรวจสอบ Return Address มันจะมองหาความผิดปกติ 2 รูปแบบหลักได้แก่

1. **Unbacked Memory** ปกติแล้วคำสั่งที่ถูกต้องควรจะมาจาก Backed Memory เช่น เรียกมาจาก `kernel32.dll` หรือ `ntdll.dll` โดยตรง แต่ถ้า EDR ย้อนรอยไปแล้วพบว่า Return Address ชี้ไปที่ Memory ลอยๆ ที่เพิ่งถูกจองขึ้นมาใหม่ ซึ่งถือเป็น Unbacked Memory ตัว EDR จะรับรู้ทันทีว่าเป็น Malicious Code และส่งสัญญาณเตือนพร้อมกับ Terminate Process นั้นทิ้งทันที

2. **Code Pattern Analysis** นอกจากการดูที่มาแล้ว EDR ยังสแกนหา Code Pattern ในบริเวณนั้นด้วย หากพบรูปแบบการจัดเรียง Register ที่สลับไปมาผิดปกติเพื่อพยายามทำ Syscalls, รูปแบบการค้นหาตำแหน่ง DLL เบื้องหลัง, หรือการสุ่มเปลี่ยนสิทธิ Protection ของ Memory แบบแปลกๆ ที่ตรงกับฐานข้อมูลพฤติกรรมมัลแวร์ มันก็จะถูกบล็อกเช่นกัน

ด้วยเหตุผลนี้ ต่อให้เราทำ `Indirect Syscall` ได้สำเร็จเพื่อหลบการ Hook แต่ถ้าตอนที่ API กำลังทำงานอยู่ แล้ว EDR แวะมาสแกน Stack พอดี มันก็จะเห็น Return Address ชี้กลับมาที่ Shellcode ของเราอยู่ดี... นี่จึงเป็นเหตุผลบังคับว่า ทำไมเราถึงต้องใช้เทคนิค Stack Spoofing เพื่อสร้าง Call Stack ปลอมขึ้นมาตบตา EDR ก่อนที่จะเรียก API นั่นเอง

### ตัวอย่าง Stack Walking

#### 1. Backed Memory

```[Call Stack - Thread 1024]
00: ntdll.dll!NtAllocateVirtualMemory + 0x14    <-- กำลังรันอยู่ใน Kernel
01: KernelBase.dll!VirtualAlloc + 0x4e          <-- DLL ระบบ
02: Calc.exe!main + 0x8a                        <-- ไฟล์โปรแกรมหลัก
```

### 2. Unbacked Memory

```[Call Stack - Thread 1024]
00: ntdll.dll!NtAllocateVirtualMemory + 0x14    <-- กำลังรันอยู่ใน Kernel
01: KernelBase.dll!VirtualAlloc + 0x4e          <-- DLL ระบบ
02: Calc.exe!main + 0x8a                        <-- ไฟล์โปรแกรมหลัก
```

### 3. Spoofed Stack

```[Call Stack - Thread 4096]
00: ntdll.dll!NtAllocateVirtualMemory + 0x14    <-- กำลังรันอยู่ใน Kernel
01: ntdll.dll!RtlUserThreadStart + 0x21         <-- JMP RBX (Trampoline)
02: kernel32.dll!BaseThreadInitThunk + 0x14     <-- โครงสร้างหลอกที่สร้างไว้
```

### รวมขั้นตอนการทำ `Stack Spoofing` ใน 5 ขั้น

**Step 1: Get NTDLL Base** - หาบ้านเลขที่ของ ntdll.dll

**Step 2: Find Gadgets** - หาประตูมิติ `Syscall` และหน้ากาก JMP RBX

**Step 3: Resolve SSNs** - ใช้ `SSN Resolver Algorithm` ไปสืบเลขรหัสฟังก์ชัน

**Step 4: Allocate Memory** - จองตู้เซฟด้วย `NtAllocateVirtualMemory`

**Step 5: Write Shellcode** - แอบเอาของใส่ตู้เซฟด้วย `NtWriteVirtualMemory`

## ลำดับการสร้าง Stack Spoofing
##### 1. Find Gadget aka RET 
ใช้สำหรับการ Return กลับมาหลังจาก execute loader ไปแล้ว เทคนิคที่นิยมมากคือ Trampoline หรือ Gadget ประเภท `JMP [Register]` หรือ `CALL [Register]` ใน `ntdll.dll` เพื่อปลอมแปลง Workflow ของกระบวนการทั้งหมด โดย DLL ที่ยอดนิยมและแนบเนียนได้แก่ kernel32.dll และ ntdll.dll เพราะเป็น DLL หลักที่ทุก Process ใช้งานทำให้ไม่น่าสงสัย

**อะไรคือ Trampoline? อ่านต่อได้ใน [_Trampoline Definition](_Trampoline%20Definition.md)**

##### 2. Contain original DLL content
กวาด RSP และ Register ที่เกี่ยวข้องทั้งหมดที่ชี้มายัง Stack ปัจจุบัน แล้วนำมาเก็บไว้ใน Register Temp เพื่อที่หลักจากปลอมแปลง Stack และ Execute แล้ว จะได้นำ Stack เดิมมาคืนค่าเพื่อสร้างร่องรอยปลอม

ซึ่งแน่นอนว่าเก็บใน Non-Volatile Register เพราะ Loader ใช้เวลาพอสมควรก่อนจะนำค่าเดิมกลับคืน

##### 3. Overwriting Stack
เขียน Stack ใหม่โดยใช้ RSP จากขั้นตอนที่แล้วเป็นตัวเลื่อนตำแหน่งเขียนจนครบ เพื่อทำการปลอมร่องรอยการเรียก Function ให้เหมือนกับเรียกมาจากไฟล์บน Disk ที่ถูกต้องจริง และเอา RET จากขั้นตอน 1 มาเขียนเพื่อปลอมแปลงเส้นทางของ Function ด้วย

##### 4. Execute proxy call
หลักจากการปลอมแปลง Stack แล้ว ทำการเรียกฟังก์ชันที่ต้องใช้งาน (เช่น Virtual, Open, Protect, Write เป็นต้น) ซึ่งแน่นอนว่าเราจะใช้ Indirect Syscall มาทำงานส่วนนี้

##### 5. Restore and Cleanup
นำเอา Register รวมถึง RSP เดิมที่เก็บค่าไว้ในขั้นตอนที่ 2 มาเริ่มเขียนใหม่บน Stack ปัจจุบันที่ถูกใช้งาน เพื่อลบร่องรอยทั้งหมดป้องกันการทำ Memory Scanning และปิด HANDLE, Register ที่ถูกเขียนทับในขั้นตอน 3 ล้างค่าขยะใน Register ทั้งหมดให้เกลี้ยงเพื่อให้ Heap และ Stack ไม่มีร่องรอยของปลอมเหลือ

ในเนื้อหาส่วนนี้ถือว่าพลาดไม่ได้สำหรับการทำ Stack Spoofing เพราะเราจะมาเรียนเกี่ยวกับหนึ่ง Algorithm กระดูกสันหลังของการทำเทคนิคนี้ นามว่า **Trampoline**

ในบริบทของ **Stack Spoofing** และ **Evasion**, **Trampoline** (แทรมโพลีน) คือ "จุดเด้ง" หรือโค้ดสั้นๆ ใน Memory ของระบบ (มักอยู่ใน `ntdll.dll` หรือ `kernel32.dll`) ที่เราจงใจ "กระโดด" เข้าไปหาเพื่อให้มัน "ส่ง" เราไปยังเป้าหมายจริงครับ

ถ้าพูดให้เห็นภาพ: แทนที่คุณจะเดินเข้าประตูหน้า (เรียก API ตรงๆ) คุณใช้ Trampoline เป็นเหมือน **"จุดเช็คอินปลอม"** เพื่อหลอกว่าคุณมาจากที่นั่นจริงๆ

---
### Trampoline

ในเนื้อหาส่วนนี้ถือว่าพลาดไม่ได้สำหรับการทำ Stack Spoofing เพราะเราจะมาเรียนเกี่ยวกับหนึ่ง Algorithm กระดูกสันหลังของการทำเทคนิคนี้ นามว่า **Trampoline**

ในบริบทของ **Stack Spoofing** และ **Evasion**, **Trampoline** คือ จุดกระโดด หรือโค้ดสั้นๆ ใน Memory ของระบบที่มักอยู่ใน `ntdll.dll` หรือ `kernel32.dll` ที่เราจงใจกระโดดเข้าไปหาเพื่อให้มันส่งเราไปยังเป้าหมายจริง
#### หลักการ
เรากระโดดไปที่ `ntdll!gadget` -> แล้วให้ gadget เรียก `syscall` แทน เมื่อ EDR ตรวจ Stack มันจะเห็นว่าคนที่เรียก `syscall` คือ `ntdll.dll` ไม่ใช่ Malicious Code ของเรา

รูปแบบของ Trampoline ที่นิยมใช้ ในสถาปัตยกรรมแบบ x64 มักจะตามหา Gadget 2 ประเภทนี้ใน DLL ของระบบ
#### 1. JMP/CALL Trampoline

หาคำสั่งอย่าง `jmp rbx` หรือ `call r10` ใน `ntdll.dll` แล้วเอาที่อยู่ของฟังก์ชันจริงใส่ไว้ใน `rbx` เมื่อได้แล้วเราจะกระโดดไปหาจุดที่มี `jmp rbx`

พอสั่งรัน CPU จะรัน `jmp rbx` แล้วพาไปหาฟังก์ชันเป้าหมาย โดยที่บน Stack จะบันทึกว่ามาจาก ntdll.dll ไม่ใช่มาจากไฟล์ของเรา .exe 
#### 2. Indirect Syscall Trampoline

คือการไปหาคำสั่ง `syscall; ret;` ที่มีอยู่แล้วใน `ntdll.dll` และวิธีนี้คือวิธีที่ใช้ใน PoC ที่กำลังจะแสดงให้ดูอีกด้วย

1. เตรียมเลข SSN ใส่ `eax`

2. เราเตรียม Parameter ใส่ Register (`rcx`, `rdx`, `r8`, `r9`)

3. เรากระโดด (jmp) ไปที่ Address ของคำสั่ง `syscall` ใน ntdll โดยตรง

เมื่อ Kernel มองย้อนกลับมา มันจะเห็นว่าคำสั่ง Syscall ถูกส่งมาจากภายใน `ntdll.dll`

เราจะใช้ Trampoline ในตอนที่ทำ **Step 3 Overwriting Stack** ซึ่งเราต้องทำขั้นตอนเพิ่มเติมเล็กน้อย คือสิ่งที่เรียกว่า **Synthetic Stack Frame** มีขั้นตอนดังนี้

1. วาง Address ของ `add rsp, [size]; ret` (address ของ Gadget) ไว้บนยอด Stack

2. เมื่อฟังก์ชันเป้าหมายเช่น `NtOpenProcess` ทำงานเสร็จ มันจะ `RET` มาที่ Gadget นี้

3. Gadget นี้จะช่วยดีด RSP ของกลับไปหา Stack จริงที่เก็บไว้ใน **Step 2 Contain original DLL content**

ในการทำ Stack Spoofing จำเป็นต้องใช้ Trampoline 2 ครั้ง คือ

1. ขาไป ใช้ Trampoline ใน `ntdll` เพื่อทำ **Indirect Syscall**

2. ขากลับ ใช้ Trampoline เพื่อกลับมาที่ **Original Stack** หลบการตรวจจับ Stack Walking ที่จะหา Unbacked Memory

#### ทำไมต้อง RBX?
เพราะในสถาปัตยกรรมแบบ x64 ที่เราต้องใช้ภาษา Assembly ในการเขียน RBX คือ Register แบบ Non-Volatile ที่จะไม่ทำลายตัวเองเมื่อโค๊ดถูกรันไปแล้ว และเราจำเป็นต้องสำรองค่า Address ของ Gadget และ Tra

#### ตัวอย่างจากโค๊ดจริง (ในนี้คือ Static Syscall Stub)

``` C++

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
		// 1. จองพื้นที่ 64 bytes สำหรับ 9 Arg
		// จุดนี้นับรวม Arg 1-4 ตั้งแต่ 0x00-0x20
		sub rsp, 0x50

		// 2. เซฟ RBX ไว้ที่ชั้นล่างสุด aka Non-volatile 
		// ตำแหน่งจริงคือ 0x28
		mov[rsp + 0x48], rbx

		// 3. ย้าย API Arguments (5 และ 6)
		mov r10, [rsp + 0x78]
		mov[rsp + 0x28], r10

		mov r10, [rsp + 0x80]
		mov[rsp + 0x30], r10

		// 4. ติดตั้ง KEY

		// Key 1 SSN (Arg 7) ต้องเป็น 0x88
		mov eax, dword ptr[rsp + 0x88]

		// ย้าย rcx เข้าเป็นตัวที่ 1 
		mov r10, rcx

		// ย้าย ReturnHere เข้า rbx ที่จองไว้
		lea rbx, [rip + ReturnHere]

		// Key 3 Jmp Rbx (Trampoline Gadget)  (Arg 9) 
		// ต้องเป็น 0x98 
		mov r11, [rsp + 0x98]
		mov[rsp], r11

		// Key 2 Syscall Gadget (Arg 8) 
		// ต้องเป็น 0x90 และห้ามสลับกับ SSN 
		// ไม่งั้นมันจะโดดไปหา 0x18 หรือ NtAllocateVirtualMemory
		mov r11, [rsp + 0x90]
		jmp r11

		ReturnHere :
		// 5. Cleanup: คืนค่า RBX และ RSP
		mov rbx, [rsp + 0x48]  // ขยับตาม RSP ที่โดน ret ไป 8
		add rsp, 0x50		   // คืนพื้นที่ทั้งหมด
		ret
	}
}
```
#### จะสั่งเกตได้ว่า

- **กระโดดครั้งที่ 1 (Kernel $\rightarrow$ Mask)** พอ Kernel ทำงานจบ มันสั่ง `ret` $\rightarrow$ CPU หยิบ address บนสุดของ Stack (`[RSP]`) ออกมา $\rightarrow$ ซึ่ง address นี้คือที่อยู่ของคำสั่ง `jmp rbx` $\rightarrow$ CPU กระโดดไปที่คำสั่งนั้น

- **กระโดดครั้งที่ 2 (Mask $\rightarrow$ .exe ของเรา)** พอ CPU มารันคำสั่ง `jmp rbx` CPU เลยดูใน Register **`RBX`** $\rightarrow$ เจอที่อยู่ของ `ReturnHere` ที่ใส่เตรียมไว้ด้วยคำสั่ง `lea` ในบรรทัด lea rbx, `[rip + ReturnHere]` $\rightarrow$ CPU กระโดดกลับมาหา .exe ของเรา

### ขั้นตอนการทำงานของ Stub 

**1. เตรียมพื้นที่**

- `sub rsp, 0x50` จองพื้นที่บน Stack ใหม่ 80 ไบต์เพื่อสร้าง Shadow Space และพื้นที่สำหรับวางพารามิเตอร์

- `mov [rsp + 0x48], rbx` เอาค่า `RBX` ดั้งเดิมของระบบไปฝากไว้ที่ก้นบ่อของ Stack ใหม่ ที่พิกัด 0x48 เพื่อรอคืนค่าตอนจบตามกฎ x64 Convention

**2. ย้ายของ**

- ตามกฎ x64 CPU จะรับพารามิเตอร์ผ่าน Register แค่ 4 ตัวแรก (RCX, RDX, R8, R9) ตัวที่ 5 เป็นต้นไปต้องวางบน Stack

- `mov r10, [rsp + 0x78] -> mov [rsp + 0x28], r10` ย้าย Arg 5 จาก Stack เดิม ที่โดนดันไปอยู่ที่ 0x78 มาวางใน Stack ใหม่ที่พิกัด 0x28

- `mov r10, [rsp + 0x80] -> mov [rsp + 0x30], r10` ทำแบบเดียวกันกับ Arg 6 ย้ายมาไว้ที่ 0x30

**3. ติดตั้ง Key**

- **Key 1 (SSN)** `mov eax, dword ptr[rsp + 0x88]` หยิบหมายเลข SSN (`0x18`) ไปใส่ใน `EAX` เพื่อเตรียมบอก Kernel ว่ากำลังจะรันฟังก์ชันอะไร

- `mov r10, rcx` กฎบังคับของการทำ Syscall คือต้องย้าย Arg 1 จาก `RCX` ไปพักไว้ที่ `R10` เสมอ

- `lea rbx, [rip + ReturnHere]`ปักหมุดพิกัดขากลับเอาไว้ใน `RBX` เพื่อให้ Trampoline รู้ว่าต้องดีดตัวกลับมาที่ไหน

- **Key 3 (Trampoline mask)** `mov r11, [rsp + 0x98] -> mov [rsp], r11` เอาที่อยู่ของคำสั่ง `jmp rbx` ไปวางแหมะไว้บน ยอดสุดของ Stack (`[rsp]`) เพื่อรอรับคำสั่ง `ret` จาก Kernel

- **Key 2 (Gadget)** `mov r11, [rsp + 0x90] -> jmp r11` หยิบที่อยู่ของคำสั่ง `syscall; ret;` ขึ้นมา แล้วกระโดดเข้าไปทำงานใน `ntdll` 

**4. กระโดดกลับบ้านและทำความสะอาด Stack**

- `ReturnHere` หลังจาก Kernel ทำงานเสร็จ มันจะเรียก `ret` -> ซึ่งจะไปดึง Key 3 ที่วางไว้บนยอด Stack มาทำงาน -> Mask คือ `jmp rbx` -> CPU กระโดดกลับมาที่ `ReturnHere`

- `mov rbx, [rsp + 0x48]` คืนค่า `RBX` กลับสู่สภาพเดิมตามที่ฝากไว้

- `add rsp, 0x50` ถม Stack Shadow คืน คืนพื้นที่ Stack 80 ไบต์ให้ระบบ
   
- `ret` จบฟังก์ชัน

ตอนสั่ง `sub rsp, 0x50` ค่าพารามิเตอร์เดิมทั้งหมดบน Stack จะถูกดันห่างออกไป **0x50 ไบต์** ดังนั้น

- Arg 5 เดิมอยู่ `0x28` -> ย้ายไป `0x28 + 0x50 = 0x78`

- Arg 6 เดิมอยู่ `0x30` -> ย้ายไป `0x30 + 0x50 = 0x80`

- Arg 7 (SSN) เดิมอยู่ `0x38` -> ย้ายไป `0x38 + 0x50 = 0x88`

- Arg 8 (Syscall) เดิมอยู่ `0x40` -> ย้ายไป `0x40 + 0x50 = 0x90`

- Arg 9 (Trampoline) เดิมอยู่ `0x48` -> ย้ายไป `0x48 + 0x50 = 0x98`

### สรุปขั้นตอนการทำงานหลังเตรียม Stack เสร็จ

- **จองพื้นที่** `sub rsp, 0x50` จองพื้นที่ 80 bytes เพื่อทำ Shadow Space และย้ายพารามิเตอร์

- **เลื่อน Stack & สำรองค่า** ย้ายพารามิเตอร์ตัวที่ 5-6 ลงมา และเอา `RBX` ดั้งเดิมของระบบไปฝากไว้ก้นบ่อ

- **เตรียมกุญแจ 1** เอา **Key 1 (SSN)** ใส่ `EAX` เพื่อรอส่งให้ Kernel และ เอา `ReturnHere` ไปฝากไว้ใน `RBX` ล่วงหน้า

- **วาง mask สำหรับขากลับ** เอา **Key 3 Trampoline `jmp rbx`** ไปวางรอไว้บนยอดสุดของ Stack (`[RSP]`)

- **CPU กระโดด** ไปหา **Key 2 Syscall Gadget** เพื่อเข้าสู่ Kernel ตรงนี้คือที่ Windows/EDR จะเห็นว่า `ntdll` เป็นคนเริ่มทำงานแบบ Backed Memory ทั่วไป

- **กระโดดครั้งแรก `ret`** เมื่อ Kernel ทำงานจบ มันจะสั่ง `ret` $\rightarrow$ CPU จะหยิบของ Key 3 Trampoline `jmp rbx` บนยอด Stack มาอ่าน

- **กระโดดครั้งสองเพื่อกลับบ้าน** CPU รันคำสั่ง `jmp rbx` แล้วก็เข้าไปดูใน `RBX` และเจอพิกัด `ReturnHere` $\rightarrow$ CPU เลยดีดกลับมาลงจอดที่บ้านเรา

- **ทำความสะอาดและคือ Stack** หลังจากนั้นก็ทำการ mov rbx, `[rsp + 0x48]` เพื่อคืนค่าดั่งเดิมของ `rbx` ที่เป็น Non-volatile และ add rsp + 0x50 เพื่อถม Stack ที่เราเอามาใช้คืนให้ระบบ

# โค๊ดตัวเต็ม ให้ไปดูที่ Portfolio/src/Stack Spoofing ที่ Function "mainStack.cpp"
