ปกติแล้วเวลาโปรแกรมบน Windows ต้องการทำอะไรสักอย่างที่สำคัญเช่น อ่านไฟล์, จองหน่วยความจำ, หรือสร้าง Process โปรแกรมเหล่านั้นไม่สามารถสั่ง Hardware ได้โดยตรง มันต้องขอความช่วยเหลือจาก **Kernel** ผ่านเส้นทางมาตรฐานดังนี้

1. **Application** เรียกใช้ฟังก์ชัน Win API ใน `kernel32.dll` (เช่น `CreateProcess`)

2. `kernel32.dll` ส่งต่อไปยัง `ntdll.dll` (Native API ฟังก์ชันระดับต่ำที่ขึ้นต้นด้วย `Nt...` เช่น `NtCreateUserProcess`)

3. `ntdll.dll` จะเตรียมคำสั่งและเรียกใช้ `Syscall` เพื่อข้ามจาก User Mode ไปยัง Kernel Mode

4. . Kernel เรียกใช้ NtOsKrnl.exe แล้วสั่งการ CPU ให้ทำงาน

=================================================

`Programmer -> Win API -> Native API (ntdll.dll) -> Kernel -> CPU`

=================================================

ปัญหาคือ ซอฟต์แวร์ความปลอดภัยอย่าง EDR จะเข้าไปทำการ Hooking ไว้ที่ `ntdll.dll` ถ้าเห็นว่ามีคำสั่งน่าสงสัย EDR จะสั่งระงับทันที

เพื่อให้เห็นถึงปัญหาของเรา อาจจะต้องย้อนรอยถอยหลังสักนิด กลับไปหาเทคนิคที่เป็นแม่แบบชื่อว่า `Direct Syscall`

### 1.1 `Direct Syscall` คืออะไร?

`Direct Syscall` คือเทคนิคที่มัลแวร์ "ข้ามหัว" `ntdll.dll` ที่ถูก EDR ยึดครองอยู่ แล้วทำการเรียกใช้คำสั่งไปยัง Kernel โดยตรงด้วยตัวเอง แทนที่จะเรียกฟังก์ชันจาก DLL ของ Windows มัลแวร์จะใส่ชุดคำสั่ง Assembly เล็กๆ ไว้ในตัวมันเอง เรียกว่า Assembly Stub เพื่อจำลองพฤติกรรมของ `ntdll.dll` ในจังหวะสุดท้ายก่อนส่งงานให้ Kernel

### 1.2 กลไกการทำงาน

การที่ CPU จะคุยกับ Kernel ได้ มันต้องมี เลขที่นั่ง หรือที่เรียกว่า **SSN (System Service Number)** ซึ่งเป็นตัวบอก Kernel ว่าต้องการใช้บริการฟังก์ชันไหน โดยขั้นตอนของ `Direct Syscall` คือ

1. **ค้นหา SSN** มัลแวร์ต้องรู้ว่าใน Windows Version นั้น ๆ ฟังก์ชันที่ต้องการใช้มีเลข SSN อะไร (เช่น `NtAllocateVirtualMemory` อาจจะเป็นเลข $0x18$)
    
2. **เตรียม Register** มัลแวร์จะนำเลข SSN ไปใส่ใน CPU Register (โดยปกติคือ `eax` หรือ `rax`)
    
3. **สั่ง `Syscall`** ใช้คำสั่ง Assembly `syscall` (สำหรับ x64) เพื่อกระโดดข้ามไปหา Kernel ทันที


ผลลัพธ์คือ EDR ที่ยืนรอตรวจอยู่ที่ `ntdll.dll` จะไม่เห็นอะไรเลย เพราะมัลแวร์ไม่ได้เดินผ่านประตูหน้า แต่มุดท่อระบายน้ำไปโผล่ใน Kernel โดยตรง

ฟังดูเหมือนง่าย แล้ว อะไรคือสิ่งที่ทำให้ `Direct Syscall` มาถึงทางตันละ?

### 1.3 ปัญหาของ `Direct Syscall` ในยุคปัจจุบัน

ในการทำ `Direct Syscall` นักพัฒนาจะคัดลอกคำสั่ง Assembly `syscall` มาไว้ในตัวไฟล์ `.exe` ของ มัลแวร์โดยตรง แม้จะข้าม User-land Hook ได้จริง แต่จะทิ้งร่องรอยที่ชัดเจน 2 ประการ

#### 1. ในสภาวะปกติ Windows ออกแบบมาให้คำสั่ง `syscall` (เลขฐาน 16 คือ `0F 05`) ปรากฏอยู่ในตำแหน่งที่เฉพาะเจาะจงมาก นั่นคือภายใน **`ntdll.dll`** และ **`win32u.dll`** เท่านั้น

- **กลไกของ `ETW-Ti`** เมื่อ Malware ทำการเรียก `syscall` ตัว Windows Kernel จะไม่ได้แค่รับคำสั่งแล้วทำตาม แต่มันจะทำการตรวจสอบด้วยว่า ใครเป็นคนส่งคำสั่งนี้มา? โดยดูจากค่าใน Register $RIP$ (Instruction Pointer) แบบที่เราอธิบายไปในเอกสารก่อนหน้า

- หาก $RIP$ ชี้กลับไปยังที่อยู่ที่อยู่ใน `malware.exe` หรือพื้นที่หน่วยความจำที่จองไว้เอง (เรียกว่า Private Memory) แทนที่จะเป็นช่วงของ Address Module Base ที่ `ntdll.dll` ถือครองอยู่ ระบบ `ETW-Ti` จะส่งสัญญาณ Warning ทันทีว่าเกิด `Manual Syscall` แล้ว Terminate ตัว Process ทันที

#### 2. การทำ Stack Walking ที่เราคุยกันก่อนหน้านี้ จะเห็นผลชัดเจนที่สุดในจุดนี้

- **Legitimate Flow** ในการเรียกใช้ฟังก์ชันมาตรฐาน Stack จะต้องมีหน้าตาเป็นลำดับขั้น เช่น
    
    1. `BaseThreadInitThunk` (จุดเริ่ม)
    
    2. `main` (โค้ดหลักของโปรแกรม)
    
    3. `CreateFile` (ใน `kernel32.dll`)
    
    4. `NtCreateFile` (ใน `ntdll.dll`) $\leftarrow$ **นี่คือจุดสุดท้ายก่อนเข้า `Syscall`**

- **`Direct Syscall Flow`** เมื่อแฮกเกอร์เขียนคำสั่ง `syscall` ลงในตัวมัลแวร์เอง เมื่อ EDR มาส่องดู Stack ในจังหวะที่มัลแวร์กำลังทำงาน มันจะเจอแค่
    
    1. `main` (โค้ดมัลแวร์)
    
    2. `DirectSyscallStub` (Assembly ที่เขียนเอง)
    
     _และจากนั้นมันก็พุ่งเข้า Kernel เฉยเลย_

- ผลลัพธ์ คือ EDR จะเห็นว่า "Frame" ของ `ntdll.dll` หายไปทั้งยวง (Missing Frames) ซึ่งในโลกของโปรแกรมมิ่งปกติ มันแทบจะเป็นไปไม่ได้ ที่ Application จะข้ามหัว DLL พื้นฐานของระบบไปคุยกับ Kernel ได้เองโดยไม่มีการโหลด Module ที่เกี่ยวข้อง ไม่มีการ IAT ที่ควรจะโหลด Library พื้นฐานอย่างน้อย 3-5 ตัว และระบบก็จัดฟันธงเลยว่าเป็น Malware 

นั่นคือปัญหาของ `Direct Syscall` และเป็นที่มาของเทคนิคการป้องกันของ EDR ยุคต่อมาอย่าง `ETW-Ti` และ Call Stack Analysis จนบรรดา Malware Developer ต้องจับเอา `Direct Syscall` มาต่อยอดพัฒนา กลายเป็น `Indirect Syscall`

## 1. **`Indirect Syscall`** 

หัวใจหลักของสถาปัตยกรรมมัลแวร์ชุดนี้คือการก้าวข้ามข้อจำกัดของ `Direct Syscall` แบบเดิมที่เริ่มถูก EDR ตรวจจับได้ผ่านการตรวจสอบ Instruction Pointer Validation และการวิเคราะห์พฤติกรรมผ่าน Kernel Callbacks จึงเป็นจุดกำเนิดของ `Indirect Syscall` ในเวลาต่อมา

ก่อนอื่น ขอพาทุกท่านไปรู้จักกลไกของ EDR ก่อนว่า มันทำงานได้ยังไง

#### Sequence Diagram ของ EDR Hooking

![](../Images/Pasted%20image%2020260509201147.png)

ภาพ: Sequence Diagram ของ EDR Hooking ระหว่าง 
(ด้านบน) การเรียกใช้ API แบบปกติ
(ด้านล่าง) การเรียกใช้ `Indirect Syscalls`

#### Workflow Diagram การเรียกใช้ API แบบปกติ

#### **Step 1**

- 1.1 เรียกใช้ฟังก์ชัน `VirtualAlloc`

- 1.2 คำสั่งนี้จะวิ่งไปหาไฟล์ DLL ที่ทำหน้าที่ผู้จัดการชื่อ **`kernel32.dll`** 

- 1.3 อย่างที่สรุปอย่างง่ายที่ด้านบน`kernel32.dll` ทำงานระดับลึกเองไม่ได้ มันจึงทำหน้าที่แค่แปลคำสั่งแล้วส่งไม้ต่อให้ **`ntdll.dll`** โดยไปเรียกฟังก์ชันชื่อ **`NtAllocateVirtualMemory`** อีกที เพื่อใช้เลข SSN ข้ามไปทำงานฝั่ง Kernel

#### **Step 2**

- 2.1 `ntdll.dll` คือประตูด่านสุดท้ายก่อนที่คำสั่งจะมุดลงสู่ Kernel

- 2.2 ตามปกติแล้ว บรรทัดแรกๆ ของฟังก์ชันใน `ntdll.dll` ควรจะเป็นการเตรียมข้อมูลใส่ Register แล้วตามด้วยคำสั่ง `syscall` ทันที

- 2.3 นี้คือจุดที่ EDR แอบมาทำ Hooking ตอนที่คอมพิวเตอร์เพิ่งเปิดเครื่อง หรือตอนที่โปรแกรมเพิ่งรัน EDR ได้แอบเอาโค้ดของตัวเอง ที่เป็น DLL ของ EDR เข้ามาฝังในโปรแกรม แล้วทำการ **"Inline Patching"**

#### **Step 3**

- 3.1 EDR จะลบคำสั่ง 5  Bytes แรกของ `NtAllocateVirtualMemory` ทิ้งไป แล้วเอาคำสั่ง **`JMP` (Jump)** มาใส่แทน

- 3.2 ทันทีที่ CPU ของคุณมาถึงบรรทัดแรกของ `NtAllocateVirtualMemory` มันจะโดนคำสั่ง `JMP` กระโดดออกนอกเส้นทางปกติที่จะไปจองพื้นที่ใน Memory ลอยไปตกที่ Inspection Routine ซึ่งอยู่ในไฟล์ DLL ของตัว EDR

#### **Step 4

   จุดตรวจสอบพฤติกรรม EDR จะหยุดโปรแกรมไว้ชั่วคราว แล้วทำการสแกนอย่างละเอียดโดยใช้หลักเกณฑ์ดังนี้

* 4.1 **ตรวจ Parameter** โปรแกรมกำลังขอแรมประเภทไหน? ถ้าขอแบบ RWX (`PAGE_EXECUTE_READWRITE`) EDR จะเพิ่ม Risk Scoring 

* 4.2 **ตรวจ Call Stack** EDR จะใช้คำสั่งเช็คประวัติย้อนหลังว่าใครเป็นคนสั่งจองแรมนี้? เรียกมาจากไฟล์ .exe อะไร? ผ่านฟังก์ชันไหนมาบ้าง?

* 4.3 **ตรวจ Signature** สแกนดูในหน่วยความจำว่ามี Pattern ของ Shellcode หรือไม่? หรือว่ามี Pattern ของโค๊ดที่ถูกใช้ในการเขียน Malware แบบที่เคยถูกบันทึกในฐานข้อมูลหรือไม่

#### **Step 5

   หลังจาก EDR สแกนเสร็จ มันจะตัดสินใจเลือกทางเดิน 2 ทาง

- 5.1 **Risk Scoring ต่ำกว่าเกณฑ์** ถ้า EDR มองว่า Loader ของเราเป็นแค่โปรแกรมแชทหรือเว็บบราวเซอร์ปกติ มันจะใช้เทคนิคที่เรียกว่า **"Trampoline"** คือมันจะรันคำสั่ง 5 ไบต์แรกที่มันแอบขโมยไปตอนแรกให้เสร็จ แล้วค่อยส่งคำสั่งมุดลง Kernel (`syscall`) ให้ โปรแกรมก็จะได้แรมไปใช้ตามปกติ

- 5.2 **Risk Scoring สูงกว่าเกณฑ์** ถ้า EDR ตรวจพบความผิดปกติ เช่น Call Stack ที่ผิดปกติหรือเจอ Shellcode มันจะปฏิเสธการทำงานทันที โดยอาจจะส่งค่า Error เช่น กลับไปหา `kernel32.dll` ทำให้ฟังก์ชัน `VirtualAlloc` คืนค่าเป็น `NULL` หรือถ้าร้ายแรง มันจะสั่ง **Kill Process** ปิดโปรแกรมทิ้งทันที พร้อมส่ง Alert ไปที่ Dashboard ของทีม SOC Analyst ทันที

#### Workflow Diagram การเรียกใช้ `Indirect Syscalls`

#### Step 1 Reconnaissance & Resolution

- 1.1 แทนที่ Loader ของเราจะเดินไปถามทางจาก `kernel32.dll` แบบโปรแกรมทั่วไป มันจะลงไปควานหาข้อมูลใน Memory ด้วยตัวเอง

- 1.2 **หา SSN:** มันจะเข้าไปอ่านไฟล์ `ntdll.dll` ดิบๆ เพื่อดูว่าฟังก์ชันเป้าหมาย เช่น `NtAllocateVirtualMemory` มี **SSN (System Service Number)** หมายเลขอะไร

- 1.3 **หา Gadget:** มันจะสแกนหาไบต์คำสั่ง `0F 05 C3` (`syscall; ret`) ที่ซ่อนอยู่ตรงไหนสักแห่งในพื้นที่ของ `ntdll.dll` ซึ่งโดยมากจะเป็น Field ที่ชื่อ `.text`และบันทึก Address ของ SSN นั้นไว้

#### **Step 2: Register Preparation**

   ก่อนจะกระโดด เราต้องจัดเรียง Registers ให้ตรงตามกฎของแกนกลาง Windows (Kernel) เป๊ะๆ ไม่งั้น Kernel จะ Error และ Loader ของเราจะ Crash ทันที

- 2.1 นำพารามิเตอร์ เช่น ขนาดแรมที่ต้องการจอง ใส่ลงใน Register `RCX`, `RDX`, `R8`, `R9`

- 2.2 ก๊อปปี้ค่าจาก `RCX` ไปไว้ที่ `R10` (`mov r10, rcx`)

- 2.3 นำเลข SSN เช่น `0x18` ใส่ลงไปใน **`EAX`** (`mov eax, 18h`)

#### **Step 3: Bypass EDR hooking**

- 3.1 แทนที่เราจะให้ CPU เดินไปที่บรรทัดแรกของ `NtAllocateVirtualMemory` แบบโปรแกรมปกติที่มีคำสั่ง `JMP` ของ EDR ดักรออยู่ แบบการเรียกใช้ API แบบปกติ

- 3.2 เราสั่งให้ CPU รันคำสั่ง **`JMP` (Jump)** พุ่งตรงไปยังพิกัดของ Gadget หรือ `syscall; ret` ที่เราจดไว้ใน Step 1 ทันที

- 3.3 ผลคือ การข้ามหัว EDR hooking เพราะคำสั่ง `syscall` จะบวกเพิ่มจากตำแหน่งเดิมไปอีกประมาณ 18 Bytes (Offset `+0x12`) จากจุดเริ่มต้นฟังก์ชัน EDR ที่ดักอยู่หน้าประตู (Offset `+0x00`) จึงถูกกระโดดข้ามหัวไปโดยสมบูรณ์ Hooking เป็นใบ้ทันที

#### **Step 4: Userland to Kernel**

- 4.1 ทันทีที่ CPU เหยียบคำสั่ง `syscall` มันจะเข้าสู่ภาวะเปลี่ยนโหมด จาก Ring 3 User Mode เปลี่ยนเป็น Ring 0 Kernel Mode

- 4.2 คราวนี้ Kernel จะเป็นคนรับช่วงต่อ มันจะเข้าไปอ่าน Register ตัวแรก ซึ่งในโหมด Kernel ก็คือ `EAX` ดูว่าเราส่งเลขอะไรมา พอเห็นพบเลข SSN ดังกล่าวแล้ว

- 4.3 Kernel จะทำการตรวจสอบสิทธิ์ และจัดสรร RAM ให้เราตามที่ขอ ทั้งหมดนี้เกิดขึ้นในระดับลึกที่ EDR ทั่วไปใน User Mode เอื้อมไม่ถึงแล้ว

#### **Step 5: Return Function**

- 5.1 พอ Kernel ทำงานเสร็จ มันจะคืนสถานะความสำเร็จ (`0x0` หรือ `STATUS_SUCCESS`) กลับมา

- 5.2 คำสั่ง `ret` (Return) ที่ต่อท้าย `syscall` จะดีด CPU กลับมาที่โค้ด Loader ของเราในบรรทัดถัดไปทันที


ต่อมาคือมา Deep Overall ของกระบวนการทั้งหมดในการทำ `Indirect Syscall`

#### 1. **Dynamic SSN Resolution** 
   การค้นหา System Service Number (SSN) ของฟังก์ชันที่ต้องการ โดยเราจะทำกันผ่านเทคนิคการ PE Parse ในหน่วยความจำ เพื่อหลบหลีกการตรวจจับด้วย String API ชื่อโดยตรง

   ใน `PoC` นี้ เราจะหาโดยใช้ Process ของ Loader เอง เพราะไม่ต้องข้ามไปหาจาก Process อื่นผ่านการใช้ Win API หรือ Native API และ เพื่อความง่ายต่อการเข้าใจในบริบทของบทความนี้ แต่ในสนามจริงสามารถถูก EDR จัดการได้ด้วยวิธี Static Scan
   
   **ขั้นตอน 1** คือ การที่ต้องหา Native DLL base หรือ ที่อยู่ของ ntdll.dll ผ่านการเข้าถึง PEB หรือ Process Environment Block แบบ Manual ของ Process หนึ่งก่อน โดย Logic การหาคือ เข้าถึง PEB ผ่าน TEB หรือ Thread Environment Block ที่ GS:0x60 (หรือ FS:0x30 บนสถาปัตยกรรม x86-32) 
   
   **ขั้นตอน 2** คือ เราจะมุดเข้าไปโดยเข้าถึง Pointer ที่ชื่อว่า PEB_LDR_DATA ด้วยการนำ Address ของ PEB + Offset 0x18 เมื่อเข้าถึง LDR แล้ว เราจะสามารถเข้าถึง Linked List 3 ตัวภายใน LDR นี้ได้ คือ
   
   * **`InLoadOrderModuleList` (Offset 0x10)** เรียงตามลำดับการโหลดเข้า Memory ตัวหลักที่ขวัญใจมหาชนในการหา `ntdll` เพราะเราหาจากลำดับที่ Module ถูกโหลดขึ้น RAM ได้เลย ไม่ต้องคิดมาก
   * **`InMemoryOrderModuleList`(Offset 0x20)** เรียงตามลำดับตำแหน่งในหน่วยความจำ
   * **`InInitializationOrderModuleList` (Offset 0x30)** เรียงตามลำดับการรันฟังก์ชัน Initialize

![](../Images/Pasted%20image%2020260329032454.png)
   
   ภาพ: เส้นทางของการเข้าถึง Double Linked List LDR Module structure
   
   เมื่อเราเข้าถึง `InLoadOrderModuleList` ได้แล้ว เราจะเริ่มไถหา ntdll.dll ด้วยชื่อ โดยการหาจาก node ที่ชื่อว่า `DllBaseName` เมื่อเทียบชื่อแล้วว่าใช่ เราก็จะ cast เป็น ULONG_PTR แล้ว return นำ Base Address ของ DLL นั้นไปใช้งานต่อในการหาทั้ง Native Header, Export table , Gadget และ SSN number หรือก็คือตลอดทั้งกระบวนการเราจะใช้ `DllBase` เป็นสารตั้งต้นหรือ Base Address หลัก
   
   จากในภาพ Code snippet เราจะเห็นได้ว่า 
   * 1. เราโดดไปที่ Offset 0x20 แทนที่จะเป็น 0x10 ซึ่งความเป็นจริงเราไม่ต้องโดดมาที่ Offset นี้เลยเพราะไม่ได้ใช้แต่แรก
   
   * แต่ผู้เขียนอยากใช้ `InLoadOrderModuleList` เลยวุ่นวายกับการมาลบ Offset ถอยหลังกลับไป 0x10 Bytes ด้วยการใช้ตัวแปรชื่อ `pEntry` เก็บจุดที่ถอยแล้ว เราจะใช้ตัวแปรนี้หา ntdll.dll base address 
   
   * 3. ใช้ Function การเปรียบเทียบว่าภายใน Field ที่ชื่อ `InLoadOrderModuleList` ด้วย แต่เราจะลงเพียง Logic การหา Native DLL base เท่านั้น

   ![](../Images/Pasted%20image%2020260329001248.png)
   
   ภาพ: Code Snippet หา `NtDllBase` Address 
   
   **ขั้นตอน 3 คือ การดึงข้อมูลจาก PE Header** หลังจากที่เราได้ `DllBase` ของ `ntdll.dll` มาเป็นสารตั้งต้นจากขั้นตอนก่อนหน้าแล้ว เป้าหมายต่อไปคือการชำแหละโครงสร้างไฟล์ PE ใน Memory เพื่อเข้าไปหา NT Header ซึ่งเป็นจุดศูนย์กลางที่จะพาเราไปสู่ Export Directory ต่อไป
   
![](../Images/Pasted%20image%2020260329011846.png)
   
   จากในภาพ Code snippet การทำงานของฟังก์ชัน `getNtHeader` เราจะเห็น Logic การเดินตามโครงสร้างดังนี้

   - **1. การเข้าถึง DOS Header** โค้ดเริ่มต้นด้วยการนำ `NtDllAddr` (ซึ่งก็คือ Base Address) มาทำ Casting ให้เป็นโครงสร้างของ `IMAGE_DOS_HEADER` ทันที และมีการ Check โดยการตรวจสอบค่า `e_magic` ว่าตรงกับ `IMAGE_DOS_SIGNATURE` (ตัวอักษร "MZ") หรือไม่ เพื่อให้แน่ใจว่าเรากำลังชี้ไปที่จุดเริ่มต้นของไฟล์ PE ที่ถูกต้องจริงๆ ไม่ใช่ขยะใน Memory
   
   - **2. การกระโดดไปหา NT Header** ความสำคัญของ DOS Header สำหรับเรามีเพียงอย่างเดียวคือ field ที่ชื่อว่า `e_lfanew` ซึ่งเป็นตัวแปรที่เก็บค่า Offset ชี้ไปยังจุดเริ่มต้นของ NT Header
   
   - **3. การคำนวณ Address จริง** โค้ดทำการคำนวณที่อยู่จริงของ NT Header โดยการนำ `e_lfanew` บวกเข้ากับ Base Address (`NtDllAddr`) แล้ว Casting ให้เป็น `IMAGE_NT_HEADERS64` พร้อมกับตรวจสอบความถูกต้องอีกครั้งผ่านการเช็คค่า `Signature` ว่าตรงกับ `IMAGE_NT_SIGNATURE` ที่เป็นตัวอักษร "PE\0\0" หรือไม่

   เมื่อผ่านเงื่อนไขการตรวจสอบทั้งหมด ฟังก์ชันก็จะคืนค่า Pointer ที่ชี้ไปยังโครงสร้าง NT Header ซึ่งพร้อมให้เรานำไปเจาะหา `OptionalHeader` และ `DataDirectory` ในขั้นตอนต่อไป 


![](../Images/Pasted%20image%2020260329012735.png)
   
   ภาพ: การเข้าถึง Export Directory

   **ขั้นตอนที่ 4 คือ การเข้าถึง Export Directory** หลังจากที่เราได้ Pointer ของ `NT_HEADER` มาแล้ว เราสามารถเจาะเข้าไปในส่วนของ `OptionalHeader` เพื่อค้นหา `DataDirectory` ซึ่งเป็นเป้าหมายหลักในการหาฟังก์ชันที่ DLL นั้นเปิดให้ Export โดยเราจะโฟกัสไปที่ `IMAGE_DIRECTORY_ENTRY_EXPORT`

   จากในภาพ Code snippet การทำงานของฟังก์ชัน `getExportTables` และโครงสร้าง `_EXPORT_TABLES` มี Logic ดังนี้

   - **1. การหา Export Directory RVA** เราเริ่มจากการดึงค่า `VirtualAddress` ของ Export Directory ซึ่งเป็นค่า RVA จาก `DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]`
   
   - **2. การคำนวณ Absolute Address ของ Export Directory** เนื่องจากค่าที่ได้มาเป็น RVA โค้ดจึงนำไปบวกกับ Base Address (`uiBaseAddr`) เพื่อให้ได้ที่อยู่จริงใน Memory (ค่า VA) และเก็บ Pointer ไว้ใน `pExportDir` ของโครงสร้างที่เรานิยามไว้
   
   - **3. การดึง Array หลักทั้ง 3** เราจะเข้าไปใน `pExportDir` เพื่อดึงและคำนวณ Absolute Address ของตัวแปรสำคัญ 3 ตัว ซึ่งเป็น Array ที่ขนานกัน

     * `AddressOfNames`: Array ที่เก็บชื่อฟังก์ชันแบบ String (เอาไว้ใช้เทียบชื่อเวลาค้นหา)
     
     * `AddressOfNameOrdinals`: Array ที่เก็บลำดับหรือ ID ของฟังก์ชัน (Ordinal)
     
     * `AddressOfFunctions`: Array ที่เก็บที่อยู่ (Address) จริงของโค้ดฟังก์ชันแต่ละตัว

   - **4. การดึงจำนวนชื่อฟังก์ชันทั้งหมด** นอกจากการหาที่อยู่ของ Array แล้ว โค้ดยังดึง `NumberOfNames` มาเก็บไว้ด้วย เพื่อใช้เป็นลิมิตในการทำ Loop ค้นหาชื่อฟังก์ชันในขั้นตอนต่อไป

   โดยข้อมูลทั้งหมดนี้ จะถูกจัดเก็บลงใน Struct `_EXPORT_TABLES` ที่เป็น Custom Struct ที่เขียนขึ้นเองเพื่องานนี้โดยเฉพาะ ผ่าน Pointer `pOutTables` ทำให้ในกระบวนการถัดไป ไม่ว่าเราจะต้องการค้นหา System Service Number (SSN) หรือหา Address ของ Gadget ใดๆ เราก็สามารถทำได้ทันทีโดยไม่ต้องพึ่งพา `GetProcAddress` ของ Windows API แม้แต่น้อย ดูได้จากภาพด้านล่าง
   
   ข้อดีของการใช้ struct แบบนี้คือเราสามารถเก็บผลลัพย์จากการเข้าไปดึงข้อมูลฟังก์ชันทั้งหมดและดึงออกมาใช้งานได้เลยผ่านการนิยามตัวแปรตัวแทนแบบเป็น Pointer (เรียกว่า Pass by Pointer) ซึ่งในทาง Performance นั้น เราเพียงแค่ชี้ไปหาตำแหน่งจริงของ Struct แล้วเรียกใช้งาน แทนที่จะต้องทำการคำนวณ Offset ใหม่ทุกครั้งที่เราจะหาฟังก์ชันมาใช้ แถมยังลดความซับซ้อนของ Code ลงไปได้ด้วย 

![](../Images/Pasted%20image%2020260329012943.png)
   
   ภาพ: การ typedef struct เก็บข้อมูลตาราง Export 

   ***เมื่อเราเตรียมตัวจนเสร็จแล้ว แล้วเราก็มาเริ่มขั้นตอนการทำ Dynamic SSN Resolution สักที นั่นคือคือการใช้ Algorithm หาเลข SSN*** 

   **อ่านต่อได้ที่บทความนี้** [SSN Resolution Algorithm](SSN%20Resolution%20Algorithm.md)
   
![](../Images/Pasted%20image%2020260329034353.png)
   
   ภาพ: 4 จตุ Algorithm สำหรับการหา SSN 

#### 2. **Searching for `Syscall Gadget`**
   Gadget ถือว่าเป็นไม้ตายของ `Indirect Syscall` หากยังจำกันได้ ในการทำ `Direct Syscall` เราจะทำการเขียนเลข SSN ที่หามาได้จากการทำ Dynamic SSN Resolution แล้วสั่งทำ `syscall; ret` จากใน Stub ของเรา ซึ่งมันจะไป Trigger ตัว Stack Walk ที่ทำหน้าที่ตรวจดู Stack sequence ว่า โปรแกรมถูกเรียกมาแบบ Unbacked Memory หรือไม่ ผ่านการตรวจข้อมูลการทำงานของ Process ที่เก็บไว้ใน `ETW-Ti`
   
   ทางออกของเรา คือ แทนที่จะใช้คำสั่ง `syscall` ในโค้ดเรา เราจะสแกนหา Address ของคำสั่ง `syscall; ret` ที่อยู่ภายในพื้นที่หน่วยความจำของ `ntdll.dll` จริงๆ

   เมื่อเราเข้าถึงโครงสร้าง PE ของ `ntdll.dll` ได้แล้ว สิ่งที่เราต้องการไม่ใช่แค่ชื่อฟังก์ชัน แต่เป็นชุดคำสั่ง `syscall` ที่ซ่อนอยู่ข้างใน เพื่อใช้เป็น "จุดกระโดด" (Trampoline) ให้โค้ดของเราทำการ Context Switch เข้าสู่ Ring 0 โดยที่ Instruction Pointer (RIP) ยังคงชี้ว่าอยู่ในพื้นที่ของ `ntdll.dll`

   โดยขั้นตอนการหา Gadget คือ

   - **ขั้นตอน 1 การเข้าถึง Section Headers** โค้ดเริ่มต้นด้วยการใช้ Macro `IMAGE_FIRST_SECTION` เพื่อดึง Pointer ที่ชี้ไปยัง Array ของ Section Header ทั้งหมดภายในไฟล์ PE และดึง `NumberOfSections` เพื่อใช้กำหนดขอบเขตของการวนลูป

   - **ขั้นตอน 2** ภายในลูป โค้ดจะทำการเปรียบเทียบชื่อ Section ด้วยฟังก์ชัน `ManualStrCmp` (การเขียนฟังก์ชันเทียบ String เองเป็นเทคนิคที่ดีมาก เพื่อหลีกเลี่ยงการ Import `strcmp` จาก CRT ซึ่งอาจทิ้งร่องรอยใน IAT) โดยเป้าหมายของเราคือ Section ที่ชื่อว่า `.text` เพราะเป็นส่วนเดียวที่ได้รับสิทธิ์ `Execute` ให้รันคำสั่งได้

   - **ขั้นตอน 3** เมื่อเจอ `".text"` แล้ว โค้ดจะคำนวณหาที่อยู่เริ่มต้น (`pStart`) โดยการนำ Base Address ไปบวกกับ `VirtualAddress` ของ Section และดึงขนาดพื้นที่ทั้งหมด (`dwSize`) มาจาก `Misc.VirtualSize`

   - **ขั้นตอน 4 สแกนหา Opcode** นี่คือหัวใจของฟังก์ชันนี้ เราจะทำการวนลูปอ่านค่าใน Memory ทีละ Byte เพื่อหาลำดับของ Opcode 3 ตัวติดกัน ด้วยการใช้ for loop แล้วใช้ Array ในการกำหนดตำแหน่งที่เราจะเข้าไปอ่านหา Opcode
   
   - `0x0F` และ `0x05` คือ คำสั่ง `syscall`
   - `0xC3` คือ คำสั่ง `ret`

   พอเราเจอ Pattern `0x0F 0x05 0xC3` โค้ดจะหยุดทำงานเพื่อไม่ให้ทำงานต่อหลังหน้าที่จบแล้ว และ Return Address ของชุดคำสั่งนี้กลับไปทันที

   เจ้าตัว Address ที่ฟังก์ชันนี้ Return กลับไป จะถูกนำไปเก็บไว้ใช้ในขั้นตอนสุดท้าย แทนที่เราจะเขียนคำสั่ง `syscall` ลงใน Payload ของเราตรงๆ เราจะใช้คำสั่ง `JMP [Gadget_Address]` เพื่อกระโดดมาที่นี่แทน ทำให้ EDR ที่จับตาดูการเรียก `Syscall (ผ่าน ETW-Ti)` เห็นว่าคำสั่งนี้ถูกเรียกมาจากพื้นที่ที่ถูกต้องตามกฎหมายของระบบปฏิบัติการ นั้นคือ ntdll.dll
   
   แต่อย่างไรก็ตาม ปัญหา Unbacked Memory ก็ยังถูกตรวจพบได้อยู่ดี แบบที่กล่าวไปใน หัวข้อ Kernel Callbacks &`ETW-Ti` ที่ [__Main](__Main.md)  

#### 3. Register Preparation 
จัดเตรียมพารามิเตอร์ลงใน CPU Registers (`rcx`, `rdx`, `r8`, `r9`, `r10`) และนำเลข SSN ใส่ใน `eax` ตามมาตรฐานของ Windows x64 Calling Convention

![](../Images/Pasted%20image%2020260329234851.png)
   
   ภาพ: การเขียน Assembly Stub แบบ Intel Syntax ด้วยรูปแบบ Generic 
 
   **การสร้าง Execution Stub สำหรับ `Indirect Syscall` (The Final Execution)**

   หลังจากที่เราได้ค่า System Service Number (SSN) และที่อยู่ของ `syscall; ret` (Gadget) มาแล้ว ขั้นตอนสุดท้ายคือการเขียนฟังก์ชันเพื่อทำหน้าที่จัดเตรียม CPU Register และ Stack ให้พร้อมก่อนจะกระโดดเข้าสู่ Ring 0

   จากภาพ Code Snippet ของฟังก์ชัน `NtAlloc` เราสามารถถอดรหัสกลไกการทำงานระดับ Assembly ได้ดังนี้:

   - **1. การใช้ Naked Function (`__attribute__((naked))`)** การประกาศแอตทริบิวต์นี้มีความสำคัญระดับคอขาดบาดตาย เพราะมันเป็นการสั่งให้ Compiler **"ห้าม"** สร้าง Function Prologue และ Epilogue (เช่น `push rbp; mov rbp, rsp`) โดยเด็ดขาด เพื่อให้เราสามารถควบคุม Stack Pointer (`RSP`) และ Register ได้แบบ 100% ป้องกันไม่ให้โครงสร้าง Stack ผิดเพี้ยนก่อนเรียก `Syscall`

   - **2. การจัดระเบียบ Parameter บน Registers (x64 Calling Convention)** ฟังก์ชัน Wrapper ของเรารับค่า `dwSSN` (เข้าทาง `RCX`) และ `pGadget` (เข้าทาง `RDX`) ซึ่งไปเบียดบังที่อยู่ของ Parameter จริงๆ ของ API เราจึงต้องทำการ "สับเปลี่ยน" (Shift) ตำแหน่งใหม่ให้ตรงตามที่ Kernel คาดหวัง:
	
       - `mov r11, rdx`  เก็บ Gadget Address ไว้ใน `r11` เพื่อเตรียมกระโดด
    
       - `mov r10, r8`  ย้าย Parameter ตัวที่ 1 (`ProcessHandle`) ไปไว้ที่ `r10` (กฎของ Syscall จะใช้ `r10` แทน `rcx`)
    
       - `mov rdx, r9`  ย้าย Parameter ตัวที่ 2 (`BaseAddress`) ไปที่ `rdx`

- **3. การจัดการ Shadow Space และ Stack Shifting** สำหรับ Parameter ตัวที่ 3 เป็นต้นไป จะถูกเก็บอยู่บน Stack โค้ดทำการดึงค่าโดยคำนวณ Offset อย่างแม่นยำ:
    
    * `[rsp + 40]` มาจาก **Shadow Space (32 Bytes) + Return Address (8 Bytes)**
    
    - เนื่องจาก `NtAllocateVirtualMemory` ต้องการพารามิเตอร์ถึง 6 ตัว โค้ดจึงทำการดึงพารามิเตอร์ตัวที่ 5 และ 6 (ที่ตกไปอยู่ตำแหน่ง `[rsp + 56]` และ `[rsp + 64]`) ย้ายกลับขึ้นมาวางแทนที่ในตำแหน่ง `[rsp + 40]` และ `[rsp + 48]` ตามลำดับ เพื่อให้เมื่อกระโดดไปหา Kernel แล้ว ระบบจะดึงค่าจาก Stack ได้อย่างถูกต้องพอดี

- **4. ส่วนการสั่งทำงาน**
	
    - `mov eax, ecx`  นำเลข SSN ที่อยู่ในส่วนล่างของ `rcx` (คือ `ecx`) ไปใส่ไว้ใน `eax` ซึ่งเป็น Register มาตรฐานที่ Kernel จะอ่านค่า SSN
    
    - `jmp r11`  แทนที่เราจะพิมพ์คำสั่ง `syscall` ในโค้ดของเราแบบ `Direct Syscall` เราสั่งให้ CPU **"กระโดด"** ไปรันคำสั่ง `syscall; ret` ที่อยู่ใน `ntdll.dll` จริงๆ นี้คือที่มาของชื่อ `Indirect Syscall`

#### 4. Wrapper Function
Wrapper ตัวนี้เป็นด่านจัดระเบียบข้อมูลก่อนโยนไปทำงานด้วย Assembly Stub

![](../Images/Pasted%20image%2020260330001845.png)

ภาพ: Wrapper Function ของ `NtAllocateVirtualMemory`

   - **1. Type Safety & Memory Alignment** ระบุชนิดตัวแปร เช่น `HANDLE`, `PVOID*` ให้ถูกต้อง ช่วยป้องกันการส่งข้อมูลผิดขนาดก่อนโยนลง Stack และ Register หากส่งผิดขนาดแม้แต่ Byte เดียว โครงสร้าง Stack จะพังและเกิด Memory Corruption ทันที 

   - **2. Zero-Overhead Bridge** โค้ดมีเพียงคำสั่ง `return NtAlloc(...)` ตัว Complier จะ Optimize ให้เป็นการ Jump ไปหา ASM Stub โดยตรง ไม่มีการสร้าง Stack Frame ใหม่ซ้ำซ้อน โค๊ดจะเร็วมาก

   - **3. Abstraction for Stability** ช่วยซ่อนตัวแปร `SSN` และ `Gadget` เอาไว้ ทำให้ Main Payload เรียกใช้งานง่ายเหมือน Windows API ปกติ ลดโอกาสเกิดบั๊กที่อาจทำให้โปรแกรมแครชขณะทำงาน

#### 5. Cleanup
การเรียกใช้ `MyNtFreeVirtualMemory` ในตอนท้ายของโปรแกรม ต้องทำเพื่อเป็นการเคลียร์ร่องรอยการจอง Memory ที่ทำไปในตอนแรก ทำให้ไม่มี Memory trace หลังช่วง Post-Exploitation ช่วยให้ตัว Shellcode ของเรารอดจากการตรวจจับมากขึ้นในทางอ้อม

![](../Images/Pasted%20image%2020260330001939.png)

ภาพ: การทำ Cleanup โดยใช้ทั้ง `NtFreeVirtualMemory`

   - **Flag `MEM_RELEASE`** สังเกตพารามิเตอร์ตัวสุดท้ายในโค้ดที่เป็น `MEM_RELEASE` การใช้ Flag นี้สั่งให้ Kernel ทำการ **`Unmap`** พื้นที่หน่วยความจำนั้นออกจาก VAD (Virtual Address Descriptor) ของโพรเซสเราอย่างถาวร
   
   - หากเราใช้แค่ `MEM_DECOMMIT` ข้อมูลจะหายไปก็จริง แต่ "โครงสร้าง" ของ Memory Page ยังคงจองไว้ ซึ่งถือเป็นพฤติกรรมน่าสงสัย การใช้ `MEM_RELEASE` คือการคืนพื้นที่ให้ OS อย่างสมบูรณ์ ทำให้ Memory Address นั้นกลับไปเป็น Unallocated Space ทันที

   - คำถามที่ตามมา ทำไมเราไม่ใช้ `VirtualFree` ธรรมดา? เพราะถ้า EDR ทำการ Hook `NtFreeVirtualMemory` อยู่ มันจะเห็นทันทีว่าเรากำลังพยายามลบ Memory Address ไหนทิ้ง (ซึ่งอาจใช้เป็นเบาะแสโยงกลับมาหาตัวเราได้) การใช้ `MyNtFreeVirtualMemory` ผ่านกลไก `Indirect Syscall` จึงทำให้แม้แต่กระบวนการทำลายหลักฐาน ก็ยังเป็น **Stealth Mode** ปิดหูปิดตา EDR ได้อย่างสมบูรณ์

   - การเช็คเงื่อนไข `if (statusFree == 0)` เป็นการรับประกัน Stability ของโปรแกรม หากการลบหน่วยความจำสำเร็จ โปรแกรมจะจบการทำงานโดยไม่เกิด Error โยนกลับไปที่ OS ซึ่งเป็นการหลีกเลี่ยงการกระตุ้น Behavioral Analytics ของ EDR ที่มักจะจับตามอง Process ที่มีพฤติกรรม Crash หรือ Terminate แบบผิดปกติ

![](../Images/Pasted%20image%2020260330002254.png)

ภาพ: การใช้ฟังก์ชัน `WaitForSingleObject` และ `CloseHandle`

#### **การ Synchronization และคืนทรัพยากรระดับ Kernel

   - **`WaitForSingleObject(hThread, 10);` (The Execution Window)** สั่ง Main Thread ให้หยุดรอเพื่อให้ Thread ของ Payload ได้เริ่มทำงาน ตามปกติแล้ว Shellcode ที่มีความซับซ้อนเช่น C2 Agent หรือ Ransomware จะตั้งเวลารอไว้นานกว่านี้ (อาจถึงหลักวินาที) แต่เพราะ PoC นี้ใช้แค่ Shellcode เครื่องคิดเลขตรวจสอบ จึงตั้งเวลาไว้แค่ 10 Millisecond พอ

   - **`CloseHandle(hThread);`** เพื่อของความปลอดภัยของ System Memory ทันทีที่ Thread จบหน้าที่แล้ว การเรียกปิด Handle คือการตัดขาดการเชื่อมต่อระหว่าง Main Process กับ Thread นั้น เพื่อป้องกันปัญหา Handle Leak ตัว Loader จะคืนทรัพยากรให้ OS ทันที และเป็นการลบร่องรอยใน Handle Table ไม่ให้ EDR ใช้แกะรอยย้อนกลับได้
### อ่านผลการทดสอบได้ที่นี่
### [Indirect Syscalls Result Tests](Test%20Results/Indirect%20Syscalls%20Result%20Tests.md)
