## Disclaimer: This project is for educational and security research purposes only, the author is not responsible for any misuse of this tool.
คำเตือน: โปรเจคนี้มีไว้เพื่อจุดประสงค์ทางการศึกษาและการวิจัยเท่านั้น ผู้เขียนไม่ขอรับผิดชอบในทุกกรณีหากมีการนำเนื้อหาไปใช้ในทางที่ผิด.

# Modern Windows Loader PoC Research

โครงการนี้เป็นโครงการวิจัย Offensive Security ที่มุ่งเน้นการพัฒนา Loader บนระบบปฏิบัติการ Windows โดยใช้เทคนิค Evasion ขั้นสูง เพื่อศึกษาการทำงานของ Endpoint Detection and Response / Antivirus และกลไกการตรวจจับในระดับ Kernel-mode และ User-mode

โปรเจกต์นี้เขียนขึ้นด้วยภาษา **C++** และ **x64 Assembly** โดยเน้นความเข้าใจในระดับ Windows Internals โดยได้มีการ Implement เทคนิคที่ใช้ในการทำ Red Teaming และ Malware Development ระดับสากล ดังนี้ต่อไปนี้

- **Indirect Syscall** เป็นเทคนิคการเรียกใช้ Native API ภายใน Loader โดยตรงเพื่อสื่อสารกับระบบ Kernel โดยตรงจากพื้นที่ Ring 3 โดยไม่ผ่านการเรียกใช้ WIN API ปกติเพื่อหลบหลีก Inline hooking ที่มักถูกวางไว้ใน Disk ใช้การทำ Dynamic SSN Resolution เพื่อหา System Service Numbers โดยตรงจาก Disk หรือ Memory หลบหลีกการดักจับแบบ Inline Hooking ของ EDR โดยการกระโดดไปยัง `syscall` instruction ภายใน `ntdll.dll` ดั้งเดิม
        
- **Module Stomping** เทคนิคการปลอมตัวของ Loader โดยต้องเขียนทับหน่วยความจำของ Legitimate Signed DLL ที่ถูกโหลดขึ้นมา เพื่อซ่อน Shellcode ไว้ในหน่วยความจำที่ดูน่าเชื่อถือ หลบการสแกนแบบ Private Memory ใช้ DLL ที่เราโหลดขึ้นมาบังหน้า
    
- **Stack Spoofing** เป็นการทำ Obfuscation เลียนแบบ Stack ที่มีขั้นตอนการเรียกใช้แบบถูกกฎหมายให้กับ Call Stack เพื่อป้องกันการทำ **Stack-based Detection** ด้วยกระบวนการ ETW-Ti จาก EDR 

---

## Build

**Compiler** 
- Visual Studio 2022 (v143)
    
**Programming Language**
- ISO C++20
- x64 Assembly
- LLVM (Clang-Cl)
    
**Architecture** 
- Windows x64

---

## Documentation

รายละเอียดเชิงลึกเกี่ยวกับที่มาที่ไป, Logic การออกแบบ, ขั้นตอนการพัฒนา และผลการวิเคราะห์ผ่าน Debugger สามารถอ่านต่อได้ที่รายงานฉบับสมบูรณ์ด้านล่างนี้


🔗 [Read Full Technical Report](https://github.com/sukritmrk/Portfolio/tree/main/docs/Report)
🔗 [View Proof-of-Concept Source code](https://github.com/sukritmrk/Portfolio/tree/main/src)
