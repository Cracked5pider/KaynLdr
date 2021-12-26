; exported functions
global SyscallPrepare
global SyscallInvoke

section .text

    ;; set syscall value in r11 register
    SyscallPrepare:
        nop
        xor r11, r11
        nop
        nop
        mov r11d, ecx
    ret

    ;; Invoke Syscall and pass given arguments
    SyscallInvoke:
        nop
        xor eax, eax
        mov r10, rcx
        nop
        mov eax, r11d
        nop
        syscall
        nop
    ret