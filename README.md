
# KaynLdr
### About
Kayn Loader is a Reflective Loader written in C / ASM.
It uses direct syscalls to allocate virtual memory as RW and changes it to RX. 

### Features
- Uses direct syscall ([TartarusGate](https://github.com/trickster0/TartarusGate) by [trickster0](https://twitter.com/trickster012)) 
- Erases the DOS header/PE header and NT header

### TODO
- Add Hooks
- Rewrite most functions in assembly
- x86 support
- Add cna file for Cobalt Strike User Defined Reflective DLL Loader

### Credits:
- [@NinjaParanoid](https://twitter.com/NinjaParanoid): Blog post about OpSec Reflective Loader
- [@0xBoku](https://twitter.com/0xBoku): User Defined Cobalt Strike Loader
- [@ilove2pwn_](https://twitter.com/ilove2pwn_): TitanLdr
- [trickster0](https://twitter.com/trickster012)
