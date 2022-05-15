
# KaynLdr
### About
KaynLdr is a Reflective Loader written in C / ASM.

### Features
- Erases the DOS and NT header
- Library/Api used:
  - ntdll.dll 
    - LdrLoadDll
    - NtAllocateVirtualMemory
    - NtProtectVirtualMemory

### TODO
- Add Hooks
- x86 support

![Preview](https://pbs.twimg.com/media/FHe1LP-X0AoPxav?format=png&name=medium)

### Credits:
- [@NinjaParanoid](https://twitter.com/NinjaParanoid): [PE Reflection: The King is Dead, Long Live the King](https://bruteratel.com/research/feature-update/2021/06/01/PE-Reflection-Long-Live-The-King/)
- [@0xBoku](https://twitter.com/0xBoku): [User Defined Cobalt Strike Loader](https://github.com/boku7/CobaltStrikeReflectiveLoader)
- [@ilove2pwn_](https://twitter.com/ilove2pwn_): [TitanLdr](https://github.com/SecIdiot/TitanLdr)
- [trickster0](https://twitter.com/trickster012) [TartarusGate](https://github.com/trickster0/TartarusGate/) direct syscall method
