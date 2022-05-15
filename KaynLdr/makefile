MAKEFLAGS += -s

COMPILER_x86 		= i686-w64-mingw32-gcc
COMPILER_x64 		= x86_64-w64-mingw32-gcc

CFLAGS 				= -s -w -Wall -Wextra -masm=intel -shared -fPIC -e DllMain -Os -fno-asynchronous-unwind-tables

INCLUDE				= -I include
SOURCE 				= $(wildcard src/*.c)

x64:
	nasm -f win64 src/Util.s -o src/Util.o
	$(COMPILER_x64) src/*.o $(INCLUDE) $(SOURCE) $(CFLAGS) -o ../bin/KaynLdr.x64.dll -lntdll -luser32 -DWIN_X64
	rm src/*.o