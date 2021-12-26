MAKEFLAGS += -s

COMPILER_x86 		= i686-w64-mingw32-gcc
COMPILER_x64 		= x86_64-w64-mingw32-gcc

CFLAGS 				= -masm=intel

INCLUDE				= -I include
SOURCE 				= $(wildcard src/*.c)

%.o : %.s
	nasm -f win64 $< -o $@

all: x64 x86

x64: src/Syscall.o
	$(COMPILER_x64) src/*.o $(INCLUDE) $(SOURCE) $(CFLAGS) -o ../bin/KaynInject.x64.exe -DDEBUG -lntdll -DWIN_X64

x86:
	$(COMPILER_x86) src/*.o $(INCLUDE) $(SOURCE) $(CFLAGS) -o ../bin/KaynInject.x86.exe -DDEBUG -lntdll
