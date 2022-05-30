CCX64	:= x86_64-w64-mingw32-gcc
CCX86	:= i686-w64-mingw32-gcc

CFLAGS	:= -Os -fno-asynchronous-unwind-tables -nostdlib
CFLAGS 	+= -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS  += -s -ffunction-sections -falign-jumps=1 -w
CFLAGS	+= -falign-labels=1 -fPIC # -Wl,-Tscripts/Linker.ld
CFLAGS	+= -Wl,-s,--no-seh,--enable-stdcall-fixup

OUTX64	:= bin/KaynStrike.x64.exe
BINX64	:= bin/KaynStrike.x64.bin

all: x64

x64:
	@ echo Compile executable...
	@ nasm -f win64 src/KAssembly.s -o bin/KAssembly.x64.o
	@ $(CCX64) src/*.c bin/KAssembly.x64.o -o $(OUTX64) $(CFLAGS) $(LFLAGS) -Iinclude -masm=intel
	@ echo [*] Extract .text section into $(BINX64)
	@ python3 scripts/extract.py -f $(OUTX64) -o $(BINX64)

clean:
	@ rm -rf bin/*.o
	@ rm -rf bin/*.bin
	@ rm -rf bin/*.exe
