# Tiny Elf

Dave Plummer posted on twitter asking out for tips to compact a computer program executable that prints a short string. This was in response to an ongoing online ruse to compare executable sizes across different programming languages. He provided well documented GNU-style assembly code albeit as a screenshot.

This is the original assembly code:

```assembly
# asm.s
.global _start
.text

_start:
    # write(1, message, 13)
    movl    $4, %eax        # sys_write
    movl    $1, %ebx        # stdout
    movl    $message, %ecx  # message
    movl    $13, %edx       # length
    int     $0x80          # syscall

    # exit(0)
    movl    $1, %eax        # sys_exit
    xorl    %ebx, %ebx      # status 0
    int     $0x80           # syscall

.data
message:
    .ascii "Hello, World!\n"
```

We can assemble this source with `gcc` driver and link the object file with `ld`. We shall choose 32-bit architecture. While linking, we shall use the `--omagic` option for `ld`. The OMAGIC format shall be chosen which uses the least amount of space. In terms of layout of the ELF file, this option will avoid page-alignment of the data segment saving extra padding. There is a downside that the text and data sections will be marked writable in addition to readable. Symbol data can be omitted with the `--strip-all` option for `ld`.

```
$ gcc -m32 -c -o asm.o asm.s
$ ld -m elf_i386 --omagic --strip-all -o asm asm.o
$
$ ls
asm asm.o asm.s
$
$ ./asm
Hello, World$
$
$ du --apparent-size -h asm
312
$
$ xxd asm
00000000: 7f45 4c46 0101 0100 0000 0000 0000 0000  .ELF............
00000010: 0200 0300 0100 0000 5480 0408 3400 0000  ........T...4...
00000020: 9800 0000 0000 0000 3400 2000 0100 2800  ........4. ...(.
00000030: 0400 0300 0100 0000 5400 0000 5480 0408  ........T...T...
00000040: 5480 0408 2d00 0000 2d00 0000 0700 0000  T...-...-.......
00000050: 0100 0000 b804 0000 00bb 0100 0000 b973  ...............s
00000060: 8004 08ba 0e00 0000 cd80 b801 0000 0031  ...............1
00000070: dbcd 8068 656c 6c6f 2c20 776f 726c 640a  ...hello, world.
00000080: 0000 2e73 6873 7472 7461 6200 2e74 6578  ...shstrtab..tex
00000090: 7400 2e64 6174 6100 0000 0000 0000 0000  t..data.........
000000a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000c0: 0b00 0000 0100 0000 0700 0000 5480 0408  ............T...
000000d0: 5400 0000 1f00 0000 0000 0000 0000 0000  T...............
000000e0: 0100 0000 0000 0000 1100 0000 0100 0000  ................
000000f0: 0300 0000 7380 0408 7300 0000 0e00 0000  ....s...s.......
00000100: 0000 0000 0000 0000 0100 0000 0000 0000  ................
00000110: 0100 0000 0300 0000 0000 0000 0000 0000  ................
00000120: 8100 0000 1700 0000 0000 0000 0000 0000  ................
00000130: 0100 0000 0000 0000                      ........
```

The ELF is quite small, about 312 bytes. It can be made smaller because there are parts that are not required for the ELF to be able to execute. 

Let us delve into the structure of an ELF file. The ELF header for 32-bit architecture is 52 bytes long, each program header entry in the program header table is 32 bytes long and each section header in the section header table is 40 bytes long. The ELF header contains architecture information, entry point in the program and information about next parts. Program headers contain information pertaining to the portions of ELF that are either loaded into the memory or provide information about how the execution process image is organized in the memory. These are called segments. Segments contain one or more sections. Each of the sections is described by an entry in the section header table. Now don't confuse between the memory segments in the address space of execution process namely `.text`, `.data`, `.bss`, `.rodata` et al. and the segments in the ELF file. We will be definitely needing the ELF header and program header table for the ELF to be able to execute but we do not need the section header table.

```
readelf -egt asm
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Intel 80386
  Version:                           0x1
  Entry point address:               0x8048054
  Start of program headers:          52 (bytes into file)
  Start of section headers:          152 (bytes into file)
  Flags:                             0x0
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         1
  Size of section headers:           40 (bytes)
  Number of section headers:         4
  Section header string table index: 3

Section Headers:
  [Nr] Name
       Type            Addr     Off    Size   ES   Lk Inf Al
       Flags
  [ 0]
       NULL            00000000 000000 000000 00   0   0  0
       [00000000]:
  [ 1] .text
       PROGBITS        08048054 000054 00001c 00   0   0  1
       [00000007]: WRITE, ALLOC, EXEC
  [ 2] .data
       PROGBITS        08048070 000070 00000e 00   0   0  1
       [00000003]: WRITE, ALLOC
  [ 3] .shstrtab
       STRTAB          00000000 00007e 000017 00   0   0  1
       [00000000]:

There are no section groups in this file.

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  LOAD           0x000054 0x08048054 0x08048054 0x0002a 0x0002a RWE 0x1

 Section to Segment mapping:
  Segment Sections...
   00     .text .data
```

Inspecting the ELF we find that there is one program header entry corresponding to a single segment containing both the `.text` and `.data` sections. At an offset of 28 (0x1C) into the ELF header there is a four byte field that points to the start of the program header table in the file. This value will be 0x00000034 for 32-bit architecture. At an offset of 4 into a program header entry there is a four byte field that stores the offset of the correspoding segment in the file. This field will be at an offset of 56 (0x38) from the beginning of the file. This value is 0x00000054 for our ELF. The size of the segment in the file is stored in a four byte field at an offset of 16 (0x10) into a program header entry, and at an offset of 68 (0x44) from the beginning of the file. This value is 42 (0x0000002a) for our ELF. Therefore we need a total of 126 bytes from the beginning of the file. 

```
$ dd bs=1 count=126 if=asm of=asm.tiny
$
$ xxd asm.tiny
00000000: 7f45 4c46 0101 0100 0000 0000 0000 0000  .ELF............
00000010: 0200 0300 0100 0000 5480 0408 3400 0000  ........T...4...
00000020: 9800 0000 0000 0000 3400 2000 0100 2800  ........4. ...(.
00000030: 0400 0300 0100 0000 5400 0000 5480 0408  ........T...T...
00000040: 5480 0408 2a00 0000 2a00 0000 0700 0000  T...*...*.......
00000050: 0100 0000 b804 0000 0031 dbb9 7080 0408  .........1..p...
00000060: ba0e 0000 00cd 80b8 0100 0000 31db cd80  ............1...
00000070: 6865 6c6c 6f2c 2077 6f72 6c64 0a00       hello, world..
$
$ readelf -egt asm.tiny
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Intel 80386
  Version:                           0x1
  Entry point address:               0x8048054
  Start of program headers:          52 (bytes into file)
  Start of section headers:          152 (bytes into file)
  Flags:                             0x0
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         1
  Size of section headers:           40 (bytes)
  Number of section headers:         4
  Section header string table index: 3
readelf: Error: Reading 160 bytes extends past end of file for section headers
readelf: Error: Section headers are not available!

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  LOAD           0x000054 0x08048054 0x08048054 0x0002a 0x0002a RWE 0x1
$
$ chmod +x asm.tiny
$ ./asm.tiny
hello, world
```

And that's it! We have an ELF which prints a short string that is 126 bytes in size. Check the [programs](https://github.com/notweerdmonk/notweerdmonk.github.io/tree/master/items/tiny_elf/programs) directory for source code.
