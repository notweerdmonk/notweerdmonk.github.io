# Not so obvious

The [previous](https://notweerdmonk.github.io/items/tiny_elf/tiny_elf) post about reducing the size of an executable that prints a short string to the standard output. In this post we shall further reduce its size but only by a tinier bit.

This is the assembly source form previous post:

```asm
# asm.s
.global _start
.text

_start:
    movl    $4, %eax
    movl    $1, %ebx
    movl    $msg, %ecx
    movl    $len, %edx
    int     $0x80

    movl    $1, %eax
    xorl    %ebx, %ebx
    int     $0x80

.data
msg:
    .asciz "hello, world\n"
.equ len, . - msg
```

There is not much scope for optimizations in the source code here. We need to think in terms of functionality of the program, that is printing a string to the standard output. If we constrain our assumptions of what printing to the standard output can imply, we may find some room. Most people run programs on a `terminal` through a program called `shell`. A Linux process has by default, the file descriptor `0` assigned to the standard input stream, the file descritor `1` assigned to the standard output stream and the file descriptor `2` assigned to the standard error stream. These streams correspond to standard I/O streams of the shell process. The `proc` filesystem provides information about a process referenced via a directory named as its `pid`. We can inspect the open file descriptors for a process by checking the `fd` subdirectory. The pid string `self` always refers to the current executing process.

```
$ bash
$ ls /proc/self/fd
0  1  2  3
$
$ stat /proc/self/fd/0 | sed -n '1,2p'
  File: /proc/self/fd/0 -> /dev/pts/2
  Size: 64              Blocks: 0          IO Block: 1024   symbolic link
$
$ stat /proc/self/fd/1 | sed -n '1,2p'
  File: /proc/self/fd/1 -> /dev/pts/2
  Size: 64              Blocks: 0          IO Block: 1024   symbolic link
$
$ stat /dev/pts/2 | sed -n '1,4p' | sed 's/\(Uid: ( [0-9]*\/\)[a-zA-Z0-9_-]*/\1lolz/g'
  File: /dev/pts/2
  Size: 0               Blocks: 0          IO Block: 1024   character special file
Device: 18h/24d Inode: 5           Links: 1     Device type: 88,2
Access: (0620/crw--w----)  Uid: ( 1000/lolz)   Gid: (    5/     tty)
```

Both the file descriptors `0` and `1` for a shell represent a single file `/dev/pts/2`. This is a character device. Notice something interesting?

**Access: (0620/crw--w----)**  Uid: ( 1000/lolz)   Gid: (    5/     tty)

```
$ echo "bello" > /dev/pts/2
bello
$
$ echo "bello" > /proc/self/fd/0
bello
```

The file is marked read-write for its owner. And writing to it indeed writes to the terminal. Consequently writing to the standard input of the shell also writes to the terminal!

In the assembly program, we can actually write to file descriptor `0` and still print the string to the terminal. How can we leverage this? We shall pass 0 as the second argument to the `write` syscall following its syscall number and this simplifies some things.

```asm
# load 0 into a register using mov
    movl    $0, %ebx

# produces such machine code
 8048059:       bb 00 00 00 00          mov    $0x0,%ebx

# clear a register using xor
    xorl    %ebx, %ebx

# produces lesser machine code
 8048059:       31 db                   xor    %ebx,%ebx
```

Here is the modified assembly source:

```asm
# asm.s
.global _start
.text

_start:
    movl    $4, %eax
    xorl    %ebx, %ebx
    movl    $msg, %ecx
    movl    $len, %edx
    int     $0x80

    movl    $1, %eax
    xorl    %ebx, %ebx
    int     $0x80

.data
msg:
    .asciz "hello, world\n"
.equ len, . - msg
```

Assembling and analyzing the assembly source:

```
$ make
gcc -m32 -c -o asm.o asm.s
ld -m elf_i386 --omagic --strip-all -o asm asm.o
Extracting 126 bytes from ELF file
$
$ du --apparent-size -h asm
312     asm
$
$ xxd asm
00000000: 7f45 4c46 0101 0100 0000 0000 0000 0000  .ELF............
00000010: 0200 0300 0100 0000 5480 0408 3400 0000  ........T...4...
00000020: 9800 0000 0000 0000 3400 2000 0100 2800  ........4. ...(.
00000030: 0400 0300 0100 0000 5400 0000 5480 0408  ........T...T...
00000040: 5480 0408 2a00 0000 2a00 0000 0700 0000  T...*...*.......
00000050: 0100 0000 b804 0000 0031 dbb9 7080 0408  .........1..p...
00000060: ba0e 0000 00cd 80b8 0100 0000 31db cd80  ............1...
00000070: 6865 6c6c 6f2c 2077 6f72 6c64 0a00 002e  hello, world....
00000080: 7368 7374 7274 6162 002e 7465 7874 002e  shstrtab..text..
00000090: 6461 7461 0000 0000 0000 0000 0000 0000  data............
000000a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000c0: 0b00 0000 0100 0000 0700 0000 5480 0408  ............T...
000000d0: 5400 0000 1c00 0000 0000 0000 0000 0000  T...............
000000e0: 0100 0000 0000 0000 1100 0000 0100 0000  ................
000000f0: 0300 0000 7080 0408 7000 0000 0e00 0000  ....p...p.......
00000100: 0000 0000 0000 0000 0100 0000 0000 0000  ................
00000110: 0100 0000 0300 0000 0000 0000 0000 0000  ................
00000120: 7e00 0000 1700 0000 0000 0000 0000 0000  ~...............
00000130: 0100 0000 0000 0000                      ........
$
$ du --apparent-size -h asm.tiny
126     asm.tiny
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
$ ./asm.tiny
hello, world
$
```

We have an ELF file which prints a short string to the terminal that is 126 bytes in size. Check the [programs](https://github.com/notweerdmonk/notweerdmonk.github.io/tree/master/items/not_so_obvious/programs) directory for source code.
