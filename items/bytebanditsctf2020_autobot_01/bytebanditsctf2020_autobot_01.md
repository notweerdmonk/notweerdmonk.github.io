# ByteBandits CTF 2020 - Autobot - Part 1

###### Prologue

This writeup walks through the `autobot` challenge from ByteBandits CTF 2020. The challenge was hosted on `pwn.byteband.it:6000`. On connecting to the service, some data is sent to the client. Analyzing this data we observe that its a stream of printable ASCII characters ending with the distinctive `==`. Off the top of one's head one might consider it to be base64 encoding. In practice this is the case. The server sends us a base64 encoded file. After sending this data, the server expects to receive some data from the client. If we sent just any ASCII string, it replies back with "Wrong pass" and closes the connection. What if we send the correct data? What is the correct data? Let us analyze the file.

The writeup shall span multiple articles. In this first part we shall merely discover the `main` function.

###### Mainly main

The provided file is 64-bit ELF that is stripped of symbols. In order to figure out the program we need to discover the `main` function.

```
$ file autobot
autobot: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=1949ab03912157bede748c49f29832aa8804d559, stripped
```

Fire up `gdb` with the ELF. We don't have any function names to attach a breakpoint to. Instead we can choose to break execution at the very first instruction itself. `gdb` has a command `starti` that accomplishes this. It sets a temporary breakpoint at the first instruction and runs the program till this breakpoint.

```
$ gdb -q ./autobot
(gdb) starti

Program stopped.
0x00007ffff7fe3290 in _start () from /lib64/ld-linux-x86-64.so.2
(gdb) where
#0  0x00007ffff7fe3290 in _start () from /lib64/ld-linux-x86-64.so.2
#1  0x0000000000000001 in ?? ()
#2  0x00007fffffffe023 in ?? ()
#3  0x0000000000000000 in ?? ()
```

Programs stored as ELF files are loaded into the process memory using a program called runtime loader (ld.so). The entry point of `ld.so` is a label `_start` in a assembly routine defined by the macro `RTLD_START`[^1]. Once the program gets loaded, execution is transferred via a jmp instruction to the program's entry point in the `.text` section[^2]. This address stores a assembly routine provided by glibc; `_start` routine that sets up the command line arguments and calls the user's `main` function by calling `__libc_start_main` with the address of the `main`, `argc`, `argv` and other arguments.

The program has been loaded into its process memory. The debugger halts the program at the first instruction at label `_start` from `ld.so`. From here onwards we need to track the execution to the instruction where `_start` from the program's `.text` section gets called. We can inspect the program for its entry point that should be beginning of the .text section.

```
(gdb) info files
Symbols from "/home/weerdmonk/vagrant_boxes/vagrant_kali/bytebandctf/autobot".
Native process:
        Using the running image of child process 2051404.
        While running this, GDB does not access memory from...
Local exec file:
        `/home/weerdmonk/vagrant_boxes/vagrant_kali/bytebandctf/autobot',
        file type elf64-x86-64.
        Entry point: 0x5555554006d0
        0x0000555555400238 - 0x0000555555400254 is .interp
        0x0000555555400254 - 0x0000555555400274 is .note.ABI-tag
        0x0000555555400274 - 0x0000555555400298 is .note.gnu.build-id
        0x0000555555400298 - 0x00005555554002bc is .gnu.hash
        0x00005555554002c0 - 0x00005555554003e0 is .dynsym
        0x00005555554003e0 - 0x0000555555400495 is .dynstr
        0x0000555555400496 - 0x00005555554004ae is .gnu.version
        0x00005555554004b0 - 0x00005555554004e0 is .gnu.version_r
        0x00005555554004e0 - 0x00005555554005d0 is .rela.dyn
        0x00005555554005d0 - 0x0000555555400648 is .rela.plt
        0x0000555555400648 - 0x000055555540065f is .init
        0x0000555555400660 - 0x00005555554006c0 is .plt
        0x00005555554006c0 - 0x00005555554006c8 is .plt.got
        0x00005555554006d0 - 0x0000555555400a92 is .text    --> entry point
        0x0000555555400a94 - 0x0000555555400a9d is .fini
        0x0000555555400aa0 - 0x0000555555400ad3 is .rodata
        0x0000555555400ad4 - 0x0000555555400b18 is .eh_frame_hdr
        0x0000555555400b18 - 0x0000555555400c40 is .eh_frame
        0x0000555555600d98 - 0x0000555555600da0 is .init_array
        0x0000555555600da0 - 0x0000555555600da8 is .fini_array
        0x0000555555600da8 - 0x0000555555600f98 is .dynamic
        0x0000555555600f98 - 0x0000555555601000 is .got
        0x0000555555601000 - 0x0000555555601018 is .data
        0x0000555555601020 - 0x0000555555601030 is .bss
```

Set a breakpoint at this address and continue execution.

```
(gdb) b *0x00005555554006d0
Breakpoint 1 at 0x5555554006d0
(gdb) c
Continuing.

Breakpoint 1, 0x00005555554006d0 in ?? ()
```

The program halts at the first instruction of `_start` from glibc. Here is an excerpt from the glibc `_start` routine.

```
file: sysdeps/x86_64/start.S
ENTRY (_start)

  ...

	/* Extract the arguments as encoded on the stack and set up
	   the arguments for __libc_start_main (int (*main) (int, char **, char **),
		   int argc, char *argv,
		   void (*init) (void), void (*fini) (void),
		   void (*rtld_fini) (void), void *stack_end).
	   The arguments are passed via registers and on the stack:
	main:		%rdi
	argc:		%rsi
	argv:		%rdx
	init:		%rcx
	fini:		%r8
	rtld_fini:	%r9
	stack_end:	stack.	*/

  ...

  	/* Call the user's main function, and exit with its value.
	   But let the libc call main.  Since __libc_start_main in
	   libc.so is called very early, lazy binding isn't relevant
	   here.  Use indirect branch via GOT to avoid extra branch
	   to PLT slot.  In case of static executable, ld in binutils
	   2.26 or above can convert indirect branch into direct
	   branch.  */
	call *__libc_start_main@GOTPCREL(%rip)

  ...

```

Although there are no symbols in the ELF file we can disassemble the machine code using a start address and a length in terms of bytes. Registers can be used in the expression to define the start address. We need the address of the current instruction, and therefore should use `$rip`, for the x86_64 program counter.

Disassemble the instructions from the program counter till 100 bytes.

 ```
(gdb) disas $rip, +100
Dump of assembler code from 0x5555554006d0 to 0x555555400734:
=> 0x00005555554006d0:  xor    ebp,ebp
   0x00005555554006d2:  mov    r9,rdx
   0x00005555554006d5:  pop    rsi
   0x00005555554006d6:  mov    rdx,rsp
   0x00005555554006d9:  and    rsp,0xfffffffffffffff0
   0x00005555554006dd:  push   rax
   0x00005555554006de:  push   rsp
   0x00005555554006df:  lea    r8,[rip+0x3aa]        # 0x555555400a90
   0x00005555554006e6:  lea    rcx,[rip+0x333]        # 0x555555400a20
   0x00005555554006ed:  lea    rdi,[rip+0x30a]        # 0x5555554009fe
   0x00005555554006f4:  call   QWORD PTR [rip+0x2008e6]        # 0x555555600fe0
   0x00005555554006fa:  hlt
   0x00005555554006fb:  nop    DWORD PTR [rax+rax*1+0x0]
   0x0000555555400700:  lea    rdi,[rip+0x200911]        # 0x555555601018
   0x0000555555400707:  push   rbp
   0x0000555555400708:  lea    rax,[rip+0x200909]        # 0x555555601018
   0x000055555540070f:  cmp    rax,rdi
   0x0000555555400712:  mov    rbp,rsp
   0x0000555555400715:  je     0x555555400730
   0x0000555555400717:  mov    rax,QWORD PTR [rip+0x2008ba]        # 0x555555600fd8
   0x000055555540071e:  test   rax,rax
   0x0000555555400721:  je     0x555555400730
   0x0000555555400723:  pop    rbp
   0x0000555555400724:  jmp    rax
   0x0000555555400726:  cs nop WORD PTR [rax+rax*1+0x0]
   0x0000555555400730:  pop    rbp
   0x0000555555400731:  ret
   0x0000555555400732:  nop    DWORD PTR [rax+0x0]
End of assembler dump.
```

This stub of code calls into address 0x555555600fe0 which stores `__libc_start_main`. Put a breakpoint at the `call` instruction, continue exection, step into the `call` instruction with the `stepi` command.

```
(gdb) b *0x00005555554006f4
Breakpoint 2 at 0x5555554006f4
(gdb) c
Continuing.

Breakpoint 2, 0x00005555554006f4 in ?? ()
(gdb) stepi
__libc_start_main_impl (main=0x5555554009fe, argc=1, argv=0x7fffffffdd08, init=0x555555400a20, fini=0x555555400a90, rtld_fini=0x7ffff7fc9040 <_dl_fini>, stack_end=0x7fffffffdcf8) at ../csu/libc-start.c:242
242     ../csu/libc-start.c: No such file or directory.
```

`__libc_start_main_impl` calls `__libc_start_call_main`. glibc contains two implementations for `__libc_start_call_main`, one is a generic version (sysdeps/generic/libc_call_start_main.h) and the other is from the native thread library (sysdeps/nptl/libc_call_start_main.h). Both call the user's `main` function.

Set a breakpoint at `__libc_start_call_main` and continue execition.

```
(gdb) b __libc_start_call_main
Breakpoint 3 at 0x7ffff7da0d10: file ../sysdeps/nptl/libc_start_call_main.h, line 29.
(gdb) c
Continuing.

Breakpoint 3, __libc_start_call_main (main=main@entry=0x5555554009fe, argc=argc@entry=1, argv=argv@entry=0x7fffffffdd18) at ../sysdeps/nptl/libc_start_call_main.h:29
29      ../sysdeps/nptl/libc_start_call_main.h: No such file or directory.
```

It is not straightforward to figure out where the call to user's `main` happens in the disassembled instructions because the address of user's `main` is variable data which gets passed on to `__libc_start_main_impl` as its first argument. As per the x86_64 calling convention, the `rdi` register shall contain this argument. Note that `argc` and `argv` are the second and third arguments passed in `rsi` and `rdx` respectively. When `main` shall get called, it will also follow the same calling convention. The arguments for `main`, `argc`, `argv` and `env` shall be passed in the registers `rdi`, `rsi` and `rdx` respectively. Check the value of `argv`. Tracking the value of either `argc` or `argv` against the `rsi` register can lead us to vicinity of the `call` instruction that calls into user's `main`.

```
(gdb) info reg $rdx
rdx            0x7fffffffdd18      140737488346392
```

We can add a watchpoint with the expression that `rsi` equals the value of `argv`.

```
(gdb) watch $rsi == 0x7fffffffdd18
Watchpoint 4: $rsi == 0x7fffffffdd18
(gdb) c
Continuing.

Watchpoint 4: $rsi == 0x7fffffffdd18

Old value = 0
New value = 1
0x00007ffff7da0d86 in __libc_start_call_main (main=main@entry=0x5555554009fe, argc=argc@entry=1, argv=argv@entry=0x7fffffffdd18) at ../sysdeps/nptl/libc_start_call_main.h:58
58      in ../sysdeps/nptl/libc_start_call_main.h
(gdb) disas
Dump of assembler code for function __libc_start_call_main:
   0x00007ffff7da0d10 <+0>:     push   rax
   0x00007ffff7da0d11 <+1>:     pop    rax
   0x00007ffff7da0d12 <+2>:     sub    rsp,0x98
   0x00007ffff7da0d19 <+9>:     mov    QWORD PTR [rsp+0x8],rdi
   0x00007ffff7da0d1e <+14>:    lea    rdi,[rsp+0x20]
   0x00007ffff7da0d23 <+19>:    mov    DWORD PTR [rsp+0x14],esi
   0x00007ffff7da0d27 <+23>:    mov    QWORD PTR [rsp+0x18],rdx
   0x00007ffff7da0d2c <+28>:    mov    rax,QWORD PTR fs:0x28
   0x00007ffff7da0d35 <+37>:    mov    QWORD PTR [rsp+0x88],rax
   0x00007ffff7da0d3d <+45>:    xor    eax,eax
   0x00007ffff7da0d3f <+47>:    call   0x7ffff7db91e0 <_setjmp>
   0x00007ffff7da0d44 <+52>:    endbr64
   0x00007ffff7da0d48 <+56>:    test   eax,eax
   0x00007ffff7da0d4a <+58>:    jne    0x7ffff7da0d97 <__libc_start_call_main+135>
   0x00007ffff7da0d4c <+60>:    mov    rax,QWORD PTR fs:0x300
   0x00007ffff7da0d55 <+69>:    mov    QWORD PTR [rsp+0x68],rax
   0x00007ffff7da0d5a <+74>:    mov    rax,QWORD PTR fs:0x2f8
   0x00007ffff7da0d63 <+83>:    mov    QWORD PTR [rsp+0x70],rax
   0x00007ffff7da0d68 <+88>:    lea    rax,[rsp+0x20]
   0x00007ffff7da0d6d <+93>:    mov    QWORD PTR fs:0x300,rax
   0x00007ffff7da0d76 <+102>:   mov    rax,QWORD PTR [rip+0x1f023b]        # 0x7ffff7f90fb8
   0x00007ffff7da0d7d <+109>:   mov    edi,DWORD PTR [rsp+0x14]
   0x00007ffff7da0d81 <+113>:   mov    rsi,QWORD PTR [rsp+0x18]
=> 0x00007ffff7da0d86 <+118>:   mov    rdx,QWORD PTR [rax]
   0x00007ffff7da0d89 <+121>:   mov    rax,QWORD PTR [rsp+0x8]
   0x00007ffff7da0d8e <+126>:   call   rax
   0x00007ffff7da0d90 <+128>:   mov    edi,eax
   0x00007ffff7da0d92 <+130>:   call   0x7ffff7dbc5f0 <__GI_exit>
   0x00007ffff7da0d97 <+135>:   call   0x7ffff7e085f0 <__GI___nptl_deallocate_tsd>
   0x00007ffff7da0d9c <+140>:   lock dec DWORD PTR [rip+0x1f0505]        # 0x7ffff7f912a8 <__nptl_nthreads>
   0x00007ffff7da0da3 <+147>:   sete   al
   0x00007ffff7da0da6 <+150>:   test   al,al
   0x00007ffff7da0da8 <+152>:   jne    0x7ffff7da0db8 <__libc_start_call_main+168>
   0x00007ffff7da0daa <+154>:   mov    edx,0x3c
   0x00007ffff7da0daf <+159>:   nop
   0x00007ffff7da0db0 <+160>:   xor    edi,edi
   0x00007ffff7da0db2 <+162>:   mov    eax,edx
   0x00007ffff7da0db4 <+164>:   syscall
   0x00007ffff7da0db6 <+166>:   jmp    0x7ffff7da0db0 <__libc_start_call_main+160>
   0x00007ffff7da0db8 <+168>:   xor    edi,edi
   0x00007ffff7da0dba <+170>:   jmp    0x7ffff7da0d92 <__libc_start_call_main+130>
End of assembler dump.
```

The address of the user's `main` function gets loaded into the `rax` register for the `call` instruction. Set a breakpoint at this instruction and continue execution.

```
(gdb) info reg $rsi
rsi            0x7fffffffdd18      140737488346392
(gdb) b *__libc_start_call_main + 126
Breakpoint 5 at 0x7ffff7da0d8e: file ../sysdeps/nptl/libc_start_call_main.h, line 58.
(gdb) c
Continuing.

Breakpoint 5, 0x00007ffff7da0d8e in __libc_start_call_main (main=main@entry=0x5555554009fe, argc=argc@entry=1, argv=argv@entry=0x7fffffffdd18) at ../sysdeps/nptl/libc_start_call_main.h:58
58      in ../sysdeps/nptl/libc_start_call_main.h
(gdb) x/i $rip
=> 0x7ffff7da0d8e <__libc_start_call_main+126>: call   rax
```

The program halts at the `call` instruction. Step inside the function call.

```
(gdb) stepi
0x00005555554009fe in ?? ()
(gdb) disas $rip, +30
Dump of assembler code from 0x5555554009fe to 0x555555400a62:
=> 0x00005555554009fe:  push   rbp
   0x00005555554009ff:  mov    rbp,rsp
   0x0000555555400a02:  mov    eax,0x0
   0x0000555555400a07:  call   0x5555554007da
   0x0000555555400a0c:  mov    eax,0x0
   0x0000555555400a11:  pop    rbp
   0x0000555555400a12:  ret
   0x0000555555400a13:  cs nop WORD PTR [rax+rax*1+0x0]
End of assembler dump.
```

We halt at the first instruction of the `main` function which starts from address `0x5555554009fe`.

###### Epilogue

This concludes the first part. It takes quite some effort to find the `main` function from a binary stripped off symbols. There are tools that make it easier. On rainydays one may benefit from this [GDB script](https://github.com/notweerdmonk/notweerdmonk.github.io/blob/main/items/bytebanditsctf2020_autobot_01/programs/find_main.py).



[^1]: https://s.eresi-project.org/inc/articles/elf-rtld.txt
[^2]: https://stevens.netmeister.org/631/elf.html
