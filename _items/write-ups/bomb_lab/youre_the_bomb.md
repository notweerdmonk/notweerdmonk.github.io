---
title: "You're the bomb"
date: 2026-06-06 09:15:18 +00:00
layout: article
permalink: /write-ups/bomb_lab/
description: ""
categories: [write-up, reverse engineering, laboratory, assignment]
tags: [write-up, rev, reverse engineering, laboratory, assignment, ELF, gdb, x86, debugger, disassembly, calling conventions]
author: "notweerdmonk"
draft: false
canonical_url: "https://notweerdmonk.github.io/write-ups/bomb_lab/"
---
# Bomb Lab CS:APP2e CMU

Before we plunge into lines of assembly code here is some background. This
reverse engineering assignment is part of a course offered at CMU[^1]. Its
appropriately named _Bomb Lab_ as the task provides a **binary bomb** to
students. This binary requires six strings from the user which are read either
from the standard input or a text file. Providing an incorrect string will set
off the bomb! The pupils need to find the six strings to successfully defuse
the bomb.

I stumbled upon this on the internet few years back when I was beginning to
learn reversing binaries. Many thanks to [xuzhezhaozhao](https://github.com/xuzhezhaozhao/) for sharing the binary
and laboratory write-up[^2]. You shall be provided with a tar file containing
the binary.

---

Now armed with linux, `bash` and the ever amazing `gdb`, we set out to defuse
this binary bomb.

```console
$ file bomb
bomb: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.0.0, not stripped
```

The convenient way is to use a virtual machine emulator/hypervisor like `qemu`,
`VirtualBox`, `vagrant` or whatever other virtual machine feels sane. Next you
need a 32-bit Linux distro (you can also do this on a Windows or Mac machine,
forage around the internet). Make sure to have atleast the common Unix tools
like `file`, `strings`, `gdb`, etc installed before you proceed. This task make
me learn using `gdb` in an entirely new light.

Load the binary with `gdb` and set a breakpoint at `main`.

```asm
$ gdb -q bomb
(gdb) b main
(gdb) r
```

`gdb` hits this breakpoint and halts the program. Disassemble the `main` function.

```asm
(gdb) disassemble main
Dump of assembler code for function main:
   0x080489b0 <+0>:    push   ebp
   0x080489b1 <+1>:    mov    ebp,esp
   0x080489b3 <+3>:    sub    esp,0x14
   0x080489b6 <+6>:    push   ebx
   ; prologue ends
   ; load argc into eax
   0x080489b7 <+7>:    mov    eax,DWORD PTR [ebp+0x8]
   ; load argv[0] into ebx
   0x080489ba <+10>:   mov    ebx,DWORD PTR [ebp+0xc]
   0x080489bd <+13>:   cmp    eax,0x1
   0x080489c0 <+16>:   jne    0x80489d0 <main+32>
   ; if argc == 1
   ; program will read input from command line
   ; ds:0x804b648 is in .bss and stores stdin@GLIBC_2.0
   ; ds:0x804b664 is in .bss and stores infile
   0x080489c2 <+18>:   mov    eax,ds:0x804b648
   0x080489c7 <+23>:   mov    ds:0x804b664,eax
   0x080489cc <+28>:   jmp    0x8048a30 <main+128>
   0x080489ce <+30>:   mov    esi,esi
   0x080489d0 <+32>:   cmp    eax,0x2
   0x080489d3 <+35>:   jne    0x8048a10 <main+96>
   ; else if argc == 2
   ; open file provided as argument as read-only and read input from it
   0x080489d5 <+37>:   add    esp,0xfffffff8
   0x080489d8 <+40>:   push   0x8049620
   0x080489dd <+45>:   mov    eax,DWORD PTR [ebx+0x4]
   0x080489e0 <+48>:   push   eax
   0x080489e1 <+49>:   call   0x8048880 <fopen@plt>
   ; store the FILE* returned by fopen in infile
   0x080489e6 <+54>:   mov    ds:0x804b664,eax
   0x080489eb <+59>:   add    esp,0x10
   ; printf error message and exit of fopen fails
   0x080489ee <+62>:   test   eax,eax
   0x080489f0 <+64>:   jne    0x8048a30 <main+128>
   0x080489f2 <+66>:   add    esp,0xfffffffc
   0x080489f5 <+69>:   mov    eax,DWORD PTR [ebx+0x4]
   0x080489f8 <+72>:   push   eax
   0x080489f9 <+73>:   mov    eax,DWORD PTR [ebx]
   0x080489fb <+75>:   push   eax
   0x080489fc <+76>:   push   0x8049622
   0x08048a01 <+81>:   call   0x8048810 <printf@plt>
   0x08048a06 <+86>:   add    esp,0xfffffff4
   0x08048a09 <+89>:   push   0x8
   0x08048a0b <+91>:   call   0x8048850 <exit@plt>
   ; else print usage and exit
   0x08048a10 <+96>:   add    esp,0xfffffff8
   0x08048a13 <+99>:   mov    eax,DWORD PTR [ebx]
   0x08048a15 <+101>:  push   eax
   0x08048a16 <+102>:  push   0x804963f
   0x08048a1b <+107>:  call   0x8048810 <printf@plt>
   0x08048a20 <+112>:  add    esp,0xfffffff4
   0x08048a23 <+115>:  push   0x8
   0x08048a25 <+117>:  call   0x8048850 <exit@plt>
   0x08048a2a <+122>:  lea    esi,[esi+0x0]
   ; initialize the bomb
   0x08048a30 <+128>:  call   0x8049160 <initialize_bomb>
   0x08048a35 <+133>:  add    esp,0xfffffff4
   0x08048a38 <+136>:  push   0x8049660
   0x08048a3d <+141>:  call   0x8048810 <printf@plt>
   0x08048a42 <+146>:  add    esp,0xfffffff4
   0x08048a45 <+149>:  push   0x80496a0
   0x08048a4a <+154>:  call   0x8048810 <printf@plt>
   0x08048a4f <+159>:  add    esp,0x20
   0x08048a52 <+162>:  call   0x80491fc <read_line>
   0x08048a57 <+167>:  add    esp,0xfffffff4
   0x08048a5a <+170>:  push   eax
   0x08048a5b <+171>:  call   0x8048b20 <phase_1>

```

The function `initialize_bomb` installs a handler for `SIGINT` signal. We need
not analyze this part of the code.

```asm
(gdb) disas initialize_bomb
Dump of assembler code for function initialize_bomb:
   0x08049160 <+0>:  push   ebp
   0x08049161 <+1>:  mov    ebp,esp
   0x08049163 <+3>:  sub    esp,0x8
   0x08049166 <+6>:  add    esp,0xfffffff8
   0x08049169 <+9>:  push   0x8048f50
   0x0804916e <+14>:  push   0x2
   0x08049170 <+16>:  call   0x8048770 <signal@plt>
   0x08049175 <+21>:  mov    esp,ebp
   0x08049177 <+23>:  pop    ebp
   0x08049178 <+24>:  ret
```

The program reads one line either from `stdin` or from the file we provide, and
passes this string to a function `phase_1`. There are six such functions which
represent the six phases we need to successfully pass inorder to defuse the
bomb.

A function `read_line` is used to read lines from the input.

```asm
(gdb) disas read_line
Dump of assembler code for function read_line:
   0x080491fc <+0>:     push   ebp
   0x080491fd <+1>:     mov    ebp,esp
   0x080491ff <+3>:     sub    esp,0x14
   0x08049202 <+6>:     push   edi
   ; skip calls fgets to read a line of eighty characters into a buffer
   0x08049203 <+7>:     call   0x80491b0 <skip>
   0x08049208 <+12>:    test   eax,eax
   0x0804920a <+14>:    jne    0x804925f <read_line+99>
```

```asm
(gdb) disas skip
Dump of assembler code for function skip:
   0x080491b0 <+0>:     push   ebp
   0x080491b1 <+1>:     mov    ebp,esp
   0x080491b3 <+3>:     sub    esp,0x14
   0x080491b6 <+6>:     push   ebx
   0x080491b7 <+7>:     add    esp,0xfffffffc
   ; ds:0x804b664 stores infile
   0x080491ba <+10>:    mov    eax,ds:0x804b664
   0x080491bf <+15>:    push   eax
   ; size of buffer for fgets is 80, this is the accepted length of each input string
   0x080491c0 <+16>:    push   0x50
   ; ds:0x804b480 stores num_input_strings
   0x080491c2 <+18>:    mov    eax,ds:0x804b480
   0x080491c7 <+23>:    lea    eax,[eax+eax*4]
   0x080491ca <+26>:    shl    eax,0x4
   ; 0x804b680 stores input_strings
   0x080491cd <+29>:    add    eax,0x804b680
   ; $eax = input_strings + ( (num_input_strings + num_input_strings * sizeof(char*)) * 16 )
   0x080491d2 <+34>:    push   eax
   ; fgets(char*, int, FILE*)
   ; fgets(infile, 80, kkkk
   0x080491d3 <+35>:    call   0x80487d0 <fgets@plt>
   0x080491d8 <+40>:    mov    ebx,eax
   0x080491da <+42>:    add    esp,0x10
   0x080491dd <+45>:    test   ebx,ebx
   0x080491df <+47>:    je     0x80491f1 <skip+65>
   0x080491e1 <+49>:    add    esp,0xfffffff4
   0x080491e4 <+52>:    push   ebx
   0x080491e5 <+53>:    call   0x804917c <blank_line>
   0x080491ea <+58>:    add    esp,0x10
   0x080491ed <+61>:    test   eax,eax
   0x080491ef <+63>:    jne    0x80491b7 <skip+7>
   0x080491f1 <+65>:    mov    eax,ebx
   0x080491f3 <+67>:    mov    ebx,DWORD PTR [ebp-0x18]
   0x080491f6 <+70>:    mov    esp,ebp
   0x080491f8 <+72>:    pop    ebp
   0x080491f9 <+73>:    ret
```

---

Let's start with the first phase.

## phase 1

Disassemble `phase_1` with `gdb`.

```asm
(gdb) disas phase_1
Dump of assembler code for function phase_1:
   0x08048b20 <+0>:  push   ebp
   0x08048b21 <+1>:  mov    ebp,esp
   0x08048b23 <+3>:  sub    esp,0x8
   ; load arg into eax
   0x08048b26 <+6>:  mov    eax,DWORD PTR [ebp+0x8]
   0x08048b29 <+9>:  add    esp,0xfffffff8
   ; push string to compare our input against
   0x08048b2c <+12>:  push   0x80497c0
   ; push input string
   0x08048b31 <+17>:  push   eax
   ; compare two strings
   0x08048b32 <+18>:  call   0x8049030 <strings_not_equal>
   0x08048b37 <+23>:  add    esp,0x10
   0x08048b3a <+26>:  test   eax,eax
   0x08048b3c <+28>:  je     0x8048b43 <phase_1+35>
   0x08048b3e <+30>:  call   0x80494fc <explode_bomb>
   0x08048b43 <+35>:  mov    esp,ebp
   0x08048b45 <+37>:  pop    ebp
   0x08048b46 <+38>:  ret    
```

> [!NOTE]
>
> Knowledge of the `x86` 32-bit C calling convention is required before you
> proceed to understand how arguments are passed and functions get called. Refer
> up this document[^3] or search the internet.


> [!NOTE]
>
> See also the GitHub official GitHub Pages Action first.
>
> - [GitHub Pages now uses Actions by default | The GitHub Blog](https://github.blog/2022-08-10-github-pages-now-uses-actions-by-default/)
> - [GitHub Pages: Custom GitHub Actions Workflows (beta) | GitHub Changelog](https://github.blog/changelog/2022-07-27-github-pages-custom-github-actions-workflows-beta/)
>

It is not entirely necessary to analyze `strings_not_equal` at this point. After
you have understood the calling convention, its easier to understand that there
are two arguments to this function which are being pushed to the stack. The
first one is the input string and the second is a read-only string in the `data`
section. The string comparision function will return 0 if two strings match
exactly else it will return 1.

```asm
Dump of assembler code for function strings_not_equal:
   0x08049055 <+37>:  je     0x8049060 <strings_not_equal+48>
   ; return 1 if strings do not match exactly
   0x08049057 <+39>:  mov    eax,0x1
   0x0804905c <+44>:  jmp    0x804907f <strings_not_equal+79>
   0x0804905e <+46>:  mov    esi,esi
   0x08049060 <+48>:  mov    edx,esi
   0x08049062 <+50>:  mov    ecx,edi
   0x08049064 <+52>:  cmp    BYTE PTR [edx],0x0
   0x08049067 <+55>:  je     0x804907d <strings_not_equal+77>
   0x08049069 <+57>:  lea    esi,[esi+eiz*1+0x0]
   0x08049070 <+64>:  mov    al,BYTE PTR [edx]
   0x08049072 <+66>:  cmp    al,BYTE PTR [ecx]
   0x08049074 <+68>:  jne    0x8049057 <strings_not_equal+39>
   0x08049076 <+70>:  inc    edx
   0x08049077 <+71>:  inc    ecx
   ; keep checking till end of input string
   0x08049078 <+72>:  cmp    BYTE PTR [edx],0x0
   0x0804907b <+75>:  jne    0x8049070 <strings_not_equal+64>
   0x0804907d <+77>:  xor    eax,eax
   0x0804907f <+79>:  lea    esp,[ebp-0x18]
   0x08049082 <+82>:  pop    ebx
   0x08049083 <+83>:  pop    esi
   0x08049084 <+84>:  pop    edi
   0x08049085 <+85>:  mov    esp,ebp
   0x08049087 <+87>:  pop    ebp
   0x08049088 <+88>:  ret
```

Inspecting the address of the second argument, we get the string against which
our input will be compared. This is in fact the input for `phase_1`.

```asm
(gdb) x/s 0x80497c0
0x80497c0:   "Public speaking is very easy."
```
## phase 2

Okay, that was somewhat straightforward! Let's proceed to `phase_2`.

Analyzing `phase_2` we find that a function `read_six_numbers` is called with
the input string along with the address of an array to hold six `int` variables.
This function simply reads six integers from the input string and stores them in
an array. Nothing fancy! The input string for `phase_2` should contain six
numbers separated by spaces.

```asm
(gdb) disas phase_2
Dump of assembler code for function phase_2:
   0x08048b48 <+0>:  push   ebp
   0x08048b49 <+1>:  mov    ebp,esp
   0x08048b4b <+3>:  sub    esp,0x20
   0x08048b4e <+6>:  push   esi
   0x08048b4f <+7>:  push   ebx
   0x08048b50 <+8>:  mov    edx,DWORD PTR [ebp+0x8]
   0x08048b53 <+11>:  add    esp,0xfffffff8
   ; load address of array of 6 int into eax
   0x08048b56 <+14>:  lea    eax,[ebp-0x18]
   0x08048b59 <+17>:  push   eax
   0x08048b5a <+18>:  push   edx
   ; read_size_numbers populates this array from input string
   0x08048b5b <+19>:  call   0x8048fd8 <read_six_numbers>
   0x08048b60 <+24>:  add    esp,0x10
   ; first integer should be 1 else bomb explodes
   0x08048b63 <+27>:  cmp    DWORD PTR [ebp-0x18],0x1
   0x08048b67 <+31>:  je     0x8048b6e <phase_2+38>
   0x08048b69 <+33>:  call   0x80494fc <explode_bomb>
   ; ebx is set to 1 and later used to index into the arry
   0x08048b6e <+38>:  mov    ebx,0x1
   ; load address of the array into esi
   0x08048b73 <+43>:  lea    esi,[ebp-0x18]
   ; eax is set as ebx + 1
   0x08048b76 <+46>:  lea    eax,[ebx+0x1]
   ; eax = (index + 1) * array[index - 1]
   0x08048b79 <+49>:  imul   eax,DWORD PTR [esi+ebx*4-0x4]
   0x08048b7e <+54>:  cmp    DWORD PTR [esi+ebx*4],eax
   ; check array[index] == eax
   0x08048b81 <+57>:  je     0x8048b88 <phase_2+64>
   0x08048b83 <+59>:  call   0x80494fc <explode_bomb>
   ; increment index
   0x08048b88 <+64>:  inc    ebx
   ; loop over the array 
   0x08048b89 <+65>:  cmp    ebx,0x5
   0x08048b8c <+68>:  jle    0x8048b76 <phase_2+46>
   0x08048b8e <+70>:  lea    esp,[ebp-0x28]
   0x08048b91 <+73>:  pop    ebx
   0x08048b92 <+74>:  pop    esi
   0x08048b93 <+75>:  mov    esp,ebp
   0x08048b95 <+77>:  pop    ebp
   0x08048b96 <+78>:  ret
```

Looking at the next instructions we find that the first number should be 1 and
rest of the terms of the sequence should obey a rule.

$$
f(n) = n * f(n-1)
$$

Starting with 1, six numbers in the sequence are 1, 2, 6, 24, 120, 720.

## phase 3

Two `int` and a `char` are extracted from the input string. Let's use literals
`a` and `b` for the two integers, and `c` for the character. `a` is used in
a switch block consisting of eight cases for each value starting with 0 till 7.
The case blocks load a 8-bit constant value into `bl` (the lowest byte of `ebx`)
which will be compared against `c`. And then there are checks comparing `b` with
constant integral values.

We need to set `a` to any number from 0 to 7, but `c` and `b` should be set
such that the checks in corresponding case blocks pass. Possible values are
listed below.

```console
0 q 777
1 b 214
2 b 755
3 k 251
4 o 160
5 t 458
6 v 780
7 { 524
```

Disasembly for `phase_3` is presented below.

```asm
(gdb) disas phase_3
Dump of assembler code for function phase_3:
   ; load arg into edx
   0x08048b9f <+7>:  mov    edx,DWORD PTR [ebp+0x8]
   0x08048ba2 <+10>:  add    esp,0xfffffff4
   ; int b
   0x08048ba5 <+13>:  lea    eax,[ebp-0x4]
   0x08048ba8 <+16>:  push   eax
   ; char c
   0x08048ba9 <+17>:  lea    eax,[ebp-0x5]
   0x08048bac <+20>:  push   eax
   ; int a
   0x08048bad <+21>:  lea    eax,[ebp-0xc]
   0x08048bb0 <+24>:  push   eax
   0x08048bb1 <+25>:  push   0x80497de
   0x08048bb6 <+30>:  push   edx
   ; sscanf(input_str, "%d %c %d", &a, &c, &b)
   0x08048bb7 <+31>:  call   0x8048860 <sscanf@plt>
   0x08048bbc <+36>:  add    esp,0x20
   0x08048bbf <+39>:  cmp    eax,0x2
   0x08048bc2 <+42>:  jg     0x8048bc9 <phase_3+49>
   0x08048bc4 <+44>:  call   0x80494fc <explode_bomb>
   ; a < 7
   0x08048bc9 <+49>:  cmp    DWORD PTR [ebp-0xc],0x7
   0x08048bcd <+53>:  ja     0x8048c88 <phase_3+240>
   ; eax = a
   0x08048bd3 <+59>:  mov    eax,DWORD PTR [ebp-0xc]
   ; switch(a)
   0x08048bd6 <+62>:  jmp    DWORD PTR [eax*6+0x80497e8]
   0x08048bdd <+69>:  lea    esi,[esi+0x0]
   ; case 0: bl = 'q'
   0x08048be0 <+72>:  mov    bl,0x71
   ; if (b == 777)
   0x08048be2 <+74>:  cmp    DWORD PTR [ebp-0x4],0x309
   0x08048be9 <+81>:  je     0x8048c8f <phase_3+247>
   0x08048bef <+87>:  call   0x80494fc <explode_bomb>
   0x08048bf4 <+92>:  jmp    0x8048c8f <phase_3+247>
   0x08048bf9 <+97>:  lea    esi,[esi+eiz*1+0x0]
   ; case 1: bl = 'b'
   0x08048c00 <+104>:  mov    bl,0x62
   ; if (b == 214)
   0x08048c02 <+106>:  cmp    DWORD PTR [ebp-0x4],0xd6
   0x08048c09 <+113>:  je     0x8048c8f <phase_3+247>
   0x08048c0f <+119>:  call   0x80494fc <explode_bomb>
   0x08048c14 <+124>:  jmp    0x8048c8f <phase_3+247>
   ; case 2: bl = 'b'
   0x08048c16 <+126>:  mov    bl,0x62
   ; if (b == 755)
   0x08048c18 <+128>:  cmp    DWORD PTR [ebp-0x4],0x2f3
   0x08048c1f <+135>:  je     0x8048c8f <phase_3+247>
   0x08048c21 <+137>:  call   0x80494fc <explode_bomb>
   0x08048c26 <+142>:  jmp    0x8048c8f <phase_3+247>
   ; case 3: bl = 'k'
   0x08048c28 <+144>:  mov    bl,0x6b
   ; if (b == 251)
   0x08048c2a <+146>:  cmp    DWORD PTR [ebp-0x4],0xfb
   0x08048c31 <+153>:  je     0x8048c8f <phase_3+247>
   0x08048c33 <+155>:  call   0x80494fc <explode_bomb>
   0x08048c38 <+160>:  jmp    0x8048c8f <phase_3+247>
   0x08048c3a <+162>:  lea    esi,[esi+0x0]
   ; case 4: bl = 'o'
   0x08048c40 <+168>:  mov    bl,0x6f
   ; if (b == 160)
   0x08048c42 <+170>:  cmp    DWORD PTR [ebp-0x4],0xa0
   0x08048c49 <+177>:  je     0x8048c8f <phase_3+247>
   0x08048c4b <+179>:  call   0x80494fc <explode_bomb>
   0x08048c50 <+184>:  jmp    0x8048c8f <phase_3+247>
   ; case 5: bl = 't'
   0x08048c52 <+186>:  mov    bl,0x74
   ; if (b == 458)
   0x08048c54 <+188>:  cmp    DWORD PTR [ebp-0x4],0x1ca
   0x08048c5b <+195>:  je     0x8048c8f <phase_3+247>
   0x08048c5d <+197>:  call   0x80494fc <explode_bomb>
   0x08048c62 <+202>:  jmp    0x8048c8f <phase_3+247>
   ; case 6: bl = 'v'
   0x08048c64 <+204>:  mov    bl,0x76
   ; if (b == 780)
   0x08048c66 <+206>:  cmp    DWORD PTR [ebp-0x4],0x30c
   0x08048c6d <+213>:  je     0x8048c8f <phase_3+247>
   0x08048c6f <+215>:  call   0x80494fc <explode_bomb>
   0x08048c74 <+220>:  jmp    0x8048c8f <phase_3+247>
   ; case 7: bl = '{'
   0x08048c76 <+222>:  mov    bl,0x62
   ; if (b == 524)
   0x08048c78 <+224>:  cmp    DWORD PTR [ebp-0x4],0x20c
   0x08048c7f <+231>:  je     0x8048c8f <phase_3+247>
   0x08048c81 <+233>:  call   0x80494fc <explode_bomb>
   0x08048c86 <+238>:  jmp    0x8048c8f <phase_3+247>
   ; default
   0x08048c88 <+240>:  mov    bl,0x78
   0x08048c8a <+242>:  call   0x80494fc <explode_bomb>
   0x08048c8f <+247>:  cmp    bl,BYTE PTR [ebp-0x5]
   ; bl == c
   0x08048c92 <+250>:  je     0x8048c99 <phase_3+257>
   0x08048c94 <+252>:  call   0x80494fc <explode_bomb>
   0x08048c99 <+257>:  mov    ebx,DWORD PTR [ebp-0x18]
   0x08048c9c <+260>:  mov    esp,ebp
   0x08048c9e <+262>:  pop    ebp
   0x08048c9f <+263>:  ret
```

We can examine the address of the argument to `sscanf` to obtain the format
string.

```asm
(gdb) x/s 0x80497de
0x80497de:   "%d %c %d"
```

```asm
(gdb) x/8xw 0x80497e8
0x80497e8:  0x08048be0  0x08048c00  0x08048c16  0x08048c28
0x80497f8:  0x08048c40  0x08048c52  0x08048c64  0x08048c76
```

## phase 4

In `phase_4` an integer is read from the input string or the input file and
passed to `func4`.

```asm
(gdb) disas phase_4
Dump of assembler code for function phase_4:
   0x08048ce0 <+0>:  push   ebp
   0x08048ce1 <+1>:  mov    ebp,esp
   0x08048ce3 <+3>:  sub    esp,0x18
   ; load arg int edx
   0x08048ce6 <+6>:  mov    edx,DWORD PTR [ebp+0x8]
   0x08048ce9 <+9>:  add    esp,0xfffffffc
   ; int a
   0x08048cec <+12>:  lea    eax,[ebp-0x4]
   0x08048cef <+15>:  push   eax
   0x08048cf0 <+16>:  push   0x8049808
   0x08048cf5 <+21>:  push   edx
   ; sscanf(edx, "%d", &a)
   0x08048cf6 <+22>:  call   0x8048860 <sscanf@plt>
   0x08048cfb <+27>:  add    esp,0x10
   0x08048cfe <+30>:  cmp    eax,0x1
   0x08048d01 <+33>:  jne    0x8048d09 <phase_4+41>
   ; a != 0
   0x08048d03 <+35>:  cmp    DWORD PTR [ebp-0x4],0x0
   0x08048d07 <+39>:  jg     0x8048d0e <phase_4+46>
   0x08048d09 <+41>:  call   0x80494fc <explode_bomb>
   0x08048d0e <+46>:  add    esp,0xfffffff4
   0x08048d11 <+49>:  mov    eax,DWORD PTR [ebp-0x4]
   0x08048d14 <+52>:  push   eax
   ; func4(a)
   0x08048d15 <+53>:  call   0x8048ca0 <func4>
   0x08048d1a <+58>:  add    esp,0x10
   ; func4(a) == 55
   0x08048d1d <+61>:  cmp    eax,0x37
   0x08048d20 <+64>:  je     0x8048d27 <phase_4+71>
   0x08048d22 <+66>:  call   0x80494fc <explode_bomb>
   0x08048d27 <+71>:  mov    esp,ebp
   0x08048d29 <+73>:  pop    ebp
   0x08048d2a <+74>:  ret
```

`func4` calculates the Fibonacci sum of first `n` elements considering 0 as the
0th element where `n` is its argument.

```asm
(gdb) disas func4
Dump of assembler code for function func4:
   0x08048ca0 <+0>:  push   ebp
   0x08048ca1 <+1>:  mov    ebp,esp
   0x08048ca3 <+3>:  sub    esp,0x10
   0x08048ca6 <+6>:  push   esi
   0x08048ca7 <+7>:  push   ebx
   ; load arg into ebx, lets call it variable a
   0x08048ca8 <+8>:  mov    ebx,DWORD PTR [ebp+0x8]
   ; if (a <= 1) return 1
   0x08048cab <+11>:  cmp    ebx,0x1
   0x08048cae <+14>:  jle    0x8048cd0 <func4+48>
   0x08048cb0 <+16>:  add    esp,0xfffffff4
   0x08048cb3 <+19>:  lea    eax,[ebx-0x1]
   0x08048cb6 <+22>:  push   eax
   ; esi = func4(a - 1)
   0x08048cb7 <+23>:  call   0x8048ca0 <func4>
   0x08048cbc <+28>:  mov    esi,eax
   0x08048cbe <+30>:  add    esp,0xfffffff4
   0x08048cc1 <+33>:  lea    eax,[ebx-0x2]
   0x08048cc4 <+36>:  push   eax
   ; esi += func4(a - 2)
   0x08048cc5 <+37>:  call   0x8048ca0 <func4>
   0x08048cca <+42>:  add    eax,esi
   ; return esi
   0x08048ccc <+44>:  jmp    0x8048cd5 <func4+53>
   0x08048cce <+46>:  mov    esi,esi
   0x08048cd0 <+48>:  mov    eax,0x1
   0x08048cd5 <+53>:  lea    esp,[ebp-0x18]
   0x08048cd8 <+56>:  pop    ebx
   0x08048cd9 <+57>:  pop    esi
   0x08048cda <+58>:  mov    esp,ebp
   0x08048cdc <+60>:  pop    ebp
   0x08048cdd <+61>:  ret
```

The returned sum is compared with 55. Fibonacci sum of first nine numbers in the
sequence is 55.

```console
0 + 1 + 1 + 2 + 3 + 5 + 8 + 13 + 21 + 34 = 55
0th 1st 2nd 3rd 4th 5th 6th 7th  8th  9th
```

## phase 5

`phase_5` requires a string of six characters as input. The lower nibble of each
the ASCII characters in our input string is used to index into a read-only
string and populate another array of six characters. This local array is then
compared to the string "giants".

```asm
(gdb) disas phase_5
Dump of assembler code for function phase_5:
   0x08048d2c <+0>:  push   ebp
   0x08048d2d <+1>:  mov    ebp,esp
   0x08048d2f <+3>:  sub    esp,0x10
   0x08048d32 <+6>:  push   esi
   0x08048d33 <+7>:  push   ebx
   ; load arg into ebx
   0x08048d34 <+8>:  mov    ebx,DWORD PTR [ebp+0x8]
   0x08048d37 <+11>:  add    esp,0xfffffff4
   ; find the length of input string
   0x08048d3a <+14>:  push   ebx
   0x08048d3b <+15>:  call   0x8049018 <string_length>
   0x08048d40 <+20>:  add    esp,0x10
   ; input string should be of six characters
   0x08048d43 <+23>:  cmp    eax,0x6
   0x08048d46 <+26>:  je     0x8048d4d <phase_5+33>
   0x08048d48 <+28>:  call   0x80494fc <explode_bomb>
   ; clear edx and use it as index variable
   0x08048d4d <+33>:  xor    edx,edx
   ; load address of a local array which can hold atleast six characters, into ecx
   0x08048d4f <+35>:  lea    ecx,[ebp-0x8]
   ; load address of character array into esi
   0x08048d52 <+38>:  mov    esi,0x804b220
   ; load each ascii character from input string into al
   0x08048d57 <+43>:  mov    al,BYTE PTR [edx+ebx*1]
   ; retain the lower nibble
   0x08048d5a <+46>:  and    al,0xf
   0x08048d5c <+48>:  movsx  eax,al
   ; use the number in eax to index into the character array which esi points to
   ; load the ascii character into al
   0x08048d5f <+51>:  mov    al,BYTE PTR [eax+esi*1]
   ; save this character at into the local array also indexed with edx
   0x08048d62 <+54>:  mov    BYTE PTR [edx+ecx*1],al
   ; loop for six characters in the input string
   0x08048d65 <+57>:  inc    edx
   0x08048d66 <+58>:  cmp    edx,0x5
   0x08048d69 <+61>:  jle    0x8048d57 <phase_5+43>
   ; add null byte 
   0x08048d6b <+63>:  mov    BYTE PTR [ebp-0x2],0x0
   0x08048d6f <+67>:  add    esp,0xfffffff8
   ; compare the local array of characters with string "giants"
   0x08048d72 <+70>:   push   0x804980b
   0x08048d77 <+75>:   lea    eax,[ebp-0x8]
   0x08048d7a <+78>:   push   eax
   0x08048d7b <+79>:   call   0x8049030 <strings_not_equal>
   0x08048d80 <+84>:   add    esp,0x10
   0x08048d83 <+87>:   test   eax,eax
   0x08048d85 <+89>:   je     0x8048d8c <phase_5+96>
   0x08048d87 <+91>:   call   0x80494fc <explode_bomb>
   0x08048d8c <+96>:   lea    esp,[ebp-0x18]
   0x08048d8f <+99>:   pop    ebx
   0x08048d90 <+100>:  pop    esi
   0x08048d91 <+101>:  mov    esp,ebp
   0x08048d93 <+103>:  pop    ebp
   0x08048d94 <+104>:  ret
```

Examining the location `0x804b220` we get a read-only string.

```asm
0x804b220 <array.123>:   "isrveawhobpnutfg\260\001"
(gdb) x/s 0x804980b
```

For each of the letters in "giants", the offsets into this string are presented
below.

```console
offset of 'g' = 15 = 0xf
offset of 'i' = 0  = 0x0
offset of 'a' = 5  = 0x5
offset of 'n' = 11 = 0xb
offset of 't' = 13 = 0xd
offset of 's' = 1  = 0x1
```

Looking up the table of ASCII codes, we need to chose six characters such that
their lower nibbles correspond with the offsets we just found out above. One
such string is presented below.

```console
opekma
0x6f,0x70,0x65,0x6b,0x6d,0x61
```

## phase 6

The last phase shall not be documented in this article and is left as an
exercise for the reader. Your hint for this phase is `4 2 6 3 1 5`.

## secret phase

---

**tl;dr**
Yes it exists, right alongside `phase 4`. If you have figured out `phase 6`
I encourage to take on the discovery of this hidden phase. A hint for you is...
 _Oh behave!_

---

I shall tell you about the `secret phase` however.

There are two stages in the secret phase. The first is detecting and entering
the secret phase and the second is solving it.

Notice how after calls to the functions corresponding to each of the phases,
there are calls to a function named `phase_defused`!

```asm
   0x08048a5b <+171>:   call   0x8048b20 <phase_1>
   0x08048a60 <+176>:   call   0x804952c <phase_defused>

   0x08048a7e <+206>:   call   0x8048b48 <phase_2>
   0x08048a83 <+211>:   call   0x804952c <phase_defused>

   0x08048aa1 <+241>:   call   0x8048b98 <phase_3>
   0x08048aa6 <+246>:   call   0x804952c <phase_defused>

   0x08048ac4 <+276>:   call   0x8048ce0 <phase_4>
   0x08048ac9 <+281>:   call   0x804952c <phase_defused>

   0x08048ae7 <+311>:   call   0x8048d2c <phase_5>
   0x08048aec <+316>:   call   0x804952c <phase_defused>

   0x08048b0a <+346>:   call   0x8048d98 <phase_6>
   0x08048b0f <+351>:   call   0x804952c <phase_defused>
```

_Let's disassemble!_

```asm
(gdb) disas phase_defused
   0x0804952c <+0>:     push   ebp
   0x0804952d <+1>:     mov    ebp,esp
   0x0804952f <+3>:     sub    esp,0x64
   0x08049532 <+6>:     push   ebx
   ; compare 4-bytes at 0x804b480 in the data segment with immediate value of 6
   0x08049533 <+7>:     cmp    DWORD PTR ds:0x804b480,0x6
   0x0804953a <+14>:    jne    0x804959f <phase_defused+115>
```

We can use the `info` command along with `symbol` subcommand to describe the
symbol at a specified memory location in `gdb`. We shall use it to examine the
location which is used for the compare operation.

```asm
(gdb) info symbol 0x804b480
num_input_strings in section .data
```

A global variable named `num_input_strings` is located at `0x804b480`.

In `gdb`, `watchpoints` can be used to stop execution when the value of an
expression changes. We can use the address of `num_input_strings` to trace where
its gets modified. Set the `watchpoint` at the address and restart the program.

```asm
(gdb) watch -l *0x804b480
(gdb) r codes
Welcome to my fiendish little bomb. You have 6 phases with
which to blow yourself up. Have a nice day!

Hardware watchpoint 2: -location *0x804b480

Old value = 0
New value = 1
0x080492b6 in read_line ()
```

The function `read_line` is modifying this variable. We disassemble the current
location to peek at what the program does.

```asm
(gdb) disas
   0x080492b0 <+180>:   inc    DWORD PTR ds:0x804b480
=> 0x080492b6 <+186>:   mov    edi,DWORD PTR [ebp-0x18]
   0x080492b9 <+189>:   mov    esp,ebp
   0x080492bb <+191>:   pop    ebp
   0x080492bc <+192>:   ret

(gdb) frame
#0  0x080492b6 in read_line ()
=> 0x080492b6 <read_line+186>:  8b 7d e8        mov    edi,DWORD PTR [ebp-0x18]
```

We are in towards the end of `read_line` function where it increments
`num_input_strings`, after reading a line of input. Refresh your memory about
how `skip` actually reads strings into a buffer from a `FILE` stream. The buffer
is located at `0x804b680` and each read consists of eighty characters.

We continue with analysis of `phase_defused`.

```asm
(gdb) disas phase_defused
   0x0804952c <+0>:     push   ebp
   0x0804952d <+1>:     mov    ebp,esp
   0x0804952f <+3>:     sub    esp,0x64
   0x08049532 <+6>:     push   ebx
   ; compare 4-bytes at 0x804b480 in the data segment with immediate value of 6
   0x08049533 <+7>:     cmp    DWORD PTR ds:0x804b480,0x6
   0x0804953a <+14>:    jne    0x804959f <phase_defused+115>
   0x0804953c <+16>:    lea    ebx,[ebp-0x50]
   0x0804953f <+19>:    push   ebx
   0x08049540 <+20>:    lea    eax,[ebp-0x54]
   0x08049543 <+23>:    push   eax
   0x08049544 <+24>:    push   0x8049d03
   0x08049549 <+29>:    push   0x804b770
   ; sscanf "%d %s" into $ebp-0x54 and $ebp-0x50 respectively from the input
   0x0804954e <+34>:    call   0x8048860 <sscanf@plt>
   0x08049553 <+39>:    add    esp,0x10
   0x08049556 <+42>:    cmp    eax,0x2
   0x08049559 <+45>:    jne    0x8049592 <phase_defused+102>
   0x0804955b <+47>:    add    esp,0xfffffff8
   0x0804955e <+50>:    push   0x8049d09
   0x08049563 <+55>:    push   ebx
   ; note that $ebx has address of the input string
   ; Location 0x8049d09 stores the string "austinpowers"
   0x08049564 <+56>:    call   0x8049030 <strings_not_equal>
   0x08049569 <+61>:    add    esp,0x10
   ; check if return value of strings_not_equal is 0
   0x0804956c <+64>:    test   eax,eax
   0x0804956e <+66>:    jne    0x8049592 <phase_defused+102>
   0x08049570 <+68>:    add    esp,0xfffffff4
   0x08049573 <+71>:    push   0x8049d20
   0x08049578 <+76>:    call   0x8048810 <printf@plt>
   0x0804957d <+81>:    add    esp,0xfffffff4
   0x08049580 <+84>:    push   0x8049d60
   0x08049585 <+89>:    call   0x8048810 <printf@plt>
   0x0804958a <+94>:    add    esp,0x20
   ; enter secret phase
   0x0804958d <+97>:    call   0x8048ee8 <secret_phase>
   0x08049592 <+102>:   add    esp,0xfffffff4
   0x08049595 <+105>:   push   0x8049da0
   0x0804959a <+110>:   call   0x8048810 <printf@plt>
   0x0804959f <+115>:   mov    ebx,DWORD PTR [ebp-0x68]
   0x080495a2 <+118>:   mov    esp,ebp
   0x080495a4 <+120>:   pop    ebp
   0x080495a5 <+121>:   ret
```

We find that the function reads an integer and a string from the input strings
buffer using `sscanf`. The location `0x804b770` is at an offset of 240 bytes
from `0x804b680`, a buffer named `input_strings`. It stores the the input string
for `phase_4`. An integer was required for this phase's input. The function
above checks the number of arguments successfully read should equal two.
Thereafter `strings_not_equal` is called with the input string and another
location in memory. This location `0x8049d09` stores a string.

```asm
(gdb) x/s 0x804b770
0x804b770 <input_strings+240>:  "9 austinpowers"
(gdb) x/s 0x8049d09
0x8049d09:      "austinpowers"
```

You must have figured out that the integer is not necessary for any comparision
in this function itself but is required so that `sscanf` reads the desired
number of arguments, in order to proceed through the true branch. Also it is
a remnant of the input to `phase_4`. When the string check passes you are
presented with murky smirky greeting.

```asm
(gdb) x/s 0x8049d20
0x8049d20:      "Curses, you've found the secret phase!\n"
(gdb) x/s 0x8049d60
0x8049d60:      "But finding it and solving it are quite different...\n"
```

Then the function `secret_phase` gets called. We now disassemble this function.

```asm
(gdb) disas secret_phase
Dump of assembler code for function secret_phase:
   0x08048ee8 <+0>:     push   ebp
   0x08048ee9 <+1>:     mov    ebp,esp
   0x08048eeb <+3>:     sub    esp,0x14
   0x08048eee <+6>:     push   ebx
   ; read a string from input, that is stdin or a file
   0x08048eef <+7>:     call   0x80491fc <read_line>
   0x08048ef4 <+12>:    push   0x0
   0x08048ef6 <+14>:    push   0xa
   0x08048ef8 <+16>:    push   0x0
   0x08048efa <+18>:    push   eax
   ; convert the string to an long integer with base of ten
   0x08048efb <+19>:    call   0x80487f0 <__strtol_internal@plt>
   0x08048f00 <+24>:    add    esp,0x10
   0x08048f03 <+27>:    mov    ebx,eax
   0x08048f05 <+29>:    lea    eax,[ebx-0x1]
   ; integer should not be greater than 1001
   0x08048f08 <+32>:    cmp    eax,0x3e8
   0x08048f0d <+37>:    jbe    0x8048f14 <secret_phase+44>
   0x08048f0f <+39>:    call   0x80494fc <explode_bomb>
   0x08048f14 <+44>:    add    esp,0xfffffff8
   0x08048f17 <+47>:    push   ebx
   0x08048f18 <+48>:    push   0x804b320
   ; call fun7 with a memory address and the integer
   0x08048f1d <+53>:    call   0x8048e94 <fun7>
   0x08048f22 <+58>:    add    esp,0x10
   ; compare return value of fun7 with seven
   0x08048f25 <+61>:    cmp    eax,0x7
   0x08048f28 <+64>:    je     0x8048f2f <secret_phase+71>
   0x08048f2a <+66>:    call   0x80494fc <explode_bomb>
   0x08048f2f <+71>:    add    esp,0xfffffff4
   0x08048f32 <+74>:    push   0x8049820
   0x08048f37 <+79>:    call   0x8048810 <printf@plt>
   0x08048f3c <+84>:    call   0x804952c <phase_defused>
   0x08048f41 <+89>:    mov    ebx,DWORD PTR [ebp-0x18]
   0x08048f44 <+92>:    mov    esp,ebp
   0x08048f46 <+94>:    pop    ebp
   0x08048f47 <+95>:    ret
End of assembler dump.
```

This function calls `read_line` and converts the read string to a long integer
with base of ten, that is a decimal integer. This integer is compared against
1001, and it should not greater than this constant. Another function `fun7` is
called with this integer and a location in memory.

This is the disassembly of `fun7`.

```asm
(gdb) disas fun7
Dump of assembler code for function fun7:
   0x08048e94 <+0>:     push   ebp
   0x08048e95 <+1>:     mov    ebp,esp
   0x08048e97 <+3>:     sub    esp,0x8
   0x08048e9a <+6>:     mov    edx,DWORD PTR [ebp+0x8]
   0x08048e9d <+9>:     mov    eax,DWORD PTR [ebp+0xc]
   0x08048ea0 <+12>:    test   edx,edx
   0x08048ea2 <+14>:    jne    0x8048eb0 <fun7+28>
   0x08048ea4 <+16>:    mov    eax,0xffffffff
   0x08048ea9 <+21>:    jmp    0x8048ee2 <fun7+78>
   0x08048eab <+23>:    nop
   0x08048eac <+24>:    lea    esi,[esi+eiz*1+0x0]
   0x08048eb0 <+28>:    cmp    eax,DWORD PTR [edx]
   0x08048eb2 <+30>:    jge    0x8048ec5 <fun7+49>
   0x08048eb4 <+32>:    add    esp,0xfffffff8
   0x08048eb7 <+35>:    push   eax
   0x08048eb8 <+36>:    mov    eax,DWORD PTR [edx+0x4]
   0x08048ebb <+39>:    push   eax
   0x08048ebc <+40>:    call   0x8048e94 <fun7>
   0x08048ec1 <+45>:    add    eax,eax
   0x08048ec3 <+47>:    jmp    0x8048ee2 <fun7+78>
   0x08048ec5 <+49>:    cmp    eax,DWORD PTR [edx]
   0x08048ec7 <+51>:    je     0x8048ee0 <fun7+76>
   0x08048ec9 <+53>:    add    esp,0xfffffff8
   0x08048ecc <+56>:    push   eax
   0x08048ecd <+57>:    mov    eax,DWORD PTR [edx+0x8]
   0x08048ed0 <+60>:    push   eax
   0x08048ed1 <+61>:    call   0x8048e94 <fun7>
   0x08048ed6 <+66>:    add    eax,eax
   0x08048ed8 <+68>:    inc    eax
   0x08048ed9 <+69>:    jmp    0x8048ee2 <fun7+78>
   0x08048edb <+71>:    nop
   0x08048edc <+72>:    lea    esi,[esi+eiz*1+0x0]
   0x08048ee0 <+76>:    xor    eax,eax
   0x08048ee2 <+78>:    mov    esp,ebp
   0x08048ee4 <+80>:    pop    ebp
   0x08048ee5 <+81>:    ret
End of assembler dump.
```

`secret_phase` passes the integer it reads from input strings as the second
argument and a memory location as the first argument. On i386 the call stack
layout is illustrated below.

```console

/──────────────────────── Stack before the call to fun7 ───────────────────────/

                                       ˄
                                       │
                                     lower
                                   addresses
             S
             t                 ┌───────────────┐ ─˃ sp (top of the stack)
             a        ˄        │   0x804b320   │
             c        │        ├───────────────┤ ─> memory location
             k        │        │      ebx      │ ─> integer returned by strtol
                      │        ├───────────────┤
             g        │        │               │
             r        │        ├───────────────┤
             o        │        │               │
             w        │
             t                      higher
             h                     addresses
                                       │
                                       v

/─────────── Stack after the call to fun7 and the function prologue ───────────/

                                       ˄
                                       │
                                     lower
                                   addresses

                               ┌───────────────┐ ─˃ esp (top of the stack)
                               │               │
                               ├───────────────┤
             S                 │               │ ─> ebp (base pointer of faun7)
             t                 ├───────────────┤
             a        ˄        │  previous ebp │ ─> base pointer of secret_phase
             c        │        ├───────────────┤
             k        │        │   0x8048f22   │ ─> return address of fun7
                      │        ├───────────────┤
             g        │        │   0x804b320   │
             r        │        ├───────────────┤
             o        │        │      ebx      │
             w        │        ├───────────────┤
             t                 │               │
             h                 ├───────────────┤
                               │               │

                                     higher
                                   addresses
                                       │
                                       v
```

`fun7` checks if the the first argument located at `ebp + 8`, a memory location
is zero or not and returns negative one (-1) if it is. The second argument that
is the integer provided as input, that is located at `ebp + 12` is compared
against the word (32-bit value) stored at the memory location that was passed as
the first argument. If both values are equal the function returns zero. If the
integer is lesser than the value in memory, the same function `fun7` is called
recursively with the address that is at an offset of four bytes from the memory
location pointed to by `ebp + 8`. But if the integer is greater than the value
in memory, `fun7` is called recursively with the address that is at an offset of
eight bytes from the memory location that was passed as the first argument.

```asm

                         ┌───────────────┐
                         │               │ ─> fun7 argument if integer is
                         ├───────────────┤    greater than value at address A
                         │               │ ─> fun7 argument if integer is
  ┌───────────────┐      ├───────────────┤    lesser than value at address A
  │    ebp + 8    │  ─>  │   address A   │
  └───────────────┘      └───────────────┘

```

One might have inferred that this represents recursive traversal of a binary
search tree, based on the comparision of the input integer against the keys
stored in the nodes of the tree. The key is the first member of the record
representing a tree node, the address of the left child is the second member and
the address of the right child is the third memeber.

```c
struct bst_node {
   long key;
   struct bst_node *left;
   struct bst_node *right;
};
```

The base cases of this recursive binary tree processing are zero for equivalence
with the key of a node and negative one (-1) for the children of a leaf node,
which are stored as empty addresses. The value returned from each recursive call
of `fun7` are doubled for the left child, that is the smaller key and doubled
then incremented by one for the right child, that is the greater key.

```c
int ret;
/* root is current tree node and n is the input integer */
if (root == NULL) {
   return -1;
} else if (n == root->key) {
   return 0;
} else if (n < root->key) {
   ret = fun7(root->left, n);
   ret *= 2;
} else if (n > root->key) {
   ret = fun7(root->right, n);
   ret += 2;
   ++ret;
}
return ret;
```

Now that we have a thorough idea of what `fun7` does, we should analzye what
`secret_phase` does with the return value of `fun7`. This value has to be equal
to seven for the hidden phase to be defused.

Therefore, we need to achieve a result of seven from the recursive traveral of
a binary search tree with the formulations presented below.

$$
f(root, n) =  0, n == key
f(root, n) = -1, root == NULL
f(root, n) = 2 * f(left, n)
f(root, n) = (2 * f(right, n)) + 1
$$

It is fairly intuitive to arrive at a conclustion that the base case of
recursion that we require is the equivalence of the input integer with a tree
node key and not the discovery of any child of a leaf node. This is becuase
a return value of negative one shall continue to remain negative and increases
in absolute magniture, hence the solution diverges from the value of seven. In
simpler words we need to start with some integer $\text{a}_{i}$ and use either of
$\text{a}_{i + 1} = 2\times\text{a}_{i}$ or $\text{a}_{i + 1} = 2\times\text{a}_{i}+1$. And we should have $\text{a}_{i}$ as zero.

The left child recursion tree is inconsequential as zero doubled, is zero. The
right child recursion yeilds one for the penultimate recursive call that is
the call with a leaf node. Subsequent antepenultimate calls can either yield
two or three based on whether the left or right child was recursed into. It is
evident that two shall not result in a value of seven. Three however does lead
to seven along a right child recursion path from a parent node. We require four
recursive calls, all into the right child nodes, starting from the root of the
tree, and with the ultimate call returning a zero by matching the key of a leaf
node with the input integer which under our control. This seems very easy. We
need to validate if this solution is feasible.

The memory location passed to `fun7` in its call from `secret_phase` is indeed the address of the root node of the binary search tree. This addresss is `0x804b320`. Examining the memory locations based on the tree node `struct` define earler, these are the values of the keys,
traversing along the right child of each node from the parent to a leaf.

```
(gdb) x/3wx 0x804b320
0x804b320 <n1>: 0x00000024      0x0804b314      0x0804b308
(gdb) p/d 0x24
$0 = 36
(gdb) x/3wx 0x804b308
0x804b308 <n22>:        0x00000032      0x0804b2f0      0x0804b2d8
(gdb) p/d 0x32
$1 = 50
(gdb) x/3wx 0x0804b2d8
0x804b2d8 <n34>:        0x0000006b      0x0804b2b4      0x0804b278
(gdb) p/d 0x6b
$2 = 107
(gdb) x/3wx 0x0804b278
0x804b278 <n48>:        0x000003e9      0x00000000      0x00000000
(gdb) p/d 0x3e9
$3 = 1001
```

We have a constraint that the input integer cannot be greater than 1001. Seems
proper considering the key of the right-most leaf is 1001. Coincidentally this
leaf node is located at a depth of three edges from the tree root, satisfying
three invocations of the rule $\text{a}_{i + 1} = 2\times\text{a}_{i}+1$ with
$\text{a}_0 = 0$.
 
As the `secret_phase` function requires six input strings to have been read by
`read_line`, but reads its input from the string passed as input for `phase_4`,
we need to pass `"9 austinpowers"` as the input to `phase_4`. The remnant string
shall get read by `secret_phase` and then another string shall be read for the
input integer. We need to provide this input at the end, after the inputs for
string should be less than or equal to 1001. But the right-most leaf node has
its key as 1001 itself. Hence the input to defuse the hidden phase shall be
1001.

```
$ cat >> bomb_codes << end
Public speaking is very easy.
1 2 6 24 120 720
0 q 777
9 austinpowers
opekma
4 2 6 3 1 5
1001
end
$ cat bomb_codes
Public speaking is very easy.
1 2 6 24 120 720
0 q 777
9 austinpowers
opekma
4 2 6 3 1 5
1001
$
$ ./bomb bomb_codes
Welcome to my fiendish little bomb. You have 6 phases with
which to blow yourself up. Have a nice day!
Phase 1 defused. How about the next one?
That's number 2.  Keep going!
Halfway there!
So you got that one.  Try this one.
Good work!  On to the next...
Curses, you've found the secret phase!
But finding it and solving it are quite different...
Wow! You've defused the secret stage!
Congratulations! You've defused the bomb!
$
```

This assignment is a reverse engineering exercise. The use of `gdb` is
demonstrated for the disassembly of the machine code and examination of the
process memory and registers. There are decompilation tools, solvers, theorem
provers, symoblic execution frameworks and several other reverse engineering
tools available. The purpose of this exercise however, is to inculcate
understanding to architecture specific concepts as in calling convenctions,
memory layouts and high-level language to assembly instructions and the machine
code transformations.

Hope luke warm water does not get cold while one waits for a solver! Modern
frameworks are fast and accurate. But one can only foster proficiency with
rigor over the acquaintance with fundamentals.

[^1]: (http://csapp.cs.cmu.edu/public/labs.html)
[^2]: (https://github.com/xuzhezhaozhao/CSAPP-Labs/tree/master/bomb%20lab)
[^3]: (https://github.com/uva-cs/pdr/blob/master/book/x86-32bit-ccc-chapter.pdf)
