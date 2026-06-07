---
title: "Bit-fields"
date: 2026-06-04 11:26:55 +00:00
layout: article
permalink: /technical/bit_fields/
description: ""
categories: [tutorial, technical, white-paper]
tags: [tutorial, technical, white-paper, bit-fields, structs, packing, inline-assembly, x86, AVR, avr-gcc]
author: "notweerdmonk"
draft: false
canonical_url: "https://notweerdmonk.github.io/technical/bit_fields/"
---
# Bit-fields

## Prelude

Bit-fields represent a sophisticated mechanism in low-level programming that
allows developers to store and manipulate individual bits within; it is
a powerful yet nuanced technique which originates from the need to efficiently
represent and store boolean flags and multiple-bit data structures providing
a memory-efficient alternative to traditional integer-based storage as they
pack multiple boolean or integer values together. Bit-fields have been around
the early days of computer science. In the C and C++ programming languages,
they enable programmers to define custom bit-level representations of data,
allowing granular control over memory layout and reducing the overall memory
footprint of data structures.

The concept of bit-fields traces its roots to the constraints of early
computing systems, where memory was an extremely scarce and expensive resource.
Programmers needed methods to compress multiple boolean or small-range integer
values into minimal storage. Languages like C formalized this approach,
allowing developers to define structures where individual bits or small bit
ranges could be explicitly controlled and accessed. There are some intricacies
associated with this construct which make it an interesting topic even with
impeccable compiler optimizations.

```C
/* Bit-fields inside a struct in C/C++ */
struct counter {
    unsigned short id               : 2;
    unsigned short count_directon   : 1;
    unsigned short repeat           : 1;
    unsigned short count            : 6;
    unsigned short top              : 6;
};
```

Bitwise and shift operations complement bit-fields by providing powerful
mechanisms for bit manipulation, enabling efficient transformations, masking,
and logical operations. These operations are useful when working with bit-fields
and bitmasks.

```c
enum counter_bitpos {
    COUNTER_FIELD_ID_BITPOS                 = 0,
    COUNTER_FIELD_COUNT_DIRECTION_BITPOS    = 2,
    COUNTER_FIELD_REPEAT_BITPOS             = 3,
    COUNTER_FIELD_COUNT_BITPOS              = 4,
    COUNTER_FIELD_TOP_BITPOS                = 10
};

enum counter_masks {
    COUNTER_COUNT_UP_REPEAT                 = 0b0000000000001100,
    COUNTER_COUNT_UP_NO_REPEAT              = 0b0000000000000100,
    COUNTER_COUNT_DOWN_REPEAT               = 0b0000000000001000,
    COUNTER_COUNT_DOWN_NO_REPEAT            = 0b0000000000000000,
    COUNTER_FIELD_ID_MASK                   = 0b0000000000000011,
    COUNTER_FIELD_COUNT_DIRECTION_MASK      = 0b0000000000000100,
    COUNTER_FIELD_REPEAT_MASK               = 0b0000000000001000,
    COUNTER_FIELD_COUNT_MASK                = 0b0000001111110000,
    COUNTER_FIELD_TOP_MASK                  = 0b1111110000000000
};

struct coutner c = {
    .id = 0,
    .count_direction = 0,
    .repeat = 0,
    .count = 0,
    .top = 0
};

c.count_direction =
    (
        COUNTER_COUNT_UP_REPEAT &
        COUNTER_FIELD_COUNT_DIRECTION_MASK
    ) << COUNTER_FIELD_COUNT_DIRECTION_BITPOS;

c.repeat =
    (
        COUNTER_COUNT_UP_REPEAT &
        COUNTER_FIELD_REPEAT_MASK
    ) << COUNTER_FIELD_REPEAT_BITPOS;
```

## A deeper look at bit-fields

A bit-field is a data structure that maps to one more adjacent bits in memory
such that a single bit or a group of bits can be accessed and manipulated.[^1]
In C/C++ bit-fields can be created within a `struct` using an integer member
(field) and specifying the number of bits the field should occupy (mentioned as
a non-negative integer literal besides the field name specifier, separated by
a colon). Bit-fields declared consecutively get packed into a larger storage
unit that shall be no larger than size of the type used to declare the fields.
Therefore such a declaration cannot specify more bits than the size of the type
of the member.

Signedness of the member decides the range of integral values represented by the
bit-field. The sign specifier can be omitted for the `bool` type which is always
unsigned whereas all other types for a bit-field require `signed` or `unsigned`
to be specifier. In case of `GCC` there is a default if the signedness of the
bit-field is not specified in the declaration. The bit-field is signed if plain
`char` is signed, except that the option `-funsigned-bitfields` forces
`unsigned` as the default.[^2]

```c
struct bit_field_struct {
    unsigned char opcode    : 4;
    signed char small       : 4;
} s;

s.opcode    = 0xa;
s.small     = 0xa;
```

Such a declaration specifies two bit-fields occupting 4 bits each. Being
consecutive and of the same type, they are combined into a single byte of type
`char`. The unsigned field can have values from 0 to 15 while the signed field
can have values from -8 to 7. Individual fields can be accessed using their
name specifiers alike structure members.

---

Bit-fields normally cannot straddle byte boundaries. A bit-field which exceeds
the byte boundary gets pushed across to the next byte in memory and the region
left behind gets padded with unused bits.

```c
struct non_packed_struct_a {
    unsigned char a : 3;
    unsigned char b : 3;
    unsigned char c : 3;
    unsigned char d : 3;
    unsigned char e : 3;
};

sizeof(non_packed_struct_a) = 3

struct non_packed_struct_b {
    unsigned char a : 3;
    unsigned char b : 3;
    unsigned int c  : 3;
    unsigned char d : 3;
    unsigned char e : 3;
};

sizeof(non_packed_struct_b) = 4
```

Using the declaration attribute `packed` which forces members to be laid out
without any padding in between.[^3] Consequently such members do not have the
normal memory alignment for their types and taking their addresses can result in
an invalid pointer. This attribute also applies to bit-fields allowing them to
be positioned across byte boundaries[^4]. Still, padding gets added when the
last bit-field member does not occupy all the bits of the byte it spans up to.

`clang` also supports this type attribute. `MSVC` however, requires the
`pragma pack` directives. `GCC` specifically warns about the change in alignment
of `char` bit-fields in a `struct` when the `packed` attribute is specified[^5].
The field `c` in the first `struct` presented below shall not be aligned to a
byte-boundary, hence the warning. `clang` and `MSVC` do not issue such warnings.
It is to be noted that with `MSVC`, the field `c` in the second `struct`
presented below occupies four bytes, with or without packing alignment.

```c
struct __attribute__((packed)) packed_struct_a {
    unsigned char a : 3;
    unsigned char b : 3;
    unsigned char c : 3;
    unsigned char d : 3;
    unsigned char e : 3;
};

sizeof(packed_struct_a) = 2

struct __attribute__((packed)) packed_struct_b {
    unsigned char a : 3;
    unsigned char b : 3;
    unsigned int  c : 3;
    unsigned char d : 3;
    unsigned char e : 3;
};

sizeof(packed_struct_a) = 2
```

---

A caveat with bit-fields is that their addresses cannot be taken and hence
they cannot be accessed with pointers, the reason for which should be clear
from prior discussions stating that a bit-field cannot be guaranteed to be
positioned at a byte boundary in memory, packed or not.

If and when the need arises to write data which spans across multiple bit-fields
with the intent of leveraging the fact that several fields occupy a single
storage unit, type-punning can be used along with bitwise operations.

```c
struct counter {
    unsigned short id               : 2;
    unsigned short count_directon   : 1;
    unsigned short repeat           : 1;
    unsigned short counter          : 6;
    unsigned short top              : 6;
} counter = {
    .id = 0,
    .count_direction = 0,
    .repeat = 0,
    .count = 0,
    .top = 0
};

/*
 * Assume you want to set the `top` field of the `struct counter` to 16.
 * An object of `struct counter is punned as an `unsigned short` the contents
 * in memory are 'OR'ed with 0b0100000000000000 or 0x4000.
 */
*(unsigned short*)&counter |= (unsigned short)(16 << 10);
```

Even though we make do with alignment of the bit-fields because of carefully
chosen field types and width, this refutes the `strict-aliasing` rule. An
elegant solution is to place the structure containing the bit-fields in an
`union` alongside a field of a datatype that has the same size as that of the
`struct` encasing the bit-fields. Choosing the type and width of the bit-field
members as in the snippet above enables us to workaround the undefined behavior
suggested by the standards. Normally accessing an inactive member of an union is
regarded as undefined behavior. Duly note that even if such tricks work
harmlessly with `x86` compilers but are not guaranteed on several other
architectures.

```c
union counter_u {
    unsigned short bytes;
    struct {
        unsigned short id               : 2;
        unsigned short count_directon   : 1;
        unsigned short repeat           : 1;
        unsigned short counter          : 6;
        unsigned short top              : 6;
    } counter;
} counter2 = { .bytes = 0 };

/*
 * Alias `struct counter` with `unsigned short` within `union counter_u`.
 * This is specific to `x86` architecture.
 */
counter2.bytes |= (unsigned short)(16 << COUNTER_FIELD_TOP_BITPOS);
assert(counter2.counter.top == 16);
```

Variable shifts like `(1 << variable)`, allow dynamic bit positioning and
extraction. Shifts using variable indices extend beyond compile-time constant
shifts, offering more flexible and dynamic bit-level transformations but come at
additional cost of iterating over single-bit shift operations in architectures
that do not support multiple bit-position shift operations. For architectures
which do support multiple bit-position shift operations, such expressions have
constant time-complexity.

```c
union counter_u* set_counter_bits(
    union counter_u *p,
    unsigned char bitpos,
    unsigned short value
) {
    p->counter |= (value << bitpos);
    return p;
}

union counter_u counter3 = { .bytes = 0 };
(void)set_counter_bits(&counter3, COUNTER_FIELD_TOP_BITPOS, 16);
```

## Optimized bit-field manipulation

### Multiple bit-position shifts - The intrigue

This section is more of an addendum, complementing the absence of multiple
bit-position shift operations on some processor architectures. Generally such
limitations are typical of `RISC` devices, microcontrollers and ASICs in
essence. 

The task of optimizing higher-level source code is shouldered by compilers.
However, it is utmost sensible for the programmer to be aware of the limitations
and nuances of the compiler in order to write optimized and performant code that
in addition to correctness is compliant. There are trade-offs certainly as
highly customized implementations lose universality. Staring at assembly
listings and getting familiar with decompilers is worthwhile unless you can
employ specific analysis tools.

Scoping this discussion to the `AVR` ISA and `avr-gcc` toolchain we shall
enunciate the use of assembly instructions to circumvent compiler limitations.
Programmers may write separate assembly stubs or inject inline assembly into
C/C++ source code. The crux of the problem lies in the implementation of a
multiple bit-position shift procedure.

---

Even with optimize for size options enabled the compiler can at best generate
a loop to iteratively shift bit positions using the left-shift or right-shift
instructions. This makes the time-complexity `O(n)` where `n` is the number of
bit positions to be shifted.  Apart from being non-deterministic this is also
prone to bugs when there are ISRs switching the processor context. Use of
`volatile` is recommended. Then again programmer foresight shall materialize if
only one has analyzed the generated assembly instructions with any rigor if not
some, which might not be expected of the average hobbyist tinkerer.

With `-Os`, `avr-gcc` produces such output for a left-shift function.

```c
unsigned char leftshift(unsigned char value, unsigned char shift) {
    return shift < 8 ? (value |= 1 << shift) : shift;
}
```

```asm
leftshift:
        ldi r18, 1
        rjmp 2f
        1:
        lsl r18
        2:
        dec r22
        brpl 1b
        or r24,r18
        ret
```

---

### Formulating the operation

Before plunging into the nooks of your mind to solve this cranny of a problem
which has the potential of aggrevating into a cleave, ponder about why the
compiler cannot do any better! Recall your algorithm analysis lectures if you
have attended any in graduate school, or flip some book pages and browser some
webpages when you find the time. Algorithm design provides you with a choice to
trade space-complexity for time-complexity and vice versa. Formulation of the bit
shift operation is presented below.

$$
leftshift(\text{value},\ \text{shift}) = \text{value}\times \left(2^\text{shift}\right)
$$

The compiler implements the exponentiation of two by a non-negative integer in
terms of repeated multiply operations. The optimal way to peform a
multiplication of a value by two is to left-shift given value by one bit
position. Therefore, exponentiation of two, that is, repeated multiplication of
two by itself, is naturally the repeated left-shifts of one by the given
exponent value. And the exponentiation of any unsigned integral value is
similarly its repeated left-shifts by the given unsigned integral exponent
value.

---

### Implementing the formulation

This repetition of left-shift operations can be transformed into a lookup of
tabular values indexed by the exponent value as the base is alwyays fixed to
two. But the compiler is restrained to forego this kind of optimizations for
implemention of a generalized operation such as multiple bit shifts because it
cannot decide the limits of values supplied for such an operaton. This is where
automata meets its maker, the blob of neurons twitching in your cranial cavity
ever since you matured from an embryo to an human offspring. As we are aware of
the possible values of the base as well as the exponent used in the exponential
formulation of such bit-shift operations, we can leverage a lookup table. But
we start with simple and naive, then gradually iterate towards the better and
more complex.

---

##### Conditional jumps

It is not mandatory to have a data structure in memory representing a lookup
table as we can use conditional control flow statements. The choice between
these approaches and also between the type of conditional statements again
relies on the behavior of the compiler regarding the generated machine code.

Consider the use case of implementing a data struture to model hardware
registers of the processing unit. Such a record data structure can be utilized.

```c
union register8 {
    unsigned char reg;
    struct __attribute__ ((packed)) {
        unsigned char bit0 : 1;
        unsigned char bit1 : 1;
        unsigned char bit2 : 1;
        unsigned char bit3 : 1;
        unsigned char bit4 : 1;
        unsigned char bit5 : 1;
        unsigned char bit6 : 1;
        unsigned char bit7 : 1;
    } byte0;
};
```

The union encapsulates two aliased fields, an `unsigned char` representing an
8-bit register and a packed `struct` containing bit-fields with each field
having a width of one bit each, aliasing the bits of the `unsigned char` member,
facilitating access of individual bits of the register.

For setting individual bits, such a function can be utilized.

```c
union register8* register8_set_bit(union register8 *ptr, unsigned char bit) {
    switch (bit) {
        case 0:
            ptr->byte0.bit0 = 1;
            break;
        case 1:
            ptr->byte0.bit0 = 1;
            break;
        case 2:
            ptr->byte0.bit2 = 1;
            break;
        case 3:
            ptr->byte0.bit3 = 1;
            break;
        case 4:
            ptr->byte0.bit4 = 1;
            break;
        case 5:
            ptr->byte0.bit5 = 1;
            break;
        case 6:
            ptr->byte0.bit6 = 1;
            break;
        case 7:
            ptr->byte0.bit7 = 1;
            break;
        default:
            return 0;
    }
    return ptr;
}
```

The resulting assembly code and corresponding machine code shall not be listed
for brevity. Refer the Compiler Explorer tree[^6]. It so happens that
`switch`...`case` statements produce obnoxious amount of jumps in assembly with
`avr-gcc`. Falling back to the good old `if`...`else` construct alleviates this
undesirable latency.

```c
union register8* register8_set_bit(union register8 *ptr, unsigned char bit) {
    if (bit >= (sizeof(union register8) * 8 - 1)) {
        return 0;
    }
    if (bit == 0) {
        ptr->byte0.bit0 = 1;
    } else if (bit == 1) {
        ptr->byte0.bit1 = 1;
    } else if (bit == 2) {
        ptr->byte0.bit2 = 1;
    } else if (bit == 3) {
        ptr->byte0.bit3 = 1;
    } else if (bit == 4) {
        ptr->byte0.bit4 = 1;
    } else if (bit == 5) {
        ptr->byte0.bit5 = 1;
    } else if (bit == 6) {
        ptr->byte0.bit6 = 1;
    } else if (bit == 7) {
        ptr->byte0.bit7 = 1;
    }
    return ptr;
}
```

The source code above produces substantially lesser assembly code and
consequently lesser machine code. As mentioned earlier, refer the Compiler
Explorer tree[^6] for complete assembly listing. Below is a chunk of the
assembly code corresponding to the conditional block for zeroeth bit position. 

```asm
;    if (bit == 0) {
;        ptr->byte0.bit0 = 1;

        cpi r22,lo8(1)      ; bit == 1
        brsh .L16
        ld r24,Z            ; False branch ; r24 <- ptr ; Same as &ptr->reg
        ori r24,lo8(1<<0)   ; r24 <- r24 | 1
.L24:
        st Z,r24            ; ptr->reg <- r24
.L15:
        mov r24,r30
        mov r25,r31
        ret
```

This is the best we can achieve without a bit-value lookup. It is evident that
the loop for repeatedly left-shifting one by the number of given bit positions
is replaced by a single `OR` operation. A programmer with moderate amount of
programming experience shall observe that the problem stated earlier in this
text has been solved. However, for programmers that delve deeper into the
programming of embedded or constrained platforms, there is still a caveat in
terms of the size of the generated machine code. The chunk above is replicated
for each conditional block for respective bit positions.

---

##### Lookup table

The time-complexity has been reduced from linear to constant. The
space-complexity has not increased also. Therefore, this solution seems optimal.
But the increase in machine code size urges the keen programmer to pursue
further.

If we place an array of bit values in the memory, corresponding to eight bits
only for the given case, we can index into such an array using the bit position
passed as an argument.

```c
static
const 
unsigned char __bitvallookup[8] = {1, 2, 4, 8, 16, 32, 64, 128};
```c

A straightforward implementation is presented below.

```c
union register8* register8_set_bit(union register8 *ptr, unsigned char bit) {
    if (bit >= (sizeof(union register8) * 8 - 1)) {
        return 0;
    }
    ptr->reg |= __bitvallookup[bit];
    return ptr
}
```

This is the resulting assembly code.

```asm
; register8_set_bit(register8*, unsigned char):
        cpi r22,lo8(7)
        brsh .L16
        mov r30,r22
        ldi r31,0
        subi r30,lo8(-(__bitvallookup))
        sbci r31,hi8(-(__bitvallookup))
        mov r26,r24
        mov r27,r25
        ld r18,X
        ld r19,Z
        or r18,r19
        mov r30,r24
        mov r31,r25
        st Z,r18
        ret
.L16:
        ldi r24,0
        ldi r25,0
        ret
```

The desired goal of reducing machine code size albeit increasing the
space-complexity by a trivial amount has been achieved. An array of eight bytes
is allocated in the read-only data region. Job done and it works splendidly!

## A thing of beauty

What if, someone insisted on pushing the lever a notch further! Is there any
more scope of improvement?

Obsession as it may seem to some, frowned upon by many if it may be and
considered eccentric by a few if it has to be; this is when inline assembly
blocks become relevant. The compilers always have some degree of determinism
associated in their machine code generation. From the abstract syntax tree, to
intermediate representations, to machine code transformations, every step is
build on generalized primitives. This is to enable universality and
completeness. Purpose built machine code, only for the sake of optimization is
almost impossible to maintain and strives to function for a wide range of
inputs. It is irrational to expect the programmer to write performant and
correct programs with ease, catering such levels of nuanced behavior.

That said, we can make the function presented earlier, leaner with this
implementation presented below.

```c
union register8* register8_set_bit(union register8 *ptr, unsigned char bit) {
    asm volatile (
        "movw   r26, r24            \n\t"
        "cpi    r22, 0x08           \n\t"
        "brsh   __ret               \n\t" // branch if same or higher (unsigned)
        "add    r30, r22            \n\t"
        "adc    r31, __zero_reg__   \n\t"
        "ld     r22, Z              \n\t"
        "ld     r24, X              \n\t"
        "or     r24, r22            \n\t"
        "st     X, r24              \n\t"
        "__ret:                     \n\t"
        "movw   r24, r30            \n\t"
        "ret"
        :
        : "z" (__bitvallookup)
        : "r26", "r27"
    )
}
```

```asm
; register8_set_bit(register8*, unsigned char):
        ldi r30,lo8(__bitvallookup)
        ldi r31,hi8(__bitvallookup)
        cpi    r22, 0x08           
        brsh   __ret               
        movw   r26, r24            
        add    r30, r22            
        adc    r31, __zero_reg__   
        ld     r22, Z              
        ld     r24, X              
        or     r24, r22            
        st     X, r24              
        __ret:                     
        movw   r24, r30            
        ret
        ret
```

This concludes our discussion regarding the topic of bit-fields. Bear in
rememberance that these approaches are presented in specifity towards the `x86`
and `AVR` architectures and therefore shall be utilized with understanding.

[^1]: [Wikipedia - Bit field](https://en.wikipedia.org/wiki/Bit_field)
[^2]: [GNU software foundation - GNU C Language Manual - Bit Fields](https://www.gnu.org/software/c-intro-and-ref/manual/html_node/Bit-Fields.html)
[^3]: [GNU software foundation - GNU C Language Manual - Packed Structures](https://www.gnu.org/software/c-intro-and-ref/manual/html_node/Packed-Structures.html)
[^4]: [GNU software foundation - GNU C Language Manual - Bit Field Packing](https://www.gnu.org/software/c-intro-and-ref/manual/html_node/Bit-Field-Packing.html)
[^5]: [GNU software foundation - Using the GNU Compiler Collection - Warning Options](https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html#index-Wpacked-bitfield-compat)
[^6]: [Compiler Explorer tree](https://godbolt.org/z/5b88ErEaP)
