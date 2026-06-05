/*
 * Copyright (c) 2026 notweerdmonk
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <https://unlicense.org>
 */

#ifdef __cplusplus
#include <cstdio>
#else
#include <stdio.h>
#endif

/* NOTE: This source code requires pointer safety checks for production */

/* Enables optimal conditional statements implementation */
//#define __OPTIMAL_CONDITIONAL__ 

/* Enables most optimal inline-assembly implementation */
#define __CUSTOM_ASM__

struct __attribute__ ((packed)) bits {
    unsigned char bit0 : 1;
    unsigned char bit1 : 1;
    unsigned char bit2 : 1;
    unsigned char bit3 : 1;
    unsigned char bit4 : 1;
    unsigned char bit5 : 1;
    unsigned char bit6 : 1;
    unsigned char bit7 : 1;
};

union register8 {
    unsigned char reg;
    struct bits byte0;
};

union register16 {
    unsigned short reg;
    struct {
        struct bits byte0;    
        struct bits byte1;    
    } bytes;
};

static
unsigned char __bitvallookup[8] = {1, 2, 4, 8, 16, 32, 64, 128};

unsigned char bit8_to_mask8(unsigned char bit) {
    if (bit < sizeof(__bitvallookup)) {
        return __bitvallookup[bit];
    }
    return 0;
}

unsigned char bits_get_bit(
        struct bits *ptr,
        unsigned char bit
) {
    if (bit >= (sizeof(union register8) * 8 - 1)) {
        return 255;
    }
    if (bit == 0) {
        return ptr->bit0;
    } else if (bit == 1) {
        return ptr->bit1;
    } else if (bit == 2) {
        return ptr->bit2;
    } else if (bit == 3) {
        return ptr->bit3;
    } else if (bit == 4) {
        return ptr->bit4;
    } else if (bit == 5) {
        return ptr->bit5;
    } else if (bit == 6) {
        return ptr->bit6;
    } else if (bit == 7) {
        return ptr->bit7;
    }
    return 255;
}

unsigned char register8_get_bit(
        union register8 *ptr,
        unsigned char bit
) {
    return bits_get_bit(&(ptr->byte0), bit);
}

union register8* register8_set_bit_intrinsic(
    union register8 *ptr,
    unsigned char bit
) {
    ptr->reg |= (1 << bit);
    return ptr;
}

struct bits* bits_set_bit(
        struct bits *ptr,
        unsigned char bit
) {
#ifdef __AVR__
#ifdef __CUSTOM_ASM__
    asm volatile (
        "cpi    r22, 0x08           \n\t"
        "brsh   __ret               \n\t" // branch if same or higher (unsigned)
        "movw   r26, r24            \n\t"
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
    );
#else
    if (bit >= (sizeof(struct bits) * 8 - 1)) {
        return 0;
    }
    if (bit == 0) {
        ptr->bit0 = 1;
    } else if (bit == 1) {
        ptr->bit1 = 1;
    } else if (bit == 2) {
        ptr->bit2 = 1;
    } else if (bit == 3) {
        ptr->bit3 = 1;
    } else if (bit == 4) {
        ptr->bit4 = 1;
    } else if (bit == 5) {
        ptr->bit5 = 1;
    } else if (bit == 6) {
        ptr->bit6 = 1;
    } else if (bit == 7) {
        ptr->bit7 = 1;
    }
#endif
#else
    switch (bit) {
        case 0:
            ptr->bit0 = 1;
            break;
        case 1:
            ptr->bit0 = 1;
            break;
        case 2:
            ptr->bit2 = 1;
            break;
        case 3:
            ptr->bit3 = 1;
            break;
        case 4:
            ptr->bit4 = 1;
            break;
        case 5:
            ptr->bit5 = 1;
            break;
        case 6:
            ptr->bit6 = 1;
            break;
        case 7:
            ptr->bit7 = 1;
            break;
        default:
            return 0;
    }
#endif
    return ptr;
}

union register8* register8_set_bit(
        union register8 *ptr,
        unsigned char bit
) {
#if defined __AVR__ && defined __OPTIMAL_CONDITIONAL__
    if (bit >= (sizeof(struct bits) * 8 - 1)) {
        return 0;
    }
    ptr->reg |= __bitvallookup[bit];
    return ptr;
#else
    (void)bits_set_bit(&(ptr->byte0), bit);
    return ptr;
#endif
}

struct bits* bits_clear_bit(
        struct bits *ptr,
        unsigned char bit
) {
    if (bit >= (sizeof(struct bits) * 8 - 1)) {
        return 0;
    }
    if (bit == 0) {
        ptr->bit0 = 0;
    } else if (bit == 1) {
        ptr->bit1 = 0;
    } else if (bit == 2) {
        ptr->bit2 = 0;
    } else if (bit == 3) {
        ptr->bit3 = 0;
    } else if (bit == 4) {
        ptr->bit4 = 0;
    } else if (bit == 5) {
        ptr->bit5 = 0;
    } else if (bit == 6) {
        ptr->bit6 = 0;
    } else if (bit == 7) {
        ptr->bit7 = 0;
    }
    return ptr;
}

union register8* register8_clear_bit(
        union register8 *ptr,
        unsigned char bit
) {
    (void)bits_clear_bit(&(ptr->byte0), bit);
    return ptr;
}

unsigned short register16_get_bit(
        union register16 *ptr,
        unsigned char bit
) {
    if (bit < (sizeof(struct bits) * 8)) {
        return (unsigned short)bits_get_bit(&(ptr->bytes.byte0), bit);
    }

    return (unsigned short)bits_get_bit(&(ptr->bytes.byte1), bit - 8);
}

union register16* register16_set_bit(
        union register16 *ptr,
        unsigned char bit
) {
    if (bit < (sizeof(struct bits) * 8)) {
        (void)bits_set_bit(&(ptr->bytes.byte0), bit);
    }
    (void)bits_set_bit(&(ptr->bytes.byte1), bit - 8);

    return ptr;
}

union register16* register16_clear_bit(
        union register16 *ptr,
        unsigned char bit
) {
    if (bit < (sizeof(struct bits) * 8)) {
        (void)bits_clear_bit(&(ptr->bytes.byte0), bit);
    }
    (void)bits_clear_bit(&(ptr->bytes.byte1), bit - 8);

    return ptr;
}

int main() {
    /* 8-bit register representation */
    union register8 R0;

    R0.byte0.bit0 = 1;
    R0.byte0.bit3 = 1;
    R0.byte0.bit5 = 1;
    R0.byte0.bit7 = 0;

    register8_set_bit(&R0, 6);

    printf("8-bit regiter bit 6 \t= %#x\n", register8_get_bit(&R0, 6));

    register8_clear_bit(&R0, 6);

    printf("8-bit regiter bit 6 \t= %#x\n", register8_get_bit(&R0, 6));

    /*************************************************************************/

    /* 16-bit register representation */
    union register16 R2;

    R2.bytes.byte0.bit1 = 1;
    R2.bytes.byte0.bit3 = 0;
    R2.bytes.byte1.bit5 = 1;
    R2.bytes.byte0.bit7 = 0;

    register16_set_bit(&R2, 12);

    printf("16-bit regiter bit 12 \t= %#x\n", register16_get_bit(&R2, 12));

    register16_clear_bit(&R2, 12);

    printf("16-bit regiter bit 12 \t= %#x\n", register16_get_bit(&R2, 12));

    /*************************************************************************/

    unsigned char mask;
    mask = bit8_to_mask8(6);

    printf("8-bit mask for bit 6 \t= %#010x\n", mask);

    return 0;
}
