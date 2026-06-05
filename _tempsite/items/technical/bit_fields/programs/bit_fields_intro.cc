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

struct counter {
    unsigned short id               : 2;
    unsigned short count_direction  : 1;
    unsigned short repeat           : 1;
    unsigned short count            : 6;
    unsigned short top              : 6;
} counter = {
    .id = 0,
    .count_direction = 0,
    .repeat = 0,
    .count = 0,
    .top = 0
};

union counter_u {
    unsigned short bytes;
    struct {
        unsigned short id               : 2;
        unsigned short count_directon   : 1;
        unsigned short repeat           : 1;
        unsigned short counter          : 6;
        unsigned short top              : 6;
    } counter;
} counter2 = {
    .bytes = 0,
};

union counter_u* set_counter_bits(
    union counter_u *p,
    unsigned char bitpos,
    unsigned short value
) {
    p->bytes |= (value << bitpos);
    return p;
}

union counter_u counter3 = { .bytes = 0 };

struct bit_field_struct {
    unsigned char opcode    : 4;
    signed char small       : 4;
} s;

int main(int argc, char *argv[]) {

    counter.count_direction =
        (
            COUNTER_COUNT_UP_REPEAT &
            COUNTER_FIELD_COUNT_DIRECTION_MASK
        ) >> COUNTER_FIELD_COUNT_DIRECTION_BITPOS;

    counter.repeat =
        (
            COUNTER_COUNT_UP_REPEAT &
            COUNTER_FIELD_REPEAT_MASK
        ) >> COUNTER_FIELD_REPEAT_BITPOS;

    printf("counter.count_direction = %#2x\n", counter.count_direction);
    printf("counter.repeat \t\t= %#2x\n", counter.repeat);

    /*************************************************************************/

    /*
     * Assume you want to set the `top` field of the `struct counter`.
     * An object of `struct counter is punned as an `unsigned short` the contents
     * in memory are 'OR'ed with 0b0100000000000000 or 0x4000.
     */
    *(unsigned short*)&counter |= (unsigned short)(16 << 10);

    printf("counter.top \t\t= %#2x\n", counter.top);

    /*
     * Alias `struct counter` with `unsigned short` within `union counter_u`.
     * This is specific to x86 architecture.
     */
    counter2.bytes |= (unsigned short)(16 << COUNTER_FIELD_TOP_BITPOS);

    printf("counter2.top \t\t= %#2x\n", counter2.counter.top);

    /*************************************************************************/

    (void)set_counter_bits(&counter3, COUNTER_FIELD_TOP_BITPOS, 16);

    printf("counter3.top \t\t= %#2x\n", counter3.counter.top);

    /*************************************************************************/

    s.opcode = 0xa;
    s.small = 0xa;

    putchar('\n');
    printf("opcode\t(hex)\t= %#010x\n", (unsigned int)s.opcode);
    printf("opcode\t(uint)\t= %u\n", (int)s.opcode);
    printf("small\t(hex)\t= %#010x\n", (unsigned int)s.small);
    printf("small\t(uint)\t= %u\n", (int)s.small);

    return 0;
}
