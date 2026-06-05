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

#if defined __cplusplus && !defined __AVR__
#include <cstdio>
#else
#include <stdio.h>
#endif

struct a_non_packed {
    unsigned char a : 3;
    unsigned char b : 3;
    unsigned char c : 3;
    unsigned char d : 3;
    unsigned char e : 3;
};

#ifdef _MSC_VER
#pragma pack(1)
struct a_packed {
#else
struct __attribute__((packed)) a_packed {
#endif
    unsigned char a : 3;
    unsigned char b : 3;
    unsigned char c : 3;
    unsigned char d : 3;
    unsigned char e : 3;
};

struct b_non_packed {
    unsigned char a : 3;
    unsigned char b : 3;
    unsigned int  c : 3;
    unsigned char d : 3;
    unsigned char e : 3;
};

#ifdef _MSC_VER
#pragma pack(1)
struct b_packed {
#else
struct __attribute__((packed)) b_packed {
#endif
    unsigned char a : 3;
    unsigned char b : 3;
    unsigned int  c : 3;
    unsigned char d : 3;
    unsigned char e : 3;
};

const unsigned long a_size = sizeof(struct a_non_packed);
const unsigned long a_packed_size = sizeof(struct a_packed);
const unsigned long b_size = sizeof(struct b_non_packed);
const unsigned long b_packed_size = sizeof(struct b_packed);

int main(int argc, char *argv[]) {
    printf(
        "%lu %lu %lu %lu\n",
        a_size,
        b_size,
        a_packed_size,
        b_packed_size
    );

    return 0;
}
