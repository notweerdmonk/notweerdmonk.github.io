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

struct {
    unsigned char a : 3;
    unsigned char b : 3;
    unsigned char c : 3;
    unsigned char d : 3;
    unsigned char e : 3;
} a;

#ifdef _MSC_VER
#pragma pack(1)
#else
struct __attribute__((packed)) {
#endif
    unsigned char a : 3;
    unsigned char b : 3;
    unsigned char c : 3;
    unsigned char d : 3;
    unsigned char e : 3;
} a_packed;

struct {
    unsigned char a : 3;
    unsigned char b : 3;
    unsigned int c : 3;
    unsigned char d : 3;
    unsigned char e : 3;
} b;

#ifdef _MSC_VER
#pragma pack(1)
#else
struct __attribute__((packed)) {
#endif
    unsigned char a : 3;
    unsigned char b : 3;
    unsigned int c : 3;
    unsigned char d : 3;
    unsigned char e : 3;
} b_packed;

const int a_size = sizeof(a);
const int a_packed_size = sizeof(a_packed);
const int b_size = sizeof(b);
const int b_packed_size = sizeof(b_packed);

int main(int argc, char *argv[]) {
    printf(
#ifdef _MSC_VER
        "%zu %zu %zu %zu\n",
#else
        "%lu %lu %lu %lu\n",
#endif
        sizeof(a),
        sizeof(b),
        sizeof(a_packed),
        sizeof(b_packed)
    );

    return 0;
}
