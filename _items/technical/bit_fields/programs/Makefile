#
# Copyright (c) 2026 notweerdmonk
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# For more information, please refer to <https://unlicense.org>
#

SOURCES := $(wildcard *.cc)
TARGETS := $(SOURCES:.cc=)

ifeq ($(strip $(TOOLCHAIN)),)
TOOLCHAIN := gnu
endif
ifeq ($(strip $(PROGRAM)),)
PROGRAM := c++
endif

ARCH := $(shell echo $(ARCH) | tr '[:upper:]' '[:lower:]')
TOOLCHAIN := $(shell echo $(TOOLCHAIN) | tr '[:upper:]' '[:lower:]')
COMPILER := $(shell echo $(COMPILER) | tr '[:upper:]' '[:lower:]')
PROGRAM := $(shell echo $(PROGRAM) | tr '[:upper:]' '[:lower:]')

ifeq ($(strip $(COMPILER)),)

ifeq ($(strip $(TOOLCHAIN)),llvm)

ifeq ($(strip $(PROGRAM)),c)
COMPILER := clang
else ifeq ($(strip $(PROGRAM)),c++)
COMPILER := clang++
else
$(info PROGRAM: possible languages are c, c++)
$(error ERROR: unrecognized language specified)
endif

else ifeq ($(strip $(TOOLCHAIN)),msvc)

ifeq ($(strip $(PROGRAM)),c)
COMPILER := cl
else ifeq ($(strip $(PROGRAM)),c++)
COMPILER := cl
else
$(info PROGRAM: possible languages are c, c++)
$(error ERROR: unrecognized language specified)
endif

else ifeq ($(strip $(TOOLCHAIN)),gnu)

ifeq ($(strip $(PROGRAM)),c)

ifeq ($(strip $(ARCH)),avr)
COMPILER := avr-gcc
else
COMPILER := gcc
endif

else ifeq ($(strip $(PROGRAM)),c++)

ifeq ($(strip $(ARCH)),avr)
COMPILER := avr-g++
else
COMPILER := g++
endif

else
$(info PROGRAM: possible languages are c, c++)
$(error ERROR: unrecognized language specified)
endif

else

$(info TOOLCHAIN: possible values are gnu, llvm, msvc)
$(error ERROR: unrecognized toolchain specified)

endif

endif

all: $(TARGETS)

%: %.cc
	$(COMPILER) -Wall -Wextra -fstrict-aliasing -Wno-unused-parameter -o $@ $<

clean:
	rm -f $(TARGETS)
