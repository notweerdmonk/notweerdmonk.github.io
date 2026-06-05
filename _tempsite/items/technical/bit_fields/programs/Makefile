SOURCES := $(wildcard *.cc)
TARGETS := $(SOURCES:.cc=)

ifeq ($(strip $(TOOLCHAIN)),)
TOOLCHAIN := gnu
endif
ifeq ($(strip $(PROGRAM)),)
PROGRAM := c++
endif

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
COMPILER := gcc
else ifeq ($(strip $(PROGRAM)),c++)
COMPILER := g++
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
