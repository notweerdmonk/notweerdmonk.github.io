.DEFAULT_GOAL: all

SHELL := /bin/bash

define run_prog
@for f in $(1); \
do \
	echo File: "$$f"; \
	cat "$$f"; \
	xxd -p "$$f" | grep -s "0a" >/dev/null || echo; \
	echo Hexdump:; \
	xxd -c 1 "$$f"; \
	echo -e "\nRunning" $<; \
	./$< "$$f"; \
	echo; \
done
endef

all: test-prog1 test-prog2 test-prog3 test-prog4 test-prog5

test-prog1: prog1
	$(call run_prog,file{1..2}.txt)

test-prog2: prog2
	$(call run_prog,file{1..3}.txt)

test-prog3: prog3
	$(call run_prog,file{1..3}.txt)

test-prog4: prog4
	$(call run_prog,file{4..9}.txt)

test-prog5: prog5
	$(call run_prog,file{4..9}.txt)

clean:
	-$(RM) prog{1..5}
