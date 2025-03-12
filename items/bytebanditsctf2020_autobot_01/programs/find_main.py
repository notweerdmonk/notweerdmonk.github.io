# Find address and/or step into the main function in an ELF stripped of symbols

import gdb
import re


rax = ""
rdx = ""
rip = ""
main_call_addr = ""
main_called = False


def get_reg_value(register):
    try:
        val = gdb.execute(f"info register ${register}", to_string=True).split()[1]
    except:
        return None
    return val

def get_instr_addr(addr, l, instruction, op_hint=""):
    if not addr:
        return None

    disas_output = gdb.execute(f"disas {addr}, +{l}", to_string=True)

    for line in disas_output.splitlines():
        if re.search(f"\s+call\s+.*{op_hint}", line):
            line = line.lstrip("=>")[: line.find(":")].strip()
            space_idx = line.find(" ")
            addr = line[:space_idx] if space_idx != -1 else line
            if addr == -1:
                return None
            return addr


def get_entry_point():
    # Halt at _start of ld.so
    gdb.execute("starti")

    info_output = gdb.execute("info files", to_string=True)

    for line in info_output.splitlines():
        if re.search("\s+Entry point", line):
            entry_point_line = line.strip()
            entry_point_address = entry_point_line.split(":")[1].strip()
            return entry_point_address


def set_breakpoint(addr):
    if addr:
        print(f"Setting breakpoint at addr: {addr}")
        gdb.execute(f"break *{addr}")
    else:
        print("Addr is None.")

def clear_all_breakpoints():
    gdb.execute("delete")

def find_main(restart=False, step=False):
    global rax
    global rdx
    global rip
    global main_call_addr
    global main_called

    if not restart:
        if step and not main_called and get_reg_value("rip") == main_call_addr:
            gdb.execute("stepi")
            main_called = True
            return rax

        if len(main_call_addr) > 0:
            return rax

    clear_all_breakpoints()
    main_called = False

    # Set breakpoint at _start of ELF
    set_breakpoint(get_entry_point())
    gdb.execute("continue")

    # Next call is to __libc_start_main
    rip = get_reg_value("rip")
    call_addr = get_instr_addr(rip, 100, "call")

    set_breakpoint(call_addr)
    gdb.execute("continue")

    gdb.execute("stepi")

    gdb.execute("break __libc_start_call_main")
    gdb.execute("continue")

    # Track argv value as it gets loaded into rsi as argument to find the call
    # to main
    rdx = get_reg_value("rdx")

    gdb.execute(f"watch $rsi == {rdx}")
    gdb.execute("continue")

    # Address of main is loaded into rax
    # Instruction looks like:
    # 0x0000xxxxxxxxxxxx:  call    rax
    rip = get_reg_value("rip")
    call_addr = get_instr_addr(rip, 20, "call")

    set_breakpoint(call_addr)
    gdb.execute("continue")

    main_call_addr = get_reg_value("rip")

    rax = get_reg_value("rax")

    if step:
        gdb.execute("stepi")
        main_called = True

    return rax


class RegisterEntryPointCommand(gdb.Command):
    def __init__(self):
        super(RegisterEntryPointCommand, self).__init__(
            "get_entry_point", gdb.COMMAND_USER
        )

    def invoke(self, arg, from_tty):
        entry_point = get_entry_point()
        if entry_point:
            print(f"Entry point address: {entry_point}")
        else:
            print("Entry point not found.")


class RegisterSetBreakpointCommand(gdb.Command):
    def __init__(self):
        super(RegisterSetBreakpointCommand, self).__init__(
            "set_breakpoint", gdb.COMMAND_USER
        )

    def invoke(self, arg, from_tty):
        set_breakpoint(arg)


class RegisterGetInstructionAddrCommand(gdb.Command):
    def __init__(self):
        super(RegisterGetInstructionAddrCommand, self).__init__(
            "get_instr_addr", gdb.COMMAND_USER
        )

    def invoke(self, arg, from_tty):
        args = [a.rstrip(",") for a in arg.split()]
        print(
            get_instr_addr(
                args[0], args[1], args[2], "" if len(args) < 4 else args[3]
            )
        )


class RegisterFindMainCommand(gdb.Command):
    def __init__(self):
        super(RegisterFindMainCommand, self).__init__(
            "find_main", gdb.COMMAND_USER
        )

    def invoke(self, arg, from_tty):
        restart = False
        if arg == "r" or arg == "restart":
            restart = True
        print(f"Address of main function is: {find_main(restart, False)}")


class RegisterStepMainCommand(gdb.Command):
    def __init__(self):
        super(RegisterStepMainCommand, self).__init__(
            "step_main", gdb.COMMAND_USER
        )

    def invoke(self, arg, from_tty):
        restart = False
        if arg == "r" or arg == "restart":
            restart = True
        print(f"Address of main function is: {find_main(restart, True)}")


RegisterEntryPointCommand()
RegisterSetBreakpointCommand()
RegisterGetInstructionAddrCommand()
RegisterFindMainCommand()
RegisterStepMainCommand()
