import gdb
import re


rax = ""
rdx = ""
rdi = ""
rip = ""
main_call_addr = ""
main_called = False


def get_entry_point(start=False):
    if start:
        # Halt at _start of ld.so
        gdb.execute("starti")

    info_output = gdb.execute("info files", to_string=True)

    for line in info_output.splitlines():
        if re.search("\s+Entry point", line):
            entry_point_line = line.strip()
            entry_point_address = entry_point_line.split(":")[1].strip()
            return entry_point_address


def get_reg_value(register):
    try:
        val = gdb.execute(f"output/x ${register}", to_string=True)
    except:
        return None
    return val


def get_instr_addr(addr, l, instruction, op_hint=""):
    if not addr:
        return None

    disas_output = gdb.execute(f"disas {addr}, +{l}", to_string=True)

    for line in disas_output.splitlines():
        if re.search(f"\s+{instruction}\s+.*{op_hint}", line):
            line = line.lstrip("=>")
            line = line[:line.find(":")].strip()
            space_idx = line.find(" ")
            addr = line[:space_idx] if space_idx != -1 else line
            if addr == -1:
                return None
            return addr


def run_until(addr):
    if addr:
        print(f"Running program till {addr}")
        if addr.startswith("0x"):
            addr = "*" + addr
        gdb.execute(f"until {addr}")
    else:
        print("Addr is None.")


def set_breakpoint(addr, temp=False):
    cmd = "tbreak" if temp else "break"
    if addr:
        print(f"Setting breakpoint at {addr}")
        if addr.startswith("0x"):
            addr = "*" + addr
        gdb.execute(f"{cmd} {addr}")
        return int(gdb.convenience_variable("bpnum"))
    else:
        print("Addr is None.")
        return None


def set_watchpoint(expr):
    if expr:
        print(f"Setting watchpoint for {expr}")
        gdb.execute(f"watch {expr}")
        return int(gdb.convenience_variable("bpnum"))
    else:
        print("Watch expression is None.")
        return None


def clear_breakpoint(num):
    if isinstance(num, int):
        gdb.execute(f"delete {num}")
    else:
        print("Invalid breakpoint number")


def clear_all_breakpoints():
    gdb.execute("delete")


# fast will override step
def find_main(step=False, fast=False, restart=False, clean=False):
    global rax
    global rdx
    global rdi
    global rip
    global main_call_addr
    global main_called

    clean = True if clean else False

    if not restart:
        if step and not main_called and get_reg_value("rip") == main_call_addr:
            gdb.execute("stepi")
            main_called = True
            return rax

        if len(main_call_addr) > 0:
            return rax

        if len(rdi) > 0:
            return rdi

    clear_all_breakpoints()
    main_called = False

    # Set breakpoint at _start of ELF
    set_breakpoint(get_entry_point(True), clean)
    gdb.execute("continue")

    # Next call is to __libc_start_main
    rip = get_reg_value("rip")
    call_addr = get_instr_addr(rip, 100, "call")

    set_breakpoint(call_addr, clean)
    gdb.execute("continue")

    if fast:
        # Calling convention wise $rdi = &main
        rdi = get_reg_value("rdi")
        set_breakpoint(rdi, clean)
        gdb.execute("continue")
        main_called = True
        return rdi

    else:
        gdb.execute("stepi")

        set_breakpoint("__libc_start_call_main", clean)
        gdb.execute("continue")

        # Track argv value as it gets loaded into rsi as argument to find the call
        # to main
        rdx = get_reg_value("rdx")

        watchpoint_num = set_watchpoint(f"$rsi == {rdx}")

        gdb.execute("continue")

        if clean:
            clear_breakpoint(watchpoint_num)

        # Address of main is loaded into rax
        # Instruction looks like:
        # 0x0000xxxxxxxxxxxx:  call    rax
        rip = get_reg_value("rip")
        call_addr = get_instr_addr(rip, 20, "call")

        set_breakpoint(call_addr, clean)
        gdb.execute("continue")

        main_call_addr = get_reg_value("rip")

        rax = get_reg_value("rax")

    if step:
        gdb.execute("stepi")
        main_called = True

    return rax


class register_get_entry_point_command(gdb.Command):
    """
    Get the entry point of the program. The program needs to be running else
    the offset in the program file will be provided.

    Usage:
        get_entry_point [start]

    Options:
        start       Start the program if any argument is given.
    """

    def __init__(self):
        super(register_get_entry_point_command, self).__init__(
            "get_entry_point", gdb.COMMAND_USER
        )

    def invoke(self, arg, from_tty):
        arg = True if arg else False
        entry_point = get_entry_point(arg)
        if entry_point:
            print(f"Entry point address: {entry_point}")
        else:
            print("Entry point not found.")


class register_run_until_command(gdb.Command):
    """
    Run the program till given address within the current frame.

    Usage:
        run_until <address>
    """

    def __init__(self):
        super(register_run_until_command, self).__init__(
            "run_until", gdb.COMMAND_USER
        )

    def invoke(self, arg, from_tty):
        run_until(arg)


class register_set_breakpoint_command(gdb.Command):
    """
    Set a breakpoint at the given address.

    Usage:
        set_breakpoint <address> [temporary]

    Options:
        temporary       Set a temporary breakpoint if any argument is given.
    """

    def __init__(self):
        super(register_set_breakpoint_command, self).__init__(
            "set_breakpoint", gdb.COMMAND_USER
        )

    def invoke(self, arg, from_tty):
        args = [a.rstrip(",") for a in arg.split()]
        if len(args) > 1:
            set_breakpoint(args[0], args[1])
        else:
            set_breakpoint(args[0])


class register_set_watchpoint_command(gdb.Command):
    """
    Set a watchpoint for the given expression.

    Usage:
        set_watchpoint <expression>
    """

    def __init__(self):
        super(register_set_watchpoint_command, self).__init__(
            "set_watchpoint", gdb.COMMAND_USER
        )

    def invoke(self, arg, from_tty):
        set_watchpoint(arg)


class register_get_instruction_addr_command(gdb.Command):
    """
    Get the address of next occurence of given instruction matching given hints
    for operands starting from given address till given number of bytes.

    Usage:
        get_instr_addr <address> <length> <instruction> <hint>
    """

    def __init__(self):
        super(register_get_instruction_addr_command, self).__init__(
            "get_instr_addr", gdb.COMMAND_USER
        )

    def invoke(self, arg, from_tty):
        args = [a.rstrip(",") for a in arg.split()]
        print(
            get_instr_addr(
                args[0], args[1], args[2], "" if len(args) < 4 else args[3]
            )
        )


class register_find_main_command(gdb.Command):
    """
    Find the main function of the program and halt before the call.

    Usage:
        find_main [fast] [restart] [clean]

    Options:
        fast        Use faster method skipping intermittent breakpoints.
        restart     Restart the procedure.
        clean       Use temporary breakpoints and clear watchpoints.
    """

    def __init__(self):
        super(register_find_main_command, self).__init__(
            "find_main", gdb.COMMAND_USER
        )

    def invoke(self, arg, from_tty):
        args = [a.rstrip(",") for a in arg.split()]
        clean = False
        if "c" in args or "clean" in args:
            clean = True
        restart = False
        if "r" in args or "restart" in args:
            restart = True
        fast = False
        if "f" in args or "fast" in args:
            fast = True
        print(f"Address of main function is: {find_main(False, fast, restart, clean)}")
        if fast:
            print("Stepped into main function")


class register_step_main_command(gdb.Command):
    """
    Step inside the main function of the program and halt before the call.

    Usage:
        step_main [fast] [restart] [clean]

    Options:
        fast        Use faster method skipping intermittent breakpoints.
        restart     Restart the procedure.
        clean       Use temporary breakpoints and clear watchpoints.
    """
    def __init__(self):
        super(register_step_main_command, self).__init__(
            "step_main", gdb.COMMAND_USER
        )

    def invoke(self, arg, from_tty):
        args = [a.rstrip(",") for a in arg.split()]
        clean = False
        if "c" in args or "clean" in args:
            clean = True
        restart = False
        if "r" in args or "restart" in args:
            restart = True
        fast = False
        if "f" in args or "fast" in args:
            fast = True
        print(f"Address of main function is: {find_main(True, fast, restart, clean)}")
        print("Stepped into main function")


register_get_entry_point_command()
register_get_instruction_addr_command()
register_run_until_command()
register_set_breakpoint_command()
register_set_watchpoint_command()
register_find_main_command()
register_step_main_command()
