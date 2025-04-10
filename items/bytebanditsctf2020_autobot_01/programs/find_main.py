import gdb
import re
from typing import Union, Any


"""
Copyright 2025 notweerdmonk

I do not give anyone permissions to use this tool for any purpose. Don't use it.

I’m not interested in changing this license. Please don’t ask.
"""

"""
Find the main function in a program and more.
"""


rax = ""
rdx = ""
rdi = ""
rip = ""
main_call_addr = ""
main_addr = ""
main_called = False
labels = {}
result = None


class token(type):
    literal = 0
    op = 1

    def __contains__(cls, item: Any):
        if hasattr(cls, "coerce"):
            try:
                item = cls.coerce(item)
            except Exception:
                return False
        return item in cls.oplist


class op(metaclass=token):
    plus = "+"
    minus = "-"
    mul = "*"
    div = "/"
    oplist = [plus, minus, mul, div]

    def __init__(self, symbol: str):
        if symbol not in type(self):
            raise ValueError(f"{symbol!r} is not a valid {type(self).__name__}")
        self.symbol = symbol

    @classmethod
    def coerce(cls, symbol: Any):
        if isinstance(symbol, str) and hasattr(cls, symbol):
            return getattr(cls, symbol)
        return str(symbol)


def expect_tok(symbol: str, expected: token):
    return (
        symbol
        if expected == token.op and symbol in op
        else symbol
        if expected == token.literal and symbol not in op
        else None
    )


def flatten(t: Union[tuple, list, dict]):
    if isinstance(t, tuple) or isinstance(t, list) or isinstance(t, dict):
        for e in t:
            yield from flatten(e)
    else:
        yield t


def check_arith_expr(string: str):
    tokidx = 0
    comma = string.find(",")
    if comma > -1:
        _, addr = check_arith_expr(string[:comma])
        if addr is not None:
            tokidx = tokidx + 1
        return tokidx, addr
    tokens = string.split()
    toklen = len(tokens)

    left = ()
    while tokidx < toklen:
        if len(left) == 0:
            left = expect_tok(tokens[tokidx], token.literal)
            if left is None:
                return tokidx, left if len(left) > 0 else None
            else:
                tokidx = tokidx + 1

        if tokidx >= toklen:
            return tokidx, None
        op = expect_tok(tokens[tokidx], token.op)
        if op is None:
            return tokidx, left

        tokidx = tokidx + 1

        right = (
            expect_tok(tokens[tokidx], token.literal)
            if tokidx < toklen
            else None
        )
        if right is None:
            return tokidx, None

        tokidx = tokidx + 1

        left = (left, op, right)

    return tokidx, left


def get_var(name: str):
    if name is None or len(name) == 0:
        return name

    if name.startswith("$"):
        val = gdb.convenience_variable(name[1:])
        if val is None:
            val = gdb.parse_and_eval(name)
        if val is not None:
            return str(val).strip('"')
    else:
        val = get_label_value(name)
        if val is not None:
            return str(val).strip('"')

    return name


def set_var(name: str, val: Any, type_signature: str = "void (*)()"):
    gdb.set_convenience_variable(
        name,
        gdb.parse_and_eval(f"({type_signature}){str(val)}")
    )


def to_addr(name: str):
    if isinstance(name, int):
        return hex(name)

    name = str(name)
    if not name.startswith("0x"):
        try:
            return hex(gdb.parse_and_eval(name))
        except gdb.error:
            return

    return name


def set_result(val: Any, type_signature: str = "long"):
    global result

    result = val
    labels["result"] = val
    set_var(
        "result",
        str(val).strip('"'),
        type_signature=str(type_signature.strip())
    )


def get_label_value(label: str):
    return labels.get(label, None)


def def_var(name: str, addr: str, type_signature: str = "int"):
    labels[name] = addr
    set_var(name, addr, type_signature=str(type_signature.strip() + "*"))


def def_label(name: str, addr: str):
    labels[name] = addr
    set_var(name, addr)


def def_function(name: str, addr: str):
    def_label(name, addr)


def lbreak(label: str):
    addr = get_label_value(label)
    if addr is not None:
        return set_breakpoint(addr)


def lwatch(label: str):
    addr = get_label_value(label)
    if addr is not None:
        return set_watchpoint(addr)


def luntil(label: str):
    addr = get_label_value(label)
    if isinstance(addr, int):
        addr = hex(addr)
    if addr is not None:
        run_until(addr)


def ldisassemble(label: str, n: int):
    addr = get_var(label)
    # addr = get_label_value(label)
    if addr is None:
        return
    if not addr.startswith("0x"):
        return
    try:
        gdb.execute(f"disassemble {addr}, +{n}")
    except gdb.error:
        return


def get_entry_point(start: bool = False):
    if start:
        # Halt at _start of ld.so
        gdb.execute("starti")

    info_output = gdb.execute("info files", to_string=True)

    for line in info_output.splitlines():
        match = re.search("(Entry point:\s+)(0x[a-fA-F0-9]*)", line)
        if match and len(match.groups()) == 2:
            entry_point = match.group(2)
            return entry_point


def get_reg_value(register: str):
    try:
        val = gdb.execute(f"output/x ${register}", to_string=True)
    except gdb.error:
        return
    return val


def get_instr_addr(addr: str, n: int, instruction: str, op_hint: str = ""):
    if not addr:
        return

    try:
        disas_output = gdb.execute(f"disas {addr}, +{n}", to_string=True)
    except gdb.error:
        print("Syntax error")
        return
    except Exception:
        return

    for line in disas_output.splitlines():
        if re.search(f"\s+{instruction}\s+.*{op_hint}", line):
            line = line.lstrip("=>")
            line = line[: line.find(":")].strip()
            space_idx = line.find(" ")
            addr = line[:space_idx] if space_idx != -1 else line
            return None if len(addr) == 0 else addr


def run_until(addr: str):
    if addr:
        print(f"Running program till {addr}")
        if addr.startswith("0x"):
            addr = "*" + addr
        try:
            gdb.execute(f"until {addr}")
        except gdb.error:
            return
    else:
        print("Addr is None.")


def set_breakpoint(addr: str, temp: bool = False):
    cmd = "tbreak" if temp else "break"

    if addr:
        print(f"Setting breakpoint at {addr}")
        if addr.startswith("0x"):
            addr = "*" + addr
        try:
            gdb.execute(f"{cmd} {addr}")
        except gdb.error:
            return
        return int(gdb.convenience_variable("bpnum"))
    else:
        print("Addr is None.")
        return


def set_watchpoint(expr: str):
    if expr:
        print(f"Setting watchpoint for {expr}")
        try:
            gdb.execute(f"watch {expr}")
        except gdb.error:
            return
        return int(gdb.convenience_variable("bpnum"))
    else:
        print("Watch expression is None.")
        return


def clear_breakpoint(num: int):
    if isinstance(num, int):
        try:
            gdb.execute(f"delete {num}")
        except gdb.error:
            return
    else:
        print("Invalid breakpoint number")


def clear_all_breakpoints():
    gdb.execute("delete")


# fast will override step
def find_main(
    step: bool = False,
    fast: bool = False,
    restart: bool = False,
    clean: bool = False
):
    global rax
    global rdx
    global rdi
    global rip
    global main_call_addr
    global main_addr
    global main_called

    clean = True if clean else False

    if not restart:
        if step and not main_called and get_reg_value("rip") == main_call_addr:
            gdb.execute("stepi")
            main_called = True
            main_addr = get_reg_value("rip")
            return main_addr

        if len(main_call_addr) > 0:
            return main_addr

        if len(main_addr) > 0:
            return main_addr

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
        main_addr = rdi = get_reg_value("rdi")
        set_var("main_addr", main_addr)
        set_breakpoint(rdi, clean)
        gdb.execute("continue")
        main_called = True
        return main_addr

    else:
        gdb.execute("stepi")

        set_breakpoint("__libc_start_call_main", clean)
        gdb.execute("continue")

        # Track argv value as it gets loaded into rsi as argument to find the
        # call to main
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

        main_call_addr = rip = get_reg_value("rip")
        set_var("main_call_addr", main_call_addr)

        main_addr = rax = get_reg_value("rax")
        set_var("main_addr", main_addr)

    if step:
        gdb.execute("stepi")
        main_called = True

    return main_addr


class register_def_var_command(gdb.Command):
    """
    Define a variable with a name and an address.

    Usage:
        def-var <name> <type> <addr>

    Options:
    """

    def __init__(self):
        super(register_def_var_command, self).__init__(
            "def-var", gdb.COMMAND_USER
        )

    def invoke(self, arg: str, from_tty: bool):
        args = [a.strip().strip('"') for a in arg.split(",", 2)]
        if len(args) < 3:
            args = [a.rstrip(",").strip('"') for a in arg.split(" ", 2)]
        if len(args) < 3:
            return

        name, type_signature, addr = args

        addr = to_addr(get_var(addr))
        if addr is None:
            return

        def_var(name.strip('"'), addr.strip('"'), type_signature.strip('"'))


class register_def_label_command(gdb.Command):
    """
    Define a label with a name and an address.

    Usage:
        def-label <name> <addr>

    Options:
    """

    def __init__(self):
        super(register_def_label_command, self).__init__(
            "def-label", gdb.COMMAND_USER
        )

    def invoke(self, arg: str, from_tty: bool):
        args = [a.strip().strip('"') for a in arg.split(",", 1)]
        if len(args) < 2:
            args = [a.rstrip(",").strip('"') for a in arg.split(" ", 1)]
        if len(args) < 2:
            return

        name, addr = args

        addr = to_addr(get_var(addr))
        if addr is None:
            return

        def_label(name, addr)


class register_def_function_command(gdb.Command):
    """
    Define a function with a name and an address.

    Usage:
        def-function <name> <addr>

    Options:
    """

    def __init__(self):
        super(register_def_function_command, self).__init__(
            "def-function", gdb.COMMAND_USER
        )

    def invoke(self, arg: str, from_tty: bool):
        args = [a.strip().strip('"') for a in arg.split(",", 1)]
        if len(args) < 2:
            args = [a.rstrip(",").strip('"') for a in arg.split(" ", 1)]
        if len(args) < 2:
            return

        name, addr = args

        addr = to_addr(get_var(addr))
        if addr is None:
            return

        def_function(name, addr)


class register_lbreak_command(gdb.Command):
    """
    Set a breakpoint at a defined label or function.

    Usage:
        lbreak <label>

    Options:
        label       Defined label or function.
    """

    def __init__(self):
        super(register_lbreak_command, self).__init__(
            "lbreak", gdb.COMMAND_USER
        )

    def invoke(self, arg: str, from_tty: bool):
        set_result(lbreak(arg))


class register_lwatch_command(gdb.Command):
    """
    Set a watchpoint at a defined label or function.

    Usage:
        lwatch <label>

    Options:
        label       Defined label or function.
    """

    def __init__(self):
        super(register_lwatch_command, self).__init__(
            "lwatch", gdb.COMMAND_USER
        )

    def invoke(self, arg: str, from_tty: bool):
        set_result(lwatch(arg))


class register_luntil_command(gdb.Command):
    """
    Run the program till defined label of function within the current frame.

    Usage:
        luntil <label>

    Options:
        label       Defined label or function.
    """

    def __init__(self):
        super(register_luntil_command, self).__init__(
            "luntil", gdb.COMMAND_USER
        )

    def invoke(self, arg: str, from_tty: bool):
        luntil(arg)


class register_ldisassemble_command(gdb.Command):
    """
    Disasseble machine code from defined label or function till given number of
    bytes.

    Usage:
        ldisassemble <label> <l>

    Options:
        label       Defined label or function.
        l           Number of bytes to disassemble.
    """

    def __init__(self):
        super(register_ldisassemble_command, self).__init__(
            "ldisassemble", gdb.COMMAND_USER
        )
        self.alias = "ldisas"

    def invoke(self, arg: str, from_tty: bool):
        args = [a.rstrip(",") for a in arg.split()]
        if len(args) < 2:
            return

        ldisassemble(args[0], args[1])


class register_get_reg_value_command(gdb.Command):
    """
    Get the value of a register.

    Usage:
        get-reg-value [register]

    Options:
    """

    def __init__(self):
        super(register_get_reg_value_command, self).__init__(
            "get-reg-value", gdb.COMMAND_USER
        )

    def invoke(self, arg: str, from_tty: bool):
        val = get_reg_value(arg)

        if not val:
            return

        if arg == "rip":
            type_signature = "void (*)()"
        else:
            type_signature = "int"

        set_result(int(val, 16), type_signature)


class register_get_entry_point_command(gdb.Command):
    """
    Get the entry point of the program. The program needs to be running else
    the offset in the program file will be provided.

    Usage:
        get-entry-point [start]

    Options:
        start       Start the program if any argument is given.
    """

    def __init__(self):
        super(register_get_entry_point_command, self).__init__(
            "get-entry-point", gdb.COMMAND_USER
        )

    def invoke(self, arg: str, from_tty: bool):
        arg = True if arg else False

        entry_point = get_entry_point(arg)

        if not entry_point:
            print("Entry point not found.")
            return
        print(f"Entry point address: {entry_point}")

        set_result(int(entry_point, 16), type_signature="void (*)()")


class register_run_until_command(gdb.Command):
    """
    Run the program till given address within the current frame.

    Usage:
        run-until <address>
    """

    def __init__(self):
        super(register_run_until_command, self).__init__(
            "run-until", gdb.COMMAND_USER
        )

    def invoke(self, arg: str, from_tty: bool):
        run_until(arg)


class register_set_breakpoint_command(gdb.Command):
    """
    Set a breakpoint at the given address.

    Usage:
        set-breakpoint <address> [temporary]

    Options:
        temporary       Set a temporary breakpoint if any argument is given.
    """

    def __init__(self):
        super(register_set_breakpoint_command, self).__init__(
            "set-breakpoint", gdb.COMMAND_USER
        )

    def invoke(self, arg: str, from_tty: bool):
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

    def invoke(self, arg: str, from_tty: bool):
        set_result(set_watchpoint(arg))


class register_get_instruction_addr_command(gdb.Command):
    """
    Get the address of next occurence of given instruction matching given hints
    for operands starting from given address till given number of bytes.

    Usage:
        get-instr-addr <address> <length> <instruction> [hint]
    """

    def __init__(self):
        super(register_get_instruction_addr_command, self).__init__(
            "get-instr-addr", gdb.COMMAND_USER
        )

    def invoke(self, arg: str, from_tty: bool):
        args = []
        if arg.find(",") > -1:
            args = [a.strip().strip('"') for a in arg.split(",")]
        if len(args) < 3:
            args = [a.strip().strip('"') for a in arg.split(" ")]
        if len(args) < 3:
            print("Missing arguments")
            return

        argidx, addr = check_arith_expr(arg)
        if addr is None:
            print("Invalid address")
            return
        addr = " ".join([a for a in flatten(addr)])

        try:
            n, instruction = args[argidx], args[argidx + 1]
        except IndexError:
            print("Missing arguments")
            return

        argidx = argidx + 2

        op_hint = "".join(args[argidx:]) if argidx < len(args) else ""

        addr = get_instr_addr(addr, n, instruction, op_hint)
        addr = int(addr, 16) if addr is not None else 0

        set_result(addr, type_signature="void (*)()")


class register_find_main_command(gdb.Command):
    """
    Find the main function of the program and halt before the call.

    Usage:
        find-main [fast] [restart] [clean]

    Options:
        fast        Use faster method skipping intermittent breakpoints.
        restart     Restart the procedure.
        clean       Use temporary breakpoints and clear watchpoints.
    """

    def __init__(self):
        super(register_find_main_command, self).__init__(
            "find-main", gdb.COMMAND_USER
        )

    def invoke(self, arg: str, from_tty: bool):
        args = [a.rstrip(",") for a in arg.split()]
        clean = True if "c" in args or "clean" in args else False
        restart = True if "r" in args or "restart" in args else False
        fast = True if "f" in args or "fast" in args else False

        addr = find_main(False, fast, restart, clean)

        print(f"Address of main function is: {addr}")
        if fast and main_called:
            print("Stepped into main function")

        set_result(int(addr, 16), type_signature="void (*)()")


class register_step_main_command(gdb.Command):
    """
    Step inside the main function of the program and halt before the call.

    Usage:
        step-main [fast] [restart] [clean]

    Options:
        fast        Use faster method skipping intermittent breakpoints.
        restart     Restart the procedure.
        clean       Use temporary breakpoints and clear watchpoints.
    """

    def __init__(self):
        super(register_step_main_command, self).__init__(
            "step-main", gdb.COMMAND_USER
        )

    def invoke(self, arg: str, from_tty: bool):
        args = [a.rstrip(",") for a in arg.split()]
        clean = True if "c" in args or "clean" in args else False
        restart = True if "r" in args or "restart" in args else False
        fast = True if "f" in args or "fast" in args else False

        addr = find_main(True, fast, restart, clean)

        print(f"Address of main function is: {addr}")
        print("Stepped into main function")

        set_result(int(addr, 16), type_signature="void (*)()")


register_def_label_command()
register_def_function_command()
register_def_var_command()

register_lbreak_command()
register_lwatch_command()
register_luntil_command()
register_ldisassemble_command()
register_lbreak_command()

register_get_entry_point_command()
register_get_reg_value_command()
register_get_instruction_addr_command()

register_run_until_command()
register_set_breakpoint_command()
register_set_watchpoint_command()

register_find_main_command()
register_step_main_command()
