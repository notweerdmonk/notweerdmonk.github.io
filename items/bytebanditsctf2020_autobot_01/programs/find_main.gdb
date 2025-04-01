# Copyright 2025 notweerdmonk
#
# I do not give anyone permissions to use this tool for any purpose. Don't use it.
#
# I’m not interested in changing this license. Please don’t ask.

# Find the main function in a program and more.

set $step_cmd = "step"
set $fast_cmd = "fast"
set $clean_cmd = "clean"
set $restart_cmd = "restart"

set $main_called = 0
set $main_call_addr = 0
set $main_addr = 0

define find-main-print-help
  echo Usage\n
  echo \tfind-main-opts [help|step [fast [clean [restart]]]]\n
  echo \tfind-main\t\tfind-main-opts x x x x\n
  echo \tfind-main-fast\t\tfind-main-opts x fast x x\n
  echo \tfind-main-clean\t\tfind-main-opts x x clean x\n
  echo \tfind-main-restart\tfind-main-opts x x x restart\n
  echo \tfind-main-help\t\tPrint this message\n
  echo \n
  echo \tstep-main-opts [help|fast [clean [restart]]]\n
  echo \tstep-main\t\tstep-main-opts x x x\n
  echo \tstep-main-clean\t\tstep-main-opts x clean x\n
  echo \tstep-main-restart\tstep-main-opts x x restart\n
  echo \tstep-main-help\t\tPrint this message\n
  echo \n
  echo Options\n
  echo \tstep\t\tStep into the main function\n
  echo \tfast\t\tUse faster method skipping intermittent breakpoints\n
  echo \t\t\tThis option implies "step\" is applied.
  echo \tclean\t\tUse temporary breakpoints and clear watchpoints\n
  echo \trestart\t\tRestart the procedure\n
end

define py_parse_var
  python var_name = '$arg0'; gdb.set_convenience_variable(var_name, '$arg1');
end

define py_strcmp
  python arg_0 = str('$arg0'); arg_0 = str(gdb.parse_and_eval(arg_0)).strip('\\"') \
    if arg_0.startswith('$') \
    else arg_0.strip('\\"') \
    # If this line gets printed with SyntaxError, you have probably used single quotes around an argument.
  python arg_1 = str('$arg1'); arg_1 = str(gdb.parse_and_eval(arg_1)).strip('\\"') \
    if arg_1.startswith('$') \
    else arg_1.strip('\\"') \
    # If this line gets printed with SyntaxError, you have probably used single quotes around an argument.
    
  python gdb.set_convenience_variable("py_strcmp_result", 0) \
    if arg_0 == arg_1 \
    else gdb.set_convenience_variable("py_strcmp_result", 1)
end

define get-entry-point
  python _ = [ \
    line \
      for line in gdb.execute("info files", to_string=True).splitlines() \
        if "Entry point" in line \
  ]; \
  entry_point = _[0][_[0].find(":") + 2:] if len(_) > 0 else None; print(entry_point)
  python gdb.set_convenience_variable("entry_point", int(entry_point, 16)) \
    if entry_point is not None \
    else None
  python print(f"Entry point of the program is 0x{entry_point}") \
    if entry_point is not None \
    else None
end

define get-instr-addr
  python _ = [ \
    line \
      for line in gdb.execute("disas $arg0, +$arg1", to_string=True).splitlines() \
        if "\t$arg2" in line or "\s$arg2" in line \
  ]; \
  _ = _[0].lstrip("=>") if len(_) > 0 else None; \
  _ = _[:_.find(":")].strip() if _ is not None else None
  python space_idx = _.find(" ") if _ is not None else -1; \
  instr_addr = _[:space_idx].strip() if space_idx != -1 else _
  python gdb.set_convenience_variable("instr_addr", int(instr_addr, 16)) \
    if _ is not None \
    else None
  python print(f"Address of next $arg0 instruction is {instr_addr}") \
    if _ is not None \
    else None
end

define get-instr-addr-hint
  python _ = [ \
    line \
      for line in [ \
        line \
          for line in gdb.execute("disas $arg0, +$arg1", to_string=True).splitlines() \
            if "\t$arg2" in line or "\s$arg2" in line \
      ] \
        if "$arg3" in line \
  ]; \
  _ = _[0].lstrip("=>") if len(_) > 0 else None; \
  _ = _[:_.find(":")].strip() if _ is not None else None
  python space_idx = _.find(" ") if _ is not None else -1; \
  instr_addr = _[:space_idx] if space_idx != -1 else _
  python gdb.set_convenience_variable("instr_addr", int(instr_addr, 16)) \
    if _ is not None \
    else None
  python print(f"Address of next $arg0 instruction is {instr_addr}") \
    if _ is not None \
    else None
end

define step-main-help
  find-main-print-help
end

define step-main
  __find_main step x x x
end

define step-main-clean
  __find_main step x clean x
end

define step-main-restart
  __find_main step x x restart
end

define step-main-opts
  py_strcmp $arg0 help
  if $py_strcmp_result == 0
    find_main_print_help
  else
    __find_main step $arg0 $arg1 $arg2
  end
end

define find-main-help
  find-main-print-help
end

define find-main
  __find_main x x x x
end

define find-main-fast
  __find_main x fast x x
end

define find-main-clean
  __find_main x x clean x
end

define find-main-restart
  __find_main x x x restart
end

define find-main-opts
  py_strcmp $arg0 help
  if $py_strcmp_result == 0
    find-main-print-help
  else
    __find_main $arg0 $arg1 $arg2 $arg3
  end
end

define found-main
  if $main_addr == 0
    set $main_addr = $arg0
  end
  printf "Found the main function at address 0x%lx\n", $main_addr
end

define show-main
  printf "Address of the main function is 0x%lx\n", $arg0
end

define set-main-called
  set $main_called = 1
  printf "Stepped into the main function\n"
end

define on-main
  found-main $arg0
  set-main-called
end

define on-libc-start-call-main
  #printf "rdx: 0x%lx\n", $rdx
  set $cur_rdx = $rdx
  #printf "0x%lx\n", $cur_rdx

  watch $rsi == $cur_rdx

  continue

  get-instr-addr $rip 20 call
  set $call_addr = $instr_addr

  py_strcmp $clean $clean_cmd
  if $py_strcmp_result == 0
    delete $bpnum
    tbreak *$call_addr
  else
    break *$call_addr
  end

  continue

  set $main_call_addr = $rip
  found-main $rax
end

define on-call-addr
  printf "info reg $rdi $rsi $rdx $rcx $r8 $r9\n"
  info reg $rdi $rsi $rdx $rcx $r8 $r9
  show-main $rdi

  set $step = $arg0
  set $fast = $arg1
  set $clean = $arg2

  # Use arguments of __libc_start_call_main to find the main function
  py_strcmp $fast $fast_cmd
  if $py_strcmp_result == 0
    set $break_addr = $rdi
    py_strcmp $clean $clean_cmd
    if $py_strcmp_result == 0
      tbreak *$break_addr
      # gdb 12.1 has some issues with nesting more than two levels of breakpoint
      # routines. Program execution halts at breakpoint but listed commands are
      # not performed until user inputs some command. A workaround is to list the
      # commands after the 'continue' command. Later versions haven't been
      # tested.
    else
      break *$break_addr
    end

    continue

    on-main $break_addr
  else
    # Step inside call to __libc_start_main
    stepi

    py_strcmp $clean $clean_cmd
    if $py_strcmp_result == 0
      tbreak __libc_start_call_main
    else
      break __libc_start_call_main
    end

    continue
    on-libc-start-call-main $step $fast $clean $restart
  end

  py_strcmp $step $step_cmd
  if $py_strcmp_result == 0
    stepi
    set-main-called
  end
end

define on-entry-point
  get-instr-addr-hint $rip 60 call rip
  set $call_addr = $instr_addr

  set $step = $arg0
  set $fast = $arg1
  set $clean = $arg2

  py_strcmp $clean $clean_cmd
  if $py_strcmp_result == 0
    tbreak *$call_addr
      commands
      on-call-addr $step $fast $clean $restart
    end
  else
    break *$call_addr
      commands
      on-call-addr $step $fast $clean $restart
    end
  end
end

define __find_main
  py_parse_var step $arg0
  py_parse_var fast $arg1
  py_parse_var clean $arg2
  py_parse_var restart $arg3

  set $done = 0

  # $restart != "restart"
  py_strcmp $restart $restart_cmd
  if $py_strcmp_result == 1
    py_strcmp $step $step_cmd
    if $py_strcmp_result == 0
      if $main_called == 0
        if $main_call_addr != 0
          stepi
          show-main $main_addr
          set_main_called
          set $done = 1
        end
      end
    end

    if $done == 0
      if $main_addr != 0
        show-main $main_addr
        set $done = 1
      end
    end
  end

  if $done == 0
    delete

    set $main_called = 0
    set $main_call_addr = 0
    set $main_addr = 0

    starti
    where

    get-entry-point

    py_strcmp $clean $clean_cmd
    if $py_strcmp_result == 0
      tbreak *$entry_point
        commands
        on-entry-point $step $fast $clean $restart
        continue
      end
    else
      break *$entry_point
        commands
        on-entry-point $step $fast $clean $restart
        continue
      end
    end

    continue
  end
end
