#!/usr/bin/env bash

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

log() {
  [[ ! -v logs_enabled || $logs_enabled -eq 0 ]] && return

  [[ $# -lt 2 ]] && return

  local func="$1"
  shift

  printf 'trim_markdown.bash: %s: %s:\n' "$(date --iso-8601=seconds)" "$func"

  while [[ $# -gt 0 ]]
  do
    declare -n varname="${1##[[:space:]]}"
    shift

    printf "  %s : %s\n" "${!varname}" "$varname"
  done
}

trace_enable() {
  [[ ! -v trace_enabled || $trace_enabled -eq 0 ]] && {
    return
  }
  printf "+ trace_enable\n" >&2
  set -x
}

trace_disable() {
  { set +x; } 2>/dev/null
}

incr() {
  [[ $# -eq 0 ]] && return

  declare -n nameref="$1"
  [[ $nameref -lt 0 ]] && nameref=0 || ((++nameref))
}

function trim_markdown {
  # Caution!
  # This causes the shell that has sourced this script to exit permanently
  [[ -v TRIM_MARKDOWN_DEV_MODE && $TRIM_MARKDOWN_DEV_MODE -ne 0 ]] && {
    trap 'set +Eeuo pipefail' RETURN
    set -Eeuo pipefail
  }

  local print_escaped=0
  local trace_enabled=0
  local logs_enabled=0

  while [[ $# -gt 0 ]]
  do
    case "$1" in
      -e|--escaped)
        print_escaped=1
        shift
        ;;
      -d|--debug)
        logs_enabled=1
        shift
        ;;
      -t|--trace)
        trace_enabled=1
        shift
        ;;
      *)
        break
    esac
  done

  local target=""
  [[  $# -gt 0 && -n "$1" ]] && {
    target="$1"
    shift
  }
  [[ -z "$target" ]] && {
    printf "No string provided\n" >&2
    return 255
  }

  local desired_len=""
  [[  $# -gt 0 && -n "$1" ]] && {
    desired_len="$1"
    shift
  }
  [[ -z $desired_len || $desired_len -eq 0 ]] && desired_len=${#target}

  log trim_markdown target desired_len

  local flag=0
  local done=0
  local count=0
  local idx=-1
  local in_square_brackets=0
  local in_parentheses=0
  local in_backticks=0
  local in_url=0
  local square_brackets_start=-1
  local square_brackets_len=0
  local paren_start=-1
  local paren_len=0
  local url_start=-1
  local url_len=0
  local backticks_start=-1
  local backticks_len=0
  local prev=""
  local skip_count=0
  local escaped=""
  local output=""
  local skipped=""

  for ((i=0; i < ${#target}; ++i))
  do
    local curr="${target:$i:1}"
    local next="${target:$((i + 1)):1}"

    skip_count=0

    ((++idx))

    log trim_markdown in_backticks in_parentheses in_square_brackets in_url

    check_tokens_except() {
      declare varname="$1"

      declare -a token_names=(
        "in_backticks"
        "in_parentheses"
        "in_square_brackets"
        "in_url"
      )

      local ret=1

      for token in "${token_names[@]}"
      do
        [[ "$varname" == "$token" ]] && continue
        declare -n ref="$token"
        [[ $ref -eq 0 ]] && ret=0 || ret=1
      done

      return $ret
    }

    trace_enable
    if [[ $curr == '`' ]] && $(check_tokens_except)
    then
      declare -n in_ref="in_backticks"
      declare -n len_ref="backticks_len"
      declare -n start_ref="backticks_start"

      skipped+=$curr

      flag=1
    elif [[ $curr == '[' ]] && (check_tokens_except)
    then
      declare -n in_ref="in_square_brackets"
      declare -n len_ref="square_brackets_len"
      declare -n start_ref="square_brackets_start"

      skipped+=$curr

      flag=1
    # Check for closing ']' following a staring '(' to flag URL/link
    elif
      [[ $prev == ']' && $curr == '(' ]] &&
      (check_tokens_except in_square_brackets)
    then
      declare -n in_ref="in_url"
      declare -n len_ref="url_len"
      declare -n start_ref="url_start"

      skipped+=$curr

      flag=1
    elif [[ $curr == '(' ]] && (check_tokens_except)
    then
      declare -n in_ref="in_parentheses"
      declare -n len_ref="paren_len"
      declare -n start_ref="paren_start"
    fi

    if [[ $flag -ne 0 ]]
    then
      skip_count=1
      in_ref=1
      start_ref=$idx
      len_ref=1

      flag=0
    fi

    log trim_markdown backticks_len backticks_len
    if [[ $in_backticks -ne 0 && $curr == '`' ]]
    then
      in_backticks=0
      ((++backticks_len))
      skipped+=$curr
      skip_count=1

      declare -n len_ref="backticks_len"
      declare -n start_ref="backticks_start"

      flag=0
    #Check for closing ']' only to flag end of square-bracketted token if the
    #next character is not a '('
    elif [[ $in_square_brackets -ne 0 && $curr == ']' && $next != '(' ]]
    then
      in_square_brackets=0
      ((++square_brackets_len))
      skipped+=$curr
      skip_count=1

      declare -n len_ref="square_brackets_len"
      declare -n start_ref="square_brackets_start"

      flag=1
    elif [[ $in_parentheses -ne 0 && $curr == ')' ]]
    then
      in_parentheses=0
      ((++paren_len))
      skipped+=$curr
      skip_count=1

      flag=0
    # Check for closing ')' only to flag end of URL/link token
    elif [[ $in_url -ne 0 && $curr == ')' ]]
    then
      in_square_brackets=0

      url_start=$square_brackets_start
      url_len=$(($square_brackets_len + $url_len))

      in_url=0
      ((++url_len))
      skipped+=$curr
      skip_count=1

      declare -n len_ref="url_len"
      declare -n start_ref="url_start"

      flag=1
    fi
    trace_disable

    trace_enable
    log trim_markdown square_brackets_start square_brackets_len
    log trim_markdown url_start url_len
    if [[ $flag -ne 0 ]]
    then
      log trim_markdown output
      log trim_markdown ${!start_ref} ${!len_ref}
      [[ "${output: -1}" == ' ' ]] && {
        ((--start_ref))
        ((++len_ref))
        log trim_markdown output
        output="${output:0:-1}"
        count="${#output}"
      }
      # Required when escaped sequences are to be returned
      while read -r -N1 a
      do
        if [[ $count -lt $desired_len ]]
        then
          escaped+=$a
        fi
      done < <(echo -n "${target:start_ref:len_ref}")
      start_ref=-1
      len_ref=0

      flag=0
    fi
    trace_disable

    if [[ $done -ne 0 ]]
    then
      break
    fi

    trace_enable
    if [[ $skip_count -eq 0 ]]
    then
      if [[ $in_backticks -ne 0 ]]
      then
        ((++backticks_len))
        skipped+=$curr
      elif [[ $in_url -ne 0 ]]
      then
        ((++url_len))
        skipped+=$curr
      elif [[ $in_square_brackets -ne 0 ]]
      then
        ((++square_brackets_len))
        skipped+=$curr
      elif [[ $in_parentheses -ne 0 ]]
      then
        ((++paren_len))
        skipped+=$curr
      else
        ((++count))
        output+=$curr
      fi
    fi
    trace_disable

    prev=$curr

    trace_enable
    if [[ $count -ge $desired_len ]]
    then
      done=1
      trace_disable
      break
    fi
    trace_disable
  done < <(echo -n "$target")

  unset in_ref
  unset len_ref
  unset start_ref

  [[ -v print_escaped && $print_escaped -ne 0 ]] && {
    declare -A reply
    reply["output"]="$output"
    reply["escaped"]="$escaped"
    declare -p reply
  } || {
    printf "%s\n" "$output"
  }
}

export -f trim_markdown
