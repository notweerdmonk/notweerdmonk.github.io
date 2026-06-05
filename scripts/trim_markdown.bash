#!/bin/bash

function trim_markdown {
  local target="$1"
  [[ -z "$target" ]] && echo "No string provided" && exit 1
  
  local desired_len="$2"
  [[ -z $desired_len || $desired_len -eq 0 ]] && desired_len=${#target}
  
  local done=0
  local count=0
  local idx=-1
  local in_square_brackets=0
  local in_parentheses=0
  local in_backticks=0
  local square_brackets_start=-1
  local square_brackets_len=0
  local paren_start=-1
  local paren_len=0
  local backticks_start=-1
  local backticks_len=0
  local prev=""
  local skip_count=0
  local escaped=""
  local output=""
  local skipped=""
  
  IFS=''
  while read -r -N1 curr
  do
    skip_count=0
  
    ((++idx))
  
    if [[ $in_backticks -eq 0 && $in_parentheses -eq 0 && $in_square_brackets -eq 0 ]]
    then
      if [[ $curr == '`' ]]
      then
        declare -n in_ref="in_backticks"
        declare -n len_ref="backticks_len"
        declare -n start_ref"backticks_start"
  
        local flag=1
      elif [[ $curr == '[' ]]
      then
        declare -n in_ref="in_square_brackets"
        declare -n len_ref="square_brackets_len"
        declare -n start_ref"square_brackets_start"
  
        skipped+=$curr
  
        flag=1
      elif [[ $prev == ']' && $curr == '(' ]]
      then
        declare -n in_ref="in_parentheses"
        declare -n len_ref="paren_len"
        declare -n start_ref"paren_start"
  
        local flag=1
      fi
  
      if [[ -n "$flag" && $flag -ne 0 ]]
      then
        skip_count=1
        in_ref=1
        start_ref=$idx
        len_ref=1
  
        unset flag
      fi
    elif [[ $in_backticks -ne 0 && $curr == '`' ]]
    then
      if [[ $backticks_len -ne 0 ]]
      then
        new_count=$(($count + $backticks_len - 1))
        if [[ $new_count -gt $desired_len ]]
        then
          output="${output:0:$((${#output} - $backticks_len))}"
          done=1
        else
          count=$new_count
        fi
      fi
  
      in_backticks=0
      ((++backticks_len))
      skipped+=$curr
      skip_count=1
    elif [[ $in_square_brackets -ne 0 && $curr == ']' ]]
    then
      in_square_brackets=0
      ((++square_brackets_len))
      skipped+=$curr
      skip_count=1
    elif [[ $in_parentheses -ne 0 && $curr == ')' ]]
    then
      if [[ $square_brackets_len -ne 0 ]]
      then
        new_count=$(($count + $square_brackets_len - 2))
        if [[ $new_count -gt $desired_len ]]
        then
          output="${output:0:$((${#output} - $square_brackets_len - $paren_len))}"
          done=1
        else
          count=$new_count
        fi
      fi
  
      in_parentheses=0
      ((++paren_len))
      skipped+=$curr
      skip_count=1
    fi
  
    if [[ $prev == ']' && $in_parentheses -eq 0 ]]
    then
      declare -n len_ref="square_brackets_len"
      declare -n start_ref"square_brackets_start"
      local flag=1
    elif [[ $square_brackets_len -eq 0 && $paren_len -ne 0 ]]
    then
      declare -n len_ref="paren_len"
      declare -n start_ref"paren_start"
      local flag=1
    fi
    if [[ -n "$flag" && $flag -ne 0 ]]
    then
      output="${output:0:$((${#output} - $len_ref))}"
      skipped="${skipped:0:$((${#skipped} - $len_ref))}"
      while read -r -N1 a
      do
        if [[ $count -lt $desired_len ]]
        then
          escaped+=$a
          output+=$a
          if [[ $((++count)) -eq $desired_len ]]
          then
            done=1
            break
          fi
        fi
      done < <(echo -n "${target:start_ref:len_ref}")
      start_ref=-1
      len_ref=0
      
      unset flag
    fi
  
    if [[ $done -ne 0 ]]
    then
      break
    fi
  
    if [[ $skip_count -eq 0 ]]
    then
      if [[ $in_backticks -ne 0 ]]
      then
        ((++backticks_len))
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
        escaped+=$curr
      fi
    fi
  
    prev=$curr
  
    output+=$curr
  
    if [[ $count -eq $desired_len ]]
    then
      done=1
      break
    fi
  done < <(echo -n "$target")
  
  if [[ $done -eq 0 ]]
  then
    if [[ $in_backticks -ne 0 && $backticks_len -ne 0 ]]
    then
      declare -n len_ref="backticks_len"
      declare -n start_ref"backticks_start"

      local flag=1
    elif [[ $in_square_brackets -ne 0 && $square_brackets_len -ne 0 ]]
    then
      declare -n len_ref="square_brackets_len"
      declare -n start_ref"square_brackets_start"

      local flag=1
    elif [[ $in_parentheses -ne 0 && $paren_len -ne 0 ]]
    then
      declare -n len_ref="paren_len"
      declare -n start_ref"paren_start"

      local flag=1
    fi
  fi
  
  if [[ -n "$flag" && $flag -ne 0 ]]
  then
    while read -r -N1 a
    do
      if [[ $count -lt $desired_len ]]
      then
        escaped+=$a
        ((++count))
      else
        done=1
        break
      fi
    done < <(echo -n "${target:start_ref:len_ref}")
    start_ref=-1
    len_ref=0
  
    unset flag
  fi
  
  unset in_ref
  unset len_ref
  unset start_ref

  echo "$output"
}

export -f trim_markdown
