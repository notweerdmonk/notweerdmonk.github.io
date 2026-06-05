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

set -euo pipefail

SRC_DIR="${1:-_items/}"
DEFAULT_LAYOUT="default"
OWNER="notweeerdmonk"

# print YAML front-matter
echo "---"
echo "layout: ""$DEFAULT_LAYOUT"
echo "title: ""$OWNER"
echo "---"

echo "| --- | --- | --- |"

tmpfile=$(mktemp)
trap 'rm -f "$tmpfile"' EXIT

# find markdown files and process each
find "$SRC_DIR" -type f -name '*.md' | sort | while IFS= read -r file; do
  # read file and separate front matter and body
  # front matter assumed between first two '---' lines
  fm=''
  body=''
  if awk 'NR==1 && $0=="---"{inside=1; next}
          inside==1 && $0=="---"{inside=0; next}
          inside==1{print > "/dev/stderr"; next}
          {print}' "$file" 2> /tmp/fm.$$ > /tmp/body.$$; then
    fm=$(cat /tmp/fm.$$)
    body=$(cat /tmp/body.$$)
    rm -f /tmp/fm.$$ /tmp/body.$$
  else
    # fallback: no front matter, whole file is body
    fm=''
    body=$(cat "$file")
  fi

  # escape pipes and newlines for table cells
  esc() {
    printf '%s' "$1" \
      | sed -e 's/|/\\|/g' \
        -e ':a;N;$!ba;s/\n/ /g' \
        -e 's/^[[:space:]]*//;s/[[:space:]]*$//';
  }

  # extract YAML keys (simple, handles basic key: value lines)
  extract_key() {
    key="$1"
    echo "$fm" \
      | sed -n -E "s/^[[:space:]]*$key:[[:space:]]*(.*)$/\1/p" \
      | sed 's/^["'\'']//;s/["'\'']$//'
  }

  title=$(extract_key title)
  date_field=$(extract_key date)
  permalink=$(extract_key permalink)

  # default title to filename if missing
  [ -z "$title" ] && title=$(basename "$file" .md)


  # normalize date_field to ISO-like sortable; if missing, use mtime (seconds -> ISO)
  if [ -n "$date_field" ]; then
    # try to parse with date; prefer keeping as-is if already YYYY-MM-DD...
    # attempt to get seconds since epoch to ensure correct sort order
    if parsed=$(date -d "$date_field" --utc +%Y-%m-%dT%H:%M:%SZ 2>/dev/null); then
      stamp="$parsed"
    else
      # fallback: keep raw string (may sort oddly) but include mtime to guarantee uniqueness
      mtime=$(stat -c %Y "$file" 2>/dev/null || stat -f %m "$file" 2>/dev/null)
      stamp=$(
        date -u -d "@$mtime" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
          || printf "%s" "$(date -u -r "$mtime" +%Y-%m-%dT%H:%M:%SZ)"
      )
    fi
  else
    mtime=$(stat -c %Y "$file" 2>/dev/null || stat -f %m "$file" 2>/dev/null)
    stamp=$(
      date -u -d "@$mtime" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || printf "%s" "$(date -u -r "$mtime" +%Y-%m-%dT%H:%M:%SZ)"
    )
  fi

  date=$(date -d "$date_field" "+%a %b %_d %Y")

  # get first non-empty paragraph from body (strip markdown code fences and images)
  excerpt=$(awk '
    BEGIN { in_fm=0; paragraph=""; started=0 }
    NR==1 && /^---$/ { in_fm=1; next }
    in_fm && /^---$/ { in_fm=0; next }
    in_fm { next }
    # skip blank lines and headings until a real paragraph starts
    !started {
      if ($0 ~ /^[[:space:]]*$/) next
      if ($0 ~ /^[[:space:]]*#/) next
      paragraph=$0; started=1; next
    }
    started {
      if ($0 ~ /^[[:space:]]*$/ || $0 ~ /\\$/) {
        print paragraph;
        paragraph = "";
        exit
      }
      paragraph = paragraph " " $0
    }
    END { if (paragraph != "") print paragraph }
  ' "$file")
  # normalize whitespace
  excerpt=$(
    printf '%s' "$excerpt" \
      | sed -E 's/[[:space:]]+/ /g; s/^[[:space:]]+//; s/[[:space:]]+$//'
  )

  # escape literal "\" (backslash) -> "" and escape <br> tags -> "\<br\>"
  excerpt=$(
    printf '%s' "$excerpt" \
      | sed -E 's/\\//g; s#<br[[:space:]]*/?>#\\<br\\>#Ig'
  )

  # shorten excerpt to 60 chars
  backticks="${excerpt//[^\`]}"
  num_backticks="${#backticks}"
  backtick_escaped_excerpt="${excerpt//\`}"
  [ ${#backtick_escaped_excerpt} -gt 60 ] &&
    {
      num_chars=$((60 - 3 - $num_backticks))
      excerpt="${excerpt:0:$num_chars}…"
    }

  id="$(basename "$file" ".md")"; id="${id/_/-}"
  printf "%s\t%s\t%s\t%s\t%s\t%s" "$stamp" "$(esc "$id")" "$(esc "$title")" \
    "$(esc "$permalink")" "$(esc "$date")" "$(esc "$excerpt")" \
      | awk -F'\t' '{print $1"\t"$2"\t"$3"\t"$4"\t"$5"\t"$6}' >> "$tmpfile"
done

sort -r "$tmpfile" \
  | while IFS=$'\t' read -r stamp id title permalink date excerpt
      do
        printf "| <span id=\"%s\">[%s](%s)</span> | %s | %s |\n" \
          "$id" "$title" "$permalink" "$date" "$excerpt"
      done
