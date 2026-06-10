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

COLLECTION_DIR="_items"   # directory containing your collection documents
TAGS_DIR="tags"           # output folder for generated tag pages
LAYOUT="tag"              # layout to use in generated pages (_layouts/tag.html)

mkdir -p "$TAGS_DIR"

# collect tags (YAML arrays like tags: [a, b] or - tags: style)
# This extracts lines between YAML front matter and looks for 'tags:' lines.
declare -A TAGS
while IFS= read -r file; do
  # read front matter block
  front=$(
    awk '/^---/{p++; next} p==1{print} /^---/{exit}' "$file" 2>/dev/null \
    || true
  )
  if [[ -z "$front" ]]; then continue; fi
  # find tags line(s)
  tags_line=$(echo "$front" \
    | sed -n 's/^[[:space:]]*tags:[[:space:]]*//Ip' | tr -d '\r')
  if [[ -n "$tags_line" ]]; then
    # tags: [one, two] or tags: one
    tags_line=$(echo "$tags_line" | tr -d '[]')
    IFS=',' read -ra parts <<< "$tags_line"
    for t in "${parts[@]}"; do
      tag=$(echo "$t" \
        | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
        | tr '[:upper:]' '[:lower:]')
      [[ -z "$tag" ]] && continue
      TAGS["$tag"]=1
    done
  else
    # also catch YAML block list form:
    # tags:
    # - one
    # - two
    mapfile -t yaml_tags < <(echo "$front" \
      | awk '/^tags:[[:space:]]*$/,/^([^[:space:]]|$)/' \
      | sed -n 's/^[[:space:]]*-\s*//p')
    for t in "${yaml_tags[@]}"; do
      tag=$(echo "$t" \
        | sed 's/^[[:space:]]*//;s/[[:space:]]*$//') \
      [[ -z "$tag" ]] && continue
      TAGS["$tag"]=1
    done
  fi
done < <(find "$COLLECTION_DIR" -type f -name '*.md' -print)

# helper slugify: lowercase, replace non-alnum with -, squeeze -
slugify() {
  echo "$1" | iconv -t ascii//TRANSLIT 2>/dev/null \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/[^a-z0-9]/-/g' | sed 's/[- ]\+/-/g' | sed 's/^-//;s/-$//'
}

# remove old generated tag dirs (but keep anything not matching pattern)
find "$TAGS_DIR" -maxdepth 1 -mindepth 1 -type d -print0 \
  | while IFS= read -r -d '' d; do rm -rf "$d"; done
mkdir -p "$TAGS_DIR"

# generate per-tag page directories
for tag in "${!TAGS[@]}"; do
  slug=$(slugify "$tag")
  dir="$TAGS_DIR/$slug"
  mkdir -p "$dir"
  cat > "$dir/index.md" <<EOF
---
layout: $LAYOUT
tag: $tag
title: "Tag: ${tag}"
permalink: /$TAGS_DIR/$slug/
---
<!-- page for tag ${tag} -->
EOF
done
