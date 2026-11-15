#!./../../tools/bats/bin/bats

setup() {
    source "$BATS_TEST_DIRNAME/../trim_markdown.bash"
    
    make_expected() {
        awk '
function clean(s, out, i, n, run, j, r, found, rel, close_at, after, paren_rel, removed) {
    out = ""
    n = length(s)
    i = 1
    removed = 0

    while (i <= n) {
        if (substr(s, i, 1) == "`") {
            run = 1
            while (substr(s, i + run, 1) == "`")
                run++

            j = i + run
            found = 0
            while (j <= n) {
                if (substr(s, j, 1) == "`") {
                    r = 1
                    while (substr(s, j + r, 1) == "`")
                        r++

                    if (r == run) {
                        close_at = j
                        found = 1
                        break
                    }
                    j += r
                } else {
                    j++
                }
            }

            if (found) {
                out = out substr(s, i + run, close_at - i - run)
                i = close_at + run
            } else {
                out = out substr(s, i, run)
                i += run
            }
            continue
        }

        if (substr(s, i, 1) == "[") {
            rel = index(substr(s, i + 1), "]")
            if (rel) {
                close_at = i + rel
                after = close_at + 1

                # Remove whitespace immediately before the bracketed token.
                sub(/[[:space:]]+$/, "", out)

                if (substr(s, after, 1) == "(") {
                    paren_rel = index(substr(s, after + 1), ")")
                    if (paren_rel) {
                        i = after + paren_rel + 1
                        continue
                    }
                }

                i = close_at + 1
                continue
            }
        }

        out = out substr(s, i, 1)
        i++
    }

    return out
}

{ print substr(clean($0), 0, 80) }
'
    }

    declare -a deterministic_test_subjects=(
            "The sensor"
            "A small bakery"
            "This algorithm"
            "The old bridge"
            "Each network node"
            "A traveling musician"
            "The new battery"
            "Local gardeners"
            "The database"
            "A coastal village"
    )
    
    declare -a deterministic_test_endings=(
            "stores each reading"
            "keeps the records"
            "updates its state"
            "shares the results"
            "changes the pattern"
    )
    
    declare -a deterministic_test_formats=(
        '[%s](https://e.test/%s) (`%s`); "%s" and '\''%s'\'''
        '`%s` appears in [%s](https://e.test/%s): "%s"'
        '"%s" describes %s ([details](https://e.test/%s)); `%s`'
        '(%s) **[%s](https://e.test/%s)** uses `%s`'
        "'%s' follows [%s](https://e.test/%s) — \`%s\`"
    )
    
    make_deterministic_test_snippets() {
        for i in {1..50}
        do
            printf -v n '%02d' "$((i + 1))"
            local subject="${deterministic_test_subjects[$((i / 5))]}"
            local ending="${deterministic_test_endings[$((i % 5))]}"
            local sentence="$subject $ending."
            local idx=$((i % 5))
            printf -v suffix "${deterministic_test_formats[idx]}" \
              "ref$n" "note$n" "item_$n" "quote$n" "aside$n"
            local base="$sentence $suffix"
            local pad_len=$((99 - ${#base}))
            printf -v padding '%*s' "$pad_len" ''
            local padding=${padding// /x}
            deterministic_test_snippets+=("$base $padding")
        done
    }
    
    declare -ga deterministic_test_snippets=()
    mapfile -t deterministic_test_snippets < <(
        make_deterministic_test_snippets
    )
    
    declare -ga deterministic_test_expected=()
    mapfile -t deterministic_test_expected < <(
        printf '%s\n' "${deterministic_test_snippets[@]}" | make_expected
    ) 

    export LC_ALL=C

    random_test_count=50
    
    random_test_subjects=("A sensor"
            "The baker"
            "Our team"
            "The archive"
            "A robot"
              "The garden"
            "One server"
            "A traveler"
            "This model"
            "The harbor"
    )
    random_test_verbs=("tracks"
            "mixes"
            "stores"
            "shares"
            "measures"
           "changes"
            "checks"
            "follows"
            "records"
            "finds"
    )
    random_test_objects=("fresh data"
            "warm bread"
            "old maps"
            "small errors"
            "new patterns"
             "rain clouds"
            "user notes"
            "quiet paths"
            "test results"
            "rare birds"
    )
    random_test_quotes=("works well"
            "look closer"
            "keep moving"
            "save changes"
            "stay curious"
    )
    random_test_asides=("for now"
            "by hand"
            "at dawn"
            "in time"
            "with care"
    )
    random_test_emphasis=("note"
            "result"
            "idea"
            "detail"
            "update"
    )
    random_test_footnote=("See here"
            "This post"
            "Refer"
            "Lookup"
            "Note"
            "Read blog"
    )
    
    make_random_test_snippets() {
        declare -A random_test_seen=()

        local i=0
        while [ $i -lt $random_test_count ]
        do
            printf -v id '%03d' "$i"
        
            subject=${random_test_subjects[RANDOM % ${#random_test_subjects[@]}]}
            verb=${random_test_verbs[RANDOM % ${#random_test_verbs[@]}]}
            object=${random_test_objects[RANDOM % ${#random_test_objects[@]}]}
            quote=${random_test_quotes[RANDOM % ${#random_test_quotes[@]}]}
            aside=${random_test_asides[RANDOM % ${#random_test_asides[@]}]}
            em=${random_test_emphasis[RANDOM % ${#random_test_emphasis[@]}]}
            footnote=${random_test_footnote[RANDOM % ${#random_test_footnote[@]}]}
            footnote_tag=$((RANDOM % 4))
        
            sentence="$subject $verb $object."
        
            case $((RANDOM % 4)) in
                0)
                    base="$sentence **[r$id](https://e.t/$id)** \`v$id\` \"$quote\" '$aside' _${em}_. $footnote[^$footnote_tag]"
                    ;;
                1)
                    base="$sentence [r$id](https://e.t/$id) (\`v$id\`) \"$quote\" + '$aside' **$em**"
                    ;;
                2)
                    base="$sentence \"$quote\" -- [r$id](https://e.t/$id) ('$aside') \`v$id\` ~~$em~~"
                    ;;
                3)
                    base="$sentence _[r$id](https://e.t/$id)_; $footnote[^$footnote_tag] '$aside' **$em** (\`v$id\`) \"$quote\""
                    ;;
            esac
        
            if ((${#base} > 199)); then
                printf 'Excerpt %s is too long (%s characters)\n' "$id" "${#base}" >&2
                exit 1
            fi
        
            pad_len=$((99 - ${#base}))
            printf -v padding '%*s' "$pad_len" ''
            padding=${padding// /x}
            line="$base $padding"
        
            if [ ${#line} -lt 100 ]; then
                printf 'Excerpt %s is not 100 characters\n' "$id" >&2
                exit 1
            fi
            if [ ${random_test_seen["$line"]+yes} ]; then
                printf 'Duplicate excerpt generated\n' >&2
                exit 1
            fi
        
            random_test_seen["$line"]=1
            printf '%s\n' "$line"

            i=$((i + 1))
        done
    }

    declare -ga random_test_snippets=()
    mapfile -t random_test_snippets < <(
        make_random_test_snippets
    )

    declare -ga random_test_expected
    mapfile -t random_test_expected < <(
        printf '%s\n' "${random_test_snippets[@]}" | make_expected
    ) 
}

@test "trim_markdown deterministic test" {
    input="$BATS_TEST_TMPDIR/terminal-input"
    output="$BATS_TEST_TMPDIR/terminal-output"

    local n="${#deterministic_test_snippets[@]}"
    for ((i=0; i < n; ++i))
    do
        run trim_markdown "${deterministic_test_snippets[$i]}" 80

        [ "$status" -eq 0 ]
        [ "$output" = "${deterministic_test_expected[$i]}" ]
    done
}

@test "trim_markdown random test" {
    input="$BATS_TEST_TMPDIR/terminal-input"
    output="$BATS_TEST_TMPDIR/terminal-output"

    local n="${#random_test_snippets[@]}"
    echo $n
    for ((i=0; i < n; ++i))
    do
        echo $i
        echo "${random_test_snippets[$i]}"
        run trim_markdown "${random_test_snippets[$i]}" 80
        echo "${random_test_expected[$i]}"
        echo "$output"

        [ "$status" -eq 0 ]
        [ "$output" = "${random_test_expected[$i]}" ]
    done
}
