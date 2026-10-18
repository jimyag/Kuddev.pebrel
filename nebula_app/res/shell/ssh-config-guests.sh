# Pebrel WSL guest reader for the OpenSSH configuration.
# nebula_app/src/platform/wsl_ssh.rs runs it as
#   wsl.exe -d <distribution> [-u <user>] --exec sh -s
# with this script on stdin, and parses the `home=` / `path=` lines it prints.
#
# Why the guest answers instead of the host reading \\wsl.localhost\ directly:
#   * the 9P share is not always mounted, and its absence must not look like an
#     empty configuration;
#   * the guest alone knows its $HOME, its Include order and its globbing.
#
# Nothing here executes ssh or evaluates the configuration: no `ssh -G`, no
# Match conditions, no command substitution. Every path is read as text by the
# host afterwards.
#
# Output is `home=<path>` first, then one `path=<absolute path>` per regular
# file, in the order OpenSSH reads them (the config first, then its Includes,
# depth first). Budgets are SSH_GUEST_FILES files and SSH_GUEST_BYTES bytes no
# matter what the configuration asks for.

budget_files=${SSH_GUEST_FILES:-64}
depth_max=8
files_seen=0
visited=$(printf '\n')

home=${HOME-}
[ -n "$home" ] || home=$(cd ~ 2>/dev/null && pwd)
[ -n "$home" ] || exit 0
printf 'home=%s\n' "$home"

# Strip one layer of matching surrounding quotes from $1 into stdout.
unquote() {
    printf '%s' "$1" | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"
}

# Print the files one Include pattern names. Runtime-dependent tokens (%h,
# $VAR, ~other/) are skipped rather than guessed: OpenSSH would resolve them
# from context the host cannot see.
expand_include() {
    include_root=$1
    pattern=$(unquote "$2")
    [ -n "$pattern" ] || return 0
    case $pattern in
        *%*|*'$'*) return 0 ;;
    esac
    case $pattern in
        '~/'*) pattern=$home/${pattern#'~/'} ;;
        /*) ;;
        '~'*) return 0 ;;
        *) pattern=$include_root/$pattern ;;
    esac
    # The unquoted expansion is the glob. IFS stays at the default blank, so a
    # path containing a space does not match, which is what OpenSSH's own glob
    # does too.
    for candidate in $pattern; do
        [ -f "$candidate" ] || continue
        [ -r "$candidate" ] || continue
        printf 'path=%s\n' "$candidate"
    done
    return 0
}

# Emit the bare words of a directive's value, consuming `=` and blanks first.
walk_value() {
    value=$1
    while :; do
        case $value in
            ''|'#'*) return 0 ;;
            '='*) value=${value#?} ;;
            ' '*) value=${value#?} ;;
            '	'*) value=${value#?} ;;
            *) break ;;
        esac
    done
    set -f
    set -- $value
    set +f
    for word in "$@"; do
        [ -n "$word" ] && expand_include "$include_root" "$word"
    done
    return 0
}

scan_file() {
    file=$1
    depth=$2
    [ "$files_seen" -lt "$budget_files" ] || return 0
    [ "$depth" -le "$depth_max" ] || return 0
    case $visited in
        *"
$file
"*) return 0 ;;
    esac
    visited="$visited$file
"
    files_seen=$((files_seen + 1))
    printf 'path=%s\n' "$file"
    case $file in
        */*) include_root=${file%/*} ;;
        *) include_root=. ;;
    esac
    [ -n "$include_root" ] || include_root=/
    while IFS= read -r line || [ -n "$line" ]; do
        # Drop leading blanks (which a BOM on the first line follows), then
        # treat a leading `#` as a comment.
        line=${line#"${line%%[![:space:]]*}"}
        case $line in
            ''|'#'*) continue ;;
        esac
        keyword=${line%%[[:space:]=]*}
        rest=${line#"$keyword"}
        case $keyword in
            [Ii][Nn][Cc][Ll][Uu][Dd][Ee]) walk_value "$rest" ;;
        esac
    done < "$file"
    return 0
}

config=$home/.ssh/config
if [ -f "$config" ] && [ -r "$config" ]; then
    scan_file "$config" 1
fi
exit 0
