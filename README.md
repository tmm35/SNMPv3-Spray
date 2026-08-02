# SNMPv3-Spray

A Bash script for brute-forcing SNMPv3 credentials against a target host using `snmpwalk`. Unlike a plain password spray, it exhaustively tests every SNMPv3 security level and every auth/privacy protocol combination supported by your local `net-snmp` build, no partial-coverage shortcuts.

## Example Output

<img width="1560" height="423" alt="image" src="https://github.com/user-attachments/assets/5c707908-87ba-4870-8284-343c49dd3b10" />

## Why

Most SNMPv3 spray scripts assume a fixed security level. That's fine if you already know the target's configuration, but during recon you often don't. A device might reject `authNoPriv` outright and only accept `authPriv`, or use `SHA-256` instead of the more common `MD5`/`SHA`. This script removes that guesswork by trying everything.

## Requirements

- `bash`
- `snmpwalk` (from `net-snmp`, typically preinstalled on Kali)
- `timeout` (coreutils)
- `xxd` (only used in debug output)

## What it tests

For every user × password pair, the script runs:

- `noAuthNoPriv` (once per user, no password)
- `authNoPriv` across all supported auth protocols: `MD5`, `SHA`, `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512`
- `authPriv` across all auth × privacy protocol combinations: privacy protocols `DES`, `AES`, `AES-192`, `AES-256`

That's 31 attempts per user/password pair (1 + 6 + 24). A 100-word list against a single user is 3,000+ requests. There is no reduced/quick mode — this script always runs the full sweep.

**Known limitation:** for `authPriv` attempts, the privacy passphrase (`-X`) is assumed to be identical to the auth passphrase (`-A`). If a target uses a different privacy passphrase, `authPriv` combinations will fail or time out even when the password is otherwise correct. Any hit at `authNoPriv` should be considered confirmed regardless of what `authPriv` reports.

## Usage

```bash
./snmpv3-spray.sh -t <target> [-u user | -U userlist] [-p pass | -P passlist] [-d]
                   [--NoAuthNoPriv] [--AuthNoPriv] [--AuthPriv]
```

| Flag | Description |
|------|-------------|
| `-t` | Target IP or hostname (required) |
| `-u` | Single username |
| `-U` | Path to a username list (one per line) |
| `-p` | Single password |
| `-P` | Path to a password list (one per line) |
| `-d` | Debug mode — print every attempt, plus raw `snmpwalk` error output on failure |
| `--NoAuthNoPriv` | Only run `noAuthNoPriv` checks |
| `--AuthNoPriv` | Only run `authNoPriv` checks |
| `--AuthPriv` | Only run `authPriv` checks |

Exactly one of `-u`/`-U` and exactly one of `-p`/`-P` is required. Passwords under 8 characters are skipped automatically (SNMPv3 USM's minimum length requirement) and excluded from the attempt count shown at startup.

The three level flags can be combined in any order and combination (e.g. `--NoAuthNoPriv --AuthPriv` runs both, skipping `authNoPriv`). If none are given, all three levels run — same as the script's original behavior.

### Examples

Single user, password list:
```bash
./snmpv3-spray.sh -t 10.10.10.10 -u john -P passwords.txt
```

Username list, single password:
```bash
./snmpv3-spray.sh -t 10.10.10.10 -U users.txt -p Summer2024!
```

Full user × password matrix with debug output:
```bash
./snmpv3-spray.sh -t 10.10.10.10 -U users.txt -P passwords.txt -d
```

Only `authNoPriv`, skipping `noAuthNoPriv` and `authPriv` entirely:
```bash
./snmpv3-spray.sh -t 10.10.10.10 -U users.txt -P passwords.txt --AuthNoPriv
```

## Output

On startup, the script prints an exact attempt count based on your inputs:

```
[*] Target: 10.10.10.10
[*] Levels: noAuthNoPriv authNoPriv authPriv
[*] Users: 1  Passwords: 100 (69 usable, min 8 chars)
[*] Auth protocols: MD5 SHA SHA-224 SHA-256 SHA-384 SHA-512
[*] Priv protocols: DES AES AES-192 AES-256
[*] Total attempts: 2139
```

Progress updates print every 200 attempts with elapsed time shown as `MM:SS`:

```
    ... 200/2139 attempts, 00:48 elapsed
    ... 400/2139 attempts, 01:36 elapsed
```

A confirmed success looks like:

```
[+] SUCCESS -> user: john  level: authNoPriv  authproto: MD5  privproto:  pass: P@ssw0rd!
    Command: snmpwalk -v3 -u john -l authNoPriv -A 'P@ssw0rd!' -a MD5 10.10.10.10
```

The script exits immediately on a confirmed success and prints the exact `snmpwalk` command to reproduce it.

Some attempts may exceed the internal timeout without a definitive success/failure result — this can happen on the first successful auth against a device, due to SNMPv3 engine boot/time synchronization overhead. These are flagged as possible hits rather than discarded as failures, and the run continues rather than exiting:

```
[?] Possible password found: P@ssw0rd! (level=authNoPriv, auth=MD5, priv=) -- Try:
      snmpwalk -v3 -u john -l authNoPriv -A 'P@ssw0rd!' -a MD5 10.10.10.10
```

At the end of a full run, the script prints:

```
[-] Script finished. Please test all possible passwords found, if any.
```

Always manually verify any flagged "possible password" with the printed command before trusting it — the script itself does not exit on these, only on a fully confirmed success.

## Wordlist notes

- Lines are stripped of trailing `\r` automatically (handles Windows-formatted wordlists).
- Empty lines are skipped.
- Passwords under 8 characters are skipped (SNMPv3 USM rejects them outright).

## Legal

- This script was written with the assistance of Claude. If you are upset over that, oh well.
- For use in CTFs and authorized penetration testing engagements only. Do not run this against systems you don't have explicit permission to test.
