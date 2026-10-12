# Hash identifier / cracker

A small learning / CTF tool that **detects a hash's type** from its length and
format, then runs a **dictionary attack** by hashing each candidate word and
comparing. Only crack hashes you are authorised to crack.

## Files
- `hash_tool.py` — the tool (Python 3, standard library only for the core)
- `wordlist.txt` — a 41-word sample list so it runs out of the box
- `README.md` — this file

## Quick start

```bash
# Identify a hash
python3 hash_tool.py identify 5f4dcc3b5aa765d61d8327deb882cf99
#  1. md5   - 32 hex chars
#  2. ntlm  - 32 hex chars
#  3. md4   - 32 hex chars

# Crack it (auto-detects md5, then tries the wordlist)
python3 hash_tool.py crack 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt
# [+] FOUND: ... -> 'password'
```

## Commands

**identify** — guess the type:
```bash
python3 hash_tool.py identify <hash>
```

**crack** — dictionary attack:
```bash
python3 hash_tool.py crack <hash> -w wordlist.txt          # auto-detect type
python3 hash_tool.py crack -t sha256 <hash> -w wordlist.txt # force a type
python3 hash_tool.py crack --hash-file hashes.txt -w wordlist.txt  # many at once
```

## What it detects

- **By hex length:** MD5 / NTLM / MD4 (32), SHA-1 (40), SHA-224 (56),
  SHA-256 / SHA3-256 (64), SHA-384 (96), SHA-512 / SHA3-512 (128).
  Lengths that several algorithms share return all plausible types, most
  common first — use `-t` to force the right one.
- **By prefix (unambiguous):** bcrypt (`$2a/2b/2y$`), Argon2 (`$argon2…$`),
  and the Unix crypt family (`$1$` md5crypt, `$5$` sha256crypt,
  `$6$` sha512crypt, `$y$`/`$7$` yescrypt/scrypt) are flagged on sight.

## What it can crack

| Type | Needs | Notes |
|------|-------|-------|
| md5, sha1, sha224, sha256, sha384, sha512, sha3_256, sha3_512, ntlm | nothing (stdlib) | fast, unsalted |
| bcrypt | `pip install bcrypt` | salted, slow by design |
| argon2 | `pip install argon2-cffi` | salted, slow by design |

The salted types are **optional**: if the library isn't installed, detection
still works and the tool tells you what to `pip install` if you try to crack
one. NTLM uses a built-in pure-Python MD4 fallback, so it works even on the
newer OpenSSL builds that disable MD4.

## Defaults chosen (not asked)

- **Wordlist:** a 41-entry sample of the usual weak passwords, enough to demo
  every type above. Point `-w` at `rockyou.txt` or similar for real work.
- **Ambiguous lengths:** cracked as the most common algorithm (e.g. 32 hex →
  md5); override with `-t` for ntlm/md4.
- **Encoding:** words hashed as UTF-8 (UTF-16-LE for NTLM); wordlist read
  leniently so odd bytes don't crash a run.

## Example end-to-end

```bash
$ python3 hash_tool.py crack $(python3 -c "import hashlib;print(hashlib.sha256(b'letmein').hexdigest())") -w wordlist.txt
[*] Target : 1c8bfe8f801d79745c4631d09fff36c82aa37fc4cce4fc946683d7b336b63032
[*] Type   : sha256 (auto-detected)
[*] Could also be: sha3_256 (use -t to force one)
[*] Wordlist: wordlist.txt
[+] FOUND: 1c8bfe...b63032 -> 'letmein'  (0.00s)
```
