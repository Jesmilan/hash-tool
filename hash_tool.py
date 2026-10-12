#!/usr/bin/env python3
"""
hash_tool.py - Hash identifier and dictionary cracker.

A learning / CTF tool: it (1) guesses what kind of hash a string is from its
length and format, and (2) tries a dictionary attack by hashing each candidate
word and comparing.

Only crack hashes you are authorised to crack.

Usage
-----
  # Identify a hash
  python3 hash_tool.py identify 5f4dcc3b5aa765d61d8327deb882cf99

  # Crack with the bundled wordlist (auto-detects the type)
  python3 hash_tool.py crack 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt

  # Force a specific type, read the hash from a file, read many hashes
  python3 hash_tool.py crack -t sha256 <hash> -w wordlist.txt
  python3 hash_tool.py crack --hash-file hashes.txt -w wordlist.txt

Supported for cracking:
  Fast unsalted:  md5, sha1, sha224, sha256, sha384, sha512, sha3_256, sha3_512, ntlm
  Salted (slow):  bcrypt  (needs `pip install bcrypt`)
                  argon2  (needs `pip install argon2-cffi`)
"""

import argparse
import hashlib
import re
import sys
import time

# Optional libraries for salted schemes. Absence is handled gracefully:
# detection still works, only cracking those types needs them.
try:
    import bcrypt  # type: ignore
    _HAS_BCRYPT = True
except ImportError:
    _HAS_BCRYPT = False

try:
    from argon2 import PasswordHasher  # type: ignore
    from argon2.exceptions import VerifyMismatchError  # type: ignore
    _HAS_ARGON2 = True
except ImportError:
    _HAS_ARGON2 = False


# --- Fast unsalted hash functions ------------------------------------------
# Each takes a UTF-8 word and returns the lowercase hex digest.

def _hl(name):
    return lambda word: hashlib.new(name, word.encode("utf-8")).hexdigest()


def _md4(data):
    """MD4 digest. Uses OpenSSL if available, else a pure-Python fallback
    (modern OpenSSL builds drop MD4, which NTLM needs)."""
    try:
        return hashlib.new("md4", data).digest()
    except Exception:
        return _md4_pure(data)


def _md4_pure(msg):
    import struct

    def lrot(x, n):
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    orig_len = len(msg)
    msg += b"\x80"
    while len(msg) % 64 != 56:
        msg += b"\x00"
    msg += struct.pack("<Q", orig_len * 8)

    for off in range(0, len(msg), 64):
        x = list(struct.unpack("<16I", msg[off:off + 64]))
        aa, bb, cc, dd = a, b, c, d

        def f(x, y, z): return (x & y) | (~x & z)
        def g(x, y, z): return (x & y) | (x & z) | (y & z)
        def h(x, y, z): return x ^ y ^ z

        for i in (0, 4, 8, 12):
            a = lrot(a + f(b, c, d) + x[i], 3)
            d = lrot(d + f(a, b, c) + x[i + 1], 7)
            c = lrot(c + f(d, a, b) + x[i + 2], 11)
            b = lrot(b + f(c, d, a) + x[i + 3], 19)
        for i in (0, 1, 2, 3):
            a = lrot(a + g(b, c, d) + x[i] + 0x5A827999, 3)
            d = lrot(d + g(a, b, c) + x[i + 4] + 0x5A827999, 5)
            c = lrot(c + g(d, a, b) + x[i + 8] + 0x5A827999, 9)
            b = lrot(b + g(c, d, a) + x[i + 12] + 0x5A827999, 13)
        for i in (0, 2, 1, 3):
            a = lrot(a + h(b, c, d) + x[i] + 0x6ED9EBA1, 3)
            d = lrot(d + h(a, b, c) + x[i + 8] + 0x6ED9EBA1, 9)
            c = lrot(c + h(d, a, b) + x[i + 4] + 0x6ED9EBA1, 11)
            b = lrot(b + h(c, d, a) + x[i + 12] + 0x6ED9EBA1, 15)

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    return struct.pack("<4I", a, b, c, d)


def _ntlm(word):
    # NTLM = MD4 of the UTF-16-LE password.
    return _md4(word.encode("utf-16-le")).hex()


FAST_HASHERS = {
    "md5": _hl("md5"),
    "sha1": _hl("sha1"),
    "sha224": _hl("sha224"),
    "sha256": _hl("sha256"),
    "sha384": _hl("sha384"),
    "sha512": _hl("sha512"),
    "sha3_256": _hl("sha3_256"),
    "sha3_512": _hl("sha3_512"),
    "ntlm": _ntlm,
}


# --- Identification ---------------------------------------------------------
# Hex-length -> candidate algorithms. Several share a length, so we return all
# plausible ones, most common first.
HEX_LEN_MAP = {
    32: ["md5", "ntlm", "md4"],
    40: ["sha1"],
    56: ["sha224"],
    64: ["sha256", "sha3_256"],
    96: ["sha384"],
    128: ["sha512", "sha3_512"],
}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def identify(h):
    """Return a list of (type, note) candidate identifications."""
    h = h.strip()
    candidates = []

    # Prefixed / structured schemes are unambiguous.
    if h.startswith(("$2a$", "$2b$", "$2y$", "$2x$")):
        return [("bcrypt", "modular crypt, salted, slow")]
    if h.startswith("$argon2"):
        variant = h.split("$", 2)[1] if "$" in h[1:] else "argon2"
        return [(variant, "Argon2, salted, slow")]
    if h.startswith(("$6$",)):
        return [("sha512crypt", "Unix crypt, salted")]
    if h.startswith(("$5$",)):
        return [("sha256crypt", "Unix crypt, salted")]
    if h.startswith(("$1$",)):
        return [("md5crypt", "Unix crypt, salted")]
    if h.startswith("$y$") or h.startswith("$7$"):
        return [("yescrypt/scrypt", "Unix crypt, salted")]

    if _HEX_RE.match(h):
        algos = HEX_LEN_MAP.get(len(h))
        if algos:
            for a in algos:
                candidates.append((a, f"{len(h)} hex chars"))
        else:
            candidates.append(("unknown", f"{len(h)} hex chars, no common match"))
    else:
        candidates.append(("unknown", "not hex and no known prefix"))

    return candidates


# --- Cracking ---------------------------------------------------------------

def _iter_words(wordlist_path):
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            yield line.rstrip("\n\r")


def crack_fast(target, algo, wordlist_path):
    """Hash each word with `algo` and compare. Returns the word or None."""
    hasher = FAST_HASHERS[algo]
    target = target.strip().lower()
    for word in _iter_words(wordlist_path):
        if hasher(word) == target:
            return word
    return None


def crack_bcrypt(target, wordlist_path):
    if not _HAS_BCRYPT:
        raise RuntimeError("bcrypt not installed. Run: pip install bcrypt")
    target_bytes = target.strip().encode("utf-8")
    for word in _iter_words(wordlist_path):
        try:
            if bcrypt.checkpw(word.encode("utf-8"), target_bytes):
                return word
        except ValueError:
            raise RuntimeError("Target does not look like a valid bcrypt hash.")
    return None


def crack_argon2(target, wordlist_path):
    if not _HAS_ARGON2:
        raise RuntimeError("argon2-cffi not installed. Run: pip install argon2-cffi")
    ph = PasswordHasher()
    target = target.strip()
    for word in _iter_words(wordlist_path):
        try:
            if ph.verify(target, word):
                return word
        except VerifyMismatchError:
            continue
        except Exception:
            raise RuntimeError("Target does not look like a valid Argon2 hash.")
    return None


def pick_type(h, forced):
    """Decide which type to crack as. Returns (type, auto_bool)."""
    if forced:
        return forced, False
    cands = identify(h)
    top = cands[0][0]
    return top, True


def do_crack(h, forced_type, wordlist_path):
    algo, auto = pick_type(h, forced_type)
    label = f"{algo} (auto-detected)" if auto else f"{algo} (forced)"
    print(f"[*] Target : {h}")
    print(f"[*] Type   : {label}")
    if auto:
        others = [c[0] for c in identify(h)[1:]]
        if others:
            print(f"[*] Could also be: {', '.join(others)} "
                  f"(use -t to force one)")
    print(f"[*] Wordlist: {wordlist_path}")

    start = time.time()
    try:
        if algo in FAST_HASHERS:
            result = crack_fast(h, algo, wordlist_path)
        elif algo == "bcrypt":
            result = crack_bcrypt(h, wordlist_path)
        elif algo.startswith("argon2"):
            result = crack_argon2(h, wordlist_path)
        else:
            print(f"[!] Don't know how to crack type '{algo}'. "
                  f"Try forcing one with -t.")
            return 2
    except RuntimeError as e:
        print(f"[!] {e}")
        return 2

    elapsed = time.time() - start
    if result is not None:
        print(f"[+] FOUND: {h} -> '{result}'  ({elapsed:.2f}s)")
        return 0
    print(f"[-] Not found in wordlist.  ({elapsed:.2f}s)")
    return 1


def do_identify(h):
    cands = identify(h)
    print(f"Hash: {h}")
    print("Possible types (most likely first):")
    for i, (t, note) in enumerate(cands, 1):
        print(f"  {i}. {t:<14} - {note}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Identify and dictionary-crack hashes (CTF / learning tool).")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("identify", help="Guess a hash's type")
    pi.add_argument("hash", help="The hash string")

    pc = sub.add_parser("crack", help="Dictionary-attack a hash")
    pc.add_argument("hash", nargs="?", help="The hash string")
    pc.add_argument("--hash-file", help="File with one hash per line")
    pc.add_argument("-w", "--wordlist", required=True, help="Wordlist path")
    pc.add_argument("-t", "--type", dest="htype",
                    help="Force a hash type instead of auto-detecting")

    args = p.parse_args(argv)

    if args.cmd == "identify":
        return do_identify(args.hash)

    if args.cmd == "crack":
        hashes = []
        if args.hash_file:
            hashes = [l.strip() for l in _iter_words(args.hash_file) if l.strip()]
        elif args.hash:
            hashes = [args.hash]
        else:
            print("[!] Provide a hash or --hash-file.")
            return 2

        rc = 1
        for i, h in enumerate(hashes):
            if i:
                print("-" * 50)
            r = do_crack(h, args.htype, args.wordlist)
            rc = 0 if r == 0 else rc
        return rc

    return 0


if __name__ == "__main__":
    sys.exit(main())
