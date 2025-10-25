
"""
q5_crack_exact.py
Usage:
  py -3.12 q5_crack_exact.py --hashfile HashedPWs --leaked LeakedPWs100k --users users
Output:
  - prints progress, time, and found creds
  - writes found credentials to found_creds.txt
"""
import argparse
import hashlib
import re
import time
from collections import defaultdict

def parse_hashed_file(path):
    """
    Parse file into dict username -> hash.
    Accepts lines like:
      user:hash
      user,hash
      user hash
      hash (no username)  -> will be stored as hash only (username None)
    """
    user_to_hash = {}
    hash_only = []
    hex_re = re.compile(r'\b[a-fA-F0-9]{64}\b')  # SHA-256 hex
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            m = hex_re.search(line)
            if m:
                h = m.group(0).lower()
                # try to find username before the hash (separators common)
                before = line[:m.start()].strip()
                if before:
                    # strip punctuation
                    before = re.sub(r'[:,\s]+$', '', before)
                    user_to_hash[before] = h
                else:
                    # try split by common separators
                    parts = re.split(r'[:,\s]+', line)
                    if len(parts) >= 2:
                        user_to_hash[parts[0]] = parts[-1].lower()
                    else:
                        hash_only.append(h)
            else:
                # no 64-hex found: try naive split "user:hashlike" or comma
                parts = re.split(r'[:,\s]+', line)
                if len(parts) >= 2 and re.fullmatch(r'[A-Fa-f0-9]{64}', parts[-1]):
                    user_to_hash[parts[0]] = parts[-1].lower()
                else:
                    # ignore unknown line
                    continue
    return user_to_hash, hash_only

def load_list(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return [l.strip() for l in f if l.strip()]

def sha256hex(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8', errors='ignore')).hexdigest()

def main(args):
    start_time = time.time()
    print(f"[+] Loading hashed file: {args.hashfile}")
    user_to_hash, hash_only = parse_hashed_file(args.hashfile)
    print(f"[+] Parsed {len(user_to_hash)} username->hash entries and {len(hash_only)} hash-only entries")

    users = load_list(args.users)
    print(f"[+] Loaded {len(users)} target users from {args.users}")

    leaked = load_list(args.leaked)
    print(f"[+] Loaded {len(leaked)} leaked base passwords from {args.leaked}")

    hash_to_user = defaultdict(list)
    for u, h in user_to_hash.items():
        hash_to_user[h].append(u)
    # If there are hash_only entries, we can still try to crack them (no username)
    for h in hash_only:
        hash_to_user[h].append(None)

    found = []  # tuples (username, plaintext)
    targets = {}
    for u in users:
        if u in user_to_hash:
            targets[u] = user_to_hash[u]
        else:
            # warn : maybe username is not present in hashed file
            lowered = None
            for uu in user_to_hash.keys():
                if uu.lower() == u.lower():
                    lowered = uu
                    break
            if lowered:
                targets[lowered] = user_to_hash[lowered]
            else:
                print(f"[-] Warning: user '{u}' not found in {args.hashfile}; skipping")

    if not targets:
        print("[-] No target users found in hashfile. Exiting.")
        return

    print(f"[+] Cracking {len(targets)} target users. Starting brute-force (leaked+00..99)...")
    total_candidates = len(leaked) * 100
    print(f"[+] Total candidates (approx): {total_candidates:,}")

    # For quicker lookup, map hashes we care about to usernames
    target_hashes = {h for h in targets.values()}
    remaining = dict(targets)  # username->hash still to find

    # iterate leaked list, build candidate with two digits
    for idx, base in enumerate(leaked, 1):
        base = base.rstrip('\n')
        
        if idx % 5000 == 0:
            elapsed = time.time() - start_time
            print(f"    scanned {idx}/{len(leaked)} leaked words, elapsed {elapsed:.1f}s, remaining {len(remaining)}")
        for d in range(100):
            cand = f"{base}{d:02d}"
            h = sha256hex(cand)
            if h in target_hashes:
                for matched_user in [u for u, hh in targets.items() if hh == h]:
                    if matched_user in remaining:
                        print(f"[FOUND] user={matched_user} password='{cand}' (hash match)")
                        found.append((matched_user, cand))
                        # verify by recompute:
                        if sha256hex(cand) == h:
                            print(f"    Verified locally for {matched_user}.")
                        else:
                            print(f"    Verification failed for {matched_user} (unexpected).")
                        # remove from remaining and target_hashes to speed up
                        del remaining[matched_user]
                        if not remaining:
                            end_time = time.time()
                            tot = end_time - start_time
                            print(f"[+] All targets cracked. Time: {tot:.2f}s")
                            with open('found_creds.txt', 'w', encoding='utf-8') as out:
                                for u,p in found:
                                    out.write(f"{u}:{p}\n")
                            print("[+] Results written to found_creds.txt")
                            return
    
    end_time = time.time()
    tot = end_time - start_time
    print(f"[+] Done scanning. Time: {tot:.2f}s. Found {len(found)} credential(s).")
    with open('found_creds.txt', 'w', encoding='utf-8') as out:
        for u,p in found:
            out.write(f"{u}:{p}\n")
    print("[+] Results written to found_creds.txt")
    if remaining:
        print(f"[-] Remaining users not cracked ({len(remaining)}): {list(remaining.keys())}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Crack leaked+two-digits passwords against hashed file (SHA256).")
    parser.add_argument('--hashfile', required=True, help='Path to HashedPWs')
    parser.add_argument('--leaked', required=True, help='Path to leaked passwords (base words)')
    parser.add_argument('--users', required=True, help='Path to users file (targets)')
    args = parser.parse_args()
    main(args)
