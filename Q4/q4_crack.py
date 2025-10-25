"""
q4_crack.py
  py -3.12 q4_crack.py
  py -3.12 q4_crack.py --logincheck ../.loginCheck --pwned PwnedPWfile --users users --limit 0

 - logincheck: ../.loginCheck
 - pwned file: PwnedPWfile
 - users file: users
--limit N : only test first N pwned passwords 
"""
import hashlib, time, argparse, sys, re, os

def load_logincheck(path):
    d = {}
    hex_re = re.compile(r'[A-Fa-f0-9]{64}')
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line: 
                continue
            parts = line.split(',', 1)
            if len(parts) != 2:
                continue
            user = parts[0].strip()
            h = parts[1].strip().lower()
            if hex_re.fullmatch(h):
                d[user] = h
    return d

def load_file_lines(path, limit=0):
    for enc in ('utf-8', 'latin-1'):
        try:
            with open(path, 'r', encoding=enc, errors='ignore') as f:
                lines = [l.rstrip('\n') for l in f if l.strip()]
            if limit and limit > 0:
                return lines[:limit]
            return lines
        except FileNotFoundError:
            raise
        except Exception:
            continue
    raise RuntimeError(f"Failed to read {path} with utf-8 or latin-1")

def iterated_hash(user, password, iterations=90000):
    h = hashlib.sha256()
    h.update(bytes(user + password, 'utf-8'))
    for _ in range(iterations):
        h.update(h.digest())
    return h.hexdigest()

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--logincheck', default='../.loginCheck', help='Path to .loginCheck (username,hash)')
    p.add_argument('--pwned', default='PwnedPWfile', help='Path to PwnedPWfile (exposed passwords)')
    p.add_argument('--users', default='users', help='Path to users file (one username per line)')
    p.add_argument('--limit', type=int, default=0, help='Limit number of pwned passwords tested (0 = all)')
    p.add_argument('--progress', type=int, default=500, help='Show progress every N candidates')
    args = p.parse_args()

    for path in (args.logincheck, args.pwned, args.users):
        if not os.path.exists(path):
            print(f"[ERROR] Required file not found: {path}")
            sys.exit(1)

    start_all = time.time()
    print(f"[+] Loading logincheck from: {args.logincheck}")
    login = load_logincheck(args.logincheck)
    print(f"[+] Loaded {len(login)} entries from .loginCheck")

    print(f"[+] Loading target users from: {args.users}")
    users = load_file_lines(args.users)
    # only consider users that exist in logincheck
    targets = [u for u in users if u in login]
    if not targets:
        print("[!] No target users from users file appear in .loginCheck. Exiting.")
        sys.exit(0)
    print(f"[+] {len(targets)} target users present in .loginCheck: {targets}")

    print(f"[+] Loading pwned passwords from: {args.pwned} (limit={args.limit})")
    pwned = load_file_lines(args.pwned, limit=args.limit or 0)
    print(f"[+] Loaded {len(pwned)} pwned entries to test")

    total_candidates = len(pwned) * len(targets)
    print(f"[+] Total user+password candidates (approx): {total_candidates:,}")
    tested = 0

    # Try each candidate; stop at first success
    for idx, pwt in enumerate(pwned, 1):
        usert,pw = pwt.split(',')
        for user in targets:
            tested += 1
            guess = iterated_hash(user, pw)
            if guess == login[user]:
                elapsed = time.time() - start_all
                print("\n[FOUND]")
                print(f"User: {user}")
                print(f"Cracked password: {pw}")
                print(f"Time elapsed: {elapsed:.4f} seconds")
                with open('q4_found.txt', 'w', encoding='utf-8') as out:
                    out.write(f"{user}:{pw}\n")
                return
        # progress
        if idx % args.progress == 0:
            elapsed = time.time() - start_all
            print(f"[+] tested {idx}/{len(pwned)} pwned words ({tested} total candidates)  elapsed {elapsed:.2f}s")
    elapsed = time.time() - start_all
    print("[!] Finished scanning without finding a reused password.")
    print(f"Total candidates tested: {tested}. Time elapsed: {elapsed:.2f}s")

if __name__ == '__main__':
    main()
