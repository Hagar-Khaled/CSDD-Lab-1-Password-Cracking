#!/usr/bin/env python3
"""
q4_crack_mp.py
Multiprocessing Q4 cracker (tries to find which user reused a password from PwnedPWfile).
Stops at first match and writes q4_found.txt with user:password.
Usage
  py -3.12 q4_crack_mp.py --logincheck ../.loginCheck --pwned PwnedPWfile --users users --limit 500 --workers 4
--limit to test only the first N pwned passwords for a quick run.
"""
import argparse, hashlib, re, time, os, sys
from multiprocessing import Pool, cpu_count

ITERATIONS = 90000

def iterated_hash(user, password, iterations=ITERATIONS):
    h = hashlib.sha256()
    h.update(bytes(user + password, 'utf-8'))
    for _ in range(iterations):
        h.update(h.digest())
    return h.hexdigest()

def parse_logincheck(path):
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

def load_lines(path, limit=0):
    for enc in ('utf-8', 'latin-1'):
        try:
            with open(path, 'r', encoding=enc, errors='ignore') as f:
                lines = [l.rstrip('\n') for l in f if l.strip()]
            return lines[:limit] if limit and limit > 0 else lines
        except Exception:
            continue
    raise RuntimeError(f"Could not read {path}")

def worker_task(args):
    user, pw, target_hash = args
    if iterated_hash(user, pw) == target_hash:
        return (user, pw)
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--logincheck', default='../.loginCheck')
    ap.add_argument('--pwned', default='PwnedPWfile')
    ap.add_argument('--users', default='users')
    ap.add_argument('--limit', type=int, default=0, help='limit pwned list for quick tests (0 = all)')
    ap.add_argument('--workers', type=int, default=0, help='number of worker processes (0 = cpu_count())')
    ap.add_argument('--progress', type=int, default=100, help='show progress every N pwned words')
    args = ap.parse_args()

    if not os.path.exists(args.logincheck):
        print(f"[ERROR] logincheck not found: {args.logincheck}", file=sys.stderr); sys.exit(1)
    if not os.path.exists(args.pwned):
        print(f"[ERROR] pwned file not found: {args.pwned}", file=sys.stderr); sys.exit(1)
    if not os.path.exists(args.users):
        print(f"[ERROR] users file not found: {args.users}", file=sys.stderr); sys.exit(1)

    workers = args.workers or cpu_count()
    print(f"[+] Using {workers} worker processes")

    login = parse_logincheck(args.logincheck)
    users_all = load_lines(args.users)
    targets = [u for u in users_all if u in login]
    if not targets:
        print("[!] No target users present in logincheck. Exiting."); sys.exit(0)
    print(f"[+] Targets: {targets}")

    pwned = load_lines(args.pwned, limit=args.limit or 0)
    print(f"[+] Loaded {len(pwned)} pwned passwords (limit={args.limit})")
    total_candidates = len(pwned) * len(targets)
    print(f"[+] Total candidates (approx): {total_candidates:,}")

    start = time.time()
    found = None

    pool = Pool(processes=workers)
    try:
        #stream tasks per pwned password to keep memory low.
        tasks_iter = []
        checked_pwned = 0
        for idx, pw in enumerate(pwned, 1):
            tasks = [(u, pw, login[u]) for u in targets]
            results = pool.map(worker_task, tasks)
            for r in results:
                if r:
                    found = r
                    break
            checked_pwned += 1
            if idx % args.progress == 0 or found:
                elapsed = time.time() - start
                print(f"[+] scanned {idx}/{len(pwned)} pwned words; elapsed {elapsed:.1f}s; found={bool(found)}")
            if found:
                break
    finally:
        pool.terminate()
        pool.join()

    elapsed = time.time() - start
    if found:
        user, pw = found
        print("\n[FOUND]")
        print(f"User: {user}")
        print(f"Password: {pw}")
        print(f"Time elapsed: {elapsed:.4f}s")
        with open('q4_found.txt', 'w', encoding='utf-8') as out:
            out.write(f"{user}:{pw}\n")
    else:
        print("[!] No reused password found in tested slice.")
        print(f"Total pwned words tested: {checked_pwned}; time elapsed {elapsed:.2f}s")

if __name__ == '__main__':
    main()
