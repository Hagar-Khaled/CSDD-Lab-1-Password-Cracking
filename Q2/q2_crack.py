"""
Usage:
  py -3.13 q2_crack.py --users users --wordlist "MostCommonPWs" --logincheck ../.loginCheck
"""
import argparse, time, os, hashlib, sys
ITER = 90000
def load_logincheck(path):
    d = {}
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            if ',' in line:
                user, h = line.split(',', 1)
            elif ':' in line:
                user, h = line.split(':', 1)
            else:
                continue
            d[user.strip()] = h.strip()
    return d

def read_lines(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return [l.strip() for l in f if l.strip()]

def make_hash(username, password, iterations=ITER):
    # replicate LoginTemplate.py exactly
    h = hashlib.sha256()
    h.update(bytes(username + password, 'utf-8'))
    for i in range(iterations):
        h.update(h.digest())
    return h.hexdigest()

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--users', required=True, help='users file (one username per line)')
    p.add_argument('--wordlist', required=True, help='wordlist file (Most CommonPWs)')
    p.add_argument('--logincheck', default='../.loginCheck', help='path to .loginCheck (username,hashedPW)')
    p.add_argument('--exclude', default='Magdy', help='username to exclude (case-insensitive)')
    args = p.parse_args()

    if not os.path.exists(args.logincheck):
        print("ERROR: logincheck file not found at:", args.logincheck)
        sys.exit(1)
    users = read_lines(args.users)
    users = [u for u in users if u.lower() != args.exclude.lower()]
    if not users:
        print("No users to test (all filtered).")
        sys.exit(0)

    wordlist = read_lines(args.wordlist)
    if not wordlist:
        print("Wordlist empty.")
        sys.exit(0)

    login_map = load_logincheck(args.logincheck)

    start = time.time()
    found = []
    for u in users:
        target_hash = login_map.get(u)
        if not target_hash:
            # user not present in logincheck ...skip 
            continue
        for pw in wordlist:
            guess = make_hash(u, pw)
            if guess == target_hash:
                elapsed = time.time() - start
                print("FOUND -> user={0} password={1}".format(u, pw))
                print("Total runtime: {0:.3f} seconds".format(elapsed))
                found.append((u, pw))
                # break after first found for this user
                break
    if not found:
        elapsed = time.time() - start
        print("No weak password found among candidates.")
        print("Total runtime: {0:.3f} seconds".format(elapsed))

if __name__ == "__main__":
    main()
