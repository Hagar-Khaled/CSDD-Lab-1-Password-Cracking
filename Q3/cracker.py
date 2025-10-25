import time
import sys
import hashlib
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor, as_completed 

# --- CONFIGURATION ---
MAX_WORKERS = 12 # Set to your 12 logical core count for max performance
found_passwords = {}


# --- 1. CORE LOGIN/HASHING LOGIC (With Explicit Data Argument) ---

# The hash_data dictionary MUST be the first argument passed to the function 
# submitted to ProcessPoolExecutor for reliable data sharing on Windows.
def check_login(hashed_data, username, password):
    """
    Performs the 90,000-iteration SHA-256 hash check.
    Returns (username, password) on success, or None on failure.
    """
    
    if username not in hashed_data:
        return None 

    # --- Hashing Logic (90000 Key Stretching Iterations) ---
    hash_obj = hashlib.sha256()
    hash_obj.update(bytes(username + password, 'utf-8'))
    
    for _ in range(90000): 
        hash_obj.update(hash_obj.digest())
        
    guess_hash = hash_obj.hexdigest()

    # Comparison using the explicitly passed data
    if guess_hash == hashed_data[username]:
        return username, password
    else:
        return None


# --- 2. MAIN EXECUTION BLOCK (Windows Multiprocessing Safeguard) ---

if __name__ == '__main__':
    
    current_time = time.perf_counter_ns()
    users_hashed_passwords = {}

    # --- File Loading (Runs only ONCE in the parent process) ---
    try:
        user_list = open("users", "r", encoding='utf-8').read().splitlines()
        pass_list = open("LeakedPWs100k", "r", encoding='utf-8').read().splitlines()

        # Load the HASHED CREDENTIALS FILE
        with open("../.loginCheck", "r") as f: 
            for row in f:
                (user, hashed_pw) = (row.strip('\n')).split(',')
                users_hashed_passwords[user] = hashed_pw
                
    except FileNotFoundError as e:
        print(f"FATAL ERROR: Required file not found. {e}")
        sys.exit(1)
        
    print(f"Starting cracking against {len(user_list)} users with {len(pass_list)} passwords...")
    
    # --- MULTIPROCESSING CRACKING ---
    try:
        # Use ProcessPoolExecutor for true CPU parallelization
        result = None
        with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
            
            for username in user_list:
                if result is not None:
                    break  # Exit if password already found for this user
                if username in ['Ahmed','Mostafa', 'Magdy']:
                    continue  # Skip already cracked users
                tqdm.write(f"\n[TARGET] Cracking passwords for user: {username}")
                
                futures = {}
                
                # Submit all password checks for the current user
                for password in pass_list:
                    # KEY FIX: Pass the users_hashed_passwords dictionary explicitly!
                    future = executor.submit(check_login, users_hashed_passwords, username, password)
                    futures[future] = password

                # Track progress and results
                for future in tqdm(as_completed(futures), total=len(pass_list), desc='  Progress', leave=False):
                    
                    result = future.result() 
                    
                    if result is not None:
                        u, p = result
                        found_passwords[u] = p
                        tqdm.write(f"  [!!! SUCCESS !!!] Password found: {p} for user {u}")
                        
                        # Cancel remaining checks for this user
                        for f in futures:
                            f.cancel()
                        break 
                        
    except Exception as e:
        # Catch unexpected errors during multiprocessing
        print(f"\nAn error occurred during execution: {e}")
        
    # --- END OF ALL TASKS AND REPORTING ---
    end_time = time.perf_counter_ns()

    print(f"\n=======================================================")
    print("  CRACKING COMPLETE")
    print("=======================================================")
    if found_passwords:
        print("Found Credentials:")
        for u, p in found_passwords.items():
            print(f"  {u}: {p}")
    else:
        print("No passwords were found for the provided users.")
    print(f"Total Time Taken: {(end_time - current_time)/1000000000:.4f} seconds")
    print("=======================================================")