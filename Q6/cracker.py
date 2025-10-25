import hashlib
import threading
from queue import Queue
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import time
import subprocess
import os
from typing import Dict, Set, List, Tuple

def read_users_list(filename: str) -> Set[str]:
    """Read the users file and return a set of usernames."""
    with open(filename, 'r') as f:
        return {line.strip() for line in f}

def read_salted_passwords(filename: str, target_users: Set[str]) -> Dict[str, Tuple[str, str]]:
    """Read salted passwords file and filter by target users."""
    salted_passwords = {}
    with open(filename, 'r') as f:
        for line in f:
            # Remove newline and split by comma
            username, salt, hash_value = line.strip().split(',')
            if username in target_users:  # Only include users from our target list
                salted_passwords[username] = (salt, hash_value)
    return salted_passwords

def verify_password(username: str, password: str) -> bool:
    """Verify a password using login.pyc."""
    try:
        result = subprocess.run(['python', 'login.pyc', username, password], 
                              capture_output=True, text=True)
        return result.returncode == 0
    except Exception as e:
        print(f"Error verifying password for {username}: {e}")
        return False

def read_leaked_passwords(filename):
    passwords = []
    # Try different encodings
    encodings = ['utf-8', 'latin-1', 'cp1252']
    for encoding in encodings:
        try:
            with open(filename, 'r', encoding=encoding) as f:
                for line in f:
                    passwords.append(line.strip())
            return passwords  # If successful, return the passwords
        except UnicodeDecodeError:
            continue  # Try next encoding if current one fails
    raise Exception("Could not read file with any of the attempted encodings")

def read_users_list(filename):
    with open(filename, 'r') as f:
        return [line.strip() for line in f]

def try_login(username, password):
    try:
        result = subprocess.run(['python', 'login.pyc', username, password], 
                              capture_output=True, text=True)
        return result.returncode == 0  # Return True if login successful
    except Exception as e:
        print(f"Error trying login with {username}: {e}")
        return False

def hash_password(salt, password):
    # Convert the salt and password to bytes and concatenate
    combined = (salt + password).encode('utf-8')
    # Create SHA-256 hash
    hash_obj = hashlib.sha256(combined)
    # Get hex digest
    return hash_obj.hexdigest()

def crack_password_for_user(args):
    username, (salt, stored_hash), leaked_passwords, verified_users = args
    
    # Skip if user already verified
    if username in verified_users:
        return None
        
    # Process passwords in chunks to improve cache usage
    chunk_size = 1000
    for i in range(0, len(leaked_passwords), chunk_size):
        chunk = leaked_passwords[i:i + chunk_size]
        
        # Try each leaked password in the chunk
        for base_password in chunk:
            # Try concatenating digits 0-9
            for digit in range(10):
                # Create password + digit combination
                password_to_try = base_password + str(digit)
                
                # Calculate hash
                calculated_hash = hash_password(salt, password_to_try)
                
                # Compare with stored hash
                if calculated_hash == stored_hash:
                    # Verify with login.pyc before returning
                    if verify_password(username, password_to_try):
                        return (username, password_to_try, base_password)
                    # If verification fails, keep trying other combinations
    
    return None

def main():
    print("Starting password cracker...")
    start_time = time.time()

    # First, read our target users list
    target_users = read_users_list('users')
    print(f"Loaded {len(target_users)} target users")

    # Read the salted passwords, filtering for our target users
    salted_passwords = read_salted_passwords('SaltedPWs', target_users)
    print(f"Found {len(salted_passwords)} salted password entries for target users")
    
    leaked_passwords = read_leaked_passwords('LeakedPWs100k')
    print(f"Loaded {len(leaked_passwords)} leaked passwords")

    # Create sets to track progress (thread-safe)
    verified_users = set()  # Users whose passwords have been verified
    verified_users_lock = threading.Lock()

    # Prepare arguments for each worker
    work_items = [(username, data, leaked_passwords, verified_users) 
                 for username, data in salted_passwords.items()]

    found_passwords = []
    found_passwords_lock = threading.Lock()
    processed_count = 0
    total_users = len(salted_passwords)
    
    def add_found_password(result, verified_users, verified_users_lock, found_passwords, found_passwords_lock):
        if result:
            username, password, base_password = result
            with verified_users_lock:
                if username not in verified_users:
                    verified_users.add(username)
                    with found_passwords_lock:
                        found_passwords.append(result)
                        print(f"\nFound and verified password for {username}")
                        print(f"Password: {password}")
                        print(f"Base password: {base_password}")
                        print(f"Added digit: {password[-1]}")
                        print("-" * 50)

    # Progress tracking with percentage and found password count
    progress_lock = threading.Lock()
    
    def update_progress():
        nonlocal processed_count
        with progress_lock:
            processed_count += 1
            percentage = (processed_count / total_users) * 100
            found_count = len(found_passwords)
            if processed_count % 5 == 0 or processed_count == total_users:
                print(f"Progress: {processed_count}/{total_users} users processed ({percentage:.1f}%)")
                print(f"Passwords cracked so far: {found_count}")
                print(f"Success rate: {(found_count/processed_count*100):.1f}%")
                print("-" * 50, flush=True)

    # Use ThreadPoolExecutor with 12 worker threads
    with ThreadPoolExecutor(max_workers=12) as executor:
        # Submit all work items and collect results as they complete
        future_to_user = {executor.submit(crack_password_for_user, item): item[0] 
                         for item in work_items}
        
        for future in concurrent.futures.as_completed(future_to_user):
            username = future_to_user[future]
            try:
                result = future.result()
                add_found_password(result, verified_users, verified_users_lock, 
                                 found_passwords, found_passwords_lock)
            except Exception as e:
                print(f"Error processing {username}: {e}")
            update_progress()

    end_time = time.time()
    elapsed_time = end_time - start_time

    print("\n=== Summary of Found Passwords ===")
    print(f"Total passwords cracked: {len(found_passwords)}")
    print(f"Time taken: {elapsed_time:.2f} seconds")
    print("\nCracked passwords by user:")
    for username, password, base in sorted(found_passwords):
        print(f"User: {username}")
        print(f"  Password: {password}")
        print(f"  Base password: {base}")
        print(f"  Added digit: {password[-1]}\n")

if __name__ == "__main__":
    main()
