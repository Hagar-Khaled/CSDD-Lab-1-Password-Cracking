import subprocess as sp
import time
import sys
current_time = time.perf_counter_ns()
username = "Magdy"
pass_list = open("MostCommonPWs", "r").read().splitlines()
for i in pass_list:
    res = sp.run([sys.executable,"login.pyc", username, i], capture_output=True, text=True)
    if res.stdout == "Login failed: incorrect password.\n":
        continue
    else:
        print(f"Password found: {i} for user {username}")
        break
end_time = time.perf_counter_ns()
print(f"Time taken: {(end_time - current_time)/1000000000} seconds") 