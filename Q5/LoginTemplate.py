# Login.py

import hashlib
import sys

def Login():
    usersHashedPWsfile = open("../.loginCheck", "r")
    users=[]
    hashed= {}

    for row in usersHashedPWsfile:
        (user,hashedPW)=(row.strip('\n')).split(',')
        hashed[user]= hashedPW
        users.append(user)

    if len(sys.argv)!=3: 
          print ('Usage: Login <user> <password>')
          return -1
          
    if sys.argv[1] not in users:
          print ('User not found')
          return -2   

    hash=hashlib.sha256()
    hash.update(bytes(sys.argv[1]+sys.argv[2],'utf-8'))  # for defenses against dictionary attack on the usersHashedPWs file
    for i in range(90000): hash.update(hash.digest())   # prepend name and iterate
    guess=hash.hexdigest()

    if (guess) == hashed[sys.argv[1]]:
        print ('Login successful.')
        return 1
    else:
        print('Login failed: incorrect password.')
        return 0

#===|[ Runtime ]|===#
if __name__ == "__main__":
    Login()
