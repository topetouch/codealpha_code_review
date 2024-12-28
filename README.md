# PYTHON CODE REVIEW (MANUAL CODE REVIEW)
A manual code review involves carefully examining the code line by line to identify potential security vulnerabilities and applying
fixes based on secure coding practices. Here's how to conduct a manual review of the given Python application and resolve the issues.
## DESCRIPTION
Using a Python application that processes user input, i would demonstrate how to identify and address security vulnerabilities. Here's a
code for a simple application that takes a username and password, hashes the password, and stores it in a file. Here is the code for the
application:

import hashlib
import os

def save_user_credentials(username, password):
    hashed_password = hashlib.md5(password.encode()).hexdigest()
    with open("users.txt", "a") as file:
        file.write(f"{username}:{hashed_password}\n")
    print("User credentials saved.")

def login(username, password):
    hashed_password = hashlib.md5(password.encode()).hexdigest()
    with open("users.txt", "r") as file:
        for line in file:
            stored_username, stored_password = line.strip().split(":")
            if username == stored_username and hashed_password == stored_password:
                print("Login successful.")
                return
    print("Invalid credentials.")

if __name__ == "__main__":
    choice = input("Enter 1 to register, 2 to login: ")
    username = input("Enter username: ")
    password = input("Enter password: ")
    
    if choice == "1":
        save_user_credentials(username, password)
    elif choice == "2":
        login(username, password)
    else:
        print("Invalid choice.")


## IDENTIFYING AND RESOLVING THE VULNERABILITIES ATTACHED TO THE ABOVE CODE.
- WEAK PASSWORD HASHING
  Issue: MD5 is outdated and insecure.

   "hashed_password = hashlib.md5(password.encode()).hexdigest()"
  Resolution: Replace MD5 with a strong password-hashing algorithm like bcrypt or argon2.

   "from bcrypt import hashpw, gensalt
   hashed_password = hashpw(password.encode(), gensalt())"

- NO PASSWORD SALT
  Issue: Lack of a salt makes passwords vulnerable to rainbow table attacks.
  Resolution: Bcrypt automatically adds a salt when generating a hash, so replacing MD5 with bcrypt resolves this.
  (This emphasises the need for using Bcrypt to secure passwords)
  
- PLAINTEXT FILE STORAGE
  Issue: Storing credentials in a plaintext file is insecure.

   "with open("users.txt", "a") as file:
    file.write(f"{username}:{hashed_password}\n")"

   Resolution: Use a database like SQLite to securely store hashed passwords with appropriate access controls.

  "import sqlite3

def save_user_to_db(username, hashed_password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""  CREATE TABLE IF NOT EXISTS users 
        (username TEXT PRIMARY KEY,
            password_hash BLOB)  """)
    cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    conn.close()"

 - NO INPUT VALIDATION
   Issue: User inputs can corrupt the file or database.
   Resolution: Validate username and password using regular expressions to ensure they meet security and format requirements.    

    "import re

def validate_input(username, password):
    if not re.match("^[a-zA-Z0-9_]{3,30}$", username):
        raise ValueError("Invalid username format. Only letters, numbers, and underscores allowed (3-30 characters).")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.") "
        
- INSUFFICIENT ERROR HANDLING
  Issue: The application does not handle file errors gracefully.
  Resolution: Add try-except blocks around file or database operations.

  def save_user(username, hashed_password):
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        print("Username already exists.")
    finally:
        conn.close()

- NO RATE LIMITING OR LOGGING
  Issue: Vulnerable to brute-force attacks.

  Resolution: Implement rate-limiting mechanisms and logging to monitor attempts.

  from time import time
from collections import defaultdict

login_attempts = defaultdict(list)

def rate_limit(username):
    current_time = time()
    login_attempts[username] = [t for t in login_attempts[username] if current_time - t < 60]  # Keep only last minute's attempts
    if len(login_attempts[username]) >= 5:
        raise Exception("Too many login attempts. Try again later.")
    login_attempts[username].append(current_time)

The manual code review revealed several critical vulnerabilities in the application, including weak password hashing, insecure data storage, lack of input validation, and insufficient protections against brute-force attacks. By systematically analyzing the code and applying secure coding practices, we addressed these issues and enhanced the application's security posture.



  
