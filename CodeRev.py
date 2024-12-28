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
