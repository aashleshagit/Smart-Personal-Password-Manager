import bcrypt
import os
import getpass


MASTER_FILE = "master.hash"

MAX_LOGIN_ATTEMPTS = 3


# --------------------------------
# CHECK IF MASTER PASSWORD EXISTS
# --------------------------------

def master_password_exists():

    return os.path.exists(MASTER_FILE)


# --------------------------------
# CREATE MASTER PASSWORD
# --------------------------------

def create_master_password():

    print("\n========== CREATE MASTER PASSWORD ==========")

    while True:

        password = getpass.getpass(
            "Create master password: "
        )

        confirm_password = getpass.getpass(
            "Confirm master password: "
        )

        if password != confirm_password:

            print("\nPasswords do not match. Try again.\n")

            continue

        if len(password) < 8:

            print(
                "\nMaster password must contain at least 8 characters.\n"
            )

            continue

        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        )

        with open(MASTER_FILE, "wb") as file:

            file.write(hashed_password)

        print("\n✓ Master password created successfully!")

        return True


# --------------------------------
# LOGIN
# --------------------------------

def login():

    print("\n========== MASTER LOGIN ==========")

    # Read stored password hash
    try:

        with open(MASTER_FILE, "rb") as file:

            stored_hash = file.read()

    except FileNotFoundError:

        print("\n✗ Master password file not found.")

        return False

    # Maximum 3 attempts
    for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):

        password = getpass.getpass(
            "Enter master password: "
        )

        if bcrypt.checkpw(
            password.encode("utf-8"),
            stored_hash
        ):

            print("\n✓ Login successful!")

            return password

        remaining_attempts = MAX_LOGIN_ATTEMPTS - attempt

        if remaining_attempts > 0:

            print(
                f"\n✗ Incorrect master password!"
                f" Attempts remaining: {remaining_attempts}"
            )

        else:

            print("\n✗ Maximum login attempts exceeded.")
            print("🔒 Access denied.")

    return False