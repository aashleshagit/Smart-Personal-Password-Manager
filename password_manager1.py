import secrets
import string
import getpass
import re

from database import (
    create_table,
    add_password,
    get_all_passwords,
    search_password,
    search_password_by_id,
    delete_password,
    update_password
)

from auth import (
    master_password_exists,
    create_master_password,
    login
)

from encryption import (
    initialize_encryption,
    encrypt_password,
    decrypt_password
)


# =========================================================
# SECURE PASSWORD GENERATOR
# =========================================================

def generate_password(length=16):

    if length < 4:
        length = 4

    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    symbols = "!@#$%^&*()_+-=[]{};:,.<>/?"

    password = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(symbols)
    ]

    all_characters = uppercase + lowercase + digits + symbols

    for _ in range(length - 4):
        password.append(secrets.choice(all_characters))

    secrets.SystemRandom().shuffle(password)

    return "".join(password)


# =========================================================
# ADVANCED PASSWORD STRENGTH CHECKER
# =========================================================

def check_password_strength(password):

    score = 0
    warnings = []

    # Length
    if len(password) >= 16:
        score += 2

    elif len(password) >= 12:
        score += 1

    else:
        warnings.append("Use at least 12 characters.")

    # Uppercase
    if re.search(r"[A-Z]", password):
        score += 1

    else:
        warnings.append("Add an uppercase letter.")

    # Lowercase
    if re.search(r"[a-z]", password):
        score += 1

    else:
        warnings.append("Add a lowercase letter.")

    # Number
    if re.search(r"\d", password):
        score += 1

    else:
        warnings.append("Add a number.")

    # Special character
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
        score += 1

    else:
        warnings.append("Add a special character.")

    # Repeated characters
    if re.search(r"(.)\1\1", password):
        score -= 1
        warnings.append("Avoid repeated characters.")

    # Sequential numbers
    sequential_numbers = [
        "123456",
        "234567",
        "345678",
        "456789",
        "987654",
        "876543",
        "765432",
        "654321"
    ]

    if any(sequence in password for sequence in sequential_numbers):
        score -= 1
        warnings.append("Avoid sequential numbers.")

    # Sequential letters
    sequential_letters = [
        "abcdef",
        "bcdefg",
        "cdefgh",
        "uvwxyz",
        "zyxwvu"
    ]

    password_lower = password.lower()

    if any(sequence in password_lower for sequence in sequential_letters):
        score -= 1
        warnings.append("Avoid sequential letters.")

    # Common passwords
    common_passwords = [
        "password",
        "password123",
        "12345678",
        "123456789",
        "qwerty",
        "admin",
        "welcome",
        "letmein",
        "iloveyou"
    ]

    if password_lower in common_passwords:
        score = 0
        warnings.append("This is a commonly used password.")

    # Strength
    if score <= 2:
        strength = "Weak"

    elif score <= 4:
        strength = "Medium"

    elif score <= 6:
        strength = "Strong"

    else:
        strength = "Very Strong"

    return strength, warnings


# =========================================================
# DISPLAY PASSWORDS - HIDDEN BY DEFAULT
# =========================================================

def display_passwords(passwords):

    if not passwords:
        print("\nNo passwords found.")
        return

    print("\n" + "=" * 80)
    print("SAVED PASSWORDS")
    print("=" * 80)

    for row in passwords:

        password_id = row[0]
        website = row[1]
        username = row[2]
        category = row[4]
        notes = row[5]
        created_at = row[6]
        updated_at = row[7]

        print("\nID:", password_id)
        print("Website:", website)
        print("Username:", username)

        # Password is hidden
        print("Password: ********")

        print("Category:", category)
        print("Notes:", notes)
        print("Created:", created_at)
        print("Updated:", updated_at)

        print("-" * 80)


# =========================================================
# REVEAL PASSWORD
# =========================================================

def reveal_password():

    print("\n" + "=" * 50)
    print("REVEAL PASSWORD")
    print("=" * 50)

    try:
        password_id = int(input("Enter Password ID: "))

    except ValueError:
        print("Please enter a valid numeric ID.")
        return

    record = search_password_by_id(password_id)

    if not record:
        print("\nPassword ID not found.")
        return

    encrypted_password = record[3]

    try:
        password = decrypt_password(encrypted_password)

    except Exception:
        print("\nUnable to decrypt password.")
        return

    print("\nWebsite:", record[1])
    print("Username:", record[2])
    print("Password:", password)


# =========================================================
# ADD PASSWORD
# =========================================================

def add_new_password():

    print("\n" + "=" * 50)
    print("ADD NEW PASSWORD")
    print("=" * 50)

    website = input("Website: ").strip()

    if not website:
        print("Website cannot be empty.")
        return

    username = input("Username/Email: ").strip()

    password = getpass.getpass("Password: ")

    if not password:
        print("Password cannot be empty.")
        return

    strength, warnings = check_password_strength(password)

    print("\nPassword Strength:", strength)

    if warnings:
        print("Suggestions:")

        for warning in warnings:
            print("-", warning)

    category = input("Category: ").strip()

    if not category:
        category = "General"

    notes = input("Notes: ").strip()

    encrypted_password = encrypt_password(password)

    add_password(
        website,
        username,
        encrypted_password,
        category,
        notes
    )

    print("\nPassword saved successfully!")


# =========================================================
# VIEW ALL PASSWORDS
# =========================================================

def view_passwords():

    passwords = get_all_passwords()

    display_passwords(passwords)


# =========================================================
# SEARCH PASSWORD
# =========================================================

def search_saved_password():

    print("\n" + "=" * 50)
    print("SEARCH PASSWORD")
    print("=" * 50)

    keyword = input("Enter website or username: ").strip()

    if not keyword:
        print("Search value cannot be empty.")
        return

    results = search_password(keyword)

    display_passwords(results)


# =========================================================
# UPDATE PASSWORD
# =========================================================

def update_saved_password():

    print("\n" + "=" * 50)
    print("UPDATE PASSWORD")
    print("=" * 50)

    try:
        password_id = int(input("Enter Password ID: "))

    except ValueError:
        print("Please enter a valid numeric ID.")
        return

    existing = search_password_by_id(password_id)

    if not existing:
        print("\nPassword ID not found.")
        return

    print("\nCurrent record:")
    display_passwords([existing])

    print("\nEnter new information.")
    print("Press Enter to keep the existing value.")

    current_website = existing[1]
    current_username = existing[2]
    current_encrypted_password = existing[3]
    current_category = existing[4]
    current_notes = existing[5]

    website = input(
        f"Website [{current_website}]: "
    ).strip()

    if not website:
        website = current_website

    username = input(
        f"Username [{current_username}]: "
    ).strip()

    if not username:
        username = current_username

    change_password = input(
        "Do you want to change the password? (y/n): "
    ).strip().lower()

    if change_password == "y":

        password = getpass.getpass("New Password: ")

        if not password:
            print("Password cannot be empty.")
            return

        strength, warnings = check_password_strength(password)

        print("\nPassword Strength:", strength)

        if warnings:
            print("Suggestions:")

            for warning in warnings:
                print("-", warning)

        encrypted_password = encrypt_password(password)

    else:
        encrypted_password = current_encrypted_password

    category = input(
        f"Category [{current_category}]: "
    ).strip()

    if not category:
        category = current_category

    notes = input(
        f"Notes [{current_notes}]: "
    ).strip()

    if not notes:
        notes = current_notes

    update_password(
        password_id,
        website,
        username,
        encrypted_password,
        category,
        notes
    )

    print("\nPassword updated successfully!")


# =========================================================
# DELETE PASSWORD
# =========================================================

def delete_saved_password():

    print("\n" + "=" * 50)
    print("DELETE PASSWORD")
    print("=" * 50)

    try:
        password_id = int(input("Enter Password ID: "))

    except ValueError:
        print("Please enter a valid numeric ID.")
        return

    existing = search_password_by_id(password_id)

    if not existing:
        print("\nPassword ID not found.")
        return

    print("\nRecord to delete:")

    display_passwords([existing])

    confirmation = input(
        "\nAre you sure you want to delete this password? (y/n): "
    ).strip().lower()

    if confirmation == "y":

        delete_password(password_id)

        print("\nPassword deleted successfully!")

    else:

        print("\nDelete operation cancelled.")


# =========================================================
# GENERATE PASSWORD
# =========================================================

def generate_new_password():

    print("\n" + "=" * 50)
    print("SECURE PASSWORD GENERATOR")
    print("=" * 50)

    try:
        length = int(
            input("Enter password length (minimum 8): ")
        )

    except ValueError:
        print("Please enter a valid number.")
        return

    if length < 8:
        print("Password length must be at least 8.")
        return

    password = generate_password(length)

    print("\nGenerated Password:")
    print(password)

    strength, warnings = check_password_strength(password)

    print("\nStrength:", strength)

    if warnings:

        print("Suggestions:")

        for warning in warnings:
            print("-", warning)


# =========================================================
# CHECK PASSWORD STRENGTH
# =========================================================

def check_existing_password_strength():

    print("\n" + "=" * 50)
    print("PASSWORD STRENGTH CHECKER")
    print("=" * 50)

    password = getpass.getpass("Enter password: ")

    if not password:
        print("Password cannot be empty.")
        return

    strength, warnings = check_password_strength(password)

    print("\nPassword Strength:", strength)

    if warnings:

        print("Suggestions:")

        for warning in warnings:
            print("-", warning)

    else:

        print("No major weaknesses detected.")


# =========================================================
# MAIN MENU
# =========================================================

def main():

    print("\n" + "=" * 60)
    print("       SMART PERSONAL PASSWORD MANAGER")
    print("=" * 60)

    # Create database table
    create_table()

    # =====================================================
    # MASTER PASSWORD SETUP
    # =====================================================

    if not master_password_exists():

        print("\nNo master password found.")
        print("Let's create your master password.")

        if not create_master_password():

            print("\nMaster password setup failed.")
            return

    # =====================================================
    # LOGIN
    # =====================================================

    print("\nPlease login to continue.")

    master_password = login()

    if not master_password:

        print("\nAccess denied.")
        return

    # =====================================================
    # INITIALIZE ENCRYPTION
    # =====================================================

    try:

        initialize_encryption(master_password)

    except Exception as error:

        print("\nEncryption initialization failed.")
        print("Error:", error)
        return

    print("\nEncryption initialized successfully.")

    # =====================================================
    # MAIN LOOP
    # =====================================================

    while True:

        print("\n")
        print("=" * 60)
        print("                    MAIN MENU")
        print("=" * 60)

        print("1. Add Password")
        print("2. View All Passwords")
        print("3. Search Password")
        print("4. Update Password")
        print("5. Delete Password")
        print("6. Generate Secure Password")
        print("7. Check Password Strength")
        print("8. Reveal Password")
        print("9. Exit")

        print("=" * 60)

        choice = input("Enter your choice: ").strip()

        # Add
        if choice == "1":

            add_new_password()

        # View
        elif choice == "2":

            view_passwords()

        # Search
        elif choice == "3":

            search_saved_password()

        # Update
        elif choice == "4":

            update_saved_password()

        # Delete
        elif choice == "5":

            delete_saved_password()

        # Generate
        elif choice == "6":

            generate_new_password()

        # Strength
        elif choice == "7":

            check_existing_password_strength()

        # Reveal
        elif choice == "8":

            reveal_password()

        # Exit
        elif choice == "9":

            print(
                "\nThank you for using "
                "Smart Personal Password Manager."
            )

            print("Goodbye!")

            break

        # Invalid
        else:

            print("\nInvalid choice.")
            print("Please select an option from 1 to 9.")


# =========================================================
# PROGRAM START
# =========================================================

if __name__ == "__main__":

    main()