import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import secrets
import string
import re
import bcrypt

from database import (
    create_table,
    add_password,
    get_all_passwords,
    search_password,
    search_password_by_id,
    delete_password,
    update_password
)

from auth import master_password_exists
from encryption import initialize_encryption, encrypt_password, decrypt_password


# =========================================================
# PASSWORD GENERATOR
# =========================================================

def generate_password(length=16):

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
# PASSWORD STRENGTH CHECKER
# =========================================================

def check_password_strength(password):

    score = 0
    warnings = []

    if len(password) >= 16:
        score += 2
    elif len(password) >= 12:
        score += 1
    else:
        warnings.append("Use at least 12 characters.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        warnings.append("Add an uppercase letter.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        warnings.append("Add a lowercase letter.")

    if re.search(r"\d", password):
        score += 1
    else:
        warnings.append("Add a number.")

    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
        score += 1
    else:
        warnings.append("Add a special character.")

    if re.search(r"(.)\1\1", password):
        score -= 1
        warnings.append("Avoid repeated characters.")

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

    if password.lower() in common_passwords:
        score = 0
        warnings.append("This is a commonly used password.")

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
# LOGIN WINDOW
# =========================================================

class LoginWindow:

    def __init__(self, root):

        self.root = root

        self.root.title("Smart Personal Password Manager")
        self.root.geometry("500x400")
        self.root.resizable(False, False)
        self.root.configure(bg="#f2f2f2")

        create_table()

        self.create_login_screen()


    # =====================================================
    # LOGIN SCREEN
    # =====================================================

    def create_login_screen(self):

        for widget in self.root.winfo_children():
            widget.destroy()

        title = tk.Label(
            self.root,
            text="🔐 Smart Password Manager",
            font=("Arial", 22, "bold"),
            bg="#f2f2f2"
        )

        title.pack(pady=40)

        subtitle = tk.Label(
            self.root,
            text="Secure Password Management System",
            font=("Arial", 11),
            bg="#f2f2f2"
        )

        subtitle.pack()

        label = tk.Label(
            self.root,
            text="Master Password",
            font=("Arial", 12),
            bg="#f2f2f2"
        )

        label.pack(pady=(35, 5))

        self.password_entry = tk.Entry(
            self.root,
            width=32,
            font=("Arial", 12),
            show="*"
        )

        self.password_entry.pack(ipady=8)

        login_button = tk.Button(
            self.root,
            text="LOGIN",
            font=("Arial", 12, "bold"),
            width=20,
            command=self.login_user
        )

        login_button.pack(pady=30)

        self.password_entry.bind(
            "<Return>",
            lambda event: self.login_user()
        )

        self.password_entry.focus()


    # =====================================================
    # LOGIN
    # =====================================================

    def login_user(self):

        password = self.password_entry.get()

        if not password:

            messagebox.showwarning(
                "Warning",
                "Please enter your master password."
            )

            return

        if not master_password_exists():

            messagebox.showerror(
                "Error",
                "Master password has not been created."
            )

            return

        try:

            with open("master.hash", "rb") as file:
                stored_hash = file.read()

            if bcrypt.checkpw(
                password.encode("utf-8"),
                stored_hash
            ):

                initialize_encryption(password)

                self.open_dashboard()

            else:

                messagebox.showerror(
                    "Login Failed",
                    "Incorrect master password."
                )

                self.password_entry.delete(
                    0,
                    tk.END
                )

        except Exception as error:

            messagebox.showerror(
                "Error",
                f"Something went wrong:\n{error}"
            )


    # =====================================================
    # DASHBOARD
    # =====================================================

    def open_dashboard(self):

        for widget in self.root.winfo_children():
            widget.destroy()

        self.root.geometry("650x600")

        title = tk.Label(
            self.root,
            text="🏠 Password Manager Dashboard",
            font=("Arial", 22, "bold"),
            bg="#f2f2f2"
        )

        title.pack(pady=25)

        subtitle = tk.Label(
            self.root,
            text="Manage your passwords securely",
            font=("Arial", 11),
            bg="#f2f2f2"
        )

        subtitle.pack(pady=(0, 20))

        button_frame = tk.Frame(
            self.root,
            bg="#f2f2f2"
        )

        button_frame.pack()

        buttons = [
            ("➕ Add Password", self.add_password_window),
            ("👁 View Passwords", self.view_passwords_window),
            ("🔍 Search Password", self.search_password_window),
            ("✏ Update Password", self.update_password_window),
            ("🗑 Delete Password", self.delete_password_window),
            ("🎲 Generate Password", self.generate_password_window),
            ("🛡 Password Strength", self.strength_window),
            ("🔓 Reveal Password", self.reveal_password_window),
            ("🚪 Logout", self.logout)
        ]

        for text, command in buttons:

            button = tk.Button(
                button_frame,
                text=text,
                width=28,
                font=("Arial", 11, "bold"),
                command=command
            )

            button.pack(pady=5)


    # =====================================================
    # ADD PASSWORD
    # =====================================================

    def add_password_window(self):

        window = tk.Toplevel(self.root)

        window.title("Add Password")
        window.geometry("450x500")
        window.resizable(False, False)

        tk.Label(
            window,
            text="➕ Add Password",
            font=("Arial", 20, "bold")
        ).pack(pady=20)

        tk.Label(window, text="Website").pack()
        website_entry = tk.Entry(window, width=40)
        website_entry.pack(pady=5)

        tk.Label(window, text="Username / Email").pack()
        username_entry = tk.Entry(window, width=40)
        username_entry.pack(pady=5)

        tk.Label(window, text="Password").pack()
        password_entry = tk.Entry(
            window,
            width=40,
            show="*"
        )
        password_entry.pack(pady=5)

        tk.Label(window, text="Category").pack()
        category_entry = tk.Entry(window, width=40)
        category_entry.pack(pady=5)

        tk.Label(window, text="Notes").pack()
        notes_entry = tk.Entry(window, width=40)
        notes_entry.pack(pady=5)

        def save():

            website = website_entry.get().strip()
            username = username_entry.get().strip()
            password = password_entry.get()
            category = category_entry.get().strip()
            notes = notes_entry.get().strip()

            if not website:
                messagebox.showwarning(
                    "Warning",
                    "Website cannot be empty."
                )
                return

            if not password:
                messagebox.showwarning(
                    "Warning",
                    "Password cannot be empty."
                )
                return

            if not category:
                category = "General"

            try:

                encrypted_password = encrypt_password(password)

                add_password(
                    website,
                    username,
                    encrypted_password,
                    category,
                    notes
                )

                messagebox.showinfo(
                    "Success",
                    "Password saved successfully!"
                )

                window.destroy()

            except Exception as error:

                messagebox.showerror(
                    "Error",
                    str(error)
                )

        tk.Button(
            window,
            text="SAVE PASSWORD",
            width=20,
            font=("Arial", 11, "bold"),
            command=save
        ).pack(pady=25)


    # =====================================================
    # VIEW PASSWORDS
    # =====================================================

    def view_passwords_window(self):

        self.show_records(
            get_all_passwords(),
            "All Saved Passwords"
        )


    # =====================================================
    # SEARCH PASSWORD
    # =====================================================

    def search_password_window(self):

        keyword = simpledialog.askstring(
            "Search Password",
            "Enter website or username:"
        )

        if not keyword:
            return

        results = search_password(keyword)

        self.show_records(
            results,
            "Search Results"
        )


    # =====================================================
    # SHOW RECORDS
    # =====================================================

    def show_records(self, records, title_text):

        window = tk.Toplevel(self.root)

        window.title(title_text)
        window.geometry("850x450")

        tk.Label(
            window,
            text=title_text,
            font=("Arial", 18, "bold")
        ).pack(pady=10)

        columns = (
            "ID",
            "Website",
            "Username",
            "Password",
            "Category",
            "Notes"
        )

        tree = ttk.Treeview(
            window,
            columns=columns,
            show="headings"
        )

        for column in columns:

            tree.heading(
                column,
                text=column
            )

            tree.column(
                column,
                width=120
            )

        tree.column("ID", width=50)

        # Search results may contain password IDs,
        # while View Passwords returns complete records.
        for row in records:

            if isinstance(row, int):
                row = search_password_by_id(row)

            if not row:
                continue

            tree.insert(
                "",
                tk.END,
                values=(
                    row[0],
                    row[1],
                    row[2],
                    "********",
                    row[4],
                    row[5]
                )
            )

        tree.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        if not records:
            tk.Label(
                window,
                text="No matching passwords found.",
                font=("Arial", 12)
            ).pack(pady=10)


    # =====================================================
    # UPDATE PASSWORD
    # =====================================================

    def update_password_window(self):

        password_id = simpledialog.askinteger(
            "Update Password",
            "Enter Password ID:"
        )

        if password_id is None:
            return

        record = search_password_by_id(password_id)

        if not record:

            messagebox.showerror(
                "Error",
                "Password ID not found."
            )

            return

        window = tk.Toplevel(self.root)

        window.title("Update Password")
        window.geometry("450x500")

        tk.Label(
            window,
            text="✏ Update Password",
            font=("Arial", 20, "bold")
        ).pack(pady=20)

        tk.Label(window, text="Website").pack()

        website_entry = tk.Entry(
            window,
            width=40
        )

        website_entry.insert(
            0,
            record[1]
        )

        website_entry.pack(pady=5)

        tk.Label(window, text="Username").pack()

        username_entry = tk.Entry(
            window,
            width=40
        )

        username_entry.insert(
            0,
            record[2]
        )

        username_entry.pack(pady=5)

        tk.Label(
            window,
            text="New Password (leave empty to keep current)"
        ).pack()

        password_entry = tk.Entry(
            window,
            width=40,
            show="*"
        )

        password_entry.pack(pady=5)

        tk.Label(window, text="Category").pack()

        category_entry = tk.Entry(
            window,
            width=40
        )

        category_entry.insert(
            0,
            record[4]
        )

        category_entry.pack(pady=5)

        tk.Label(window, text="Notes").pack()

        notes_entry = tk.Entry(
            window,
            width=40
        )

        notes_entry.insert(
            0,
            record[5]
        )

        notes_entry.pack(pady=5)

        def update():

            website = website_entry.get().strip()
            username = username_entry.get().strip()
            new_password = password_entry.get()
            category = category_entry.get().strip()
            notes = notes_entry.get().strip()

            if not website:

                messagebox.showwarning(
                    "Warning",
                    "Website cannot be empty."
                )

                return

            if new_password:

                encrypted_password = encrypt_password(
                    new_password
                )

            else:

                encrypted_password = record[3]

            try:

                update_password(
                    password_id,
                    website,
                    username,
                    encrypted_password,
                    category,
                    notes
                )

                messagebox.showinfo(
                    "Success",
                    "Password updated successfully!"
                )

                window.destroy()

            except Exception as error:

                messagebox.showerror(
                    "Error",
                    str(error)
                )

        tk.Button(
            window,
            text="UPDATE",
            width=20,
            font=("Arial", 11, "bold"),
            command=update
        ).pack(pady=25)


    # =====================================================
    # DELETE PASSWORD
    # =====================================================

    def delete_password_window(self):

        password_id = simpledialog.askinteger(
            "Delete Password",
            "Enter Password ID:"
        )

        if password_id is None:
            return

        record = search_password_by_id(password_id)

        if not record:

            messagebox.showerror(
                "Error",
                "Password ID not found."
            )

            return

        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Delete password for {record[1]}?"
        )

        if not confirm:
            return

        try:

            delete_password(password_id)

            messagebox.showinfo(
                "Success",
                "Password deleted successfully!"
            )

        except Exception as error:

            messagebox.showerror(
                "Error",
                str(error)
            )


    # =====================================================
    # REVEAL PASSWORD
    # =====================================================

    def reveal_password_window(self):

        password_id = simpledialog.askinteger(
            "Reveal Password",
            "Enter Password ID:"
        )

        if password_id is None:
            return

        record = search_password_by_id(password_id)

        if not record:

            messagebox.showerror(
                "Error",
                "Password ID not found."
            )

            return

        try:

            password = decrypt_password(record[3])

            messagebox.showinfo(
                "Password",
                f"Website: {record[1]}\n"
                f"Username: {record[2]}\n\n"
                f"Password: {password}"
            )

        except Exception as error:

            messagebox.showerror(
                "Error",
                f"Unable to decrypt password:\n{error}"
            )


    # =====================================================
    # PASSWORD GENERATOR
    # =====================================================

    def generate_password_window(self):

        window = tk.Toplevel(self.root)

        window.title("Password Generator")
        window.geometry("450x350")

        tk.Label(
            window,
            text="🎲 Secure Password Generator",
            font=("Arial", 18, "bold")
        ).pack(pady=25)

        tk.Label(
            window,
            text="Password Length"
        ).pack()

        length_entry = tk.Entry(
            window,
            width=10
        )

        length_entry.insert(
            0,
            "16"
        )

        length_entry.pack(pady=10)

        result_entry = tk.Entry(
            window,
            width=40,
            font=("Arial", 11)
        )

        result_entry.pack(pady=15)

        def generate():

            try:

                length = int(
                    length_entry.get()
                )

                if length < 8:

                    messagebox.showwarning(
                        "Warning",
                        "Minimum length is 8."
                    )

                    return

                password = generate_password(length)

                result_entry.delete(
                    0,
                    tk.END
                )

                result_entry.insert(
                    0,
                    password
                )

            except ValueError:

                messagebox.showwarning(
                    "Warning",
                    "Enter a valid number."
                )

        tk.Button(
            window,
            text="GENERATE",
            width=20,
            command=generate
        ).pack(pady=10)


    # =====================================================
    # STRENGTH CHECKER
    # =====================================================

    def strength_window(self):

        window = tk.Toplevel(self.root)

        window.title("Password Strength")
        window.geometry("450x350")

        tk.Label(
            window,
            text="🛡 Password Strength Checker",
            font=("Arial", 18, "bold")
        ).pack(pady=25)

        password_entry = tk.Entry(
            window,
            width=40,
            show="*"
        )

        password_entry.pack(pady=15)

        result_label = tk.Label(
            window,
            text="Strength: -",
            font=("Arial", 14, "bold")
        )

        result_label.pack(pady=15)

        suggestions_label = tk.Label(
            window,
            text="",
            justify="left",
            wraplength=380
        )

        suggestions_label.pack()

        def check():

            password = password_entry.get()

            if not password:

                messagebox.showwarning(
                    "Warning",
                    "Please enter a password."
                )

                return

            strength, warnings = check_password_strength(
                password
            )

            result_label.config(
                text=f"Strength: {strength}"
            )

            if warnings:

                suggestions_label.config(
                    text="Suggestions:\n\n" +
                    "\n".join(
                        "• " + warning
                        for warning in warnings
                    )
                )

            else:

                suggestions_label.config(
                    text="✓ No major weaknesses detected."
                )

        tk.Button(
            window,
            text="CHECK STRENGTH",
            width=20,
            command=check
        ).pack(pady=10)


    # =====================================================
    # LOGOUT
    # =====================================================

    def logout(self):

        confirm = messagebox.askyesno(
            "Logout",
            "Are you sure you want to logout?"
        )

        if confirm:

            self.root.geometry("500x400")

            self.create_login_screen()


# =========================================================
# START PROGRAM
# =========================================================

if __name__ == "__main__":

    root = tk.Tk()

    app = LoginWindow(root)

    root.mainloop()