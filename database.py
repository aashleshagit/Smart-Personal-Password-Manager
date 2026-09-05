import sqlite3


DATABASE_NAME = "password_manager.db"


# Connect to database
def connect_database():

    connection = sqlite3.connect(DATABASE_NAME)

    return connection


# Create table
def create_table():

    connection = connect_database()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            website TEXT NOT NULL,

            username TEXT NOT NULL,

            password TEXT NOT NULL,

            category TEXT,

            notes TEXT,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

        )
    """)

    connection.commit()

    connection.close()


# Add password
def add_password(website, username, password, category, notes):

    connection = connect_database()

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO passwords
        (website, username, password, category, notes)

        VALUES (?, ?, ?, ?, ?)
    """, (
        website,
        username,
        password,
        category,
        notes
    ))

    connection.commit()

    connection.close()


# Get all passwords
def get_all_passwords():

    connection = connect_database()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM passwords
    """)

    records = cursor.fetchall()

    connection.close()

    return records


# Search password
def search_password(website):

    connection = connect_database()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM passwords
        WHERE website = ?
    """, (website,))

    record = cursor.fetchone()

    connection.close()

    return record

# Get password by ID
def search_password_by_id(password_id):

    connection = connect_database()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM passwords
        WHERE id = ?
    """, (password_id,))

    record = cursor.fetchone()

    connection.close()

    return record

# Delete password
def delete_password(password_id):

    connection = connect_database()

    cursor = connection.cursor()

    cursor.execute("""
        DELETE FROM passwords
        WHERE id = ?
    """, (password_id,))

    connection.commit()

    connection.close()
    
# --------------------------------
# GET PASSWORD BY ID
# --------------------------------

def search_password_by_id(password_id):

    connection = connect_database()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM passwords
        WHERE id = ?
    """, (password_id,))

    record = cursor.fetchone()

    connection.close()

    return record


# --------------------------------
# UPDATE PASSWORD
# --------------------------------

def update_password(
    password_id,
    website,
    username,
    password,
    category,
    notes
):

    connection = connect_database()

    cursor = connection.cursor()

    cursor.execute("""
        UPDATE passwords

        SET website = ?,
            username = ?,
            password = ?,
            category = ?,
            notes = ?,
            updated_at = CURRENT_TIMESTAMP

        WHERE id = ?
    """, (
        website,
        username,
        password,
        category,
        notes,
        password_id
    ))

    connection.commit()

    connection.close()


# --------------------------------
# DELETE PASSWORD
# --------------------------------

def delete_password(password_id):

    connection = connect_database()

    cursor = connection.cursor()

    cursor.execute("""
        DELETE FROM passwords
        WHERE id = ?
    """, (password_id,))

    connection.commit()

    connection.close()