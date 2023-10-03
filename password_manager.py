import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import sqlite3
import bcrypt
import sys



# Function to derive a key from a master password
def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,  # You can adjust the number of iterations as needed for security
        salt=salt,
        length=32,  # Length of the derived key in bytes
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

# Function to encrypt a password using Fernet
def encrypt_password(master_password, plaintext_password):
    salt = os.urandom(16)  # Generate a random salt
    key = derive_key(master_password, salt)
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(plaintext_password.encode())
    return salt, encrypted_password

# Function to decrypt a password using Fernet
def decrypt_password(master_password, salt, encrypted_password):
    key = derive_key(master_password, salt)
    cipher_suite = Fernet(key)
    plaintext_password = cipher_suite.decrypt(encrypted_password).decode()
    return plaintext_password

def save_passwords(master_password):
    website = input("Enter website name: ")
    username = input("Enter username: ")
    password = input("Enter password: ")
    salt, encrypted_password = encrypt_password(master_password, password)
    cursor.execute('INSERT INTO passwords (website, username, password, salt) VALUES (?,?,?,?)', (website, username, encrypted_password, salt))
    conn.commit()
    print(f"{username} password for {website} is saved !!!")

def retrive_passwords(master_password):
    website = input("Enter website name: ")
    username = input("Enter username: ")
    cursor.execute("SELECT password from passwords WHERE website=(?) AND username=(?)", (website, username))
    encrypted_password = cursor.fetchone()[0]
    # print(cursor.fetchone())
    cursor.execute("SELECT salt from passwords WHERE website=(?) AND username=(?)", (website, username))
    salt = cursor.fetchone()[0]
    # print(cursor.fetchone())
    decrypted_password = decrypt_password(master_password, salt, encrypted_password)
    print(f"Your password is : {decrypted_password}")

def password_encrypt(new_password):
    # Generate a salt and hash the password using bcrypt
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), salt)
    return hashed_password

def creating_master_password():
    new_password = input("Enter a new master password: ")
    new_password = password_encrypt(new_password=new_password)
    cursor.execute("INSERT INTO users (password) VALUES (?)",(new_password,))
    conn.commit()

def checking_master_password():
    master_password = input("Enter your master password: ")
    cursor.execute("SELECT password from users LIMIT 1")
    database_password = cursor.fetchone()[0]
    if bcrypt.checkpw(master_password.encode('utf-8'), database_password):
        choice = int(input('[1] Do you want to save the password\n[2] Do you want to retrive the password\nChoice: '))

        if choice == 1:
            save_passwords(master_password)
        elif choice == 2:
            retrive_passwords(master_password)
        else:
            print("Invaild Choice")
    else:
        print("Access Denied")
        sys.exit()

conn = sqlite3.connect('testing_database.db')
cursor = conn.cursor()

cursor.execute("CREATE TABLE IF NOT EXISTS users (id number PRIMARY KEY, password text)")
conn.commit()

cursor.execute("CREATE TABLE IF NOT EXISTS passwords (id number PRIMARY KEY, website text, username text , password text, salt text)")
conn.commit()


cursor.execute("SELECT COUNT(*) FROM users")
master_password = cursor.fetchone()[0]

if master_password:
    checking_master_password()
else:
    creating_master_password()

conn.close()
