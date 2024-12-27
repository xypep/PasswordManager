import os
import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
from cryptography.fernet import Fernet
import pyperclip
import random
import string

def load_or_create_key():
    base_path = os.path.dirname(os.path.abspath(__file__))
    key_path = os.path.join(base_path, "key.key")

    try:
        with open(key_path, "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open(key_path, "wb") as key_file:
            key_file.write(key)
        return key

key = load_or_create_key()
cipher_suite = Fernet(key)

def init_db():
    base_path = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(base_path, "passwords.db")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(''' 
    CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        platform TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    conn.commit()
    return conn, cursor

conn, cursor = init_db()

def generate_random_password():
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(12))
    return password

class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Login")

        tk.Label(root, text="Username").grid(row=0, column=0, padx=10, pady=10)
        tk.Label(root, text="Password").grid(row=1, column=0, padx=10, pady=10)

        self.username_entry = tk.Entry(root)
        self.username_entry.grid(row=0, column=1, padx=10, pady=10)

        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.grid(row=1, column=1, padx=10, pady=10)

        tk.Button(root, text="Login", command=self.login).grid(row=2, column=0, columnspan=2, pady=10)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username == "admin" and password == "1234":
            self.root.destroy()
            root = tk.Tk()
            PasswordManager(root, username)
        else:
            messagebox.showerror("wrong", "wrong username or password")

        if username == "guest" and password == "":
            self.root.destroy()
            root = tk.Tk()
            PasswordManager(root, username, guest_mode=True)


class PasswordManager:
    def __init__(self, root, username, guest_mode=False):
        self.root = root
        self.username = username
        self.guest_mode = guest_mode
        self.root.title(f"Password Manager - {username}")

        paned_window = tk.PanedWindow(root, orient="horizontal")
        paned_window.pack(fill=tk.BOTH, expand=True)

        left_frame = tk.Frame(paned_window, padx=10, pady=10)
        paned_window.add(left_frame)

        tk.Label(left_frame, text="Url").grid(row=0, column=0, padx=10, pady=5)
        tk.Label(left_frame, text="Username").grid(row=1, column=0, padx=10, pady=5)
        tk.Label(left_frame, text="Password").grid(row=2, column=0, padx=10, pady=5)

        self.platform_entry = tk.Entry(left_frame)
        self.platform_entry.grid(row=0, column=1, padx=10, pady=5)

        self.username_entry = tk.Entry(left_frame)
        self.username_entry.grid(row=1, column=1, padx=10, pady=5)

        self.password_entry = tk.Entry(left_frame, show="*")
        self.password_entry.grid(row=2, column=1, padx=10, pady=5)

        if not self.guest_mode:
            tk.Button(left_frame, text="Save", command=self.save_password).grid(row=3, column=0, columnspan=2, pady=5)
            tk.Button(left_frame, text="Delete", command=self.delete_password).grid(row=4, column=0, columnspan=2, pady=5)
            tk.Button(left_frame, text="Edit", command=self.edit_password).grid(row=5, column=0, columnspan=2, pady=5)

        tk.Button(left_frame, text="Copy", command=self.copy_password).grid(row=6, column=0, columnspan=2, pady=5)
        tk.Button(left_frame, text="Random Password", command=self.generate_password).grid(row=7, column=0, columnspan=2, pady=5)

        self.show_passwords_var = tk.BooleanVar(value=False)
        self.show_passwords_checkbutton = tk.Checkbutton(left_frame, text="Show Password", variable=self.show_passwords_var, command=self.toggle_password_visibility)
        self.show_passwords_checkbutton.grid(row=8, column=0, columnspan=2, pady=5)

        right_frame = tk.Frame(paned_window, padx=10, pady=10)
        paned_window.add(right_frame)

        search_label = tk.Label(right_frame, text="Url Search:")
        search_label.pack(padx=10, pady=10)

        self.search_entry = tk.Entry(right_frame)
        self.search_entry.pack(padx=10, pady=5)
        self.search_entry.bind("<KeyRelease>", self.search_passwords)

        self.tree = ttk.Treeview(right_frame, columns=("ID", "Url", "Username", "Password"), show="headings")
        self.tree.heading("ID", text="ID")
        self.tree.heading("Url", text="Url")
        self.tree.heading("Username", text="Username")
        self.tree.heading("Password", text="Password")
        self.tree.pack(fill=tk.BOTH, expand=True)

        self.load_passwords()

    def toggle_password_visibility(self):
        """Toggel between '*' and normal"""
        if self.show_passwords_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
        
        self.load_passwords()
    
    def load_passwords(self):
        """Load passwords"""
        for row in self.tree.get_children():
            self.tree.delete(row)

        cursor.execute("SELECT * FROM passwords")
        for row in cursor.fetchall():
            decrypted_password = cipher_suite.decrypt(row[3].encode()).decode()

            if not self.show_passwords_var.get():
                decrypted_password = "*" * len(decrypted_password)
            
            self.tree.insert("", "end", values=(row[0], row[1], row[2], decrypted_password))

    def save_password(self):
        platform = self.platform_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        if platform and username and password:
            encrypted_password = cipher_suite.encrypt(password.encode()).decode()
            cursor.execute("INSERT INTO passwords (platform, username, password) VALUES (?, ?, ?)",
                        (platform, username, encrypted_password))
            conn.commit()

            self.load_passwords()

            self.platform_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
        else:
            messagebox.showerror("Error", "all or 1 field is empty.")

    def delete_password(self):
        selected_item = self.tree.selection()
        if selected_item:
            item_id = self.tree.item(selected_item, "values")[0]

            cursor.execute("DELETE FROM passwords WHERE id = ?", (item_id,))
            conn.commit()

            self.rearrange_ids()

            self.load_passwords()
        else:
            messagebox.showerror("Error", "Please select an entry.")

    def rearrange_ids(self):

        cursor.execute(''' 
        CREATE TABLE IF NOT EXISTS temp_passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            platform TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
        ''')
        
        cursor.execute("INSERT INTO temp_passwords (platform, username, password) SELECT platform, username, password FROM passwords")
        conn.commit()

        cursor.execute("DROP TABLE passwords")
        
        cursor.execute("ALTER TABLE temp_passwords RENAME TO passwords")
        conn.commit()
            
    def edit_password(self):
        selected_item = self.tree.selection()
        if selected_item:
            item_id = self.tree.item(selected_item, "values")[0]
            current_platform = self.tree.item(selected_item, "values")[1]
            current_username = self.tree.item(selected_item, "values")[2]
            current_password = self.tree.item(selected_item, "values")[3]

            self.platform_entry.delete(0, tk.END)
            self.platform_entry.insert(0, current_platform)
            self.username_entry.delete(0, tk.END)
            self.username_entry.insert(0, current_username)
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, current_password)

            if not hasattr(self, "update_button"):
                self.update_button = tk.Button(self.root, text="Refresh", command=lambda: self.update_password(item_id))
                self.update_button.pack(pady=5)

        else:
            messagebox.showerror("Error", "Please select an entry.")

    def update_password(self, item_id):

        new_platform = self.platform_entry.get()
        new_username = self.username_entry.get()
        new_password = self.password_entry.get()
        selected_item = self.tree.selection()

        if new_platform and new_username and new_password:
            encrypted_password = cipher_suite.encrypt(new_password.encode()).decode()
            cursor.execute("UPDATE passwords SET platform = ?, username = ?, password = ? WHERE id = ?",
                           (new_platform, new_username, encrypted_password, item_id))
            conn.commit()
            self.load_passwords()

            self.platform_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            self.update_button.destroy()

        else:
            messagebox.showerror("Error", "All fields needs to be full.")


    
    def copy_password(self):
        selected_item = self.tree.selection()
        if selected_item:
            item_id = self.tree.item(selected_item, "values")[0]
            cursor.execute("SELECT password FROM passwords WHERE id = ?", (item_id,))
            password = cursor.fetchone()[0]

            decrypted_password = cipher_suite.decrypt(password.encode()).decode()

            pyperclip.copy(decrypted_password)
            messagebox.showinfo("Success", "Password has been copied to the clipboard.")
        else:
            messagebox.showerror("Error", "Please select an entry.")
        
    def generate_password(self):
        random_password = generate_random_password()
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, random_password)
    
    def search_passwords(self, event=None):
       
        search_term = self.search_entry.get().lower()

        for row in self.tree.get_children():
            self.tree.delete(row)

        cursor.execute("SELECT * FROM passwords")
        for row in cursor.fetchall():
            platform = row[1].lower()
            if search_term in platform:
                decrypted_password = cipher_suite.decrypt(row[3].encode()).decode()
                self.tree.insert("", "end", values=(row[0], row[1], row[2], "*****" if not self.show_passwords_var.get() else decrypted_password))

if __name__ == "__main__":
    root = tk.Tk()
    LoginWindow(root)
    root.mainloop()

    conn.close()
