import tkinter as tk
from tkinter import messagebox
import customtkinter
import sqlite3
import re

customtkinter.set_appearance_mode("Dark")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("green")  # Themes: "blue" (standard), "green", "dark-blue"

class LoginApp:
    API_KEY = "129124b09cdff6292a9970660cd37091"

    def __init__(self, root):
        self.root = root
        self.root.title("Weather App")
        self.root.geometry("800x400")

        self.center_window()

        self.create_database_connection()
        self.create_table()

        # create base info frame
        self.login_frame = customtkinter.CTkFrame(master=root, fg_color="transparent")
        self.login_frame.pack(pady=20)

        self.username_label = customtkinter.CTkLabel(self.login_frame, text="Username:", font=("Arial", 12))
        self.username_label.grid(row=0, column=0, sticky="w")
        self.username_entry = customtkinter.CTkEntry(self.login_frame, font=("Arial", 12))
        self.username_entry.grid(row=0, column=1, padx=10)

        self.password_label = customtkinter.CTkLabel(self.login_frame, text="Password:", font=("Arial", 12))
        self.password_label.grid(row=1, column=0, sticky="w")
        self.password_entry = customtkinter.CTkEntry(self.login_frame, show="*", font=("Arial", 12))
        self.password_entry.grid(row=1, column=1, padx=10)

        self.login_button = customtkinter.CTkButton(self.login_frame, text="Login", font=("Arial", 12), command=self.login)
        self.login_button.grid(row=2, columnspan=2, pady=10)

        # set up register frame
        self.register_frame = customtkinter.CTkFrame(master=root, fg_color="transparent")
        self.register_frame.pack()

        self.register_button = customtkinter.CTkButton(self.register_frame, text="Register", font=("Arial", 12), command=self.register)
        self.register_button.pack(pady=10)

        # create weather placeholder frame
        self.weather_frame = None

        self.preferred_zipcode = None
        self.current_username = None
        
    def create_database_connection(self):
        self.conn = sqlite3.connect('users.db')
        self.cursor = self.conn.cursor()

    def create_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS Users (
                UserId INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL UNIQUE,
                Password TEXT NOT NULL,
                PreferredZip TEXT,
                IsMember INTEGER DEFAULT 0
            )
        ''')
        self.conn.commit()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        self.cursor.execute("SELECT * FROM Users WHERE Username = ? AND Password = ?", (username, password))
        user = self.cursor.fetchone()

        if user:
            self.current_username = user[1]
            self.preferred_zipcode = user[3]
            self.show_weather_page()
            self.update_welcome_label()
        else:
            messagebox.showerror("Login Failed", "Incorrect username or password")

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username.strip() == "" or password.strip() == "":
            messagebox.showerror("Registration Failed", "Username or password cannot be empty")
            return

        try:
            self.cursor.execute("INSERT INTO Users (Username, Password) VALUES (?, ?)", (username, password))
            self.conn.commit()
            messagebox.showinfo("Registration Successful", "User registered successfully")
        except sqlite3.IntegrityError:
            messagebox.showerror("Registration Failed", "Username already exists")

    def show_weather_page(self):
        if self.weather_frame is None:
            self.weather_frame = customtkinter.CTkFrame(self.root)
            self.weather_label = customtkinter.CTkLabel(self.weather_frame, text="WEATHER", font=("Arial", 20))
            self.weather_label.pack(expand=True)

            self.welcome_label = customtkinter.CTkLabel(self.weather_frame, text="", font=("Arial", 12))
            self.welcome_label.pack()

            self.weather_button = customtkinter.CTkButton(self.weather_frame, text="Logout", font=("Arial", 12), command=self.logout)
            self.weather_button.pack(pady=10)

            self.account_settings_button = customtkinter.CTkButton(self.weather_frame, text="Account Settings", font=("Arial", 12), command=self.show_account_settings)
            self.account_settings_button.pack(pady=10)

        # hide login frame
        self.login_frame.pack_forget()
        self.register_frame.pack_forget()

        # show logged in weather frame
        self.weather_frame.pack(fill=tk.BOTH, expand=True)

    def center_window(self):
        """
        This function centers the gui on start
        """
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        x = (screen_width - self.root.winfo_reqwidth()) / 2
        y = (screen_height - self.root.winfo_reqheight()) / 2

        self.root.geometry("+%d+%d" % (x, y))    

    def logout(self):
        # hide logged in frame
        self.weather_frame.pack_forget()

        # show reg frame
        self.login_frame.pack()
        self.register_frame.pack()

    def show_account_settings(self):
        # hide weather frame
        self.weather_frame.pack_forget()

        # show account settings frame
        self.account_settings_frame = customtkinter.CTkFrame(master=self.root)
        self.account_settings_frame.pack(pady=20)

        label_title = customtkinter.CTkLabel(self.account_settings_frame, text="Account Settings", font=("Arial", 16))
        label_title.grid(row=0, columnspan=2, pady=10)

        label_username = customtkinter.CTkLabel(self.account_settings_frame, text="Username:")
        label_username.grid(row=1, column=0, sticky="w", padx=10)

        entry_username = customtkinter.CTkEntry(self.account_settings_frame, font=("Arial", 12))
        entry_username.grid(row=1, column=1, padx=10)

        if self.current_username:
            entry_username.insert(0, self.current_username)

        label_password = customtkinter.CTkLabel(self.account_settings_frame, text="New Password:")
        label_password.grid(row=2, column=0, sticky="w", padx=10)

        entry_password = customtkinter.CTkEntry(self.account_settings_frame, show="*", font=("Arial", 12))
        entry_password.grid(row=2, column=1, padx=10)

        label_confirm_password = customtkinter.CTkLabel(self.account_settings_frame, text="Confirm New Password:")
        label_confirm_password.grid(row=3, column=0, sticky="w", padx=10)

        entry_confirm_password = customtkinter.CTkEntry(self.account_settings_frame, show="*", font=("Arial", 12))
        entry_confirm_password.grid(row=3, column=1, padx=10)

        label_zipcode = customtkinter.CTkLabel(self.account_settings_frame, text="Preferred Zipcode:")
        label_zipcode.grid(row=4, column=0, sticky="w", padx=10)

        entry_zipcode = customtkinter.CTkEntry(self.account_settings_frame, font=("Arial", 12))
        entry_zipcode.grid(row=4, column=1, padx=10)

        if self.preferred_zipcode:
            entry_zipcode.insert(0, self.preferred_zipcode)

        btn_save_changes = customtkinter.CTkButton(self.account_settings_frame, text="Save Changes",
                                     command=lambda: self.save_account_changes(
                                         entry_username.get(),
                                         entry_password.get(),
                                         entry_confirm_password.get(),
                                         entry_zipcode.get()
                                     ))
        btn_save_changes.grid(row=5, columnspan=2, pady=10)

        btn_cancel = customtkinter.CTkButton(self.account_settings_frame, text="Cancel", command=self.cancel_account_settings)
        btn_cancel.grid(row=6, columnspan=2, pady=10)
        
    def is_valid_zipcode(zipcode):
        # 5 digits or 5 digits followed by a hyphen and 4 digits
        pattern = r'^\d{5}(?:-\d{4})?$'
        return bool(re.match(pattern, zipcode))
    
    def is_secure_password(password):
        if len(password) < 8:
            return False

        if not re.search(r'[A-Z]', password):
            return False

        if not re.search(r'[a-z]', password):
            return False

        if not re.search(r'\d', password):
            return False

        if not re.search(r'[!@#$%^&*()-_=+{};:,<.>?\'"\\|~`]', password):
            return False

        return True
    
    def save_account_changes(self, new_username, new_password, confirm_password, new_zipcode):

        if not is_valid_zipcode(new_zipcode):
            messagebox.showerror("Zip Code Error", "Invalid zip code.")
            return

        if new_password.strip() != "":
            if new_password == confirm_password:
                # make sure the password reaches secure reqs
                if not is_secure_password(new_password):
                    messagebox.showerror("Password Error", "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")
                    return
            else:
                messagebox.showerror("Password Error", "Passwords do not match")
                return

        update_data = {}
        if new_username.strip() != "":
            if new_username != self.current_username:
                update_data["Username"] = new_username
                self.current_username = new_username

        if new_zipcode.strip() != "":
            update_data["PreferredZip"] = new_zipcode
            self.preferred_zipcode = new_zipcode

        if update_data:
            update_query = "UPDATE Users SET " + ", ".join(f"{key} = ?" for key in update_data.keys()) + " WHERE Username = ?"
            update_values = tuple(update_data.values()) + (self.current_username,)

            self.cursor.execute(update_query, update_values)
            self.conn.commit()

        if new_password.strip() != "":
            self.cursor.execute("UPDATE Users SET Password = ? WHERE Username = ?", (new_password, self.current_username))
            self.conn.commit()

        self.update_welcome_label()
        messagebox.showinfo("Changes Saved", "Account settings updated successfully")




    def cancel_account_settings(self):
        # hide account settings frame
        self.account_settings_frame.pack_forget()

        # show weather frame
        self.weather_frame.pack(fill=tk.BOTH, expand=True)

    def update_welcome_label(self):
        welcome_message = f"Welcome, {self.current_username}!"
        if self.preferred_zipcode:
            welcome_message += f" (Preferred Zip Code: {self.preferred_zipcode})"
        self.welcome_label.configure(text=welcome_message)


if __name__ == "__main__":
    root = customtkinter.CTk() #CustomTkinter
    app = LoginApp(root)
    root.mainloop()
