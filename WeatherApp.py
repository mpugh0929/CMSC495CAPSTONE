import hashlib
import time
import tkinter as tk
from tkinter import messagebox
import customtkinter
import sqlite3
import re
import requests
from uszipcode import SearchEngine

# setup custom tkinter 
customtkinter.set_appearance_mode("Dark")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("green")  # Themes: "blue" (standard), "green", "dark-blue"

class LoginApp:
    API_KEY = "129124b09cdff6292a9970660cd37091"
    # max login attempts
    MAX_LOGIN_ATTEMPTS = 5
    # max duration to be blocked
    BLOCK_DURATION = 30 * 60

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
        self.userid = 0
        self.failed_login_attempts = {}
        
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
        hashed_password = self.hash_password(password)

        # check if the user is blocked
        if username in self.failed_login_attempts and self.failed_login_attempts[username]["blocked"]:
            if time.time() - self.failed_login_attempts[username]["timestamp"] < self.BLOCK_DURATION:
                messagebox.showerror("Login Blocked", "You have exceeded the maximum number of login attempts. Please try again later.")
                return

        self.cursor.execute("SELECT * FROM Users WHERE Username = ?", (username,))
        user = self.cursor.fetchone()

        if user:
            stored_hashed_password = user[2]
            if stored_hashed_password == hashed_password:
                self.reset_failed_attempts(username)
                self.userid = user[0]
                self.current_username = user[1]
                self.preferred_zipcode = user[3]
                self.show_weather_page()
                self.update_welcome_label()
            else:
                self.handle_failed_login(username)
                attemptsRemaining = self.MAX_LOGIN_ATTEMPTS - self.failed_login_attempts[username]["attempts"];
                if not self.failed_login_attempts[username]["blocked"]:
                    messagebox.showerror("Login Failed", f"Incorrect username or password. You have {attemptsRemaining} {'attempt' if attemptsRemaining == 1 else 'attempts'} remaining.")
        else:
            messagebox.showerror("Login Failed", "User not found")

    def handle_failed_login(self, username):
        # increment failed login attempts for the user
        if username in self.failed_login_attempts:
            self.failed_login_attempts[username]["attempts"] += 1
        else:
            self.failed_login_attempts[username] = {"attempts": 1, "timestamp": time.time(), "blocked": False}

        if self.failed_login_attempts[username]["attempts"] >= self.MAX_LOGIN_ATTEMPTS:
            self.block_user(username)

    def block_user(self, username):
        # block the user from logging in for BLOCK_DURATION seconds
        self.failed_login_attempts[username]["timestamp"] = time.time()
        self.failed_login_attempts[username]["blocked"] = True
        messagebox.showerror("Login Blocked", "You have exceeded the maximum number of login attempts. Please try again later.")

    def reset_failed_attempts(self, username):
        # reset failed login attempts for the user upon successful login
        if username in self.failed_login_attempts:
            del self.failed_login_attempts[username]

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username.strip() == "" or password.strip() == "":
            messagebox.showerror("Registration Failed", "Username or password cannot be empty")
            return
        
        if not self.is_secure_password(password):
            messagebox.showerror("Registration Failed", "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")
            return
        try:
            hashed_password = self.hash_password(password)
            self.cursor.execute("INSERT INTO Users (Username, Password) VALUES (?, ?)", (username, hashed_password))
            self.conn.commit()
            messagebox.showinfo("Registration Successful", "User registered successfully")
            self.current_username = username
            self.cursor.execute("SELECT * FROM Users WHERE Username = ?", (username,))
            user = self.cursor.fetchone()
            self.userid = user[0]

            self.show_weather_page()
            self.update_welcome_label()
        except sqlite3.IntegrityError:
            messagebox.showerror("Registration Failed", "Username already exists")

    def show_weather_page(self):
        if self.weather_frame is None:
            self.weather_frame = customtkinter.CTkFrame(self.root)
            self.weather_frame.pack(fill=tk.BOTH, expand=True)
            self.weather_label = customtkinter.CTkLabel(self.weather_frame, text="WEATHER", font=("Arial", 20))
            self.weather_label.pack(expand=True)

            self.welcome_label = customtkinter.CTkLabel(self.weather_frame, text="", font=("Arial", 12))
            self.welcome_label.pack()

            self.weather_search_frame = customtkinter.CTkFrame(self.weather_frame)
            self.weather_search_frame.pack(pady=10)

            self.zipcode_label = customtkinter.CTkLabel(self.weather_search_frame, text="Enter Zip Code:", font=("Arial", 12))
            self.zipcode_label.grid(row=0, column=0, padx=5)

            self.zipcode_entry = customtkinter.CTkEntry(self.weather_search_frame, font=("Arial", 12))
            self.zipcode_entry.grid(row=0, column=1, padx=5)

            self.search_button = customtkinter.CTkButton(self.weather_search_frame, text="Search", font=("Arial", 12), command=self.search_weather)
            self.search_button.grid(row=0, column=2, padx=5)

            self.weather_info_frame = customtkinter.CTkFrame(self.weather_frame)
            self.weather_info_frame.pack(fill=tk.BOTH, expand=True)

            self.weather_details_label = customtkinter.CTkLabel(self.weather_info_frame, text="", font=("Arial", 12))
            self.weather_details_label.pack(pady=10)

            self.weather_trend_button = customtkinter.CTkButton(self.weather_info_frame, text="Trend & Forecast", font=("Arial", 12), command=self.show_trend_and_forecast)
            self.weather_trend_button.pack(pady=10)

            self.account_settings_button = customtkinter.CTkButton(self.weather_frame, text="Account Settings", font=("Arial", 12), command=self.show_account_settings)
            self.account_settings_button.pack(pady=10)

            self.logout_button = customtkinter.CTkButton(self.weather_info_frame, text="Logout", font=("Arial", 12), command=self.logout)
            self.logout_button.pack(pady=10)

        # hide login frame
        self.login_frame.pack_forget()
        self.register_frame.pack_forget()

    def search_weather(self):
        zipcode = self.zipcode_entry.get()
        if not self.is_valid_zipcode(zipcode):
            messagebox.showerror("Invalid Zip Code", "Please enter a valid 5-digit zip code.")
            return

        cityData = self.get_lat_long_from_zip(zipcode)
        if cityData is None:
            messagebox.showerror("Error", "Could not find city information for the provided zip code.")
            return
        
        lat = cityData[0]
        long = cityData[1]
        city = cityData[2]

        weather_data = self.get_weather_response(lat, long)
        if weather_data is None:
            messagebox.showerror("Error", "Could not retrieve weather information.")
            return

        # Display weather information

        description = weather_data['current']['weather'][0]['description']
        temperature = weather_data['current']['temp']
        feels_like = weather_data['current']['feels_like']
        humidity = weather_data['current']['humidity']
        wind_speed = weather_data['current']['wind_speed']
        wind_direction_degrees = weather_data['current']['wind_speed']
        wind_direction = self.degrees_to_cardinal(wind_direction_degrees)

        weather_info = f"City: {city}\n"
        weather_info += f"Weather: {description}\n"
        weather_info += f"Temperature: {temperature}°F\n"
        weather_info += f"Humidity: {humidity}%\n"
        weather_info += f"Wind Speed: {wind_speed} mph, Direction: {wind_direction}°\n"

        self.weather_label.configure(text=weather_info)

    def show_trend_and_forecast(self):
        zipcode = self.zipcode_entry.get()
        if not self.is_valid_zipcode(zipcode):
            messagebox.showerror("Invalid Zip Code", "Please enter a valid 5-digit zip code.")
            return

        # Implement trend and forecast functionality here

    def degrees_to_cardinal(self, degrees):
        directions = ["N", "NE", "E", "SE", "S", "SW", "W", "NW"]
        index = round(degrees / 45) % 8
        return directions[index]
    
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
        
    def is_valid_zipcode(self, zipcode):
        # 5 digits or 5 digits followed by a hyphen and 4 digits
        pattern = r'^\d{5}(?:-\d{4})?$'
        return bool(re.match(pattern, zipcode))
    
    def is_secure_password(self, password):
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
        update_data = {}

        if new_password.strip() != "":
            if new_password == confirm_password:
                # make sure the password reaches secure reqs
                if not self.is_secure_password(new_password):
                    messagebox.showerror("Password Error", "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")
                    return
                else:
                    self.cursor.execute("UPDATE Users SET Password = ? WHERE UserId = ?", (new_password, self.userid))
                    self.conn.commit()
            else:
                messagebox.showerror("Password Error", "Passwords do not match")
                return

        if new_username.strip() != "":
            if new_username != self.current_username:
                update_data["Username"] = new_username
                self.current_username = new_username

        if new_zipcode.strip() != "":
            if not self.is_valid_zipcode(new_zipcode):
                messagebox.showerror("Zip Code Error", "Invalid zip code.")
                return
            else:
                update_data["PreferredZip"] = new_zipcode
                self.preferred_zipcode = new_zipcode

        if update_data:
            update_query = "UPDATE Users SET " + ", ".join(f"{key} = ?" for key in update_data.keys()) + " WHERE UserId = ?"
            update_values = tuple(update_data.values()) + (self.userid,)

            self.cursor.execute(update_query, update_values)
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

    def hash_password(self, password):
        # hash the password using hashlib
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        return hashed_password
    
    def get_lat_long_from_zip(self, zip_code):
        """
        Get latitude and longitude from a given zip code using the uszipcode library.
        
        Args:
        - zip_code (str): The zip code for which latitude and longitude are needed.
        
        Returns:
        - tuple: A tuple containing latitude and longitude (lat, lng).
        """
        search = SearchEngine()
        result = search.by_zipcode(zip_code)
        if result:
            return [result.lat, result.lng, result.city]
        else:
            messagebox.showerror("Search Error", f"Unable to retrieve data for the given zip code. Please try a different zip code.")

    def get_weather_response(self, lat, long):
        endpointURL = f"https://api.openweathermap.org/data/3.0/onecall?lat={lat}&lon={long}&appid={self.API_KEY}&units=imperial"
        
        response = requests.get(endpointURL)
        
        if response.status_code == 200:
            return response.json()
        
        messagebox.showerror("Search Error", f"Failed to retrieve data. Status code: {response.status_code}")

if __name__ == "__main__":
    root = customtkinter.CTk() #CustomTkinter
    app = LoginApp(root)
    root.mainloop()
