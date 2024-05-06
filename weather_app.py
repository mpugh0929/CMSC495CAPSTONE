"""
This file contains all the code for the Weather App Project
"""
import sqlite3
import re
import hashlib
import time
import tkinter as tk
from datetime import date
from tkinter import messagebox
import customtkinter
from CTkToolTip import *
import requests
from uszipcode import SearchEngine
import tkintermapview
from datetime import date,datetime
from tkinter import *

# setup custom tkinter
customtkinter.set_appearance_mode("Dark")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("green")  # Themes: "blue" (standard), "green", "dark-blue"

class WeatherApp:
    """
    Instance of the Weather App
    """
    # API key for the weather API
    API_KEY = "129124b09cdff6292a9970660cd37091"
    # max login attempts
    MAX_LOGIN_ATTEMPTS = 5
    # max duration to be blocked
    BLOCK_DURATION = 30 * 60

    def __init__(self, app_root):
        """
        This function initalizes the app
        """
        # start up app
        self.root = app_root
        self.root.title("Weather App")
        self.root.geometry("525x300")
        self._center_window()
        self.root.iconbitmap('weather-icon.ico')
        # begin DB connection
        self._create_database_connection()
        self._create_table()
        self.show_login_page()

        # init weather frame
        self.weather_frame = None
        self.map_widget = None


        # init properties - make PyLint happy
        self.preferred_zipcode = None
        self.current_username = None
        self.userid = 0
        self.failed_login_attempts = {}
        self.weather_info_frame = None
        self.top_nav_frame = None
        self.weather_search_frame = None
        self.weather_details_label = None
        self.welcome_label = None
        self.search_button = None
        self.weather_trend_button = None
        self.map_frame = None
        self.account_settings_frame = None
        self.account_settings_button = None
        self.weather_label = None
        self.weather_temperature = None
        self.zipcode_entry = None
        self.zipcode_label = None

    def show_login_page(self):
        """
        This function creates the login frame
        """
        
        self.login_frame = customtkinter.CTkFrame(self.root,fg_color='black')
        self.login_frame.pack(fill=tk.BOTH,
                               expand=True)

        
        # custom tkinter doesnt support padding top, so this will help to give breathing room
        spacer = customtkinter.CTkLabel(self.login_frame,
                                         text="",
                                         height=30)
        spacer.pack()

        title_label = customtkinter.CTkLabel(self.login_frame,
                                              text="Welcome to the Weather App!",
                                              font=("Arial", 20))
        title_label.pack(pady=10)

        subheading_label = customtkinter.CTkLabel(self.login_frame,
                                                   text="Log In or Register to Get Started!",
                                                   font=("Arial", 12))
        subheading_label.pack()

        entry_frame = customtkinter.CTkFrame(self.login_frame,
                                              fg_color="transparent")
        entry_frame.pack(pady=10)

        username_label = customtkinter.CTkLabel(entry_frame,
                                                 text="Username:",
                                                 font=("Arial", 12))

        username_label.grid(row=0, column=0, padx=5, pady=5)

        self.username_entry = customtkinter.CTkEntry(entry_frame,
                                                      font=("Arial", 12))
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        password_label = customtkinter.CTkLabel(entry_frame,
                                                 text="Password:",
                                                 font=("Arial", 12))
        password_label.grid(row=1, column=0, padx=5, pady=5)

        self.password_entry = customtkinter.CTkEntry(entry_frame,
                                                     show="*",
                                                     font=("Arial", 12))

        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        button_frame = customtkinter.CTkFrame(self.login_frame,
                                              fg_color="transparent")
        button_frame.pack(pady=10)

        login_button = customtkinter.CTkButton(button_frame,
                                                text="Log In",
                                                font=("Arial", 12),
                                                command=self._login)
        login_button.grid(row=0, column=0, padx=5)
        login_tip = CTkToolTip(login_button,
                               delay=0.5,
                               message="For Returning Users")

        register_button = customtkinter.CTkButton(button_frame,
                                                   text="Register",
                                                    font=("Arial", 12),
                                                     command=self._register)
        register_button.grid(row=0, column=1, padx=5)
        password_tip = CTkToolTip(register_button,
                                  delay=0.5,
                                  message="For new Users")

    def _create_database_connection(self):
        """
        This function connects to SQLite db
        """
        self.conn = sqlite3.connect('users.db')
        self.cursor = self.conn.cursor()

    def _create_table(self):
        """
        This function creates the Users table upon app start if it does not exist
        """
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS Users (
                UserId INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL UNIQUE,
                Password TEXT NOT NULL,
                PreferredZip TEXT
            )
        ''')
        self.conn.commit()

    def _login(self):
        """
        This function is the login authentication method
        """
        # sanitize user input
        username = self._sanitize_input(self.username_entry.get())
        password = self._sanitize_input(self.password_entry.get())

        # hash the password
        hashed_password = self._hash_password(password)

        # check if the user is blocked
        if username in self.failed_login_attempts and self.failed_login_attempts[username]["blocked"]:
            # if theyre blocked, check the timestamp on their user vs the timeout
            if time.time()-self.failed_login_attempts[username]["timestamp"] < self.BLOCK_DURATION:
                messagebox.showerror("Login Blocked",
                                      "You have exceeded the maximum number of login attempts. Please try again later.")
                return

        # query for the user
        self.cursor.execute("SELECT * FROM Users WHERE Username = ?", (username,))
        user = self.cursor.fetchone()

        # if the user exists, then compare the hashed password vs the one in the db
        if user:
            stored_hashed_password = user[2]
            if stored_hashed_password == hashed_password:
                self._reset_failed_attempts(username)
                self.userid = user[0]
                # set session variables, boot up the weather page
                self.current_username = user[1]
                self.preferred_zipcode = user[3]
              #  self.password_entry.set("")
                self.login_frame.pack_forget()
                self.show_weather_page()
                self._update_welcome_label()
            else:
                # handle an unsuccessful login, toll attempts
                self._handle_failed_login(username)
                attempts_remaining = self.MAX_LOGIN_ATTEMPTS - self.failed_login_attempts[username]["attempts"]
                if not self.failed_login_attempts[username]["blocked"]:
                    messagebox.showerror("Login Failed",
                                          f"Incorrect username or password. You have {attempts_remaining} {'attempt' if attempts_remaining == 1 else 'attempts'} remaining.")
        else:
            messagebox.showerror("Login Failed", "User not found")

    def _handle_failed_login(self, username):
        """
        This function handles an unsuccessful login 
        by tolling the attempts for the user and blocking them if necessary

        Args:
            username (string): the username attempted
        """
        # increment failed login attempts for the user
        if username in self.failed_login_attempts:
            self.failed_login_attempts[username]["attempts"] += 1
        else:
            self.failed_login_attempts[username] = {"attempts": 1,
                                                     "timestamp": time.time(),
                                                     "blocked": False }

        if self.failed_login_attempts[username]["attempts"] >= self.MAX_LOGIN_ATTEMPTS:
            self._block_user(username)

    def _block_user(self, username):
        """Blocks the user from logging in for BLOCK_DURATION seconds

        Args:
            username (string): the username blocked
        """
        self.failed_login_attempts[username]["timestamp"] = time.time()
        self.failed_login_attempts[username]["blocked"] = True
        messagebox.showerror("Login Blocked",
                              "Maximum log in attempts exceeded. Please try again later.")

    def _reset_failed_attempts(self, username):
        """
        This function resets the failed attempts for the user upon successful login

        Args:
            username (string): the username that needs their attempts reset
        """
        # reset failed login attempts for the user upon successful login
        if username in self.failed_login_attempts:
            del self.failed_login_attempts[username]

    def _register(self):
        """
        This function is for registration 
        """
        username = self.username_entry.get()
        password = self.password_entry.get()

        # make sure fields are not empty
        if username.strip() == "" or password.strip() == "":
            messagebox.showerror("Registration Failed", "Username or password cannot be empty")
            return

        # ensure the password is secure
        if not self._is_secure_password(password):
            messagebox.showerror("Registration Failed",
                                 "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")
            return
        try:
            # hash the password and store it in the DB
            hashed_password = self._hash_password(password)
            self.cursor.execute("INSERT INTO Users (Username, Password) VALUES (?, ?)",
                                 (username, hashed_password))

            self.conn.commit()
            messagebox.showinfo("Registration Successful", "User registered successfully")
            self.current_username = username
            self.cursor.execute("SELECT * FROM Users WHERE Username = ?", (username,))
            user = self.cursor.fetchone()
            self.userid = user[0]

            # show authenticated view
            self.login_frame.pack_forget()
            self.show_weather_page()
            self._update_welcome_label()
        except sqlite3.IntegrityError:
            messagebox.showerror("Registration Failed", "Username already exists")
    def show_weather_page(self):
        """
        This function loads the tkinter logic for the weather page
        """
        
        
        #resizes window for new frame 
        root.geometry('525x400')
        
        # top nav
        self.top_nav_frame = customtkinter.CTkFrame(self.root, fg_color="transparent")
        self.top_nav_frame.pack(fill=tk.X, pady=10)

        self.account_settings_button = customtkinter.CTkButton(self.top_nav_frame,
                                                                text="Account Settings",
                                                                font=("Arial", 12),
                                                                fg_color="grey",
                                                                command=self.show_account_settings)

        self.account_settings_button.pack(side=tk.RIGHT, padx=10)
        settings_tip_msg = "Click here to change information about your account or log out"
        settings_tip = CTkToolTip(self.account_settings_button, delay=0.5, message=settings_tip_msg)

        self.weather_frame = customtkinter.CTkFrame(self.root,fg_color="transparent")
        self.weather_frame.pack(fill=tk.BOTH, expand=True)
        self.weather_temperature = customtkinter.CTkLabel(self.weather_frame,
                                                     text="",
                                                     font=("Arial", 40),
                                                     pady = 10)
        self.weather_label = customtkinter.CTkLabel(self.weather_frame,
                                                     text="Start Your Search Below!",
                                                     font=("Arial", 20),
                                                     pady = 10)

        self.weather_temperature.pack(expand=True)
        self.weather_label.pack(expand=True)

        # search frame
        self.weather_search_frame = customtkinter.CTkFrame(self.weather_frame,
                                                            fg_color="transparent")
        self.weather_search_frame.pack(pady=5)
        self.zipcode_label = customtkinter.CTkLabel(self.weather_search_frame,
                                                    text="Zip Code:",
                                                    font=("Arial", 12))

        self.zipcode_label.grid(row=0, column=0, padx=5)

        self.zipcode_entry = customtkinter.CTkEntry(self.weather_search_frame,
                                                    font=("Arial", 12))
        self.zipcode_entry.grid(row=0, column=1, padx=5)

        self.search_button = customtkinter.CTkButton(self.weather_search_frame,
                                                     text="Current Weather",
                                                     font=("Arial", 12),
                                                     command=self._search_weather)
        self.search_button.grid(row=0, column=2, padx=5)
        search_tip = CTkToolTip(self.search_button,
                                delay=0.5,
                                message="Click here for up-to-date weather statistics")

        self.weather_trend_button = customtkinter.CTkButton(self.weather_search_frame,
                                                            text="Trend & Forecast",
                                                            font=("Arial", 12),
                                                            command=self.show_trend_and_forecast)
        self.weather_trend_button.grid(row=0, column=3, padx=5)
        trend_tip = CTkToolTip(self.weather_trend_button,
                                delay=0.5,
                                message="Click here for calculated weather predictions")

        # welcome label and results related info
        self.welcome_label = customtkinter.CTkLabel(self.weather_frame,
                                                    text="",
                                                    font=("Arial", 12))
        self.welcome_label.pack()

        self.weather_info_frame = customtkinter.CTkFrame(self.weather_frame,
                                                         fg_color="transparent")
        self.weather_info_frame.pack(fill=tk.BOTH, expand=True)

        self.weather_details_label = customtkinter.CTkLabel(self.weather_info_frame,
                                                            text="",
                                                            font=("Arial", 12))
        self.weather_details_label.pack(side=tk.LEFT,
                                        pady=10)

        self.map_frame = customtkinter.CTkFrame(self.weather_info_frame)
        self.map_frame.pack(side=tk.TOP, pady=10)

        # if we have a zip, run a search
        if self.preferred_zipcode:
            self._search_weather(True)
            self.zipcode_entry.insert(0, self.preferred_zipcode)
        else:
            default_results = self._get_lat_long_from_zip(10001) # default search
            self.zipcode_entry.insert(0, 10001)
            self.show_map(default_results['lat'], default_results['long'], "Start your search!")

        # hide login frame
        self.login_frame.pack_forget()

    def _search_weather(self, use_preferred_zip = False):
        """
        This function searches for weather results in a certain location and displays it

        Args:
            use_preferred_zip (bool, optional): Use preferred zip for the search? Defaults to False.
        """
        zipcode = self.zipcode_entry.get()
        if use_preferred_zip:
            zipcode = self.preferred_zipcode
        location_info = self._get_city_data_from_zip(zipcode)

        # query the API
        weather_data_response = self._get_weather_response(location_info["lat"], location_info["long"])
        if weather_data_response is None:
            messagebox.showerror("Error", "Could not retrieve weather information.")
            return
        weather_data_response = self._get_weather_response(location_info["lat"], location_info["long"])
        if weather_data_response is None:
            messagebox.showerror("Error", "Could not retrieve weather information.")
            return

        # display results from the API
        description = weather_data_response['current']['weather'][0]['description']
        temperature = weather_data_response['current']['temp']
        humidity = weather_data_response['current']['humidity']
        wind_speed = weather_data_response['current']['wind_speed']
        wind_direction_degrees = weather_data_response['current']['wind_deg']
        wind_direction = self._degrees_to_cardinal(wind_direction_degrees)

        # create weather label text
        weather_info = f"{location_info['city']}\n"
        weather_info += str(date.today().strftime("%d %b, %Y")) + "\n"
        weather_info += str(datetime.now().strftime("%H:%M")) + "\n\n"
        weather_info += f"Description: {description} | "
        weather_info += f"Humidity: {humidity}%\n"
        weather_info += f"Wind: {wind_speed} mph {wind_direction}\n"

        self.weather_temperature.configure(text = f"{str(temperature)}°F")
        self.weather_label.configure(text=weather_info)
        self.show_map(location_info["lat"], location_info["long"], description)
        self.weather_frame.update_idletasks()

        #expands window to fit in the map and data
        root.geometry('525x550')


    def show_map(self, lat, long, description):
        """This function shows the map of the queried location

        Args:
            lat (float): latitude of the queried location
            long (float): longitude of the queried location
            description (string): text to display on the map
        """

        if self.map_widget is None:
            self.map_widget = tkintermapview.TkinterMapView(self.map_frame,
                                                            width=200,
                                                            height=175,
                                                            corner_radius=5)
            self.map_widget.pack(fill=tk.BOTH, expand=True)

        self.map_widget.set_position(lat, long)
        self.map_widget.set_zoom(12)
        self.map_widget.set_marker(lat, long, text=f"{description}")
        self.map_frame.update_idletasks()


    def show_trend_and_forecast(self):
        """
        This function loads the forecast into the weather label
        """
        location_info = self._get_city_data_from_zip(self.zipcode_entry.get())

        # query the API
        weather_data_response = self._get_weather_response(location_info["lat"],
                                                            location_info["long"])
        if weather_data_response is None:
            messagebox.showerror("Error", "Could not retrieve weather information.")
            return
        weather_data_response = self._get_weather_response(location_info["lat"],
                                                            location_info["long"])

        # display results from the API
        # Implement trend and forecast functionality here
        one_day_avg, five_day_avg = self._trend_calculations(weather_data_response)

        # create weather label text
        weather_info = f"{location_info['city']}\n"
        weather_info += f"One Day Prediction: {one_day_avg}°F\n"
        weather_info += f"Five Day Average: {five_day_avg}°F\n"
        description = weather_data_response['current']['weather'][0]['description']

        self.weather_label.configure(text=weather_info)
        self.show_map(location_info["lat"], location_info["long"], description)
        self.weather_frame.update_idletasks()

    def _trend_calculations(self, weather_data_response):
        """
        Calculates the 1-day prediction using a 24-hour average
        and a 5-day prediction using a 5-day average

        Args:
            weeather_data_response (dictionary): JSON API response

        Returns:
            tuple (float, float): one day average, 5 day average
        """
        # 1 day avg
        hourly_temperatures = [hour["temp"] for hour in weather_data_response["hourly"][:24]]
        one_day_average = round(sum(hourly_temperatures) / len(hourly_temperatures), 2)

        # 5 day avg
        daily_temperatures = [day["temp"]["day"] for day in weather_data_response["daily"][:5]]
        five_day_average = round(sum(daily_temperatures) / len(daily_temperatures), 2)

        return one_day_average, five_day_average

    def _degrees_to_cardinal(self, degrees):
        """
        This function changes degrees to cardinal direction

        Args:
            degrees (int): degrees of direction, ex. 170

        Returns:
            string: cardinal direction matched to the degree value
        """
        directions = ["N", "NE", "E", "SE", "S", "SW", "W", "NW"]
        index = round(degrees / 45) % 8
        return directions[index]

    def _get_city_data_from_zip(self, zipcode):
        """
        Helper method to validate the response from the API integration

        Returns:
            dictionary: city information
        """
        # make sure the zip is valid and found
        if not self._is_valid_zipcode(zipcode):
            messagebox.showerror("Invalid Zip Code", "Please enter a valid 5-digit zip code.")
            return

        city_data = self._get_lat_long_from_zip(zipcode)
        if city_data is None or city_data["lat"] is None:
            messagebox.showerror("Error",
                                "Could not find city information for the provided zip code.")
            return

        return city_data

    def _center_window(self):
        """
        This function centers the gui on start
        """
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        # find the center of each
        x = (screen_width - self.root.winfo_reqwidth()) / 2
        y = (screen_height - self.root.winfo_reqheight()) / 2

        self.root.geometry(f"+{int(x)}+{int(y)}")

    def _logout(self):
        """
        This function logs the user out
        """
        # hide logged in frame
        self.account_settings_frame.pack_forget()

        # reset session variables
        self.preferred_zipcode = None
        self.current_username = None
        self.userid = 0

        # show reg frame
        self.login_frame.pack(fill=tk.BOTH, expand=True)

    def show_account_settings(self):
        """
        This function shows the tkinter for the account settings form
        """
        # hide weather frame
        self.weather_frame.pack_forget()
        self.top_nav_frame.pack_forget()
        # show account settings frame
        self.account_settings_frame = customtkinter.CTkFrame(master=self.root,
                                                             fg_color="transparent")
        self.account_settings_frame.pack(fill=tk.BOTH, expand=True)

        label_title = customtkinter.CTkLabel(self.account_settings_frame,
                                             text="Account Settings",
                                             font=("Arial", 16))
        label_title.pack(pady=10)

        entry_frame = customtkinter.CTkFrame(self.account_settings_frame, fg_color="transparent")
        entry_frame.pack(pady=10)

        label_username = customtkinter.CTkLabel(entry_frame, text="Username:")
        label_username.grid(row=0, column=0, sticky="w", padx=10, pady=5)

        entry_username = customtkinter.CTkEntry(entry_frame, font=("Arial", 12))
        entry_username.grid(row=0, column=1, padx=10, pady=5)

        # prefill information
        if self.current_username:
            entry_username.insert(0, self.current_username)

        label_password = customtkinter.CTkLabel(entry_frame, text="New Password:")
        label_password.grid(row=1, column=0, sticky="w", padx=10, pady=5)

        entry_password = customtkinter.CTkEntry(entry_frame, show="*", font=("Arial", 12))
        entry_password.grid(row=1, column=1, padx=10, pady=5)

        label_confirm_password = customtkinter.CTkLabel(entry_frame, text="Confirm New Password:")
        label_confirm_password.grid(row=2, column=0, sticky="w", padx=10, pady=5)

        entry_confirm_password = customtkinter.CTkEntry(entry_frame, show="*", font=("Arial", 12))
        entry_confirm_password.grid(row=2, column=1, padx=10, pady=5)

        label_zipcode = customtkinter.CTkLabel(entry_frame, text="Preferred Zipcode:")
        label_zipcode.grid(row=3, column=0, sticky="w", padx=10, pady=5)

        entry_zipcode = customtkinter.CTkEntry(entry_frame, font=("Arial", 12))
        entry_zipcode.grid(row=3, column=1, padx=10, pady=5)

        # prefill information
        if self.preferred_zipcode:
            entry_zipcode.insert(0, self.preferred_zipcode)

        btn_frame = customtkinter.CTkFrame(self.account_settings_frame, fg_color="transparent")
        btn_frame.pack()

        btn_save_changes = customtkinter.CTkButton(btn_frame, text="Save Changes",
                                    command=lambda: self._save_account_changes(
                                        entry_username.get(),
                                        entry_password.get(),
                                        entry_confirm_password.get(),
                                        entry_zipcode.get()
                                    ))
        btn_save_changes.pack(side=tk.LEFT, padx=5, pady=10)
        save_tip = CTkToolTip(btn_save_changes,
                              delay=0.5,
                              message="Click here to update your account information")

        btn_cancel = customtkinter.CTkButton(btn_frame,
                                              text="Cancel",                                              
                                              fg_color="grey",
                                              command=self._cancel_account_settings)
        btn_cancel.pack(side=tk.LEFT, padx=5, pady=10)
        cancel_tip = CTkToolTip(btn_cancel,
                                delay=0.5,
                                message="Click here to return to the main menu")

        logout_button = customtkinter.CTkButton(self.account_settings_frame,
                                                     text="Log Out",
                                                     font=("Arial", 12),
                                                     command=self._logout,
                                                     fg_color="red",
                                                     text_color="black")
        logout_button.pack(pady=10)
        logout_tip = CTkToolTip(logout_button,
                                delay=0.5,
                                message="Click here to log out of your account")

    def _is_valid_zipcode(self, zipcode):
        """
        This function checks if the provided zip code is valid with REGEX

        Args:
            zipcode (int): the provided zip code

        Returns:
            bool: True if valid, False if not
        """
        # 5 digits or 5 digits followed by a hyphen and 4 digits
        pattern = r'^\d{5}(?:-\d{4})?$'
        return bool(re.match(pattern, zipcode))

    def _is_secure_password(self, password):
        """
        This function checks if the provided password is secure. 
        They must be:
         - 8 or more chars in length
         - contain 1 uppercase letter
         - contain 1 lowercase letter
         - contain 1 number
         - contain 1 symbol

        Args:
            password (string): the provided password

        Returns:
            bool: True if secure, False if not
        """
        # check if password meets secure requirements
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

    def _save_account_changes(self, new_username, new_password, confirm_password, new_zipcode):
        """
        This function saves the changes made in the account settings form

        Args:
            new_username (string): username provided in the form
            new_password (string): new password provided in the form
            confirm_password (string): second password field to ensure user knows it
            new_zipcode (int): zip code provided in the form
        """
        update_data = {}
        # sanitize all input to guard against SQL injection or other attacks
        new_username = self._sanitize_input(new_username)
        new_password = self._sanitize_input(new_password)
        confirm_password = self._sanitize_input(confirm_password)
        new_zipcode = self._sanitize_input(new_zipcode)
        # verify inputs are there, compare against old versions to be sure we need to update it
        if new_password.strip() != "":
            if new_password == confirm_password:
                # make sure the password reaches secure reqs
                if not self._is_secure_password(new_password):
                    messagebox.showerror("Password Error",
                                          "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")
                    return
                # hash password for security
                new_hashed_password = self._hash_password(new_password)
                self.cursor.execute("UPDATE Users SET Password = ? WHERE UserId = ?",
                                        (new_hashed_password, self.userid))
                self.conn.commit()
            else:
                messagebox.showerror("Password Error", "Passwords do not match")
                return

        if new_username.strip() != "":
            if new_username != self.current_username:
                update_data["Username"] = new_username
                self.current_username = new_username

        if new_zipcode.strip() != "":
            if not self._is_valid_zipcode(new_zipcode):
                messagebox.showerror("Zip Code Error", "Invalid zip code.")
                return
            update_data["PreferredZip"] = new_zipcode
            self.preferred_zipcode = new_zipcode

        # update fields filled by the user
        if update_data:
            update_query = "UPDATE Users SET "
            update_query += ", ".join(f"{key} = ?" for key in update_data.keys())
            update_query += " WHERE UserId = ?"

            update_values = tuple(update_data.values()) + (self.userid,)

            self.cursor.execute(update_query, update_values)
            self.conn.commit()

        # update welcome label with new user info
        self._update_welcome_label()
        messagebox.showinfo("Changes Saved", "Account settings updated successfully")

    def _cancel_account_settings(self):
        """
        This function sends the user back to the main page
        """
        # hide account settings frame
        self.account_settings_frame.pack_forget()

        # run a search with the preferred zip and populate
        if self.preferred_zipcode:
            self._search_weather(True)
            # clear it out and enter the preferred
            self.zipcode_entry.delete(0, tk.END)
            self.zipcode_entry.insert(0, self.preferred_zipcode)

        # show weather frame
        self.top_nav_frame.pack(fill=tk.X, pady=10)
        self.weather_frame.pack(fill=tk.BOTH, expand=True)

    def _update_welcome_label(self):
        """
        This function updates the welcome label with username and zip code information
        """
        welcome_message = f"Welcome, {self.current_username}!"
        if self.preferred_zipcode:
            welcome_message += f" (Preferred Zip Code: {self.preferred_zipcode})"
        self.welcome_label.configure(text=welcome_message)

    def _hash_password(self, password):
        """
        This function hashes passwords with SHA256

        Args:
            password (string): the provided password
            
        Returns:
            string: hashed password result
        """
        # hash the password using hashlib
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        return hashed_password

    def _get_lat_long_from_zip(self, zip_code):
        """
        Get latitude and longitude from a given zip code using the uszipcode library.
        
        Args:
        - zip_code (str): The zip code for which latitude and longitude are needed.
        
        Returns:
        - list: A list containing the lat, long, and city name
        """
        search = SearchEngine()
        result = search.by_zipcode(zip_code)
        if result:
            # return dictionary of info
            city_data = {
                "lat": result.lat,
                "long": result.lng,
                "city": result.post_office_city
            }
            return city_data

        messagebox.showerror("Search Error",
                                "Unable to retrieve data for the given zip code." + 
                                "Please try a different zip code.")
        # return error level dictionary
        city_data = {
            "lat": None,
            "long": None,
            "city": None
        }
        return city_data

    def _get_weather_response(self, lat, long):
        """
        This function queries the weather API and returns the response JSON

        Args:
            lat (float): latitude value
            long (float): longitude value

        Returns:
            dictionary: JSON response from API
        """
        # set up GET request
        endpoint_url = "https://api.openweathermap.org/data/3.0/onecall"
        endpoint_url += f"?lat={lat}&lon={long}&appid={self.API_KEY}&units=imperial"

        response = requests.get(endpoint_url, timeout=10)

        if response.status_code == 200:
            return response.json()
        # if not a 200, return an error string
        messagebox.showerror("Search Error",
                              f"Failed to retrieve data. Status code: {response.status_code}")
        return "Error"

    def _sanitize_input(self, input_string):
        """
        Remove characters that could potentially lead to SQL injection
        """
        # removes all except white space, alphanumeric characters,
        # and specific safe symbols like . , ! ? @ and #
        if input_string is not None and input_string.strip() != '':
            return re.sub(r'[^\w\s.,!?@#]', '', input_string)
        return ''

# this kicks off the app
if __name__ == "__main__":
    root = customtkinter.CTk() #CustomTkinter
    app = WeatherApp(root)
    root.mainloop()
