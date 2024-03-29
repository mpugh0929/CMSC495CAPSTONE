import tkinter as tk
from tkinter import messagebox

class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Weather App")
        self.root.geometry("400x200")  # Set the initial size of the window

        # Center the window on the screen
        self.center_window()

        # Create frames for better organization
        self.login_frame = tk.Frame(root, pady=20)
        self.login_frame.pack()

        self.username_label = tk.Label(self.login_frame, text="Username:", font=("Arial", 12))
        self.username_label.grid(row=0, column=0, sticky="w")
        self.username_entry = tk.Entry(self.login_frame, font=("Arial", 12))
        self.username_entry.grid(row=0, column=1, padx=10)

        self.password_label = tk.Label(self.login_frame, text="Password:", font=("Arial", 12))
        self.password_label.grid(row=1, column=0, sticky="w")
        self.password_entry = tk.Entry(self.login_frame, show="*", font=("Arial", 12))
        self.password_entry.grid(row=1, column=1, padx=10)

        self.login_button = tk.Button(self.login_frame, text="Login", font=("Arial", 12), command=self.login)
        self.login_button.grid(row=2, columnspan=2, pady=10)

        # Create a separate frame for registration
        self.register_frame = tk.Frame(root)
        self.register_frame.pack()

        self.register_button = tk.Button(self.register_frame, text="Register", font=("Arial", 12), command=self.register)
        self.register_button.pack(pady=10)

        # Load existing user credentials
        self.user_credentials = self.load_credentials()

        # Create a frame for displaying weather information
        self.weather_frame = tk.Frame(root)
        self.weather_label = tk.Label(self.weather_frame, text="WEATHER", font=("Arial", 20))
        self.weather_label.pack(expand=True)

        self.weather_button = tk.Button(self.weather_frame, text="Logout", font=("Arial", 12), command=self.logout)
        self.weather_button.pack(pady=10)

    def center_window(self):
        # Get the screen width and height
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        # Calculate the x and y coordinates to center the window
        x = (screen_width - self.root.winfo_reqwidth()) / 2
        y = (screen_height - self.root.winfo_reqheight()) / 2

        # Set the new coordinates
        self.root.geometry("+%d+%d" % (x, y))

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username in self.user_credentials:
            if self.user_credentials[username] == password:
                self.show_weather_page()
            else:
                messagebox.showerror("Login Failed", "Incorrect password")
        else:
            messagebox.showerror("Login Failed", "Username not found")

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username.strip() == "" or password.strip() == "":
            messagebox.showerror("Registration Failed", "Username or password cannot be empty")
        elif username in self.user_credentials:
            messagebox.showerror("Registration Failed", "Username already exists")
        else:
            self.user_credentials[username] = password
            self.save_credentials()
            messagebox.showinfo("Registration Successful", "User registered successfully")

    def load_credentials(self):
        try:
            with open("user_credentials.txt", "r") as file:
                lines = file.readlines()
                credentials = {}
                for line in lines:
                    username, password = line.strip().split(":")
                    credentials[username] = password
                return credentials
        except FileNotFoundError:
            return {}

    def save_credentials(self):
        with open("user_credentials.txt", "w") as file:
            for username, password in self.user_credentials.items():
                file.write(f"{username}:{password}\n")

    def show_weather_page(self):
        # Hide the login and registration frames
        self.login_frame.pack_forget()
        self.register_frame.pack_forget()

        # Display the weather frame
        self.weather_frame.pack(fill=tk.BOTH, expand=True)

    def logout(self):
        # Hide the weather frame
        self.weather_frame.pack_forget()

        # Show the login and registration frames again
        self.login_frame.pack()
        self.register_frame.pack()

if __name__ == "__main__":
    root = tk.Tk()
    app = LoginApp(root)
    root.mainloop()