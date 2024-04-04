import tkinter as tk
from tkinter import messagebox
import customtkinter

customtkinter.set_appearance_mode("Dark")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("green")  # Themes: "blue" (standard), "green", "dark-blue"

class LoginApp:
    API_KEY = "129124b09cdff6292a9970660cd37091"

    def __init__(self, root):
        """
        This is the initialization function
        """
        self.root = root
        self.root.title("Weather App")
        self.root.geometry("400x200")  # Set the initial size of the window

        # Center the window on the screen
        self.center_window()

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

        self.user_credentials = self.load_credentials()

        # create weather placeholder frame
        self.weather_frame = customtkinter.CTkFrame(root)
        self.weather_label = customtkinter.CTkLabel(self.weather_frame, text="WEATHER", font=("Arial", 20))
        self.weather_label.pack(expand=True)

        self.weather_button = customtkinter.CTkButton(self.weather_frame, text="Logout", font=("Arial", 12), command=self.logout)
        self.weather_button.pack(pady=10)

    def center_window(self):
        """
        This function centers the gui on start
        """
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        x = (screen_width - self.root.winfo_reqwidth()) / 2
        y = (screen_height - self.root.winfo_reqheight()) / 2

        self.root.geometry("+%d+%d" % (x, y))

    def login(self):
        """
        This function is executed when the login button is clicked
        """
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
        """
        This function is executed when the register button is clicked
        """
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
        """This function loads the credentials written to file

        Returns:
            dictionary: list of credentials, empty if cannot find file
        """
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
        """
        This function saves the user entered credentials to file
        """
        with open("user_credentials.txt", "w") as file:
            for username, password in self.user_credentials.items():
                file.write(f"{username}:{password}\n")

    def show_weather_page(self):
        # hide login frame
        self.login_frame.pack_forget()
        self.register_frame.pack_forget()

        # show logged in weather frame
        self.weather_frame.pack(fill=tk.BOTH, expand=True)

    def logout(self):
        # hide logged in frame
        self.weather_frame.pack_forget()

        # show reg frame
        self.login_frame.pack()
        self.register_frame.pack()

if __name__ == "__main__":
    root = customtkinter.CTk() #CustomTkinter
    app = LoginApp(root)
    root.mainloop()

#hello