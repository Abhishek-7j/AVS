import customtkinter as ctk
from tkinter import messagebox

from config import login_password, login_username


def show_login(root, open_main_app):

    login_window = ctk.CTkToplevel(root)
    login_window.title("AutoVuln Scanner Login")
    login_window.geometry("400x300")

    title = ctk.CTkLabel(login_window, text="AutoVuln Scanner Login",
                         font=("Arial", 22, "bold"))
    title.pack(pady=20)

    username_entry = ctk.CTkEntry(login_window, placeholder_text="Username")
    username_entry.pack(pady=10)

    password_entry = ctk.CTkEntry(login_window, placeholder_text="Password", show="*")
    password_entry.pack(pady=10)

    def login():

        username = username_entry.get()
        password = password_entry.get()

        if username == login_username() and password == login_password():

            messagebox.showinfo("Login Success", "Welcome!")

            login_window.destroy()
            open_main_app()

        else:
            messagebox.showerror("Error", "Invalid credentials")

    login_button = ctk.CTkButton(login_window, text="Login", command=login)
    login_button.pack(pady=20)