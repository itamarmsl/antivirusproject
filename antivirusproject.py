import requests
import tkinter as tk
from tkinter import filedialog
import os

API_KEY = "0404997641d12cc3b0b26064812e62f31da645bd33e929307be09123c01aa0ca"

def select_dir():
    dir_path = filedialog.askdirectory()
    if dir_path:
        print(f"Selected directory: {str(dir_path)}")

def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        print(f"Selected file: {file_path}")

def main() -> None:
    global window
    window = tk.Tk()
    window.title("Anti-Virus Project")
    window.geometry("480x375")
    window.resizable(True,True)

    dir_select = tk.Button(window,text="Select directory", command=select_dir)
    file_select = tk.Button(window, text="Select file", command=select_file)
    exit_btn = tk.Button(window, text="Exit",command=exit)
    
    dir_select.config(font=("Arial",30), padx=10,pady=10)
    file_select.config(font=("Arial",30), padx=10,pady=10)
    exit_btn.config(font=("Arial",30), padx=10,pady=10, fg="red")
    
    dir_select.pack(expand=True)
    file_select.pack(expand=True)
    exit_btn.pack(expand=True)

    # Adds a button to get window size
    # get_info = tk.Button(window, text="Get info", command=print_window_size)
    # get_info.config(font=("Arial",30), padx=10,pady=10)
    # get_info.pack(expand=True)

    window.mainloop()

def print_window_size() -> None:
    """
    Prints the dimensions of the window
    Width x Height
    """
    width = window.winfo_width()
    height = window.winfo_height()
    print(window.winfo_pixels(10))
    print(f"Window size: {width}x{height}")

if __name__ == "__main__":
    main()