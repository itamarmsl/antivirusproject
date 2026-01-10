import requests
import tkinter as tk
from tkinter import filedialog
import threading
import time
import json
import os
import re

API_KEY = "0404997641d12cc3b0b26064812e62f31da645bd33e929307be09123c01aa0ca"
URL = "https://www.virustotal.com/api/v3/files"

def select_dir():
    dir_path = filedialog.askdirectory()
    if dir_path:
        print(f"Selected directory: {str(dir_path)}")
        dir_safe_var.set("Scanning directory...")
        file_safe_var.set("Scanning file...")
        threading.Thread(target=scan_dir, args=(dir_path,),daemon=True).start()   

def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        basename = os.path.basename(file_path)
        print(f"Selected file: {file_path}")
        file_safe_var.set("Scanning file...")
        progress_var.set(f"Scanning '{basename}'")
        threading.Thread(target=scan_file, args=(file_path,), daemon=True).start()

def update_label_safe(label_var, text):
    window.after(0, lambda: label_var.set(text))

def get_filepaths(dir_path):
    files = []
    i=0
    for dirpath, dirnames, filenames in os.walk(dir_path):
        for file in filenames:
            file_path = os.path.join(dirpath, file)
            files.append(file_path)
        # print(f"-{i}-")
        i+=1
    # print(files)
    return files

def scan_dir(dir_path):
    file_paths = get_filepaths(dir_path)
    total_files = len(file_paths)
    directory_safe = True

    for i, file_path in enumerate(file_paths, start=1):
        update_label_safe(progress_var, f"Scanning {os.path.basename(file_path)} ({i}/{total_files})")

        print("Now scanning:", file_path)

        result = scan_file(file_path)
        if result == "malicious":
            directory_safe = False
        time.sleep(1)
        print(f"Done scanning {file_path}\n")
    
    if directory_safe:
        update_label_safe(dir_safe_var, "Directory is safe ✅")
    else:
        update_label_safe(dir_safe_var, "Directory has malware ⚠️")
    update_label_safe(progress_var, f"Finished scanning {total_files} files")
    time.sleep(10)
    update_label_safe(file_safe_var, "File status")

def scan_file(file_path):
    headers = {
        "x-apikey": API_KEY
    }
    try: 
        with open(file_path, "rb") as f:
            files = {
                "file": f
            }
            response = requests.post(URL, headers=headers, files=files)
    except Exception as e:
        print(f"Cannot open {file_path}: {e}")
        update_label_safe(file_safe_var, "Error opening file")
        return "error"

    if response.ok:
        try: 
            data = response.json()
        except ValueError:
            print("Failed to parse JSON:", response.text)
            update_label_safe(file_safe_var, "Scan failed")
            return "error"

        # save json per file
        safe_name = os.path.basename(file_path)
        safe_name = re.sub(r'[<>:"/\\|?*]', '_', safe_name)
        output_path = f"C:/Users/itama/Downloads/responses/{safe_name}.json"
        with open(output_path, "w") as rf:
            json.dump(data, rf, indent=2)

        analysis_id = data["data"]["id"]
        print("Uploaded. Analysis ID:", analysis_id)
        stats = wait_for_results(analysis_id)
        if stats is None:
            update_label_safe(file_safe_var, "Scan timed out")
            return "error"
        malicious = stats.get("malicious", 0)
        if malicious > 0:
            update_label_safe(file_safe_var, "Malicious ⚠️")
            return "malicious"
        else:
            update_label_safe(file_safe_var, "Safe ✅")
            return "safe"
    else:
        print("Upload failed: ", response.status_code, response.text)
        update_label_safe(file_safe_var, "Upload failed")
        return "error"
    
def wait_for_results(analysis_id, max_tries = 10):
    for attempt in range(max_tries):
        data = get_analysis(analysis_id)
        if data is None:
            return None
        status = data["data"]["attributes"]["status"]
        if status == "completed":
            return data["data"]["attributes"]["stats"]
        remaining = max_tries - attempt - 1
        print(f"Waiting for VirusTotal result... {remaining} tries left")
        time.sleep(15)
    print("Timed out waiting for analysis")
    return None

def get_analysis(analysis_id):
    headers = {"x-apikey": API_KEY}
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    response = requests.get(url, headers=headers)

    if response.ok:
        data = response.json()
        return data
    else:
        print("Failed to get analysis:", response.status_code)
        return None

# GUI
window = tk.Tk()
window.title("Anti-Virus Project")
window.geometry("800x800")
window.resizable(True,True)

dir_safe_var = tk.StringVar()
file_safe_var = tk.StringVar()
progress_var = tk.StringVar()

dir_safe_var.set("Directory status")
file_safe_var.set("File status")

# Buttons
dir_select = tk.Button(window,text="Select directory", command=select_dir)
file_select = tk.Button(window, text="Select file", command=select_file)
exit_btn = tk.Button(window, text="Exit",command=window.destroy)

# Labels
dir_safe = tk.Label(window, textvariable=dir_safe_var)
file_safe = tk.Label(window, textvariable=file_safe_var)
progress_label = tk.Label(window, textvariable=progress_var)

for w in [dir_select, file_select, exit_btn, dir_safe, file_safe, progress_label]:
    w.config(font=("Arial",30), padx=10,pady=10)
progress_label.config(font=("Arial", 20))
exit_btn.config(fg="red")

# dir_select.config(font=("Arial",30), padx=10,pady=10)
# file_select.config(font=("Arial",30), padx=10,pady=10)
# exit_btn.config(font=("Arial",30), padx=10,pady=10, fg="red")
# dir_safe.config(font=("Arial",30), padx=10,pady=10)
# file_safe.config(font=("Arial",30), padx=10,pady=10)

# Pack
dir_select.pack(expand=True)
file_select.pack(expand=True)
dir_safe.pack(expand=True)
progress_label.pack(expand=True)
file_safe.pack(expand=True)
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