from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.ttk import Progressbar
import threading

def select_file(label):
    file_path = filedialog.askopenfilename(title="Select File")
    if file_path:
        label.config(text=file_path)

def select_directory(label):
    directory_path = filedialog.askdirectory(title="Select Directory")
    if directory_path:
        label.config(text=directory_path)

def update_progress(progress):
    progress_bar["value"] = progress
    window.update_idletasks()

def encrypt_file(file_path, public_key_path, output_directory):
    try:
        # Load the public key
        with open(public_key_path, 'r') as public_key_file:
            public_key = RSA.import_key(public_key_file.read())

        # Generate a random symmetric key
        symmetric_key = AES.get_random_bytes(32)

        # Create the cipher for asymmetric encryption
        cipher_asymmetric = PKCS1_OAEP.new(public_key)

        # Encrypt the symmetric key using the public key
        encrypted_symmetric_key = cipher_asymmetric.encrypt(symmetric_key)

        # Create the cipher for symmetric encryption
        cipher_symmetric = AES.new(symmetric_key, AES.MODE_EAX)

        # Get the file size for progress bar
        file_size = os.path.getsize(file_path)

        # Read the file contents
        with open(file_path, 'rb') as file:
            file_data = file.read()

        # Encrypt the file data using the symmetric key
        ciphertext_parts = []
        chunk_size = 1024  # Adjust the chunk size as needed
        total_chunks = file_size // chunk_size if file_size >= chunk_size else 1
        chunks_done = 0
        progress_increment = 2  # Update progress every 2%
        progress = 0
        for i in range(0, len(file_data), chunk_size):
            chunk = file_data[i:i+chunk_size]
            ciphertext_parts.append(cipher_symmetric.encrypt(chunk))
            chunks_done += 1
            new_progress = (chunks_done / total_chunks) * 100
            if new_progress - progress >= progress_increment:
                progress = new_progress
                update_progress(progress)

        # Create the output file path
        output_filename = 'encrypted_' + os.path.basename(file_path)
        output_path = os.path.join(output_directory, output_filename)

        # Concatenate the encrypted symmetric key, nonce, and ciphertext
        encrypted_data = b"".join(ciphertext_parts)
        data_to_mac = encrypted_symmetric_key + cipher_symmetric.nonce + encrypted_data

        # Generate the HMAC using the symmetric key and concatenated data
        mac = HMAC.new(symmetric_key, digestmod=SHA256)
        mac.update(data_to_mac)
        hmac_value = mac.digest()

        # Prepend the HMAC to the encrypted file data
        encrypted_data_with_hmac = hmac_value + encrypted_symmetric_key + cipher_symmetric.nonce + encrypted_data

        # Write the encrypted file data with HMAC to the output file
        with open(output_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data_with_hmac)
            
        progress_bar["value"] = progress_bar["value"] + 2

        messagebox.showinfo("Encryption Successful", "File encrypted successfully!")
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

def encrypt_file_with_progress():
    try:
        # Check if all fields are filled
        if not file_label.cget("text"):
            messagebox.showerror("Error", "Please select a file.")
            return
        if not public_key_label.cget("text"):
            messagebox.showerror("Error", "Please select a public key file.")
            return
        if not output_directory_label.cget("text"):
            messagebox.showerror("Error", "Please select an output directory.")
            return

        file_path = file_label.cget("text")
        public_key_path = public_key_label.cget("text")
        output_directory = output_directory_label.cget("text")

        # Set progress bar to 2%
        progress_bar["value"] = 2

        # Start encryption in a separate thread
        threading.Thread(target=encrypt_file, args=(file_path, public_key_path, output_directory)).start()
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

# Create the GUI window
window = tk.Tk()
window.title("File Encryption")
window.geometry("800x300")

# Create the file selection section
file_frame = tk.Frame(window)
file_frame.pack(pady=20)

file_label = tk.Label(file_frame, text="No file selected")
file_label.pack(side="left", padx=10)

file_button = tk.Button(file_frame, text="Select File To Encrypt", command=lambda: select_file(file_label))
file_button.pack(side="left")

# Create the public key selection section
public_key_frame = tk.Frame(window)
public_key_frame.pack(pady=10)

public_key_label = tk.Label(public_key_frame, text="No public key file selected")
public_key_label.pack(side="left", padx=10)

public_key_button = tk.Button(public_key_frame, text="Select Public Key", command=lambda: select_file(public_key_label))
public_key_button.pack(side="left")

# Create the output directory selection section
output_directory_frame = tk.Frame(window)
output_directory_frame.pack(pady=10)

output_directory_label = tk.Label(output_directory_frame, text="No output directory selected")
output_directory_label.pack(side="left", padx=10)

output_directory_button = tk.Button(output_directory_frame, text="Select Output Directory", command=lambda: select_directory(output_directory_label))
output_directory_button.pack(side="left")

# Create the "Encrypt File" button
encrypt_button = tk.Button(window, text="Encrypt File", command=encrypt_file_with_progress)
encrypt_button.pack(pady=30)

# Create the progress bar
progress_bar = Progressbar(window, orient="horizontal", length=500, mode="determinate")
progress_bar.pack(pady=10)

# Run the GUI event loop
window.mainloop()
