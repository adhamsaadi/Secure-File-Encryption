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

def verify_mac(symmetric_key, data, hmac_value):
    mac = HMAC.new(symmetric_key, digestmod=SHA256)
    mac.update(data)
    calculated_hmac = mac.digest()
    return hmac_value == calculated_hmac

def decrypt_file(file_path, private_key_path, output_directory):
    try:
        # Load the private key
        with open(private_key_path, 'r') as private_key_file:
            private_key = RSA.import_key(private_key_file.read())

        # Read the encrypted file
        with open(file_path, 'rb') as encrypted_file:
            hmac_value = encrypted_file.read(32)
            encrypted_symmetric_key = encrypted_file.read(private_key.size_in_bytes())
            nonce = encrypted_file.read(16)
            ciphertext = encrypted_file.read()

        # Create the cipher for asymmetric decryption
        cipher_asymmetric = PKCS1_OAEP.new(private_key)

        # Decrypt the symmetric key using the private key
        symmetric_key = cipher_asymmetric.decrypt(encrypted_symmetric_key)

        # Verify the HMAC
        data_to_mac = encrypted_symmetric_key + nonce + ciphertext
        if not verify_mac(symmetric_key, data_to_mac, hmac_value):
            messagebox.showerror("Decryption Error", "MAC verification failed. The file may have been tampered with.")
            return

        # Create the cipher for symmetric decryption
        cipher_symmetric = AES.new(symmetric_key, AES.MODE_EAX, nonce)

        # Decrypt the file data using the symmetric key
        decrypted_data_parts = []
        chunk_size = 1024
        total_chunks = len(ciphertext) // chunk_size if len(ciphertext) >= chunk_size else 1
        chunks_done = 0
        progress_increment = 2  # Update progress every 2%
        progress = 0
        for i in range(0, len(ciphertext), chunk_size):
            chunk = ciphertext[i:i + chunk_size]
            decrypted_data_parts.append(cipher_symmetric.decrypt(chunk))
            chunks_done += 1
            new_progress = (chunks_done / total_chunks) * 100
            if new_progress - progress >= progress_increment:
                progress = new_progress
                update_progress(progress)

        # Concatenate the decrypted data parts
        decrypted_data = b"".join(decrypted_data_parts)

        # Get the original file name
        original_file_name = os.path.basename(file_path)
        if original_file_name.startswith("encrypted_"):
            original_file_name = original_file_name[10:]  # Remove "encrypted_" prefix

        # Create the output file path
        output_filename = 'decrypted_' + original_file_name
        output_path = os.path.join(output_directory, output_filename)

        # Write the decrypted data to the output file
        with open(output_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)
            
        progress_bar["value"] = progress_bar["value"] + 2

        messagebox.showinfo("Decryption Successful", "File decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))

def decrypt_file_with_progress():
    try:
        # Check if all fields are filled
        if not encrypted_file_label.cget("text"):
            messagebox.showerror("Error", "Please select an encrypted file.")
            return
        if not private_key_label.cget("text"):
            messagebox.showerror("Error", "Please select a private key file.")
            return
        if not output_directory_label.cget("text"):
            messagebox.showerror("Error", "Please select an output directory.")
            return

        file_path = encrypted_file_label.cget("text")
        private_key_path = private_key_label.cget("text")
        output_directory = output_directory_label.cget("text")

        # Set progress bar to 2%
        progress_bar["value"] = 2

        # Start decryption in a separate thread
        threading.Thread(target=decrypt_file, args=(file_path, private_key_path, output_directory)).start()
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))

# Create the GUI window
window = tk.Tk()
window.title("File Decryption")
window.geometry("800x300")

# Create the encrypted file selection section
encrypted_file_frame = tk.Frame(window)
encrypted_file_frame.pack(pady=20)

encrypted_file_label = tk.Label(encrypted_file_frame, text="No encrypted file selected")
encrypted_file_label.pack(side="left", padx=10)

encrypted_file_button = tk.Button(encrypted_file_frame, text="Select Encrypted File", command=lambda: select_file(encrypted_file_label))
encrypted_file_button.pack(side="left")

# Create the private key selection section
private_key_frame = tk.Frame(window)
private_key_frame.pack(pady=10)

private_key_label = tk.Label(private_key_frame, text="No private key file selected")
private_key_label.pack(side="left", padx=10)

private_key_button = tk.Button(private_key_frame, text="Select Private Key", command=lambda: select_file(private_key_label))
private_key_button.pack(side="left")

# Create the output directory selection section
output_directory_frame = tk.Frame(window)
output_directory_frame.pack(pady=10)

output_directory_label = tk.Label(output_directory_frame, text="No output directory selected")
output_directory_label.pack(side="left", padx=10)

output_directory_button = tk.Button(output_directory_frame, text="Select Output Directory", command=lambda: select_directory(output_directory_label))
output_directory_button.pack(side="left")

# Create the "Decrypt File" button
decrypt_button = tk.Button(window, text="Decrypt File", command=decrypt_file_with_progress)
decrypt_button.pack(pady=30)

# Create the progress bar
progress_bar = Progressbar(window, length=400, mode="determinate")
progress_bar.pack(pady=10)

# Run the GUI event loop
window.mainloop()
