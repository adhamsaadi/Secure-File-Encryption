from Crypto.PublicKey import RSA
import tkinter as tk
from tkinter import filedialog, messagebox

def generate_key_pair():
    try:
        # Generate the RSA key pair
        key = RSA.generate(2048)

        # Prompt the user to select a directory to save the keys
        output_dir = filedialog.askdirectory()
        
        if output_dir:
            private_key_path = output_dir + '/private_key.pem'
            public_key_path = output_dir + '/public_key.pem'

            # Save the private key to a file
            with open(private_key_path, 'wb') as private_key_file:
                private_key_file.write(key.export_key('PEM'))

            # Save the public key to a file
            with open(public_key_path, 'wb') as public_key_file:
                public_key_file.write(key.publickey().export_key('PEM'))

            # Display a success message
            messagebox.showinfo("Success", "Key pair generated successfully.")
        else:
            # Display an error message if no output directory is selected
            messagebox.showerror("Error", "No output directory selected.")
    except Exception as e:
        # Display an error message if an exception occurs during key generation
        messagebox.showerror("Error", "Failed to generate key pair: " + str(e))

# Create the GUI
window = tk.Tk()
window.title("RSA Key Pair Generator")
window.geometry("200x100")

# Create a button to generate the key pair
generate_button = tk.Button(window, text="Generate Key Pair", command=generate_key_pair)
generate_button.pack(pady=20)

# Run the GUI main loop
window.mainloop()
