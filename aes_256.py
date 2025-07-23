import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading

class FileEncryptor:
    def __init__(self, master):
        self.master = master
        master.title("Secure File Cryptor - AES-256")
        master.geometry("600x400")
        
        # Configure main container
        self.main_frame = ttk.Frame(master, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        self.create_widgets()
        self.setup_colors_and_styles()
        
        # Encryption parameters
        self.salt = None
        self.key = None
        self.operation_in_progress = False
    
    def setup_colors_and_styles(self):
        style = ttk.Style()
        style.configure('TFrame', background='#f0f0f0')
        style.configure('TButton', padding=6, font=('Segoe UI', 10))
        style.configure('TLabel', background='#f0f0f0', font=('Segoe UI', 10))
        style.configure('Header.TLabel', font=('Segoe UI', 14, 'bold'))
        style.configure('Progress.Horizontal.TProgressbar', thickness=20)
        
    def create_widgets(self):
        # Header
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill=tk.X, pady=10)
        ttk.Label(header_frame, text="Secure File Cryptor", style='Header.TLabel').pack()
        
        # Input Frame
        input_frame = ttk.Frame(self.main_frame)
        input_frame.pack(fill=tk.X, pady=10)
        
        # File Selection
        ttk.Label(input_frame, text="File:").grid(row=0, column=0, sticky=tk.W)
        self.file_path = tk.StringVar()
        self.file_entry = ttk.Entry(input_frame, textvariable=self.file_path, width=50)
        self.file_entry.grid(row=0, column=1, padx=5)
        ttk.Button(input_frame, text="Browse...", command=self.browse_file).grid(row=0, column=2)
        
        # Password
        ttk.Label(input_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.password = tk.StringVar()
        self.password_entry = ttk.Entry(input_frame, textvariable=self.password, show="*", width=50)
        self.password_entry.grid(row=1, column=1, padx=5)
        
        # Operation Buttons
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        self.encrypt_btn = ttk.Button(button_frame, text="Encrypt File", command=lambda: self.start_operation('encrypt'))
        self.encrypt_btn.pack(side=tk.LEFT, padx=5)
        self.decrypt_btn = ttk.Button(button_frame, text="Decrypt File", command=lambda: self.start_operation('decrypt'))
        self.decrypt_btn.pack(side=tk.LEFT, padx=5)
        
        # Status Area
        status_frame = ttk.Frame(self.main_frame)
        status_frame.pack(fill=tk.BOTH, expand=True)
        
        self.status_label = ttk.Label(status_frame, text="Ready")
        self.status_label.pack(anchor=tk.W)
        
        self.progress = ttk.Progressbar(status_frame, orient=tk.HORIZONTAL, length=100, mode='determinate', style='Progress.Horizontal.TProgressbar')
        self.progress.pack(fill=tk.X, pady=10)
        
        self.log_text = tk.Text(status_frame, height=10, wrap=tk.WORD, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)
            self.log(f"Selected file: {filename}")
    
    def log(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def update_status(self, message):
        self.status_label.config(text=message)
        self.master.update()
    
    def update_progress(self, value):
        self.progress['value'] = value
        self.master.update()
    
    def start_operation(self, operation):
        if self.operation_in_progress:
            messagebox.showwarning("Warning", "An operation is already in progress")
            return
            
        file = self.file_path.get()
        password = self.password.get()
        
        if not file:
            messagebox.showerror("Error", "Please select a file")
            return
            
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
            
        # Validate the file exists and is accessible
        try:
            with open(file, 'rb') as f:
                pass
        except IOError as e:
            messagebox.showerror("Error", f"Could not access file: {str(e)}")
            return
            
        self.operation_in_progress = True
        self.encrypt_btn.config(state=tk.DISABLED)
        self.decrypt_btn.config(state=tk.DISABLED)
        
        # Run in a separate thread to keep UI responsive
        thread = threading.Thread(
            target=self.perform_operation,
            args=(operation, file, password),
            daemon=True
        )
        thread.start()
    
    def perform_operation(self, operation, input_file, password):
        try:
            self.update_status(f"{operation.capitalize()}ing file...")
            self.log(f"Starting {operation} operation on {input_file}")
            self.update_progress(0)
            
            if operation == 'encrypt':
                output_file = input_file + '.enc'
                self.encrypt_file(input_file, output_file, password)
            else:
                if input_file.endswith('.enc'):
                    output_file = input_file[:-4]
                else:
                    output_file = input_file + '.decrypted'
                self.decrypt_file(input_file, output_file, password)
            
            self.log(f"{operation.capitalize()}ion completed successfully")
            self.log(f"Output file: {output_file}")
            messagebox.showinfo("Success", f"File {operation}ion completed successfully")
            
        except Exception as e:
            self.log(f"Error during {operation}ion: {str(e)}")
            messagebox.showerror("Error", f"{operation.capitalize()}ion failed: {str(e)}")
            
        finally:
            self.operation_in_progress = False
            self.master.after(0, self.enable_buttons)
            self.update_status("Ready")
            self.update_progress(0)
    
    def enable_buttons(self):
        self.encrypt_btn.config(state=tk.NORMAL)
        self.decrypt_btn.config(state=tk.NORMAL)
    
    def encrypt_file(self, input_file, output_file, password, key_size=32):
        # Generate random salt
        self.salt = get_random_bytes(16)
        
        # Derive key from password and salt
        self.key = PBKDF2(password, self.salt, dkLen=key_size, count=1000000)
        
        # Generate random nonce
        nonce = get_random_bytes(12)
        
        # Create cipher object
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        
        file_size = os.path.getsize(input_file)
        processed = 0
        
        with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            # Write salt and nonce to output file
            f_out.write(self.salt)
            f_out.write(nonce)
            
            # Process file in chunks
            chunk_size = 64 * 1024  # 64KB
            
            while True:
                chunk = f_in.read(chunk_size)
                if len(chunk) == 0:
                    break
                
                # Encrypt the chunk and write to output
                encrypted_chunk = cipher.encrypt(chunk)
                f_out.write(encrypted_chunk)
                
                # Update progress
                processed += len(chunk)
                progress = (processed / file_size) * 100
                self.master.after(0, self.update_progress, progress)
            
            # Get and store the MAC tag
            tag = cipher.digest()
            f_out.write(tag)
        
        self.log("Encryption completed with AES-256-GCM")
    
    def decrypt_file(self, input_file, output_file, password, key_size=32):
        with open(input_file, 'rb') as f_in:
            # Read salt and nonce from beginning of file
            self.salt = f_in.read(16)
            nonce = f_in.read(12)
            
            # Get file size and calculate data size (excluding salt, nonce and tag)
            file_size = os.path.getsize(input_file)
            data_size = file_size - 16 - 12 - 16  # salt + nonce + tag
            
            # Derive key from password and salt
            self.key = PBKDF2(password, self.salt, dkLen=key_size, count=1000000)
            
            # Create cipher object
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            
            processed = 0
            with open(output_file, 'wb') as f_out:
                chunk_size = 64 * 1024  # 64KB
                
                # Process all but the last chunk (which includes the tag)
                while processed < data_size - chunk_size:
                    chunk = f_in.read(chunk_size)
                    decrypted_chunk = cipher.decrypt(chunk)
                    f_out.write(decrypted_chunk)
                    processed += len(chunk)
                    
                    # Update progress
                    progress = (processed / data_size) * 100
                    self.master.after(0, self.update_progress, progress)
                
                # Process final chunk
                remaining = data_size - processed
                if remaining > 0:
                    chunk = f_in.read(remaining)
                    decrypted_chunk = cipher.decrypt(chunk)
                    f_out.write(decrypted_chunk)
                
                # Verify authentication tag
                tag = f_in.read(16)
                try:
                    cipher.verify(tag)
                    self.log("File authenticated successfully")
                except ValueError:
                    raise ValueError("Authentication failed - file may be corrupted or password incorrect")

def main():
    root = tk.Tk()
    app = FileEncryptor(root)
    
    # Set application icon (replace with your own icon path)
    try:
        root.iconbitmap('lock.ico')  # Optional: provide an icon file
    except:
        pass
    
    root.mainloop()

if __name__ == "__main__":
    # Check for required libraries
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("Required libraries not found. Please install:")
        print("pip install pycryptodome")
        exit(1)
    
    main()
