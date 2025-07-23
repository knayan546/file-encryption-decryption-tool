File Encryption/Decryption Tool with AES-256

Below is a complete Python application with a Tkinter GUI that provides AES-256 encryption and decryption for files. The application includes:

•	Secure key derivation with PBKDF2
•	Authenticated encryption (GCM mode)
•	File integrity verification
•	User-friendly interface
•	Progress tracking

Features

1.	Strong Encryption: Uses AES-256 in GCM mode for authenticated encryption
2.	Secure Key Derivation: Implements PBKDF2 with 1 million iterations
3.	File Integrity: Verifies file authenticity during decryption
4.	User-Friendly Interface:
•	Simple file selection
•	Operation progress tracking
•	Detailed logging
5.	Responsive Design: Operations run in background threads
6.	Safety Features:
•	Prevents multiple simultaneous operations
•	Validates inputs before processing
•	Provides clear feedback

How to Use

1.	Install dependencies:
pip install pycryptodome

3.	Run the application:
python file_encryptor.py

4.	Using the application:
   
•	Select a file using the "Browse" button
•	Enter a strong password
•	Click "Encrypt File" or "Decrypt File"
•	Monitor progress in the status area

Security Notes

•	The password is never stored or transmitted
•	Each encryption generates new random salts and nonces
•	Encrypted files include authentication tags to detect tampering
•	The key derivation uses industry-standard PBKDF2 with high iteration count.

Enhancement Options

1.	Add password strength meter
3.	Implement file drag-and-drop support
4.	Add command-line interface version
5.	Include checks for encrypted file structure before decryption
6.	Add option for custom iteration counts in key derivation

