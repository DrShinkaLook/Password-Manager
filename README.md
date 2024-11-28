Secure Password Manager

A simple Python-based password manager that uses Fernet encryption for secure storage of account credentials.
Features:

    Encryption Key Management: Automatically generates and validates encryption keys.
    Secure Storage: Encrypts passwords and saves them to a local file.
    Password Retrieval: Decrypts and displays stored credentials for easy access.
    User-Friendly Interface: Simple menu for saving and viewing passwords.
    Error Handling: Regenerates encryption keys if invalid or missing.

How to Use:

    Run the script using Python 3.
    Follow the menu options to:
        Save new passwords.
        View stored passwords.
    All data is securely encrypted and stored locally.

    Dependencies: Requires the cryptography library. Install via pip install cryptography.
