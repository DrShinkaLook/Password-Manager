import os
from cryptography.fernet import Fernet

#  Encryption Key Management 
def generate_key():
    """
    Generates valid encryption key and saves to 'key.key' if it doesn't exist.
    """
    key_file = "key.key"
    if not os.path.exists(key_file):
        print("Generating a new encryption key...")
        key = Fernet.generate_key()
        with open(key_file, "wb") as file:
            file.write(key)
        print("Encryption key generated and saved to 'key.key'.")

def load_key():
    """
    Loads encryption key from 'key.key' and validates it.
    Invalid = generate new key.
    Returns key as bytes.
    """
    key_file = "key.key"
    try:
        with open(key_file, "rb") as file:
            key = file.read()
            print(f"Loaded key (length {len(key)} bytes).")
            # Validate key length and format (Fernet keys are 44 bytes in length)
            if len(key) != 44:
                print("Invalid key length detected. Regenerating key.")
                raise ValueError("Invalid key length. Regenerating key.")
            return key
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}")
        print("Regenerating key...")
        generate_key()
        return load_key()

#  Password Encryption and Decryption 
def encrypt_data(data, key):
    """
    Encrypts string using the encryption key.
    Returns the encrypted data string.
    """
    fernet = Fernet(key)
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data, key):
    """
    Decrypts encrypted string using provided encryption key.
    Returns the decrypted data as string.
    """
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data.encode()).decode()

#  Password Storage 
def save_password(account, password, key):
    """
    Encrypts and saves password to 'passwords.txt' associated with the account.
    """
    encrypted_password = encrypt_data(password, key)
    try:
        with open("passwords.txt", "a") as file:
            file.write(f"{account}:{encrypted_password}\n")
        print(f"Password for '{account}' saved successfully!")
    except Exception as e:
        print(f"Error saving password: {e}")

def retrieve_passwords(key):
    """
    Reads and decrypts passwords stored in 'passwords.txt'.
    Displays all account/password pairs.
    """
    if not os.path.exists("passwords.txt"):
        print("No passwords have been saved yet.")
        return

    print("\nStored Passwords:")
    try:
        with open("passwords.txt", "r") as file:
            for line in file:
                account, encrypted_password = line.strip().split(":")
                decrypted_password = decrypt_data(encrypted_password, key)
                print(f"Account: {account}, Password: {decrypted_password}")
    except Exception as e:
        print(f"Error retrieving passwords: {e}")

#  Validation and Input Management 
def get_valid_input(prompt, allow_empty=False):
    """
    Prompts user for input and make sure itsvalid (non empty unless allowed).
    """
    while True:
        user_input = input(prompt).strip()
        if user_input or allow_empty:
            return user_input
        print("Input cannot be empty. Please try again.")

#  Menu Logic 
def main_menu():
    """
    Displays main menu and handles user actions.
    """
    print("=== Secure Password Manager ===")
    generate_key()
    key = load_key()

    while True:
        print("\nMain Menu:")
        print("1. Save a new password")
        print("2. View stored passwords")
        print("3. Exit")

        choice = get_valid_input("Choose an option (1-3): ")
        if choice == "1":
            account = get_valid_input("Enter a account name: ")
            password = get_valid_input("Enter a password: ")
            save_password(account, password, key)
        elif choice == "2":
            retrieve_passwords(key)
        elif choice == "3":
            print("Exiting Password Manager....................................... Buh Byeeeeee!")
            break
        else:
            print("Invalid choice. Please select 1, 2, or 3.")

# Entry Point 
if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nProgram interrupted. Retrying...")
