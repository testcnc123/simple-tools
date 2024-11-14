import base64
import os
import pyperclip
import threading
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from getpass import getpass
import sys
import signal


def derive_key(passkey: str) -> bytes:
    """Derive a fixed Fernet encryption key from a master passkey."""
    salt = b'\x00' * 16
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))


def validate_passkey(fernet: Fernet, filepath: str) -> bool:
    """Attempt to validate the master passkey by decrypting the first key in the file."""
    try:
        with open(filepath, 'rb') as file:
            encrypted_key = file.readline().strip()
            if not encrypted_key:
                return True  # Empty file is considered valid
            fernet.decrypt(encrypted_key)  # Attempt to decrypt the first key to validate the passkey
        return True
    except Exception:
        return False


def store_key_and_password(fernet: Fernet, key: str, password: str, filepath: str):
    """Encrypt and store the key and password in a file using the same fernet instance."""
    encrypted_key = fernet.encrypt(key.encode())
    encrypted_password = fernet.encrypt(password.encode())

    # Save the encrypted key and encrypted password to the file
    with open(filepath, 'ab') as file:  # Append mode to store multiple keys/passwords
        file.write(encrypted_key + b'\n' + encrypted_password + b'\n')


def list_keys(fernet: Fernet, filepath: str) -> list:
    """List all stored keys in the file."""
    keys = []
    try:
        with open(filepath, 'rb') as file:
            while True:
                encrypted_key = file.readline().strip()
                if not encrypted_key:
                    break  # End of file
                encrypted_password = file.readline().strip()  # Read the associated encrypted password

                # Try to decrypt the key name
                try:
                    decrypted_key = fernet.decrypt(encrypted_key).decode()
                    keys.append((decrypted_key, encrypted_key, encrypted_password))
                except Exception:
                    # Append a placeholder if decryption fails
                    keys.append(("[Cannot display: Invalid passkey or corrupted entry]", None, None))
    except FileNotFoundError:
        print("No keys found. Store a password first.")
    return keys


def retrieve_password(fernet: Fernet, encrypted_password: bytes) -> str:
    """Retrieve and decrypt the password for a selected key."""
    decrypted_password = fernet.decrypt(encrypted_password).decode()
    return decrypted_password


def clear_clipboard_with_interrupt():
    """Clear the clipboard with a countdown, blocking user input and allowing interruption."""
    countdown = 30
    print("\nPress Ctrl+C to stop the countdown and clear the clipboard immediately.")
    try:
        for seconds in range(countdown, 0, -1):
            sys.stdout.write(f"\rClipboard will be cleared in {seconds} seconds... ")
            sys.stdout.flush()
            time.sleep(1)

        pyperclip.copy("")  # Clear the clipboard
        sys.stdout.write("\rClipboard cleared.                          \n")
        sys.stdout.flush()
    except KeyboardInterrupt:
        # Handle interruption by immediately clearing the clipboard
        pyperclip.copy("")
        sys.stdout.write("\rClipboard cleared immediately due to interruption.     \n")
        sys.stdout.flush()


# Main usage
filepath = 'key_passwords.enc'

# Prompt for master passkey with validation
while True:
    master_passkey = getpass("Enter master passkey to access stored passwords: ")
    fernet = Fernet(derive_key(master_passkey))
    
    # Validate the passkey by trying to decrypt the first entry in the file (if it exists)
    if validate_passkey(fernet, filepath):
        break
    else:
        print("Incorrect master passkey. Please try again.")

# Action loop
while True:
    action = input("\nDo you want to (S)tore, (R)etrieve a key and password, or (E)xit? ").strip().lower()

    if action == 's':
        key = input("Enter the key to store: ")
        password = getpass("Enter the password to store: ")
        store_key_and_password(fernet, key, password, filepath)
        print("Key and password stored securely.")

    elif action == 'r':
        keys = list_keys(fernet, filepath)

        if keys:
            print("\nAvailable keys:")
            for i, (key_name, _, _) in enumerate(keys, 1):
                print(f"{i}. {key_name}")

            choice = int(input("\nEnter the number of the key you want to retrieve: "))
            selected_key, _, encrypted_password = keys[choice - 1]

            if "[Cannot display" not in selected_key:
                try:
                    password = retrieve_password(fernet, encrypted_password)
                    pyperclip.copy(password)  # Copy password to clipboard
                    print("Password copied to clipboard.")

                    # Start the countdown to clear the clipboard, blocking all other actions
                    clear_clipboard_with_interrupt()

                except Exception as e:
                    print("Failed to retrieve password. Ensure the passkey is correct and the key is valid.")
            else:
                print("Invalid selection. Please try again with a valid key.")
        else:
            print("No keys found.")
    
    elif action == 'e':
        print("Exiting the program.")
        break

    else:
        print("Invalid action. Please choose (S)tore, (R)etrieve, or (E)xit.")
