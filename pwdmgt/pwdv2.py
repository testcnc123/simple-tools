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
from datetime import datetime
import sys


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
    if not os.path.exists(filepath):
        # If the file doesn't exist, create it and consider it valid for first-time use
        open(filepath, 'w').close()
        return True
    try:
        with open(filepath, 'rb') as file:
            encrypted_key = file.readline().strip()
            if not encrypted_key:
                return True  # Empty file is considered valid
            fernet.decrypt(encrypted_key)  # Attempt to decrypt the first key to validate the passkey
        return True
    except Exception:
        return False


def store_entry(fernet: Fernet, key: str, url: str, username: str, password: str, filepath: str):
    """Encrypt and store key, URL, username, password, and timestamp in a file."""
    encrypted_key = fernet.encrypt(key.encode())
    encrypted_url = fernet.encrypt(url.encode())
    encrypted_username = fernet.encrypt(username.encode())
    encrypted_password = fernet.encrypt(password.encode())
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    encrypted_timestamp = fernet.encrypt(timestamp.encode())

    # Save all encrypted fields to the file
    with open(filepath, 'ab') as file:
        file.write(encrypted_key + b'\n' + encrypted_url + b'\n' + encrypted_username + b'\n' +
                   encrypted_password + b'\n' + encrypted_timestamp + b'\n')


def list_entries(fernet: Fernet, filepath: str) -> list:
    """List all stored entries with timestamps in the file."""
    entries = []
    try:
        with open(filepath, 'rb') as file:
            while True:
                encrypted_key = file.readline().strip()
                if not encrypted_key:
                    break  # End of file
                encrypted_url = file.readline().strip()
                encrypted_username = file.readline().strip()
                encrypted_password = file.readline().strip()
                encrypted_timestamp = file.readline().strip()

                # Try to decrypt all fields
                try:
                    decrypted_key = fernet.decrypt(encrypted_key).decode()
                    decrypted_url = fernet.decrypt(encrypted_url).decode()
                    decrypted_username = fernet.decrypt(encrypted_username).decode()
                    decrypted_timestamp = fernet.decrypt(encrypted_timestamp).decode()
                    entries.append((decrypted_key, decrypted_url, decrypted_username, decrypted_timestamp, encrypted_password))
                except Exception:
                    # Append a placeholder if decryption fails
                    entries.append(("[Cannot display: Invalid passkey or corrupted entry]", "Unknown", "Unknown", "Unknown", None))
    except FileNotFoundError:
        print("No entries found. Store an entry first.")
    return entries


def retrieve_password(fernet: Fernet, encrypted_password: bytes) -> str:
    """Retrieve and decrypt the password for a selected entry."""
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
filepath = 'key_entries.enc'

# Prompt for master passkey with validation
while True:
    master_passkey = getpass("Enter master passkey to access stored entries: ")
    fernet = Fernet(derive_key(master_passkey))
    
    # Validate the passkey by trying to decrypt the first entry in the file (if it exists)
    if validate_passkey(fernet, filepath):
        break
    else:
        print("Incorrect master passkey. Please try again.")

# Action loop
while True:
    action = input("\nDo you want to (S)tore, (R)etrieve an entry, or (E)xit? ").strip().lower()

    if action == 's':
        key = input("Enter a unique identifier for this entry (e.g., website name): ")
        url = input("Enter the URL (optional): ")
        username = input("Enter the username (optional): ")
        password = getpass("Enter the password: ")
        store_entry(fernet, key, url, username, password, filepath)
        print("Entry stored securely.")

    elif action == 'r':
        entries = list_entries(fernet, filepath)

        if entries:
            print("\nAvailable entries:")
            for i, (key_name, url, username, timestamp, _) in enumerate(entries, 1):
                print(f"{i}. {key_name} | URL: {url} | Username: {username} | Stored on: {timestamp}")

            choice = int(input("\nEnter the number of the entry you want to retrieve: "))
            selected_key, selected_url, selected_username, _, encrypted_password = entries[choice - 1]

            if "[Cannot display" not in selected_key:
                try:
                    password = retrieve_password(fernet, encrypted_password)
                    print(f"\nURL: {selected_url}\nUsername: {selected_username}\nPassword copied to clipboard.")
                    pyperclip.copy(password)  # Copy password to clipboard

                    # Start the countdown to clear the clipboard, blocking all other actions
                    clear_clipboard_with_interrupt()

                except Exception as e:
                    print("Failed to retrieve entry. Ensure the passkey is correct and the entry is valid.")
            else:
                print("Invalid selection. Please try again with a valid entry.")
        else:
            print("No entries found.")
    
    elif action == 'e':
        print("Exiting the program.")
        break

    else:
        print("Invalid action. Please choose (S)tore, (R)etrieve, or (E)xit.")
