import os
import json
from cryptography.fernet import Fernet, InvalidToken

class PasswordManager:
    def __init__(self, key_file='key.key', credentials_file='credentials.json'):
        self.key_file = key_file # File to store the encryption key
        self.credentials_file = credentials_file # File to store encrypted credentials
        self.key = self.load_or_generate_key() # Load or generate the encryption key

    def load_or_generate_key(self): # Check if the key file exists  
        if not os.path.exists(self.key_file): 
            key = Fernet.generate_key() # Generate a new encryption key
            self.save_key(key) # Save the generated key to file
            return key
        return self.load_key()

    def save_key(self, key): # Save the encryption key to file
        with open(self.key_file, 'wb') as file:
            file.write(key)

    def load_key(self): # Load the encryption key from file
        try: 
            with open(self.key_file, 'rb') as file:
                return file.read()
        except Exception as e:
            print(f"Error loading key: {str(e)}") # Error handling 
            raise

    def encrypt_data(self, data): # Encrypt the provided data using the Fernet object
        f = Fernet(self.key) # Create a Fernet object with the encryption key
        return f.encrypt(data.encode()) # Encrypt the data and return it

    def decrypt_data(self, encrypted_data): # Decrypt the file using the Fernet object
        f = Fernet(self.key)
        try:
            return f.decrypt(encrypted_data).decode()
        except InvalidToken:
            print("Error: Decryption failed. The data may be corrupted or invalid.") # Error handling 
            return None

    def save_credentials(self, credentials): # Saves the credentials 
        with open(self.credentials_file, 'wb') as file:
            file.write(credentials)

    def load_credentials(self):
        if not os.path.exists(self.credentials_file): # Error handling 
            return b''
        try:
            with open(self.credentials_file, 'rb') as file:
                return file.read()
        except Exception as e:
            print(f"Error loading credentials: {str(e)}")
            return b''

    def add_credentials(self, credentials_list): # Add multiple credentials, checking for existing usernames
        existing_credentials = self.load_existing_credentials()
        for username, password in credentials_list:
            if username in existing_credentials:
                print(f"Warning: Credential for '{username}' already exists. It will be overwritten.")
            existing_credentials[username] = password # Add/overwrite the credential
        self.save_all_credentials(existing_credentials) # Save the updated credentials

    def load_existing_credentials(self):
        encrypted_credentials = self.load_credentials()
        if not encrypted_credentials:
            return {}
        decrypted_credentials = self.decrypt_data(encrypted_credentials)
        if decrypted_credentials is None:
            return {}
        try:
            return json.loads(decrypted_credentials)
        except json.JSONDecodeError:
            print("Error: Failed to decode the credentials. The file may be corrupted.") # Error handling if file couldn't decrypt 
            return {}

    def save_all_credentials(self, credentials):
        credentials_json = json.dumps(credentials)
        encrypted_credentials = self.encrypt_data(credentials_json)
        self.save_credentials(encrypted_credentials)

    def delete_credential(self, username): # Deletes the credentials saved 
        existing_credentials = self.load_existing_credentials()
        if username in existing_credentials:
            del existing_credentials[username]
            self.save_all_credentials(existing_credentials)
            print(f"Credential for '{username}' has been deleted.")
        else:
            print(f"No credential found for '{username}'.")

    def view_credentials(self): # Displays the existing credentials on file 
        try:
            existing_credentials = self.load_existing_credentials()
            if existing_credentials:
                for username, password in existing_credentials.items():
                    print(f"Username: {username}, Password: {password}")
            else:
                print("No credentials found.")
        except Exception as e:
            print("Failed to load credentials:", str(e))

def main():
    manager = PasswordManager()
    
    while True:
        print('\n~~~Welcome to the encrypted password manager!~~~') # User menu 
        action = input("Do you want to (add), (view), (delete), or (exit) your credentials?\n").strip().lower()

        if action == 'add':
            credentials_list = []
            while True:
                username = input("Enter your username (or type 'done' to finish):")
                if username.lower() == 'done': # User is able to enter/store multiple credentials 
                    break
                if not username.strip():
                    print("Username cannot be empty. Please try again.") # User has to enter a name
                    continue
                password = input("Enter your password: ")
                credentials_list.append((username, password)) # List stores both username/password
            if credentials_list:
                manager.add_credentials(credentials_list)
                print("Credentials saved securely.") # Display if added securely on file 
        
        elif action == 'view':
            manager.view_credentials() # Displays all added credentials on file 

        elif action == 'delete': # User required to input username in order to delete 
            username = input("Enter the username of the credential to delete: ")
            if username.strip():
                manager.delete_credential(username)
            else:
                print("Username cannot be empty.") # Error handling 

        elif action == 'exit':
            print("Exiting the Password Manager.")
            break

        else: # More error handling 
            print("Invalid action. Please type 'add', 'view', 'delete', or 'exit'.")

if __name__ == "__main__": 
    main()