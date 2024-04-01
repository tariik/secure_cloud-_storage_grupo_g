from ast import arg
import os
import base64
from cryptography.fernet import Fernet
import getpass
from saltManager import derive_key
from cryptography.exceptions import InvalidKey, InvalidSignature


class Client:
    def __init__(self, args):
        self.derived_key = None
        self.master_key = None
        password = bytes(getpass.getpass(prompt='Enter your password for Master Key:'), 'utf-8')
        self.generateMasterKey(password)
        print()
        if self.master_key:
            if "encrypt_master_key" in args and args["encrypt_master_key"]:
                self.fernet = Fernet(self.master_key)
                self.encryptAllFilesWithMasterKey()

            elif "encrypt_data_key" in args and args["encrypt_data_key"]:
                # Ask the user for a password to protect the master key
                self.encryptEachFileWithDataKey()

            elif "decrypt" in args and args["decrypt"] != '':
                self.decryptFile(args["decrypt"].split("/")[-1])

            else:
                print("Invalid arguments...")
                return

    def generateMasterKey(self, password):
        for root, dirs, files in os.walk('./samples/'):
            if 'master_key.key' not in files:
                # Generate a unique master key
                self.master_key = Fernet.generate_key()

                print("Master key generated")
                self.derived_key = derive_key(password, True)
                self.encryptMasterKey()

            else:
                # Get master key from file
                with open('./samples/master_key.key', 'rb') as fileMasterKey:
                    self.master_key = fileMasterKey.read()

                print("Existing Master key")
                self.derived_key = derive_key(password)
                self.decryptMasterKey()

        print("The master key is:", self.master_key)

    def encryptMasterKey(self):
        fernet = Fernet(self.derived_key)

        with open('./samples/master_key.key', 'wb') as f:
            f.write(fernet.encrypt(self.master_key))

    def decryptMasterKey(self):
        try:
            fernet = Fernet(self.derived_key)

            with open('./samples/master_key.key', 'rb') as f:
                encrypted_master_key = f.read()

            self.master_key = fernet.decrypt(encrypted_master_key)
        except:
            print("Incorrect password!")
            self.master_key = None

    def encryptAllFilesWithMasterKey(self):
        # Encrypt all files in the current directory and its subdirectories
        for root, dirs, files in os.walk('./samples/'):
            for file in files:
                # Ignore the master key file
                if file == 'master_key.key':
                    continue

                # Read the contents of the file
                with open(os.path.join(root, file), 'rb') as f:
                    content = f.read()

                # Encrypt the content and write the result to the same file
                encrypted_content = self.fernet.encrypt(content)
                with open(os.path.join(root, file), 'wb') as f:
                    f.write(encrypted_content)

    def encryptEachFileWithDataKey(self):
        # Encrypt all files in the current directory and its subdirectories
        for root, dirs, files in os.walk('./samples/'):
            for file in files:
                # Ignore the master key and dek files
                if file == 'master_key.key' or '.key' in file or file.split('.')[0] + '.key' in files:
                    continue

                # Load the file data to be encrypted
                with open(os.path.join(root, file), 'rb') as fileToEncrypt:
                    file_data = fileToEncrypt.read()

                # Generate a new DEK for the file
                dek = Fernet.generate_key()

                # Encrypt the file using the DEK and Master Key
                fernet = Fernet(dek)
                encrypted_file = fernet.encrypt(file_data)

                # Encrypt the DEK with MK and password
                fernet2 = Fernet(self.master_key)
                encrypted_key = fernet2.encrypt(dek)

                # Save the encrypted file and encrypted DEK to files
                with open(os.path.join(root, file), 'wb') as fileEncrypted:
                    fileEncrypted.write(encrypted_file)

                with open(os.path.join(root, file.split('.')[0] + '.key'), 'wb') as fileKey:
                    fileKey.write(encrypted_key)

                print(f'File {file} encrypted')

    def decryptFile(self, name_file):
        dataEncryptionKeyExist = False
        for root, dirs, files in os.walk('./samples/'):
            with open(os.path.join(root, name_file), 'rb') as fileToDecrypt:
                self.file_data = fileToDecrypt.read()

            if name_file.split(".")[0] + '.key' in files:
                with open(os.path.join(root, name_file.split(".")[0] + '.key'), 'rb') as keyToDecrypt:
                    self.key_data = keyToDecrypt.read()
                    dataEncryptionKeyExist = True

        if dataEncryptionKeyExist:
            fernet = Fernet(self.master_key)
            key_decrypted = fernet.decrypt(self.key_data)

            fer = Fernet(key_decrypted)
            file_decrypted = fer.decrypt(self.file_data)

        else:
            fer = Fernet(self.master_key)
            file_decrypted = fer.decrypt(self.file_data)

        print(f"File decrypted: {file_decrypted.decode('utf-8')}")
