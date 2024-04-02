from ast import arg
import os, json, sys, time
import base64
from cryptography.fernet import Fernet
import getpass
from saltManager import derive_key
import shutil
import datetime

class Client:
    def __init__(self, args):
        self.root_folder = './client-side/'
        self.current_folder = './client-side/'
        self.config_folder = ''
        password = bytes(getpass.getpass(prompt='Enter your password for Master Key:'), 'utf-8')
        self.createConfigFile()
        if "encrypt_master_key" in args and args["encrypt_master_key"]:
            self.generateMasterKey(password)
            self.fernet = Fernet(self.master_key)
            if args["encrypt_master_key"] == '*':
                self.config_folder = '.\\client-side\\'
                self.encryptAllFilesWithMasterKey()
            else:
                self.encryptFileWithMasterKey(args["encrypt_master_key"])

        elif "encrypt_data_key" in args and args["encrypt_data_key"]:
            self.generateMasterKey(password)
            if args["encrypt_data_key"] == '*':
                self.config_folder = '.\\client-side\\'
                self.encryptAllFilesWithDataKey()
            else:
                self.encryptFileWithDataKey(args["encrypt_data_key"])

        elif "key_timeout" in args and args["key_timeout"] and args["key_timeout"] != 0:
            self.moveFilesToFolder()
            self.generateMasterKey(password)
            self.fernet = Fernet(self.master_key)
            self.encryptAllFilesWithMasterKey()
            while True:
                print("********************************* Regenerating keys *********************************")
                time.sleep(args["key_timeout"])
                self.decryptFilesWithMasterKey()
                os.remove(self.config_folder + 'master_key.key')
                self.generateMasterKey(password)
                self.fernet = Fernet(self.master_key)
                self.encryptAllFilesWithMasterKey()

        elif "decrypt" in args and args["decrypt"] and args["decrypt"] != '':
            self.generateMasterKey(password)
            self.decryptFile(args["decrypt"])

        elif "decrypt_rotation" in args and args["decrypt_rotation"] != '':
            path = args['decrypt_rotation'].split('\\')
            self.config_folder = '.\\client-side\\' + path[-2] + '\\'
            self.current_folder = './client-side/' + path[-2] + '/'
            self.generateMasterKey(password)
            self.decryptFile(args['decrypt_rotation'])

        else:
            print("Invalid arguments...")
            return

    def createConfigFile(self):
        for root, dirs, files in os.walk(self.root_folder):
            if 'config.json' not in files:
                with open(self.root_folder + 'config.json', 'w') as f:
                    f.write("{}")
            
            else:
                with open(self.root_folder + 'config.json', 'r') as f:
                    self.config = json.loads(f.read())

    def editConfigFile(self, file, property):
        file = self.config_folder + file
        with open(self.root_folder + 'config.json', 'w') as conf:
            if file not in self.config:
                self.config[file] = {property: True}
            
            else:
                self.config[file][property] = True

            conf.write(json.dumps(self.config))

    def generateMasterKey(self, password):
        for root, dirs, files in os.walk(self.current_folder):
            if 'master_key.key' not in files:
                # Generate a unique master key
                self.master_key = Fernet.generate_key()
                
                print("Master key generated")
                self.derived_key = derive_key(password, True)
                self.encryptMasterKey()

            else:
                # Get master key from file
                with open(self.current_folder + 'master_key.key', 'rb') as fileMasterKey:
                    self.master_key = fileMasterKey.read()

                print("Existing Master key")
                self.derived_key = derive_key(password)
                self.decryptMasterKey()

        print("The master key is:", self.master_key)


    def encryptMasterKey(self):
        fernet = Fernet(self.derived_key)

        with open(self.current_folder + 'master_key.key', 'wb') as f:
            f.write(fernet.encrypt(self.master_key))


    def decryptMasterKey(self):
        try:
            fernet = Fernet(self.derived_key)

            with open(self.current_folder + '/master_key.key', 'rb') as f:
                encrypted_master_key = f.read()

            self.master_key = fernet.decrypt(encrypted_master_key)
        except:
            self.master_key = None
            sys.exit("Incorrect password!")

    def checkIfFileIsAlreadyEncrypted(self, file):
        file = self.config_folder + file
        fileAlreadyEncrypted = False
        if file in self.config:
            print(f'File {file} is already encrypted...')
            fileAlreadyEncrypted = True

        return fileAlreadyEncrypted

    def encryptAllFilesWithMasterKey(self):
        # Encrypt all files in the current directory and its subdirectories
        for root, dirs, files in os.walk(self.current_folder):
            for file in files:
                # Ignore the master key file
                if file == 'master_key.key' or file == 'config.json'  or '.key' in file or file.split('.')[0] + '.key' in files:
                    continue

                fileAlreadyEncrypted = self.checkIfFileIsAlreadyEncrypted(file)
                if fileAlreadyEncrypted == False:
                    # Read the contents of the file
                    with open(os.path.join(root, file), 'rb') as f:
                        content = f.read()
                    # Encrypt the content and write the result to the same file
                    encrypted_content = self.fernet.encrypt(content)
                    with open(os.path.join(root, file), 'wb') as f:
                        f.write(encrypted_content)

                    self.editConfigFile(file, 'encrypted_with_master_key')
                        
                    print(f'File {file} encrypted...')

    def encryptFileWithMasterKey(self, path):
        fileAlreadyEncrypted = self.checkIfFileIsAlreadyEncrypted(path)
        if fileAlreadyEncrypted == False:
            # Read the contents of the file
            with open(os.path.join(path), 'rb') as f:
                content = f.read()

            # Encrypt the content and write the result to the same file
            encrypted_content = self.fernet.encrypt(content)
            with open(os.path.join(path), 'wb') as f:
                f.write(encrypted_content)

            self.editConfigFile(path, 'encrypted_with_master_key')

            print(f'File {path} encrypted...')

    def decryptFilesWithMasterKey(self):
        for root, dirs, files in os.walk(self.current_folder):
            for file in files:
                # Ignore the master key and dek files
                if file == 'master_key.key' or file == 'config.json'  or '.key' in file or file.split('.')[0] + '.key' in files:
                    continue

                self.decryptFile(self.config_folder + file)
                # if self.current_folder + data_file in self.config:
                #     self.config[self.current_folder + data_file]['hasKeyRotation'] = True

                with open(os.path.join(self.config_folder + file), 'wb') as f:
                    f.write(self.file_decrypted)
                
                del self.config[self.config_folder + file]

                with open(self.root_folder + 'config.json', 'w') as conf:
                    conf.write(json.dumps(self.config))
                

    def encryptAllFilesWithDataKey(self):
        # Encrypt all files in the current directory and its subdirectories
        for root, dirs, files in os.walk(self.root_folder):
            for file in files:
                # Ignore the master key and dek files
                if file == 'master_key.key' or file == 'config.json'  or '.key' in file or file.split('.')[0] + '.key' in files:
                    continue

                fileAlreadyEncrypted = self.checkIfFileIsAlreadyEncrypted(file)
                if fileAlreadyEncrypted == False:
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

                    self.editConfigFile(file, 'encrypted_with_data_key')

                    print(f'File {file} encrypted')

    def encryptFileWithDataKey(self, file):
        fileAlreadyEncrypted = self.checkIfFileIsAlreadyEncrypted(file)
        if fileAlreadyEncrypted == False:
            # Load the file data to be encrypted
            with open(os.path.join(file), 'rb') as fileToEncrypt:
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
            with open(os.path.join(file), 'wb') as fileEncrypted:
                fileEncrypted.write(encrypted_file)

            with open(os.path.join(file.split('.')[0] + '.key'), 'wb') as fileKey:
                fileKey.write(encrypted_key)
                
            self.editConfigFile(file, 'encrypted_with_data_key')

            print(f'File {file} encrypted')
                

    def decryptFile(self, file):
        if file in self.config:
            with open(os.path.join(file), 'rb') as fileToDecrypt:
                self.file_data = fileToDecrypt.read()

            if 'encrypted_with_master_key' in self.config[file] and self.config[file]['encrypted_with_master_key']:
                fer = Fernet(self.master_key)
                self.file_decrypted = fer.decrypt(self.file_data)
            
            elif 'encrypted_with_data_key' in self.config[file] and self.config[file]['encrypted_with_data_key']:
                file = (file.split(".")[-2]).split("\\")[-1]
                with open(os.path.join(self.current_folder + file + '.key'), 'rb') as keyToDecrypt:
                    self.key_data = keyToDecrypt.read()

                fernet = Fernet(self.master_key)
                key_decrypted = fernet.decrypt(self.key_data)

                fer = Fernet(key_decrypted)
                self.file_decrypted = fer.decrypt(self.file_data)

            elif 'hasKeyRotation' in self.config[file] and self.config[file]['hasKeyRotation']:
                print("hi")

            print(f"File decrypted: {self.file_decrypted.decode('utf-8')}")
        else:
            print(f'File {file} not found!')


    def moveFilesToFolder(self):
        # Get a list of numeric identifiers from existing folders
        identifiers = [int(folder.split("_")[1]) for folder in os.listdir(self.root_folder) if folder.startswith("MKR_")]

        # Get the last consecutive number
        last_consecutive = max(identifiers) if identifiers else 0

        # Create a new folder with the next consecutive number
        new_folder_name = f"MKR_{last_consecutive + 1}"
        new_folder_path = os.path.join(self.root_folder, new_folder_name)
        self.config_folder = '.\\client-side\\' + new_folder_name + '\\'

        # Check if the folder already exists
        if not os.path.exists(new_folder_path):
            os.mkdir(new_folder_path)
            print("Folder", new_folder_name, "has been created.")
            self.current_folder = new_folder_path +'/'

        # Check files that aren't encrypted yet
        files = [f for f in os.listdir(self.root_folder) if os.path.isfile(os.path.join(self.root_folder, f))]
        for file in files:
            # Ignore the master key and dek files
            if file == 'master_key.key' or '.key' in file or file.split('.')[0] + '.key' in files or file == 'config.json':
                continue

            fileIsAlreadyEncrypted = self.checkIfFileIsAlreadyEncrypted(file)
            if fileIsAlreadyEncrypted == False:
                shutil.move(self.root_folder + file, self.current_folder)
                print(f'File {file} moved to {self.current_folder}')

