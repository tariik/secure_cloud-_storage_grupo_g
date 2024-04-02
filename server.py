from flask import Flask, request
import os
from Crypto.Cipher import AES
from cryptography.fernet import Fernet
import pickle
import random
import string
from OpenSSL import crypto, SSL
import base64

BLOCK_SIZE = 1024 * 1024 # 1MB chunk size

def ssl_creat():
     # Generate a new private key
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # Generate a new self-signed certificate
    cert = crypto.X509()
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")

    # Save the private key and certificate to files
    with open("key.pem", "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    with open("cert.pem", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

def get_master_key():
    if not os.path.isfile("key.key"):
        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)

    with open("key.key", "rb") as key_file:
        return key_file.read().decode()

def encrypt_file(file, master_key):
    with open(file, 'rb') as f:
        original_file= f.read()
    
    f=Fernet(master_key)
    encrypted=f.encrypt(original_file)
    with open(file,'wb') as f:
        f.write(encrypted)
        

def decrypt_file(key, filename):
    f = Fernet(key)
    with open(filename, 'rb') as file:
        encrypted_file = file.read()
    return f.decrypt(encrypted_file)
     
    



def generate_random_string(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

def encrypt_chunk(file):
	# Generate a random encryption key and IV
	key = os.urandom(32)
	iv = os.urandom(16)

	# Create a list to store the metadata for each encrypted chunk
	metadata_list = []

	# Open the input file and read it in chunks
	with open(file, 'rb') as in_file:

		chunk_index = 0
		while True:
			# Read a chunk of data from the input file
			chunk_data = in_file.read(BLOCK_SIZE)
			
			# If there is no more data to read, break out of the loop
			if not chunk_data:
				break
			
			# Pad the chunk with zeroes if necessary
			if len(chunk_data) < BLOCK_SIZE:
				chunk_data += b'\x00' * (BLOCK_SIZE - len(chunk_data))
			
			# Encrypt the chunk with a randomly generated key and IV
			cipher = AES.new(key, AES.MODE_CBC, iv)
			encrypted_chunk = cipher.encrypt(chunk_data)
			
			# Write the encrypted chunk to a separate file
			chunk_name = f'{generate_random_string(32)}-{file}'
			chunk_path = os.path.join("chunk", chunk_name)
			with open(chunk_path, 'wb') as out_file:
				out_file.write(encrypted_chunk)
			
			# Add the metadata for the encrypted chunk to the metadata list
			metadata_list.append({
				'chunk_index': chunk_index,
				'key': key,
				'iv': iv,
				'chunk_name': chunk_name
			})
			
			# Generate a new random key and IV for the next chunk
			key = os.urandom(32)
			iv = os.urandom(16)
			
			# Increment the chunk index
			chunk_index += 1
	# Save the metadata list to a file
	if not os.path.exists("metadata"):
		os.makedirs("metadata")
	meta_path = os.path.join("metadata", file)
	with open(meta_path, 'wb') as metadata_file:
		pickle.dump(metadata_list, metadata_file)
                
def decrypt_chunk(file):
    ##steeel not working
    # Load the metadata list from the file
    with open(file, 'rb') as metadata_file:
        metadata_list = pickle.load(metadata_file)

    # Create a buffer to store the decrypted chunks
    decrypted_buffer = bytearray()

    # Decrypt each chunk using its metadata
    for metadata in metadata_list:
        # Read the encrypted chunk from the corresponding file
        chunk_path = os.path.join("chunk", metadata['chunk_name'])
        with open(chunk_path, 'rb') as in_file:
            encrypted_chunk = in_file.read()

        # Decrypt the chunk with its key and IV
        cipher = AES.new(metadata['key'], AES.MODE_CBC, metadata['iv'])
        decrypted_chunk = cipher.decrypt(encrypted_chunk)

        # Remove any padding added during encryption
        decrypted_chunk = decrypted_chunk.rstrip(b'\x00')

        # Add the decrypted chunk to the buffer
        decrypted_buffer += decrypted_chunk

    # Write the decrypted data to a new file
    decrypted_file = file.replace('.enc', '')
    with open(decrypted_file, 'wb') as out_file:
        out_file.write(decrypted_buffer)
                

def check_file_in_directories(file_name):
    metadata_dir = "metadata"
    storage_dir = "storage"
    
    # Check if the file exists in the metadata directory
    metadata_path = os.path.join(metadata_dir, file_name)
    if os.path.exists(metadata_path):
        return metadata_dir
    
    # Check if the file exists in the storage directory
    storage_path = os.path.join(storage_dir, file_name)
    if os.path.exists(storage_path):
        return storage_dir
    
    # If the file doesn't exist in either directory, return None
    return 'file dosn''t exist'






app = Flask(__name__)


@app.route("/")
def index():
    metadata_dir = "metadata"
    storage_dir = "storage"
    metadata_files = os.listdir(metadata_dir)
    storage_files = os.listdir(storage_dir)
    html= """
		<!DOCTYPE html>
		<html>
		<head>
			<title>Exemple de formulaire pour télécharger plusieurs fichiers et des boutons radio</title>
			<!-- Inclure les fichiers CSS de Bootstrap -->
			<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
		</head>
		<body>
			<div class="container">
				<h1>Télécharger plusieurs fichiers et sélectionner une option</h1>
				<form method="POST" action="/upload" enctype="multipart/form-data">
					<div class="form-group">
						<label for="file">Fichiers à télécharger :</label>
						<input type="file" class="form-control-file" id="file" name="file[]" multiple>
					</div>
					<div class="form-group">
						<label>Options :</label>
						<div class="form-check">
							<input class="form-check-input" type="radio" name="option" id="option1" value="Master_Key">
							<label class="form-check-label" for="option1">
								Customer 
		Master Key to protect 
		all the files of the user.
							</label>
						</div>
						<div class="form-check">
							<input class="form-check-input" type="radio" name="option" id="option2" value="chunks">
							<label class="form-check-label" for="option2">
								Divide files into chunk
							</label>
						</div>
						<div class="form-check">
							<input class="form-check-input" type="radio" name="option" id="option3" value="option3">
							<label class="form-check-label" for="option3">
								Implement re-encryption
		from old Master Key to 
		current Master Key 
		(requires Key Rotation).
							</label>
						</div>
					</div>
					<button type="submit" class="btn btn-primary">UPLOAD</button>
				</form>
				
				<!-- Afficher la liste des fichiers sélectionnés -->
				<div id="file-list"></div>

				<h1>Liste of files :</h1>
				<form method='POST' action='/download'><ul>"""
    for filename in metadata_files:
        html += f"<li><input type='checkbox' name='selected_files' value='{filename}'>{filename}</li>"
    for filename in storage_files:
        html += f"<li><input type='checkbox' name='selected_files' value='{filename}'>{filename}</li>"
    html += """</ul>
    <button type='submit' class='btn btn-primary'>Download</button></form>
			</div>
		</body>
		</html>"""

    # Retourner le contenu HTML généré
    return html


@app.route('/upload', methods=["POST"])
def upload():
    
    uploaded_files = request.files.getlist("file[]")
    selected_option = request.form.get("option")
    # Create the "uploads" folder if it doesn't exist
    
    if selected_option == "Master_Key":
        if not os.path.exists("storage"):
            os.makedirs("storage")
        encrypted_files = []
        master_key=get_master_key()
        print(master_key)
        for file in uploaded_files:
            # Save the uploaded file to disk
            file_path = os.path.join("storage", file.filename)
            file.save(file_path)
            # Encrypt the file with the master key
            encrypted_file = encrypt_file(file_path, master_key)
        return "Files uploaded successfully!" 
    elif selected_option == "chunks":
        if not os.path.exists("chunk"):
            os.makedirs("chunk")
        for file in uploaded_files:
            # Save the uploaded file to disk
            file_path = os.path.join(file.filename)
            file.save(file_path)
            # Encrypt the file with the master key
            encrypted_file = encrypt_chunk(file_path)
        return "Files uploaded successfully!"
    
@app.route('/download', methods=["POST"])
def download():
    master_key=get_master_key()
    print(master_key)
    selected_files = request.form.getlist('selected_files')
    # Faire quelque chose avec les fichiers sélectionnés
    for file_name in selected_files:
        if(check_file_in_directories(file_name)=='storage'):
             file_path = os.path.join("storage", file_name)
             decrypt_file(master_key,file_path)
        elif(check_file_in_directories(file_name)=='metadata'):
             file_path = os.path.join("metadata", file_name)
             decrypt_chunk(file_path)
               
    return "Fichiers sélectionnés: " + ", ".join(selected_files)
     
if __name__ == "__main__":
    ssl_creat()
    app.run(ssl_context=('cert.pem', 'key.pem'))
