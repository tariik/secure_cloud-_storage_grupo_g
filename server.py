from Crypto.Cipher import AES
from flask import Flask, request
import os
from cryptography.fernet import Fernet
import pickle
import random
import string

BLOCK_SIZE = 1024 * 1024  # 1MB chunk size


def get_master_key():
    if not open("key.key", "rb").read():
        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)
    return open("key.key", "rb").read()


def encrypt_file(file, master_key):
    with open(file, 'rb') as f:
        original_file = f.read()

    f = Fernet(master_key)
    encrypted = f.encrypt(original_file)
    with open(file, 'wb') as f:
        f.write(encrypted)


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
    meta_path = os.path.join("metadata", file)
    with open(meta_path, 'wb') as metadata_file:
        pickle.dump(metadata_list, metadata_file)


app = Flask(__name__)


@app.route("/")
def index():
    return """
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
			<button type="submit" class="btn btn-primary">Envoyer</button>
		</form>
		
		<!-- Afficher la liste des fichiers sélectionnés -->
		<div id="file-list"></div>
	</div>
</body>
</html>
"""


@app.route('/upload', methods=["POST"])
def upload():
    uploaded_files = request.files.getlist("file[]")
    selected_option = request.form.get("option")
    # Create the "uploads" folder if it doesn't exist

    if selected_option == "Master_Key":
        if not os.path.exists("storage"):
            os.makedirs("storage")
        encrypted_files = []
        master_key = get_master_key()
        print(master_key)
        for file in uploaded_files:
            # Save the uploaded file to disk
            file_path = os.path.join("storage", file.filename)
            print(file_path)
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
            print(file_path)
            file.save(file_path)
            # Encrypt the file with the master key
            encrypted_file = encrypt_chunk(file_path)
        return "Files uploaded successfully!"


if __name__ == "__main__":
    app.run(ssl_context=('cert.pem', 'key.pem'))
