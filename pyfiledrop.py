#!/usr/bin/env python
# -*- coding: utf-8 -*-

# source: https://github.com/cdgriffith/pyfiledrop

from pathlib import Path
from threading import Lock
from collections import defaultdict
import shutil, os,  base64
from google.cloud import kms as gkms
import argparse
import getpass
import uuid, json
from bottle import Bottle, route, run, request, error, response, HTTPError, static_file
from werkzeug.utils import secure_filename
from OpenSSL import crypto, SSL
from cheroot.wsgi import Server as WSGIServer
from cheroot.ssl.builtin import BuiltinSSLAdapter
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from saltManager import derive_key
from cryptography.fernet import Fernet
import access_google_kms as kms
from google.api_core.exceptions import AlreadyExists
import google.protobuf
import boto3

with open('credentials.json') as credentials:
    credentials = json.load(credentials)

session = boto3.Session(
    aws_access_key_id=credentials['ACCESS_KEY_ID'],
    aws_secret_access_key=credentials['SECRET_ACCESS_KEY'],
    region_name=credentials['REGION_NAME']
)
kms = session.client("kms")


storage_path: Path = Path(__file__).parent / "storage"
chunk_path: Path = Path(__file__).parent / "chunk"

allow_downloads = True
dropzone_cdn = "https://cdnjs.cloudflare.com/ajax/libs/dropzone"
dropzone_version = "5.7.6"
dropzone_timeout = "120000"
dropzone_max_file_size = "100000"
dropzone_chunk_size = "1000000"
dropzone_parallel_chunks = "true"
dropzone_force_chunking = "true"
MASTER_KEY = None



app = Bottle()
lock = Lock()
chucks = defaultdict(list)

@error(500)
def handle_500(error_message):
    response.status = 500
    response.body = f"Error: {error_message}"
    return response


@app.route("/")
def index():
    index_file = Path(__file__) / "index.html"
    if index_file.exists():
        return index_file.read_text()
    return get_base_html()


@app.route("/upload", method="POST")
def upload():
    file = request.files.get("file")
    if not file:
        raise HTTPError(status=400, body="No file provided")

    dz_uuid = request.forms.get("dzuuid")
    if not dz_uuid:
        # Assume this file has not been chunked
        with open(storage_path / f"{uuid.uuid4()}_{secure_filename(file.filename)}", "wb") as f:
            file.save(f)
        return "File Saved"

    # Chunked download
    try:
        current_chunk = int(request.forms["dzchunkindex"])
        total_chunks = int(request.forms["dztotalchunkcount"])
    except KeyError as err:
        raise HTTPError(status=400, body=f"Not all required fields supplied, missing {err}")
    except ValueError:
        raise HTTPError(status=400, body=f"Values provided were not in expected format")

    save_dir = chunk_path / dz_uuid

    chunk_dir = chunk_path / file.filename
    chunk_keys = chunk_path / file.filename / "keys"
    chunk_chunks = chunk_path / file.filename / "chunks"

    if not save_dir.exists():
        save_dir.mkdir(exist_ok=True, parents=True)
    if not chunk_dir.exists():
        chunk_dir.mkdir(exist_ok=True, parents=True)
        chunk_keys.mkdir(exist_ok=True, parents=True)
        chunk_chunks.mkdir(exist_ok=True, parents=True)
        
    # Save the individual chunk
    dek = generate_dek()
    nonce = os.urandom(12)
    cipher = Cipher(algorithm=algorithms.AES256(MASTER_KEY), mode=modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(chunk_chunks / str(current_chunk), "wb") as f:
        encrypted_chunk = encrypt_chunk(dek,nonce,file.file.read())
        f.write(encrypted_chunk)
        data = {
        "chunk_index": current_chunk,
        "key": f"{chunk_dir}/keys/{current_chunk}.key",
        "nonce": nonce.hex(),
        "chunk_size": len(encrypted_chunk)
        }
        with open(chunk_dir /"config.json", "ab") as archivo:
            archivo.write(json.dumps(data).encode("utf-8"))

    with open(chunk_dir /"keys"/ f"{current_chunk}.key", "wb") as archivo:
        dek_encripted = encryptor.update(dek)
        archivo.write(dek_encripted)



    # See if we have all the chunks downloaded
    with lock:
        chucks[dz_uuid].append(current_chunk)
        completed = len(chucks[dz_uuid]) == total_chunks

    # Concat all the files into the final file when all are downloaded
    if completed:
        with open(storage_path / f"{dz_uuid}", "wb") as f:
            for file_number in range(total_chunks):
                f.write((chunk_chunks / str(file_number)).read_bytes())
        print(f"{file.filename} has been uploaded")

    return "Chunk upload successful"


@app.route("/download/<name>")
def download(name):
    path = chunk_path / name
    with open(path / "config.json") as f:
        data = json.loads(f.read())
        print(data)
        chunk_index = data["chunk_index"]
        key = data["key"]
        nonce = data["nonce"]
        chunk_size = data["chunk_size"]

    cipher = Cipher(algorithm=algorithms.AES256(MASTER_KEY), mode=modes.GCM(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    print(data)
    
    if not allow_downloads:
        raise HTTPError(status=403)
    for file in path.iterdir():
        if file:
            return static_file(file.name, root=file.parent.absolute(), download=True)
    return HTTPError(status=404)

def generate_dek():
    dek = kms.generate_data_key(KeyId=credentials['KEY_ID'],KeySpec="AES_256")
    return dek["Plaintext"]

def encrypt_chunk(dek, nonce, chunk):
    cipher = chooseEncryptionAlgorithm(dek,nonce)
    encrypted_chunk = cipher.encryptor().update(chunk)
    return encrypted_chunk

def chooseEncryptionAlgorithm(key,nonce):
    if hasattr(args, 'encryption_algorithm'):
        case = args.encryption_algorithm.lower()
        if case == "aes":
            return Cipher(algorithm=algorithms.AES256(key), mode=modes.GCM(nonce), backend=default_backend())
        elif case == "camellia":
            return Cipher(algorithm=algorithms.Camellia(key), mode=modes.CTR(nonce), backend=default_backend())
        elif case == "chacha20":
            return Cipher(algorithm=algorithms.ChaCha20(key,nonce),mode=None, backend=default_backend())
        else:
            return 'Authenticated encyption algorithm not found!'
    elif hasattr(args, 'encryption_algorithm_additionasl_data'):
        case = args.encryption_algorithm_additional_data.lower()
        if case == "aes":
            return Cipher(algorithm=algorithms.AES256(key), mode=modes.GCM(nonce), backend=default_backend())
        elif case == "chacha20":
            return Cipher(algorithm=algorithms.ChaCha20(key, nonce),mode=None, backend=default_backend())
        else:
            return 'Authenticated encyption and additional data algorithm not found!'


def get_base_html():
    return f"""
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <link rel="stylesheet" href="{dropzone_cdn.rstrip('/')}/{dropzone_version}/min/dropzone.min.css"/>
        <link rel="stylesheet" href="{dropzone_cdn.rstrip('/')}/{dropzone_version}/min/basic.min.css"/>
        <script type="application/javascript"
            src="{dropzone_cdn.rstrip('/')}/{dropzone_version}/min/dropzone.min.js">
        </script>
        <title>pyfiledrop</title>
    </head>
    <body>

        <div id="content" style="width: 800px; margin: 0 auto;">
            <h2>Upload new files</h2>
            <form method="POST" action='/upload' class="dropzone dz-clickable" id="dropper" enctype="multipart/form-data">
            </form>

            <h2>
                Uploaded
                <input type="button" value="Clear" onclick="clearCookies()" />
            </h2>
            <div id="uploaded">

            </div>

            <script type="application/javascript">
                function clearCookies() {{
                    document.cookie = "files=; Max-Age=0";
                    document.getElementById("uploaded").innerHTML = "";
                }}

                function getFilesFromCookie() {{
                    try {{ return document.cookie.split("=", 2)[1].split("||");}} catch (error) {{ return []; }}
                }}

                function saveCookie(new_file) {{
                        let all_files = getFilesFromCookie();
                        all_files.push(new_file);
                        document.cookie = `files=${{all_files.join("||")}}`;
                }}

                function generateLink(combo){{
                    const uuid = combo.split('|^^|')[0];
                    const name = combo.split('|^^|')[1];
                    if ({'true' if allow_downloads else 'false'}) {{
                        return `<a href="/download/${{name}}" download="${{name}}">${{name}}</a>`;
                    }}
                    return name;
                }}


                function init() {{

                    Dropzone.options.dropper = {{
                        paramName: 'file',
                        chunking: true,
                        forceChunking: {dropzone_force_chunking},
                        url: '/upload',
                        retryChunks: true,
                        parallelChunkUploads: {dropzone_parallel_chunks},
                        timeout: {dropzone_timeout}, // microseconds
                        maxFilesize: {dropzone_max_file_size}, // megabytes
                        chunkSize: {dropzone_chunk_size}, // bytes
                        init: function () {{
                            this.on("complete", function (file) {{
                                let combo = `${{file.upload.uuid}}|^^|${{file.upload.filename}}`;
                                saveCookie(combo);
                                document.getElementById("uploaded").innerHTML += generateLink(combo)  + "<br />";
                            }});
                        }}
                    }}

                    if (typeof document.cookie !== 'undefined' ) {{
                        let content = "";
                        getFilesFromCookie().forEach(function (combo) {{
                            content += generateLink(combo) + "<br />";
                        }});

                        document.getElementById("uploaded").innerHTML = content;
                    }}

                }}

                init();
                clearCookies();
                

            </script>
        </div>
    </body>
    </html>
    """

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", type=int, default=443, required=False)
    parser.add_argument("--host", type=str, default="localhost", required=False)
    parser.add_argument("-s", "--storage", type=str, default=str(storage_path), required=False)
    parser.add_argument("-c", "--chunks", type=str, default=str(chunk_path), required=False)
    parser.add_argument(
        "--max-size",
        type=str,
        default=dropzone_max_file_size,
        help="Max file size (Mb)",
    )
    parser.add_argument(
        "--timeout",
        type=str,
        default=dropzone_timeout,
        help="Timeout (ms) for each chuck upload",
    )
    parser.add_argument("--chunk-size", type=str, default=dropzone_chunk_size, help="Chunk size (bytes)")
    parser.add_argument("--disable-parallel-chunks", required=False, default=False, action="store_true")
    parser.add_argument("--disable-force-chunking", required=False, default=False, action="store_true")
    parser.add_argument("-a", "--allow-downloads", required=False, default=False, action="store_true")
    parser.add_argument("--dz-cdn", type=str, default=None, required=False)
    parser.add_argument("--dz-version", type=str, default=None, required=False)
    parser.add_argument("-ae", "--encryption_algorithm", dest="encryption_algorithm",
        choices=["aes", "camellia", "chacha20"], default="aes", help="the algorithm for authenticated encryption of messages")
    parser.add_argument("-aead", "--encryption_algorithm_additional_data", dest="encryption_algorithm_additional_data",
        choices=["aes", "chacha20"], default="aes", help="the algorithm for authenticated encryption and additional data of messages")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    storage_path = Path(args.storage)
    chunk_path = Path(args.chunks)
    dropzone_chunk_size = args.chunk_size
    dropzone_timeout = args.timeout
    dropzone_max_file_size = args.max_size
    try:
        if int(dropzone_timeout) < 1 or int(dropzone_chunk_size) < 1 or int(dropzone_max_file_size) < 1:
            raise Exception("Invalid dropzone option, make sure max-size, timeout, and chunk-size are all positive")
    except ValueError:
        raise Exception("Invalid dropzone option, make sure max-size, timeout, and chunk-size are all integers")

    if args.dz_cdn:
        dropzone_cdn = args.dz_cdn
    if args.dz_version:
        dropzone_version = args.dz_version
    if args.disable_parallel_chunks:
        dropzone_parallel_chunks = "false"
    if args.disable_force_chunking:
        dropzone_force_chunking = "false"
    if args.allow_downloads:
        allow_downloads = True

    if not storage_path.exists():
        storage_path.mkdir(exist_ok=True)
    if not chunk_path.exists():
        chunk_path.mkdir(exist_ok=True)

    print(
        f"""Timeout: {int(dropzone_timeout) // 1000} seconds per chunk
Chunk Size: {int(dropzone_chunk_size) // 1024} Kb
Max File Size: {int(dropzone_max_file_size)} Mb
Force Chunking: {dropzone_force_chunking}
Parallel Chunks: {dropzone_parallel_chunks}
Storage Path: {storage_path.absolute()}
Chunk Path: {chunk_path.absolute()}
"""
    )
    
    if not(os.path.isfile("masterkey.key")):
        MASTER_KEY =  os.urandom(32)
        with open("masterkey.key", "wb") as archivo:
            archivo.write(MASTER_KEY)
    else:
        with open("masterkey.key", "rb") as archivo:
            MASTER_KEY = archivo.read()
    server = WSGIServer(("localhost", 443), app)
    server.ssl_adapter = BuiltinSSLAdapter(certificate='cert.pem', private_key='key.pem')
    print(f"URL access of the platform: https://localhost")
    server.start()