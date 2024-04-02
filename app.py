from argparse import ArgumentParser
from tokenize import String
from client import Client
from datetime import datetime, timedelta
import threading, time

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-em", "--encrypt_master_key", dest="encrypt_master_key", help="Encrypt all files using just master key (MK).", required=False)
    parser.add_argument("-ed", "--encrypt_data_key", dest="encrypt_data_key", help="Encrypt all files using a data encryption key (DEK) protected with master key (MK) and a password.", required=False)
    parser.add_argument("-d", "--decrypt", dest="decrypt", help="Decrypt a file", required=False)
    parser.add_argument("-dr", "--decrypt-rotation", dest="decrypt_rotation", help="Decrypt a file that has been encrypted with key rotation", required=False)
    parser.add_argument("-kt", "--key_timeout", dest="key_timeout", type=int, default=0, help="The time after which we need to regenerate the encryption keys in seconds")
    args = vars(parser.parse_args())
    print(args)
    client = Client(args)
