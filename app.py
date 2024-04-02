from argparse import ArgumentParser
from client import Client


def main():
    parser = ArgumentParser()

    parser.add_argument(
        "-em",
        "--encrypt_master_key",
        dest="encrypt_master_key",
        default=False, action='store_true',
        help="Encrypt all files using just master key (MK)."
    )

    parser.add_argument(
        "-ed",
        "--encrypt_data_key",
        dest="encrypt_data_key",
        default=False,
        action='store_true',
        help="Encrypt all files using a data encryption key (DEK) protected with master key (MK) and a password."
    )

    parser.add_argument(
        "-d",
        "--decrypt",
        dest="decrypt",
        help="Decrypt a file",
        required=False
    )

    args = vars(parser.parse_args())
    client = Client(args)


if __name__ == "__main__":
    main()
